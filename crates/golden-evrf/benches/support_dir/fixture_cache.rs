//! Checked-in opaque dealer-message fixtures shared across benches.
//!
//! Each hard-cut fixture persists exactly one designated participant's
//! `OwnDealing` through its validated application serde representation,
//! plus every dealer's opaque bytes, proof length, and proof digest. Before a
//! fixture is accepted, that local state and all exact opaque bytes pass
//! through `complete`; a private delegating proof system also binds the
//! recorded proof metadata to the proof suffixes core parsed.
//!
//! Bench loads may trust a matching `.sha256` sidecar after that completion
//! check has been performed once. The CI check and the regeneration example
//! always complete again, so verifier regressions cannot hide behind a stale
//! but byte-identical fixture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use golden_core::{
    complete, deal, DealerProofRef, DealerProofStatement, DealerProofSystem, DealerProofWitness,
    DkgConfig, Error, OwnDealing, ParticipantIndex, Result,
};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{identity_secret, BENCH_SEED};

const FIXTURE_MAGIC: [u8; 8] = *b"GDKGBF01";
const FIXTURE_HEADER_BYTES: usize = FIXTURE_MAGIC.len() + 4;
/// Bench fixtures are trusted application persistence, but a corrupt checkout
/// must still fail before an unbounded read or allocation.
const MAX_FIXTURE_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// One tagged frame contains either one opaque dealer message plus metadata or
/// the designated participant's persisted local state.
const MAX_FIXTURE_FRAME_BYTES: usize = 20 * 1024 * 1024;

/// The command printed in panic/log messages so a stale or missing fixture
/// tells the reader exactly how to fix it.
const REGENERATE_HINT: &str = "cargo run --profile optimized --example warm_bench_fixtures \
    --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel,golden-evrf/serde";

#[derive(Serialize, Deserialize)]
struct CachedDealerMessage {
    dealer: ParticipantIndex,
    dealer_message_bytes: Vec<u8>,
    proof_len: u64,
    proof_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
enum CachedFrame {
    OwnDealing(OwnDealing<Secp256k1GoldenGroup>),
    DealerMessage(CachedDealerMessage),
}

#[derive(Serialize)]
enum CachedFrameRef<'a> {
    OwnDealing(&'a OwnDealing<Secp256k1GoldenGroup>),
    DealerMessage(&'a CachedDealerMessage),
}

struct CachedFixture {
    own_dealing: OwnDealing<Secp256k1GoldenGroup>,
    dealer_messages: BTreeMap<ParticipantIndex, CachedDealerMessage>,
}

fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures/dealer-messages")
}

fn cache_path(threshold: usize, n: usize) -> PathBuf {
    cache_dir().join(format!("t{threshold}-n{n}.bin"))
}

/// Sidecar path recording a fixture's last-verified SHA-256 digest.
fn stamp_path(threshold: usize, n: usize) -> PathBuf {
    cache_dir().join(format!("t{threshold}-n{n}.bin.sha256"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Write `stamp_path(threshold, n)` recording `digest` as verified.
/// Best-effort: a failed write only costs the next load a fresh completion.
fn write_stamp(threshold: usize, n: usize, digest: &str) {
    let path = stamp_path(threshold, n);
    let tmp_path = path.with_extension("sha256.tmp");
    if fs::write(&tmp_path, digest).is_ok() {
        let _ = fs::rename(&tmp_path, &path);
    }
}

struct RecordingProofSystem<'a> {
    inner: &'a SecpSecqBulletproofs,
    proof: std::sync::Mutex<Option<(ParticipantIndex, Vec<u8>)>>,
}

impl<'a> RecordingProofSystem<'a> {
    fn new(inner: &'a SecpSecqBulletproofs) -> Self {
        Self {
            inner,
            proof: std::sync::Mutex::new(None),
        }
    }

    fn take(&self) -> (ParticipantIndex, Vec<u8>) {
        self.proof
            .lock()
            .unwrap()
            .take()
            .expect("deal must invoke the production prover")
    }
}

impl DealerProofSystem<Secp256k1GoldenGroup> for RecordingProofSystem<'_> {
    fn prove(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        witness: &DealerProofWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let proof = self.inner.prove(config, statement, witness, rng)?;
        let previous = self
            .proof
            .lock()
            .unwrap()
            .replace((statement.dealer(), proof.clone()));
        assert!(previous.is_none(), "one deal must produce one proof");
        Ok(proof)
    }

    fn verify(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        proof: &[u8],
    ) -> Result<()> {
        self.inner.verify(config, statement, proof)
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        proofs: &[DealerProofRef<'_, Secp256k1GoldenGroup>],
    ) -> Result<()> {
        self.inner.verify_batch(config, proofs)
    }
}

/// Build every opaque dealer message and the canonical last participant's
/// local state, sequentially consuming one seeded RNG in registry order.
fn build_dealings(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
) -> CachedFixture {
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let designated = config
        .registry()
        .indexes()
        .last()
        .expect("validated registry must not be empty");
    let mut designated_own_dealing = None;
    let mut dealer_messages = BTreeMap::new();

    for dealer in config.registry().indexes() {
        let recorder = RecordingProofSystem::new(proof_system);
        let own_dealing = deal(
            &recorder,
            config,
            dealer,
            &identity_secret(dealer),
            &mut rng,
        )
        .unwrap();
        let (proof_dealer, proof) = recorder.take();
        assert_eq!(proof_dealer, dealer);
        let cached_message = CachedDealerMessage {
            dealer,
            dealer_message_bytes: own_dealing.dealer_message_bytes().to_vec(),
            proof_len: u64::try_from(proof.len()).expect("proof length must fit u64"),
            proof_digest: sha256(&proof),
        };
        assert!(
            dealer_messages.insert(dealer, cached_message).is_none(),
            "validated registry indexes must be unique"
        );
        if dealer == designated {
            assert!(
                designated_own_dealing.replace(own_dealing).is_none(),
                "fixture must designate exactly one participant"
            );
        }
    }

    CachedFixture {
        own_dealing: designated_own_dealing.expect("designated participant must deal"),
        dealer_messages,
    }
}

fn encode_frame(buf: &mut Vec<u8>, frame: &CachedFrameRef<'_>) -> io::Result<()> {
    let encoded = postcard::to_allocvec(frame).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to encode fixture frame: {error}"),
        )
    })?;
    if encoded.len() > MAX_FIXTURE_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encoded fixture frame exceeds the application limit",
        ));
    }
    let len = u32::try_from(encoded.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "encoded fixture frame does not fit u32",
        )
    })?;
    let additional = 4usize
        .checked_add(encoded.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture size overflow"))?;
    let final_len = buf
        .len()
        .checked_add(additional)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture size overflow"))?;
    let final_len = u64::try_from(final_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture size does not fit u64"))?;
    if final_len > MAX_FIXTURE_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encoded fixture exceeds the application limit",
        ));
    }
    buf.try_reserve_exact(additional)
        .map_err(|error| io::Error::other(format!("failed to allocate fixture frame: {error}")))?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&encoded);
    Ok(())
}

fn encode_cache(fixture: &CachedFixture) -> io::Result<Vec<u8>> {
    let frame_count = fixture
        .dealer_messages
        .len()
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture count overflow"))?;
    let count = u32::try_from(frame_count).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "fixture count does not fit u32")
    })?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&FIXTURE_MAGIC);
    buf.extend_from_slice(&count.to_be_bytes());
    encode_frame(&mut buf, &CachedFrameRef::OwnDealing(&fixture.own_dealing))?;
    for message in fixture.dealer_messages.values() {
        encode_frame(&mut buf, &CachedFrameRef::DealerMessage(message))?;
    }
    Ok(buf)
}

fn write_cache(threshold: usize, n: usize, buf: &[u8]) -> io::Result<()> {
    let len = u64::try_from(buf.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture size does not fit u64"))?;
    if len > MAX_FIXTURE_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture exceeds the application file limit",
        ));
    }
    let path = cache_path(threshold, n);
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, buf)?;
    fs::rename(&tmp_path, &path)?;
    write_stamp(threshold, n, &sha256_hex(buf));
    Ok(())
}

/// Decode only the current fixture envelope and exact application persistence
/// values. Any legacy, truncated, overlong, or trailing representation fails.
fn decode_cache(buf: &[u8], expected_dealer_count: usize) -> Option<CachedFixture> {
    if u64::try_from(buf.len()).ok()? > MAX_FIXTURE_FILE_BYTES {
        return None;
    }
    if buf.get(..FIXTURE_MAGIC.len())? != FIXTURE_MAGIC {
        return None;
    }
    let count_offset = FIXTURE_MAGIC.len();
    let count = u32::from_be_bytes(
        buf.get(count_offset..FIXTURE_HEADER_BYTES)?
            .try_into()
            .ok()?,
    );
    let count = usize::try_from(count).ok()?;
    if count != expected_dealer_count.checked_add(1)? {
        return None;
    }

    let mut offset = FIXTURE_HEADER_BYTES;
    let mut own_dealing = None;
    let mut dealer_messages = BTreeMap::new();
    for _ in 0..count {
        let end = offset.checked_add(4)?;
        let len = u32::from_be_bytes(buf.get(offset..end)?.try_into().ok()?);
        let len = usize::try_from(len).ok()?;
        if len > MAX_FIXTURE_FRAME_BYTES {
            return None;
        }
        offset = end;
        let end = offset.checked_add(len)?;
        let encoded = buf.get(offset..end)?;
        offset = end;
        let (frame, trailing) = postcard::take_from_bytes::<CachedFrame>(encoded).ok()?;
        if !trailing.is_empty() {
            return None;
        }
        match frame {
            CachedFrame::OwnDealing(dealing) => {
                if own_dealing.replace(dealing).is_some() {
                    return None;
                }
            }
            CachedFrame::DealerMessage(message) => {
                if dealer_messages.insert(message.dealer, message).is_some() {
                    return None;
                }
            }
        }
    }
    if offset != buf.len() || dealer_messages.len() != expected_dealer_count {
        return None;
    }
    Some(CachedFixture {
        own_dealing: own_dealing?,
        dealer_messages,
    })
}

struct FixtureVerifier<'a> {
    inner: &'a SecpSecqBulletproofs,
    proofs: BTreeMap<ParticipantIndex, (u64, [u8; 32])>,
}

impl FixtureVerifier<'_> {
    fn check(
        &self,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        proof: &[u8],
    ) -> Result<()> {
        let (expected_len, expected_digest) = self
            .proofs
            .get(&statement.dealer())
            .ok_or(Error::ProofVerificationFailed)?;
        if u64::try_from(proof.len()).ok() != Some(*expected_len)
            || sha256(proof) != *expected_digest
        {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    }
}

impl DealerProofSystem<Secp256k1GoldenGroup> for FixtureVerifier<'_> {
    fn prove(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        witness: &DealerProofWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.inner.prove(config, statement, witness, rng)
    }

    fn verify(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        proof: &[u8],
    ) -> Result<()> {
        self.check(statement, proof)?;
        self.inner.verify(config, statement, proof)
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        proofs: &[DealerProofRef<'_, Secp256k1GoldenGroup>],
    ) -> Result<()> {
        for proof in proofs {
            self.check(proof.statement, proof.proof)?;
        }
        self.inner.verify_batch(config, proofs)
    }
}

fn validate_fixture_shape(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    fixture: CachedFixture,
) -> Option<CachedFixture> {
    if fixture.dealer_messages.len() != config.registry().len()
        || !config
            .registry()
            .indexes()
            .eq(fixture.dealer_messages.keys().copied())
    {
        return None;
    }
    let designated = config.registry().indexes().last()?;
    if fixture.own_dealing.participant() != designated
        || fixture
            .dealer_messages
            .get(&designated)?
            .dealer_message_bytes
            .as_slice()
            != fixture.own_dealing.dealer_message_bytes()
    {
        return None;
    }
    Some(fixture)
}

fn validate_fixture(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
    fixture: &CachedFixture,
) -> Option<()> {
    let participant = fixture.own_dealing.participant();
    let peers: Vec<_> = fixture
        .dealer_messages
        .iter()
        .filter(|(dealer, _)| **dealer != participant)
        .map(|(dealer, message)| (*dealer, message.dealer_message_bytes.clone()))
        .collect();
    let verifier = FixtureVerifier {
        inner: proof_system,
        proofs: fixture
            .dealer_messages
            .iter()
            .map(|(dealer, message)| (*dealer, (message.proof_len, message.proof_digest)))
            .collect(),
    };
    complete(
        &verifier,
        config,
        &identity_secret(participant),
        &fixture.own_dealing,
        &peers,
    )
    .ok()?;
    Some(())
}

/// Load and validate the fixture for `(threshold, n)`.
fn load_valid(
    threshold: usize,
    n: usize,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
    force_verify: bool,
) -> Option<CachedFixture> {
    let path = cache_path(threshold, n);
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FIXTURE_FILE_BYTES {
        return None;
    }
    let raw = fs::read(path).ok()?;
    let raw_len = u64::try_from(raw.len()).ok()?;
    if raw_len != metadata.len() || raw_len > MAX_FIXTURE_FILE_BYTES {
        return None;
    }
    let fixture = validate_fixture_shape(config, decode_cache(&raw, n)?)?;

    let digest = sha256_hex(&raw);
    let already_verified = !force_verify
        && fs::read_to_string(stamp_path(threshold, n))
            .is_ok_and(|stamped| stamped.trim() == digest);
    if !already_verified {
        validate_fixture(config, proof_system, &fixture)?;
        write_stamp(threshold, n, &digest);
    }
    Some(fixture)
}

fn expect_valid(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
    force_verify: bool,
) -> CachedFixture {
    let n = config.registry().len();
    let threshold = config.threshold();
    let message = format!(
        "bench fixture missing or invalid at {}\n\
         Regenerate it with:\n  {REGENERATE_HINT}\n\
         then `git add` and commit the result.",
        cache_path(threshold, n).display()
    );
    load_valid(threshold, n, config, proof_system, force_verify).expect(&message)
}

/// Return every exact opaque dealer-message byte string from a checked-in
/// fixture. A matching sidecar may skip its already-completed validation.
pub fn cached_dealer_bytes(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
) -> BTreeMap<ParticipantIndex, Vec<u8>> {
    expect_valid(config, proof_system, false)
        .dealer_messages
        .into_iter()
        .map(|(dealer, message)| (dealer, message.dealer_message_bytes))
        .collect()
}

/// Return the production proof byte length recorded for every opaque fixture
/// message. Completion binds these values to the parsed proof suffixes.
pub fn cached_proof_lengths(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
) -> BTreeMap<ParticipantIndex, usize> {
    expect_valid(config, proof_system, false)
        .dealer_messages
        .into_iter()
        .map(|(dealer, message)| {
            (
                dealer,
                usize::try_from(message.proof_len).expect("fixture proof length must fit usize"),
            )
        })
        .collect()
}

/// Always complete the fixture through production rather than trusting its
/// sidecar. Used by the CI fixture gate.
pub fn validate_dealer_fixture(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
) -> usize {
    expect_valid(config, proof_system, true)
        .dealer_messages
        .len()
}

/// Rebuild one hard-cut fixture only when the current one cannot complete.
pub fn regenerate_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
) -> bool {
    let n = config.registry().len();
    if load_valid(config.threshold(), n, config, proof_system, true).is_some() {
        return false;
    }

    let fixture = build_dealings(config, proof_system);
    let encoded = encode_cache(&fixture).expect("new fixture persistence must encode");
    let restored = decode_cache(&encoded, n).expect("new fixture persistence must round trip");
    let restored =
        validate_fixture_shape(config, restored).expect("canonical designated fixture state");
    validate_fixture(config, proof_system, &restored)
        .expect("new fixture must complete before it is written");
    let message = format!(
        "failed to write bench fixture at {}",
        cache_path(config.threshold(), n).display()
    );
    write_cache(config.threshold(), n, &encoded).expect(&message);
    true
}

/// Restore one participant's matching `OwnDealing` and all peer opaque bytes
/// for a Round 1 completion benchmark.
pub fn cached_round1_setup(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    proof_system: &SecpSecqBulletproofs,
    receiver: ParticipantIndex,
) -> (
    OwnDealing<Secp256k1GoldenGroup>,
    Vec<(ParticipantIndex, Vec<u8>)>,
) {
    let fixture = expect_valid(config, proof_system, false);
    let designated = fixture.own_dealing.participant();
    assert_eq!(
        receiver, designated,
        "fixture stores local state only for the canonical last participant"
    );
    let peers = fixture
        .dealer_messages
        .into_iter()
        .filter(|(dealer, _)| *dealer != designated)
        .map(|(dealer, message)| (dealer, message.dealer_message_bytes))
        .collect();
    (fixture.own_dealing, peers)
}
