//! Checked-in dealer-message fixtures shared across benches.
//!
//! Building `n` real dealer proofs is pure benchmark-harness cost, not what
//! `evrf_verify`, `dkg_round`, `evrf_proof_size`, or `dkg_communication`
//! measure. This module reads those `n` messages for a `(threshold, n)`
//! shape from `benches/fixtures/dealer-messages/` (wire-codec encoded and
//! git-tracked), so the cost is paid once and shared via git history.
//!
//! [`cached_dealer_messages`] and [`verify_dealer_messages`] (used by the
//! benches and CI's fixture-check job, respectively) are read-only: a
//! missing, corrupt, or stale fixture panics with regeneration
//! instructions instead of silently re-proving, so a real bug can't get
//! papered over by quietly rebuilding a still-valid-looking proof.
//!
//! [`regenerate_dealer_messages`] (used by the `warm_bench_fixtures`
//! example, the only writer) rebuilds a fixture only when it's missing or
//! invalid, so regenerating after a code change replaces just the files
//! whose proof bytes moved instead of piling up new ones.
//!
//! `verify_dealings` is real per-proof crypto work — tens of minutes at the
//! largest shape (`n = 100`). A `.sha256` sidecar next to each fixture
//! memoizes it: once a byte-identical file has verified, later loads trust
//! the sidecar and skip re-verifying. Editing a fixture without updating
//! its sidecar changes the digest and falls back to a real verify, so this
//! can't mask a fixture that actually changed. The shortcut is reserved for
//! [`cached_dealer_messages`] (bench loads); [`verify_dealer_messages`] and
//! [`regenerate_dealer_messages`] always re-verify, so a verifier
//! regression can't hide behind a stale-but-byte-identical fixture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::{fs, io};

use golden_core::wire::{from_wire_bytes, to_wire_bytes};
use golden_core::{create_dealing, verify_dealings, DealerMessage, DkgConfig, ParticipantIndex};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha256};

use super::{identity_secret, legacy_beta, BENCH_SEED};

/// The command printed in panic/log messages so a stale or missing fixture
/// tells the reader exactly how to fix it.
const REGENERATE_HINT: &str = "cargo run --profile optimized --example warm_bench_fixtures \
    --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel";

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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Write `stamp_path(threshold, n)` recording `digest` as verified.
/// Best-effort: a failed write only costs the next load a fresh
/// `verify_dealings`, it does not affect correctness.
fn write_stamp(threshold: usize, n: usize, digest: &str) {
    let path = stamp_path(threshold, n);
    let tmp_path = path.with_extension("sha256.tmp");
    if fs::write(&tmp_path, digest).is_ok() {
        let _ = fs::rename(&tmp_path, &path);
    }
}

/// Build all `n` dealer messages for `config` from scratch, sequentially
/// consuming one seeded RNG in registry order (dealer 1, 2, ..., n).
fn build_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> Vec<DealerMessage<Secp256k1GoldenGroup>> {
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    config
        .registry()
        .indexes()
        .map(|dealer| {
            create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                &legacy_beta(),
                &mut rng,
            )
            .unwrap()
            .message()
            .clone()
        })
        .collect()
}

fn write_cache(
    threshold: usize,
    n: usize,
    messages: &[DealerMessage<Secp256k1GoldenGroup>],
) -> io::Result<()> {
    let path = cache_path(threshold, n);
    fs::create_dir_all(path.parent().unwrap())?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&(messages.len() as u32).to_le_bytes());
    for message in messages {
        let encoded = to_wire_bytes(message);
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
    }
    // Write-then-rename so a crash never leaves a partially written file at
    // the tracked path (which `git status` would otherwise flag as dirty).
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &buf)?;
    fs::rename(&tmp_path, &path)?;
    // Freshly built messages are correct by construction (just proved
    // against `config`), so stamp them without re-verifying.
    write_stamp(threshold, n, &sha256_hex(&buf));
    Ok(())
}

/// Decode a cache file. Returns `None` on any structural problem (truncated
/// length prefixes, trailing bytes, bad wire encoding).
fn decode_cache(
    buf: &[u8],
    expected_count: usize,
) -> Option<Vec<DealerMessage<Secp256k1GoldenGroup>>> {
    let count = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    if count != expected_count {
        return None;
    }
    let mut offset = 4;
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_le_bytes(buf.get(offset..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        let encoded = buf.get(offset..offset + len)?;
        offset += len;
        messages.push(from_wire_bytes(encoded).ok()?);
    }
    (offset == buf.len()).then_some(messages)
}

/// Load and validate the fixture for `(threshold, n)`. `None` covers every
/// way it can be unusable: missing, truncated, wrong count, wrong dealer
/// set, or cryptographically invalid/stale.
///
/// Skips `verify_dealings` when the bytes match the `.sha256` sidecar,
/// unless `force_verify` is set — callers where a verifier regression must
/// not hide behind a stale-but-matching digest pass `true`. Either way, a
/// fresh verify updates the sidecar.
fn load_valid(
    threshold: usize,
    n: usize,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    force_verify: bool,
) -> Option<BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>>> {
    let raw = fs::read(cache_path(threshold, n)).ok()?;
    let messages = decode_cache(&raw, n)?;

    let digest = sha256_hex(&raw);
    let already_verified = !force_verify
        && fs::read_to_string(stamp_path(threshold, n))
            .is_ok_and(|stamped| stamped.trim() == digest);

    if !already_verified {
        let refs: Vec<_> = messages.iter().collect();
        verify_dealings::<Secp256k1GoldenGroup, SecpSecqBackend>(&refs, config, &legacy_beta())
            .ok()?;
        write_stamp(threshold, n, &digest);
    }

    let expected_dealers: BTreeSet<_> = config.registry().indexes().collect();
    let by_dealer: BTreeMap<_, _> = messages.into_iter().map(|m| (m.dealer, m)).collect();
    (by_dealer.keys().copied().collect::<BTreeSet<_>>() == expected_dealers).then_some(by_dealer)
}

/// Panics with regeneration instructions; shared by every fixture-loading
/// entry point below so a missing, corrupt, or stale fixture fails the same
/// way regardless of caller.
fn expect_valid(
    threshold: usize,
    n: usize,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    force_verify: bool,
) -> BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>> {
    let message = format!(
        "bench fixture missing or invalid at {}\n\
         Regenerate it with:\n  {REGENERATE_HINT}\n\
         then `git add` and commit the result.",
        cache_path(threshold, n).display()
    );
    load_valid(threshold, n, config, force_verify).expect(&message)
}

/// Return all `n` dealer messages for `config`, loaded from the checked-in
/// fixture at `benches/fixtures/dealer-messages/t{threshold}-n{n}.bin`.
///
/// Panics if the fixture is missing, corrupt, or no longer verifies against
/// `config` (e.g. the wire format or protocol changed) — callers regenerate
/// explicitly with the `warm_bench_fixtures` example rather than have this
/// silently re-prove and potentially mask a real regression. Trusts the
/// `.sha256` sidecar to skip `verify_dealings` on a byte-identical fixture;
/// use [`verify_dealer_messages`] where that shortcut isn't wanted.
pub fn cached_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>> {
    let n = config.registry().indexes().count();
    expect_valid(config.threshold(), n, config, false)
}

/// Like [`cached_dealer_messages`], but always re-runs `verify_dealings`
/// instead of trusting the `.sha256` sidecar.
///
/// Used by CI's fixture-check job, where trusting a stale-but-matching
/// digest would let a verifier regression stay hidden as long as the
/// fixture bytes hadn't changed.
pub fn verify_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>> {
    let n = config.registry().indexes().count();
    expect_valid(config.threshold(), n, config, true)
}

/// (Re)build the fixture for `config` and overwrite it on disk, but only if
/// the tracked file is missing or no longer valid. Returns `true` if it was
/// rebuilt, `false` if the existing fixture was already up to date.
pub fn regenerate_dealer_messages(config: &DkgConfig<Secp256k1GoldenGroup>) -> bool {
    let n = config.registry().indexes().count();
    if load_valid(config.threshold(), n, config, true).is_some() {
        return false;
    }
    let messages = build_dealer_messages(config);
    let message = format!(
        "failed to write bench fixture at {}",
        cache_path(config.threshold(), n).display()
    );
    write_cache(config.threshold(), n, &messages).expect(&message);
    true
}

/// Build the setup for one participant's Round 1: its own full dealing
/// (message plus `private_share`, which cannot be cached because it is
/// never put on the wire) alongside every peer's fixture message.
///
/// Only `receiver`'s dealing is proved fresh; the other `n - 1` messages
/// come from [`cached_dealer_messages`].
pub fn cached_round1_setup(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    receiver: ParticipantIndex,
) -> (
    golden_core::DkgDealing<Secp256k1GoldenGroup>,
    BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>>,
) {
    let mut peer_messages = cached_dealer_messages(config);
    peer_messages.remove(&receiver);

    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let own_dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        receiver,
        &identity_secret(receiver),
        config,
        &legacy_beta(),
        &mut rng,
    )
    .unwrap();

    (own_dealing, peer_messages)
}
