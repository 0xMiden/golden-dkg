//! Shared harness for the Secp/Secq Golden DKG benchmarks.
//!
//! The harness drives the public `deal` / opaque bytes / `complete` workflow
//! with explicitly prepared `SecpSecqBulletproofs` state. A pair of private
//! recording adapters captures the flat proof inputs already constructed by
//! core when a benchmark needs to isolate the production prover or verifier;
//! it does not recreate a second statement-building seam.
//!
//! Numbers from these benches are NOT comparable 1:1 with Tables 4 and 5 of
//! the paper. The paper zkalc-estimates BLS12-381; this tree implements the
//! Secp256k1/Secq256k1 curve cycle. We report real measurements here, the
//! paper reports asymptotic estimates. Treat the comparison as directional.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::type_complexity)]

use std::sync::Mutex;

use golden_core::{
    complete, deal, DealerProofRef, DealerProofStatement, DealerProofSystem, DealerProofWitness,
    DkgConfig, GoldenGroup, GoldenScalar, OwnDealing, ParticipantIndex, ParticipantRegistry,
    Result, SessionId,
};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::CryptoRngCore;

/// Table 4 columns: number of receiver statements covered by one batched
/// proof. The paper sweeps `n_e in {1, 9, 49, 99}` (DKG application: `n_e`
/// receivers for an `(n_e + 1)`-participant DKG).
pub const NE_VALUES: &[usize] = &[1, 9, 49, 99];

/// Threshold used by the Table 4 helpers.
pub const TABLE4_THRESHOLD: usize = 2;

/// Table 5 columns: number of DKG participants in an `(n - 1)`-of-`n`
/// configuration.
pub const N_VALUES: &[usize] = &[2, 10, 50, 100];

fn selected_values(variable: &str, defaults: &[usize]) -> Vec<usize> {
    std::env::var(variable).map_or_else(
        |_| defaults.to_vec(),
        |raw| {
            raw.split(',')
                .map(|value| {
                    value
                        .parse()
                        .expect("benchmark row must be a positive integer")
                })
                .collect()
        },
    )
}

/// Table 4 rows selected for this run.
pub fn table4_ne_values() -> Vec<usize> {
    selected_values("GOLDEN_TABLE4_NE_VALUES", NE_VALUES)
}

/// Table 5 rows selected for this run.
pub fn table5_n_values() -> Vec<usize> {
    selected_values("GOLDEN_TABLE5_N_VALUES", N_VALUES)
}

/// Sample size passed to criterion for the slowest benches.
pub const SLOW_SAMPLE_SIZE: usize = 10;

/// Deterministic seed used across all bench setup so reruns are reproducible.
pub const BENCH_SEED: [u8; 32] = [7u8; 32];

/// Build a `ParticipantIndex` for value `v`.
pub fn idx(v: u32) -> ParticipantIndex {
    ParticipantIndex::new(v).unwrap()
}

/// Deterministic identity secret for participant `p`.
pub fn identity_secret(p: ParticipantIndex) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(100 + u64::from(p.get())).unwrap()
}

/// Build a `DkgConfig` for `n` participants at threshold `t`.
pub fn build_config(n: usize, t: usize) -> DkgConfig<Secp256k1GoldenGroup> {
    let participants: Vec<_> = (1..=n as u32).map(idx).collect();
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|p| {
                (
                    *p,
                    Secp256k1GoldenGroup::mul_generator(&identity_secret(*p)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new_random(t, SessionId([42u8; 32]), registry).unwrap()
}

type CapturedProverInputs = (
    DealerProofStatement<Secp256k1GoldenGroup>,
    DealerProofWitness<Secp256k1GoldenGroup>,
    Vec<u8>,
);

/// Private adapter which delegates to production and records the exact flat
/// inputs core supplied to the prover.
struct RecordingProver<'a> {
    inner: &'a SecpSecqBulletproofs,
    captured: Mutex<Option<CapturedProverInputs>>,
}

impl<'a> RecordingProver<'a> {
    fn new(inner: &'a SecpSecqBulletproofs) -> Self {
        Self {
            inner,
            captured: Mutex::new(None),
        }
    }

    fn take(&self) -> CapturedProverInputs {
        self.captured
            .lock()
            .unwrap()
            .take()
            .expect("deal must invoke the production prover exactly once")
    }
}

impl DealerProofSystem<Secp256k1GoldenGroup> for RecordingProver<'_> {
    fn prove(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        witness: &DealerProofWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let proof = self.inner.prove(config, statement, witness, rng)?;
        let previous = self.captured.lock().unwrap().replace((
            statement.clone(),
            witness.clone(),
            proof.clone(),
        ));
        assert!(previous.is_none(), "one deal must produce one dealer proof");
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

/// Inputs needed to isolate one production dealer proof.
pub struct DealerProofFixture {
    pub config: DkgConfig<Secp256k1GoldenGroup>,
    pub proof_system: SecpSecqBulletproofs,
    pub statement: DealerProofStatement<Secp256k1GoldenGroup>,
    pub witness: DealerProofWitness<Secp256k1GoldenGroup>,
    pub proof: Vec<u8>,
}

/// Build one real Main Golden dealer proof covering exactly `n_e` receivers.
pub fn dealer_proof_fixture(n_e: usize) -> DealerProofFixture {
    let config = build_config(n_e + 1, TABLE4_THRESHOLD);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let dealer = idx(1);
    let (statement, witness, proof) = {
        let recorder = RecordingProver::new(&proof_system);
        let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
        deal(
            &recorder,
            &config,
            dealer,
            &identity_secret(dealer),
            &mut rng,
        )
        .unwrap();
        recorder.take()
    };
    proof_system.verify(&config, &statement, &proof).unwrap();
    DealerProofFixture {
        config,
        proof_system,
        statement,
        witness,
        proof,
    }
}

/// Private adapter which delegates one honest completion and records the
/// ordered flat statement/proof collection supplied to batch verification.
struct RecordingVerifier<'a> {
    inner: &'a SecpSecqBulletproofs,
    captured: Mutex<Option<Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)>>>,
}

impl<'a> RecordingVerifier<'a> {
    fn new(inner: &'a SecpSecqBulletproofs) -> Self {
        Self {
            inner,
            captured: Mutex::new(None),
        }
    }

    fn take(&self) -> Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)> {
        self.captured
            .lock()
            .unwrap()
            .take()
            .expect("complete must invoke batch verification")
    }
}

impl DealerProofSystem<Secp256k1GoldenGroup> for RecordingVerifier<'_> {
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
        self.inner.verify(config, statement, proof)
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        proofs: &[DealerProofRef<'_, Secp256k1GoldenGroup>],
    ) -> Result<()> {
        self.inner.verify_batch(config, proofs)?;
        let captured = proofs
            .iter()
            .map(|item| (item.statement.clone(), item.proof.to_vec()))
            .collect();
        let previous = self.captured.lock().unwrap().replace(captured);
        assert!(
            previous.is_none(),
            "honest completion must batch-verify exactly once"
        );
        Ok(())
    }
}

/// Complete once through the public workflow and return the exact ordered
/// proof inputs observed by the optimized verifier.
pub fn capture_verified_proofs(
    proof_system: &SecpSecqBulletproofs,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    participant: ParticipantIndex,
    own_dealing: &OwnDealing<Secp256k1GoldenGroup>,
    peer_dealer_messages: &[(ParticipantIndex, Vec<u8>)],
) -> Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)> {
    let recorder = RecordingVerifier::new(proof_system);
    complete(
        &recorder,
        config,
        &identity_secret(participant),
        own_dealing,
        peer_dealer_messages,
    )
    .unwrap();
    recorder.take()
}

mod fixture_cache;
#[allow(unused_imports)]
pub use fixture_cache::{
    cached_dealer_bytes, cached_proof_lengths, cached_round1_setup, regenerate_dealer_messages,
    validate_dealer_fixture,
};
