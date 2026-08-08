//! Shared harness for the Secp/Secq Golden eVRF and DKG benchmarks.
//!
//! Mirrors the wiring in `crates/golden-evrf/tests/dkg_integration.rs` so the
//! benches drive the real public DKG surface (`create_dealing`, `verify_dealing`,
//! `complete`) bound to `SecpSecqBackend`, plus the in-crate batched eVRF
//! entry points (`evrf_batched_prove`, `evrf_batched_verify`) for Table 4
//! isolation of the Bulletproofs prover/verifier.
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

use std::collections::BTreeMap;

use golden_core::{
    DkgConfig, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::secp_secq::{
    evrf_batched_prove, evrf_batched_verify, testing, BatchedEvrfStatement, BatchedEvrfWitness,
    Gin, GinScalar, R1csField,
};
use golden_evrf::paper::MESSAGE_BYTES;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// Table 4 columns: number of receiver statements covered by one batched
/// proof. The paper sweeps `n_e in {1, 9, 49, 99}` (DKG application: `n_e`
/// receivers for an `(n_e + 1)`-participant DKG).
pub const NE_VALUES: &[usize] = &[1, 9, 49, 99];

/// Threshold used by the Table 4 helpers. The isolated batched fixture has
/// two Feldman coefficients, so full-DKG fixtures must use the same threshold.
pub const TABLE4_THRESHOLD: usize = 2;

/// Table 5 columns: number of DKG participants in an n-of-n configuration.
pub const N_VALUES: &[usize] = &[2, 10, 50, 100];

/// Sample size passed to criterion for the slowest benches. Matches the
/// `crates/bulletproofs-cycle/benches/r1cs.rs` convention: at `n_e = 99` a
/// single prove iteration is paper-estimated around 13.5s, so the default
/// `sample_size = 10` keeps wall time bounded.
pub const SLOW_SAMPLE_SIZE: usize = 10;

/// Deterministic seed used across all bench setup so reruns are reproducible.
pub const BENCH_SEED: [u8; 32] = [7u8; 32];

/// Build a `ParticipantIndex` for value `v` (1-indexed; 0 is reserved for the
/// polynomial secret).
pub fn idx(v: u32) -> ParticipantIndex {
    ParticipantIndex::new(v).unwrap()
}

/// Deterministic identity secret for participant `p` (paper-style: `100 + p`).
pub fn identity_secret(p: ParticipantIndex) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(100 + u64::from(p.get())).unwrap()
}

/// Build a deterministic receiver public key for a synthetic receiver with
/// index `j` (1-indexed), used to drive the eVRF prover in isolation without
/// paying the cost of a full DKG `create_dealing`.
pub fn synthetic_pkj(j: usize) -> Gin {
    // Distinct per-receiver secret; only the public key is needed by the
    // batched eVRF statement.
    let sk = GinScalar::from(1_000 + j as u64);
    Gin::generator() * sk
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
    DkgConfig::new(
        t,
        SessionId([42u8; 32]),
        Secp256k1Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

/// Build a batched eVRF statement/witness pair covering exactly `n_e`
/// receivers, using the in-crate `testing::build_batched` helper. Returns
/// everything needed to call `evrf_batched_prove` / `evrf_batched_verify`.
pub fn build_batched_at_ne(
    n_e: usize,
) -> (
    BatchedEvrfStatement,
    BatchedEvrfWitness,
    Vec<Gin>,
    R1csField,
) {
    // Distinct dealer message and sk1 from the test setup.
    let mut msg = [0u8; MESSAGE_BYTES];
    msg[0] = 0x42;
    let sk1 = GinScalar::from(7u64);
    let pkjs: Vec<Gin> = (0..n_e).map(synthetic_pkj).collect();
    let beta = R1csField::from(77u64);
    let (statement, witness) = testing::build_batched(&msg, sk1, &pkjs, beta);
    assert_eq!(statement.threshold, TABLE4_THRESHOLD);
    (statement, witness, pkjs, beta)
}

/// Build and prove one batched eVRF proof covering `n_e` receivers. Returns
/// `(statement, proof)` so callers can verify or measure size.
pub fn prove_one_batched(n_e: usize) -> (BatchedEvrfStatement, Vec<u8>) {
    let (statement, witness, _pkjs, _beta) = build_batched_at_ne(n_e);
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let proof = evrf_batched_prove(&statement, &witness, &mut rng).unwrap();
    // Sanity: the proof must verify before any bench iterates on it.
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    evrf_batched_verify(&statement, &proof, &mut rng).unwrap();
    (statement, proof)
}

/// Run a full DKG Round 0 for `n` participants and return all `n` dealings.
/// Each dealing carries one batched eVRF proof over `n - 1` receivers.
pub fn round0_all_dealings(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> BTreeMap<ParticipantIndex, golden_core::DkgDealing<Secp256k1GoldenGroup>> {
    use golden_core::create_dealing;
    use golden_evrf::paper::secp_secq::SecpSecqBackend;
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                &mut rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}
