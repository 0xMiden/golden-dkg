//! Shared harness for the BLS12-381/Jubjub Golden eVRF and DKG benchmarks.
//!
//! Mirrors `crates/golden-evrf/benches/support_dir/mod.rs`'s Secp/Secq
//! harness, including its checked-in dealer-message fixture cache (see
//! [`fixture_cache`]) — this backend's own on-disk namespace lives under
//! `benches/fixtures/dealer-messages-bls-jubjub/`, since the two backends'
//! wire encodings aren't interchangeable.
//!
//! Numbers from these benches are NOT comparable 1:1 with Tables 4 and 5 of
//! the paper: the paper zkalc-*estimates* BLS12-381 costs rather than
//! measuring a real implementation. We report real measurements here, the
//! paper reports asymptotic estimates. Treat the comparison as directional.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::type_complexity)]

use golden_bls_jubjub::golden_group::{JubjubGoldenGroup, JubjubScalar};
use golden_core::{
    DkgConfig, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::bls_jubjub::{
    evrf_batched_prove, evrf_batched_verify, testing, BatchedEvrfPublicParams,
    BatchedEvrfStatement, BatchedEvrfWitness, Gin, GinScalar, R1csField,
};
use golden_evrf::paper::MESSAGE_BYTES;
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// Table 4 columns: number of receiver statements covered by one batched
/// proof, matching the paper's `{1, 9, 49, 99}` sweep.
pub const NE_VALUES: &[usize] = &[1, 9, 49, 99];

/// Threshold used by the Table 4 helpers, matching `secp_secq`'s.
pub const TABLE4_THRESHOLD: usize = 2;

/// Table 5 columns: number of DKG participants in an n-of-n configuration,
/// matching the paper's `{2, 10, 50, 100}` sweep.
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
    selected_values("GOLDEN_BLS_TABLE4_NE_VALUES", NE_VALUES)
}

/// Table 5 rows selected for this run.
pub fn table5_n_values() -> Vec<usize> {
    selected_values("GOLDEN_BLS_TABLE5_N_VALUES", N_VALUES)
}

/// Sample size passed to criterion for the slowest benches.
pub const SLOW_SAMPLE_SIZE: usize = 10;

/// Deterministic seed used across all bench setup so reruns are reproducible.
pub const BENCH_SEED: [u8; 32] = [7u8; 32];

/// Build a `ParticipantIndex` for value `v` (1-indexed; 0 is reserved for the
/// polynomial secret).
pub fn idx(v: u32) -> ParticipantIndex {
    ParticipantIndex::new(v).unwrap()
}

/// Deterministic identity secret for participant `p` (paper-style: `100 + p`).
pub fn identity_secret(p: ParticipantIndex) -> JubjubScalar {
    JubjubScalar::from_u64(100 + u64::from(p.get())).unwrap()
}

/// Build a deterministic receiver public key for a synthetic receiver with
/// index `j` (1-indexed), used to drive the eVRF prover in isolation without
/// paying the cost of a full DKG `create_dealing`.
pub fn synthetic_pkj(j: usize) -> Gin {
    let sk = GinScalar::from(1_000 + j as u64);
    Gin::generator() * sk
}

/// Build a `DkgConfig` for `n` participants at threshold `t`.
pub fn build_config(n: usize, t: usize) -> DkgConfig<JubjubGoldenGroup> {
    let participants: Vec<_> = (1..=n as u32).map(idx).collect();
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|p| (*p, JubjubGoldenGroup::mul_generator(&identity_secret(*p))))
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        t,
        SessionId([42u8; 32]),
        JubjubScalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

/// Build a batched eVRF statement/witness pair covering exactly `n_e`
/// receivers, using the in-crate `testing::build_batched` helper.
pub fn build_batched_at_ne(
    n_e: usize,
) -> (
    BatchedEvrfStatement,
    BatchedEvrfWitness,
    Vec<Gin>,
    R1csField,
) {
    let mut msg = [0u8; MESSAGE_BYTES];
    msg[0] = 0x42;
    let sk1 = GinScalar::from(7u64);
    let pkjs: Vec<Gin> = (0..n_e).map(synthetic_pkj).collect();
    let beta = R1csField::from(77u64);
    let (statement, witness) = testing::build_batched(&msg, sk1, &pkjs, beta);
    assert_eq!(statement.threshold, TABLE4_THRESHOLD);
    (statement, witness, pkjs, beta)
}

/// Build and prove one batched eVRF proof covering `n_e` receivers.
pub fn prove_one_batched(n_e: usize) -> (BatchedEvrfPublicParams, BatchedEvrfStatement, Vec<u8>) {
    let (statement, witness, _pkjs, _beta) = build_batched_at_ne(n_e);
    let params = BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len())
        .expect("valid public parameter shape");
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let proof = evrf_batched_prove(&params, &statement, &witness, &mut rng).unwrap();
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    evrf_batched_verify(&params, &statement, &proof, &mut rng).unwrap();
    (params, statement, proof)
}

mod fixture_cache;
#[allow(unused_imports)]
pub use fixture_cache::{
    cached_dealer_messages, cached_round1_setup, regenerate_dealer_messages, verify_dealer_messages,
};
