//! Table 4 verifier columns over BLS12-381/Jubjub.
//!
//! Two groups per `n_e`:
//!
//! 1. `paper/table-4/BLS12-381-Jubjub/verifier` runs `evrf_batched_verify` on
//!    one proof covering `n_e` statements. Compare to the paper's "Verifier"
//!    column: n_e=1 -> 0.1s, n_e=9 -> 0.5s, n_e=49 -> 2.5s, n_e=99 -> 4.8s.
//!
//! 2. `paper/table-4/BLS12-381-Jubjub/batch-verification` runs the DKG
//!    receiver's actual Round 1 work over `n_e` independent dealer messages.
//!    Compare to the paper's "Batch Verification" column:
//!    0.6s / 6.7s / 22.1s at n_e = 9 / 49 / 99.
//!
//! `GOLDEN_BLS_TABLE4_NE_VALUES` may select a comma-separated subset.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "bls_support_dir/mod.rs"]
mod support;

use std::collections::BTreeMap;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use golden_bls_jubjub::golden_group::JubjubGoldenGroup;
use golden_core::{verify_dealings, DealerMessage, DkgConfig};
use golden_evrf::paper::bls_jubjub::{evrf_batched_verify, BlsJubjubBackend};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{
    build_config, idx, prove_one_batched, table4_ne_values, BENCH_SEED, SLOW_SAMPLE_SIZE,
    TABLE4_THRESHOLD,
};

/// Time `evrf_batched_verify` on one precomputed proof covering `n_e`
/// statements.
fn evrf_verify_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/BLS12-381-Jubjub/verifier");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let (params, statement, proof) = prove_one_batched(n_e);
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    evrf_batched_verify(&params, &statement, &proof, &mut rng).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Build `n_e` independent dealer messages for an `(n_e + 1)`-participant
/// DKG (threshold 2).
fn build_n_independent_messages(
    n_e: usize,
) -> (
    DkgConfig<JubjubGoldenGroup>,
    BTreeMap<golden_core::ParticipantIndex, DealerMessage<JubjubGoldenGroup>>,
) {
    let n = n_e + 1;
    let config = build_config(n, TABLE4_THRESHOLD);
    let receiver = idx(n as u32);
    let mut messages = support::cached_dealer_messages(&config);
    messages.remove(&receiver);
    assert_eq!(messages.len(), n_e);
    (config, messages)
}

/// Time `verify_dealings` over `n_e` independent dealer messages.
fn evrf_verify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/BLS12-381-Jubjub/batch-verification");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let (config, messages) = build_n_independent_messages(n_e);
            let peer_messages: Vec<_> = messages.values().cloned().collect();
            let peer_refs: Vec<_> = peer_messages.iter().collect();
            verify_dealings::<JubjubGoldenGroup, BlsJubjubBackend>(&peer_refs, &config).unwrap();
            b.iter_batched(
                || peer_messages.clone(),
                |msgs| {
                    let refs: Vec<_> = msgs.iter().collect();
                    verify_dealings::<JubjubGoldenGroup, BlsJubjubBackend>(&refs, &config).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    evrf_verify_single(c);
    evrf_verify_batch(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
