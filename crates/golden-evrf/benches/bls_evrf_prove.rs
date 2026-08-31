//! Table 4 prover column over BLS12-381/Jubjub: `evrf_batched_prove` cost as
//! a function of the number of receiver statements `n_e` covered by one
//! batched proof.
//!
//! The timed region is the Bulletproofs R1CS prover only. Statement/witness
//! construction is outside the timed region via `iter_batched`.
//!
//! Compare against Table 4 (BLS12-381, zkalc):
//! n_e=1 -> 0.3s, n_e=9 -> 1.8s, n_e=49 -> 6.8s, n_e=99 -> 13.5s.
//! Our numbers will differ: these are real measurements against a real
//! circuit (see `crates/golden-evrf/src/paper/bls_jubjub.rs`), not zkalc's
//! asymptotic estimate.
//!
//! `GOLDEN_BLS_TABLE4_NE_VALUES` may select a comma-separated subset.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "bls_support_dir/mod.rs"]
mod support;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use golden_evrf::paper::bls_jubjub::{evrf_batched_prove, BatchedEvrfPublicParams};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{build_batched_at_ne, table4_ne_values, BENCH_SEED, SLOW_SAMPLE_SIZE};

fn evrf_prove_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/BLS12-381-Jubjub/prover");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let params = BatchedEvrfPublicParams::setup(support::TABLE4_THRESHOLD, n_e).unwrap();
            b.iter_batched(
                || {
                    let (statement, witness, _pkjs, _beta) = build_batched_at_ne(n_e);
                    let rng = ChaCha20Rng::from_seed(BENCH_SEED);
                    (statement, witness, rng)
                },
                |(statement, witness, mut rng)| {
                    evrf_batched_prove(&params, &statement, &witness, &mut rng).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, evrf_prove_bench);
criterion_main!(benches);
