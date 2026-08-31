//! Table 4 prover column over the Secp256k1/Secq256k1 cycle:
//! production `DealerProofSystem::prove` cost as a function of the number of
//! receiver statements `n_e` covered by one dealer proof.
//!
//! The timed region is the Bulletproofs R1CS prover only. Statement/witness
//! construction is outside the timed region. A private recording adapter gets
//! the exact flat statement and witness from one public `deal` call; the timed
//! region invokes the production proof system directly on those inputs.
//!
//! Compare against Table 4 (BLS12-381, zkalc):
//! n_e=1 -> 0.3s, n_e=9 -> 1.8s, n_e=49 -> 6.8s, n_e=99 -> 13.5s.
//! Direction: scales roughly linearly in `n_e`. Our numbers will differ in
//! absolute terms because this proof system runs over Secp256k1/Secq256k1, not
//! BLS12-381.
//!
//! `GOLDEN_TABLE4_NE_VALUES` may select a comma-separated subset for tracked
//! runs. Local runs use the complete paper row set by default.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use golden_core::DealerProofSystem;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{dealer_proof_fixture, table4_ne_values, BENCH_SEED, SLOW_SAMPLE_SIZE};

fn evrf_prove_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/Secp256k1-Secq256k1/prover");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let fixture = dealer_proof_fixture(n_e);
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    fixture
                        .proof_system
                        .prove(
                            &fixture.config,
                            &fixture.statement,
                            &fixture.witness,
                            &mut rng,
                        )
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, evrf_prove_bench);
criterion_main!(benches);
