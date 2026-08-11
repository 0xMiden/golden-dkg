//! Transparent parameter setup benchmarks for batched paper eVRF shapes.
//!
//! `BulletproofGens` derivation is memoized process-wide (see
//! `bulletproofs_cycle::generators`), so each sample clears that cache first
//! to keep measuring cold derivation cost, not cache hits.

#![allow(missing_docs)]

use codspeed_criterion_compat as criterion;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use golden_evrf::paper::secp_secq::BatchedEvrfPublicParams;

fn bench_batched_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper eVRF batched parameter setup");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    for receiver_count in [1usize, 4, 9] {
        group.bench_function(format!("2 coefficients/{receiver_count} receivers"), |b| {
            b.iter_batched(
                bulletproofs_cycle::generators::clear_generator_cache,
                |()| {
                    BatchedEvrfPublicParams::setup(black_box(2), black_box(receiver_count))
                        .expect("valid public parameter shape")
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_batched_setup);
criterion_main!(benches);
