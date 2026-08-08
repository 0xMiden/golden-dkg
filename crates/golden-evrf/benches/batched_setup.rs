//! Transparent parameter setup benchmarks for batched paper eVRF shapes.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use golden_evrf::paper::secp_secq::BatchedEvrfPublicParams;

fn bench_batched_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper eVRF batched parameter setup");
    group.sample_size(10);
    for receiver_count in [1usize, 4, 9] {
        group.bench_function(format!("2 coefficients/{receiver_count} receivers"), |b| {
            b.iter(|| {
                BatchedEvrfPublicParams::setup(black_box(2), black_box(receiver_count))
                    .expect("valid public parameter shape")
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_batched_setup);
criterion_main!(benches);
