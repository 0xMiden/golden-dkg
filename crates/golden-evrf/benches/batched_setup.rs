//! Prepared-generator setup benchmarks for production Main Golden shapes.
//!
//! `BulletproofGens` derivation is memoized process-wide (see
//! `bulletproofs_cycle::generators`), so each sample clears that cache first
//! to keep measuring cold derivation cost, not cache hits.

#![allow(missing_docs)]

use codspeed_criterion_compat as criterion;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use golden_core::{
    DkgConfig, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::secp_secq::SecpSecqPreparedGenerators;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};

fn config(receiver_count: usize) -> DkgConfig<Secp256k1GoldenGroup> {
    let registry = ParticipantRegistry::new(
        (1..=receiver_count + 1)
            .map(|value| {
                let participant = ParticipantIndex::new(value as u32)
                    .expect("benchmark participants are positive");
                let secret = Secp256k1Scalar::from_u64(100 + value as u64)
                    .expect("small benchmark identity secret is canonical");
                (participant, Secp256k1GoldenGroup::mul_generator(&secret))
            })
            .collect(),
    )
    .expect("benchmark registry is valid");
    DkgConfig::new_random(2, SessionId([42u8; 32]), registry)
        .expect("benchmark configuration is valid")
}

fn bench_prepared_generators(c: &mut Criterion) {
    let mut group = c.benchmark_group("Main Golden prepared-generator setup");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    for receiver_count in [1usize, 4, 9] {
        let config = config(receiver_count);
        group.bench_function(format!("2 coefficients/{receiver_count} receivers"), |b| {
            b.iter_batched(
                bulletproofs_cycle::generators::clear_generator_cache,
                |()| {
                    SecpSecqPreparedGenerators::prepare_for(black_box(&config))
                        .expect("valid production proof shape")
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prepared_generators);
criterion_main!(benches);
