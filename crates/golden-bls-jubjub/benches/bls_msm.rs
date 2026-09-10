#![allow(missing_docs)]

use bls12_381::Scalar;
use bulletproofs_cycle::{generators::BulletproofGens, Cycle};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use golden_bls_jubjub::Bls12_381G1Cycle;

type C = Bls12_381G1Cycle;

const MSM_SIZES: &[usize] = &[2, 16, 256, 8_192, 65_536, 262_144, 524_288];

fn msm_benchmarks(c: &mut Criterion) {
    let max_size = *MSM_SIZES.last().expect("MSM sizes are nonempty");
    let generators = BulletproofGens::<C>::new(max_size, 1);
    let affine: Vec<_> = generators.share(0).G(max_size).copied().collect();
    let projective: Vec<_> = affine.iter().map(C::affine_to_point).collect();
    let scalars: Vec<_> = (0..max_size)
        .map(|i| Scalar::from((i as u64).wrapping_mul(0x9e37_79b9).wrapping_add(1)))
        .collect();

    for &size in MSM_SIZES {
        let expected = C::vartime_msm_affine(&scalars[..size], &affine[..size]);
        assert_eq!(
            expected,
            C::vartime_msm(&scalars[..size], &projective[..size])
        );
    }

    let mut affine_group = c.benchmark_group("bls12-381/msm/affine-preprocessed");
    affine_group.sample_size(10);
    for &size in MSM_SIZES {
        affine_group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                black_box(C::vartime_msm_affine(
                    black_box(&scalars[..size]),
                    black_box(&affine[..size]),
                ))
            });
        });
    }
    affine_group.finish();

    let mut projective_group = c.benchmark_group("bls12-381/msm/projective-input");
    projective_group.sample_size(10);
    for &size in MSM_SIZES {
        projective_group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                black_box(C::vartime_msm(
                    black_box(&scalars[..size]),
                    black_box(&projective[..size]),
                ))
            });
        });
    }
    projective_group.finish();
}

criterion_group!(benches, msm_benchmarks);
criterion_main!(benches);
