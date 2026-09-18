#![allow(missing_docs)]

use bls12_381::Scalar;
use bulletproofs_cycle::{generators::BulletproofGens, Cycle};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;
use golden_bls_jubjub::Bls12_381G1Cycle;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type C = Bls12_381G1Cycle;

const MSM_SIZES: &[usize] = &[2, 16, 256, 8_192, 65_536, 262_144, 524_288];

// Existing Bulletproof verifier equation shapes for Golden's Table 4 rows.
// Each equation evaluates two fixed-generator MSMs of `static_len` terms
// and one projective MSM of `dynamic_len` proof and Pedersen terms.
const GOLDEN_VERIFIER_SHAPES: &[(usize, usize)] =
    &[(8_192, 39), (65_536, 45), (262_144, 49), (524_288, 51)];

fn msm_benchmarks(c: &mut Criterion) {
    let max_size = *MSM_SIZES.last().expect("MSM sizes are nonempty");
    let generators = BulletproofGens::<C>::new(max_size, 1);
    let affine: Vec<_> = generators.share(0).G(max_size).copied().collect();
    let affine_h: Vec<_> = generators.share(0).H(max_size).copied().collect();
    let projective: Vec<_> = affine.iter().map(C::affine_to_point).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(0x676f_6c64_656e_6d73);
    let scalars: Vec<_> = (0..max_size).map(|_| Scalar::random(&mut rng)).collect();

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

    let mut verifier_group = c.benchmark_group("bls12-381/msm/golden-verifier-split");
    verifier_group.sample_size(10);
    for &(static_len, dynamic_len) in GOLDEN_VERIFIER_SHAPES {
        verifier_group.bench_with_input(
            BenchmarkId::new("static-dynamic", format!("{static_len}-{dynamic_len}")),
            &(static_len, dynamic_len),
            |b, &(static_len, dynamic_len)| {
                b.iter(|| {
                    let dynamic = C::vartime_msm(
                        black_box(&scalars[..dynamic_len]),
                        black_box(&projective[..dynamic_len]),
                    );
                    let g = C::vartime_msm_affine(
                        black_box(&scalars[..static_len]),
                        black_box(&affine[..static_len]),
                    );
                    let h = C::vartime_msm_affine(
                        black_box(&scalars[..static_len]),
                        black_box(&affine_h[..static_len]),
                    );
                    black_box(dynamic + g + h)
                });
            },
        );
    }
    verifier_group.finish();

    for &(static_len, dynamic_len) in GOLDEN_VERIFIER_SHAPES {
        let mut paired_group = c.benchmark_group(format!(
            "bls12-381/msm/golden-verifier-paired/{static_len}-{dynamic_len}"
        ));
        paired_group.sample_size(10);
        paired_group.bench_function("split", |b| {
            b.iter(|| {
                let dynamic = C::vartime_msm(
                    black_box(&scalars[..dynamic_len]),
                    black_box(&projective[..dynamic_len]),
                );
                let g = C::vartime_msm_affine(
                    black_box(&scalars[..static_len]),
                    black_box(&affine[..static_len]),
                );
                let h = C::vartime_msm_affine(
                    black_box(&scalars[..static_len]),
                    black_box(&affine_h[..static_len]),
                );
                black_box(dynamic + g + h)
            });
        });
        paired_group.bench_function("mixed", |b| {
            b.iter(|| {
                black_box(C::vartime_msm_mixed(
                    black_box(&[
                        (&scalars[..static_len], &affine[..static_len]),
                        (&scalars[..static_len], &affine_h[..static_len]),
                    ]),
                    black_box(&scalars[..dynamic_len]),
                    black_box(&projective[..dynamic_len]),
                ))
            });
        });
        paired_group.finish();
    }
}

criterion_group!(benches, msm_benchmarks);
criterion_main!(benches);
