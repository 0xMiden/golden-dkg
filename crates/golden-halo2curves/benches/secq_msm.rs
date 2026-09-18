//! MSM schedules for Golden's vanilla Secq verifier equation.

#![allow(missing_docs)]

use bulletproofs_cycle::{BulletproofGens, Cycle};
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type C = Secq256k1Cycle;

// Existing Bulletproof verifier equation shapes for Golden's Table 4 rows.
const GOLDEN_VERIFIER_SHAPES: &[(usize, usize)] =
    &[(8_192, 39), (65_536, 45), (262_144, 49), (524_288, 51)];

fn split(
    static_scalars: &[<C as Cycle>::Scalar],
    dynamic_scalars: &[<C as Cycle>::Scalar],
    g: &[<C as Cycle>::Affine],
    h: &[<C as Cycle>::Affine],
    dynamic: &[<C as Cycle>::Point],
) -> <C as Cycle>::Point {
    C::vartime_msm(dynamic_scalars, dynamic)
        + C::vartime_msm_affine(static_scalars, g)
        + C::vartime_msm_affine(static_scalars, h)
}

fn joined(
    static_scalars: &[<C as Cycle>::Scalar],
    dynamic_scalars: &[<C as Cycle>::Scalar],
    g: &[<C as Cycle>::Affine],
    h: &[<C as Cycle>::Affine],
    dynamic: &[<C as Cycle>::Point],
) -> <C as Cycle>::Point {
    let dynamic = C::batch_normalize(dynamic);
    let mut scalars = Vec::with_capacity(2 * static_scalars.len() + dynamic_scalars.len());
    scalars.extend_from_slice(static_scalars);
    scalars.extend_from_slice(static_scalars);
    scalars.extend_from_slice(dynamic_scalars);
    let mut points = Vec::with_capacity(g.len() + h.len() + dynamic.len());
    points.extend_from_slice(g);
    points.extend_from_slice(h);
    points.extend_from_slice(&dynamic);
    C::vartime_msm_affine(&scalars, &points)
}

fn segmented(
    static_scalars: &[<C as Cycle>::Scalar],
    dynamic_scalars: &[<C as Cycle>::Scalar],
    g: &[<C as Cycle>::Affine],
    h: &[<C as Cycle>::Affine],
    dynamic: &[<C as Cycle>::Point],
) -> <C as Cycle>::Point {
    let dynamic = C::batch_normalize(dynamic);
    C::vartime_msm_affine(static_scalars, g)
        + C::vartime_msm_affine(static_scalars, h)
        + C::vartime_msm_affine(dynamic_scalars, &dynamic)
}

fn msm_schedules(c: &mut Criterion) {
    let max_size = GOLDEN_VERIFIER_SHAPES
        .iter()
        .map(|&(static_len, _)| static_len)
        .max()
        .expect("verifier shapes are nonempty");
    let generators = BulletproofGens::<C>::new(max_size, 1);
    let g: Vec<_> = generators.share(0).G(max_size).copied().collect();
    let h: Vec<_> = generators.share(0).H(max_size).copied().collect();
    let dynamic: Vec<_> = g.iter().take(64).map(C::affine_to_point).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(0x7365_6371_6d73_6d21);
    let scalars: Vec<_> = (0..max_size)
        .map(|_| <C as Cycle>::Scalar::random(&mut rng))
        .collect();

    for &(static_len, dynamic_len) in GOLDEN_VERIFIER_SHAPES {
        let mut group = c.benchmark_group(format!(
            "secq256k1/msm/golden-verifier/{static_len}-{dynamic_len}"
        ));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        let static_scalars = &scalars[..static_len];
        let dynamic_scalars = &scalars[..dynamic_len];
        let g = &g[..static_len];
        let h = &h[..static_len];
        let dynamic = &dynamic[..dynamic_len];

        group.bench_function("split", |b| {
            b.iter(|| {
                black_box(split(
                    black_box(static_scalars),
                    black_box(dynamic_scalars),
                    black_box(g),
                    black_box(h),
                    black_box(dynamic),
                ))
            });
        });
        group.bench_function("joined", |b| {
            b.iter(|| {
                black_box(joined(
                    black_box(static_scalars),
                    black_box(dynamic_scalars),
                    black_box(g),
                    black_box(h),
                    black_box(dynamic),
                ))
            });
        });
        group.bench_function("segmented", |b| {
            b.iter(|| {
                black_box(segmented(
                    black_box(static_scalars),
                    black_box(dynamic_scalars),
                    black_box(g),
                    black_box(h),
                    black_box(dynamic),
                ))
            });
        });
        group.finish();
    }
}

criterion_group!(benches, msm_schedules);
criterion_main!(benches);
