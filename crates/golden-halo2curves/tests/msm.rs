//! MSM dispatch tests for the halo2curves-backed [`Cycle`] adapters.

#![allow(clippy::unwrap_used)]

#[cfg(feature = "halo2curves-secp256k1")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::Cycle;
    use ff::Field;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use group::{Curve, Group};
    use rand_chacha::rand_core::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    macro_rules! msm_cases {
        ($test_name:ident, $cycle:ty, $point:ty, $affine:ty) => {
            #[test]
            fn $test_name() {
                type C = $cycle;

                fn reference_msm(
                    scalars: &[<C as Cycle>::Scalar],
                    points: &[<C as Cycle>::Point],
                ) -> <C as Cycle>::Point {
                    use halo2curves::msm::msm_best;

                    let identity = <$point as Group>::identity();
                    let filtered: Vec<_> = scalars
                        .iter()
                        .zip(points.iter())
                        .filter(|(_, p)| **p != identity)
                        .collect();

                    if filtered.is_empty() {
                        return identity;
                    }

                    let scalars: Vec<_> = filtered.iter().map(|(s, _)| **s).collect();
                    let filtered_points: Vec<$point> = filtered.iter().map(|(_, p)| **p).collect();
                    let mut bases = vec![<$affine>::default(); filtered_points.len()];
                    <$point as Curve>::batch_normalize(&filtered_points, &mut bases);
                    msm_best::<$affine>(&scalars, &bases)
                }

                fn point(seed: u8) -> <C as Cycle>::Point {
                    let mut bytes = [0u8; 64];
                    bytes[0] = seed;
                    C::point_hash_from_uniform(&bytes)
                }

                fn random_point(rng: &mut ChaCha20Rng) -> <C as Cycle>::Point {
                    loop {
                        let mut bytes = [0u8; 64];
                        rng.fill_bytes(&mut bytes);
                        let point = C::point_hash_from_uniform(&bytes);
                        if point != <$point as Group>::identity() {
                            return point;
                        }
                    }
                }

                fn assert_msm_matches_reference(
                    label: &str,
                    scalars: &[<C as Cycle>::Scalar],
                    points: &[<C as Cycle>::Point],
                ) {
                    let got = C::vartime_msm(scalars, points);
                    let expected = reference_msm(scalars, points);
                    assert!(got == expected, "{label}");
                }

                fn assert_affine_msm_matches_reference(
                    label: &str,
                    scalars: &[<C as Cycle>::Scalar],
                    points: &[<C as Cycle>::Point],
                ) {
                    let affine = C::batch_normalize(points);
                    let got = C::vartime_msm_affine(scalars, &affine);
                    let expected = reference_msm(scalars, points);
                    assert!(got == expected, "{label}");
                }

                let mut rng = ChaCha20Rng::seed_from_u64(0x2b4d_5015);
                let identity = <$point as Group>::identity();
                let points = [point(1), point(2), point(3), point(4)];
                let scalars = [
                    <C as Cycle>::Scalar::ZERO,
                    <C as Cycle>::Scalar::ONE,
                    <C as Cycle>::Scalar::from(2),
                    random_scalar::<C>(&mut rng),
                ];

                assert_msm_matches_reference("empty msm", &[], &[]);
                assert_msm_matches_reference("one point", &scalars[..1], &points[..1]);
                assert_msm_matches_reference("two points", &scalars[..2], &points[..2]);
                assert_msm_matches_reference(
                    "two points with random scalar",
                    &[scalars[3], scalars[2]],
                    &points[..2],
                );
                for _ in 0..32 {
                    let a = random_scalar::<C>(&mut rng);
                    let b = random_scalar::<C>(&mut rng);
                    let p = random_point(&mut rng);
                    let q = random_point(&mut rng);

                    assert_msm_matches_reference("random two-point msm", &[a, b], &[p, q]);
                    assert_msm_matches_reference("random two-point msm reversed", &[b, a], &[q, p]);
                }
                assert_msm_matches_reference(
                    "identity is filtered",
                    &scalars[..2],
                    &[identity, points[1]],
                );
                assert_msm_matches_reference("three points", &scalars[..3], &points[..3]);
                assert_msm_matches_reference("larger msm", &scalars, &points);
                assert_affine_msm_matches_reference("affine msm", &scalars, &points);
            }
        };
    }

    msm_cases!(
        vartime_msm_matches_halo2curves_best_for_secp256k1,
        Secp256k1Cycle,
        halo2curves::secp256k1::Secp256k1,
        halo2curves::secp256k1::Secp256k1Affine
    );

    msm_cases!(
        vartime_msm_matches_halo2curves_best_for_secq256k1,
        Secq256k1Cycle,
        halo2curves::secq256k1::Secq256k1,
        halo2curves::secq256k1::Secq256k1Affine
    );
}
