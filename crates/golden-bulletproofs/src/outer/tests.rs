//! Preserved adapter regressions from the former curve-pair crates.
#![allow(clippy::unwrap_used)]

use bulletproofs_cycle::Cycle;
use ff::Field;
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn reference_msm<C: Cycle>(scalars: &[C::Scalar], points: &[C::Point]) -> C::Point {
    scalars
        .iter()
        .zip(points)
        .fold(C::Point::identity(), |sum, (scalar, point)| {
            sum + *point * scalar
        })
}

fn assert_msm_paths<C: Cycle>(scalars: &[C::Scalar], points: &[C::Point]) {
    let expected = reference_msm::<C>(scalars, points);
    assert_eq!(C::vartime_msm(scalars, points), expected);
    let affine = C::batch_normalize(points);
    assert_eq!(C::vartime_msm_affine(scalars, &affine), expected);
    let optional: Vec<_> = points.iter().copied().map(Some).collect();
    assert_eq!(C::vartime_msm_optional(scalars, &optional), Some(expected));

    // Preserve mixed fixed/dynamic and empty-group cases. The 64-term case
    // reaches the optimized segmented BLS path as well as small-MSM dispatch.
    let split = scalars.len() / 2;
    let empty_scalars: &[C::Scalar] = &[];
    let empty_affine: &[C::Affine] = &[];
    assert_eq!(
        C::vartime_msm_mixed(
            &[
                (empty_scalars, empty_affine),
                (&scalars[..split], &affine[..split]),
                (empty_scalars, empty_affine)
            ],
            &scalars[split..],
            &points[split..],
        ),
        expected
    );
    assert_eq!(
        C::vartime_msm_mixed(
            &[
                (&scalars[..split], &affine[..split]),
                (empty_scalars, empty_affine),
                (&scalars[split..], &affine[split..])
            ],
            &[],
            &[],
        ),
        expected
    );
    assert_eq!(C::vartime_msm_mixed(&[], scalars, points), expected);
}

fn msm_edges<C: Cycle>() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x2b4d_5015);
    for length in [0, 1, 2, 3, 5, 17, 64] {
        let mut scalars: Vec<_> = (0..length).map(|_| C::Scalar::random(&mut rng)).collect();
        let mut points: Vec<_> = (0..length).map(|_| C::Point::random(&mut rng)).collect();
        assert_msm_paths::<C>(&scalars, &points);
        if length != 0 {
            points[0] = C::Point::identity();
            scalars[length - 1] = C::Scalar::ZERO;
            assert_msm_paths::<C>(&scalars, &points);
        }
    }
    let point = C::Point::random(&mut rng);
    let scalar = C::Scalar::random(&mut rng);
    assert_msm_paths::<C>(&[scalar, -scalar], &[point, point]);
    assert_msm_paths::<C>(&[scalar, scalar], &[point, -point]);
    assert_msm_paths::<C>(
        &[scalar, -scalar, scalar],
        &[point, point, C::Point::identity()],
    );
    assert_msm_paths::<C>(&[C::Scalar::ZERO; 3], &[point; 3]);
    assert_msm_paths::<C>(&[scalar; 3], &[C::Point::identity(); 3]);
    assert_eq!(C::vartime_msm_optional(&[scalar], &[None]), None);

    // Retain independent random coverage of the special two-point dispatch.
    for _ in 0..32 {
        let scalars = [C::Scalar::random(&mut rng), C::Scalar::random(&mut rng)];
        let points = [C::Point::random(&mut rng), C::Point::random(&mut rng)];
        let expected = reference_msm::<C>(&scalars, &points);
        assert_eq!(C::vartime_msm(&scalars, &points), expected);
        assert_eq!(
            C::vartime_msm(&[scalars[1], scalars[0]], &[points[1], points[0]]),
            expected
        );
    }
}

fn codec_edges<C: Cycle>() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0043_4f44_4543);
    let identity = C::Point::identity();
    for point in [
        identity,
        C::Point::generator(),
        -C::Point::generator(),
        C::Point::random(&mut rng),
    ] {
        let affine = C::point_to_affine(&point);
        assert_eq!(C::affine_to_point(&affine), point);
        let compressed = C::point_compress(&point);
        assert_eq!(C::compressed_is_identity(&compressed), point == identity);
        assert_eq!(
            C::compressed_as_bytes(&C::affine_compress(&affine)),
            C::compressed_as_bytes(&compressed)
        );
        assert_eq!(C::compressed_decompress(&compressed), Some(point));
        let reconstructed = C::compressed_from_bytes(C::compressed_as_bytes(&compressed));
        assert_eq!(C::compressed_decompress(&reconstructed), Some(point));
    }
    assert!(C::batch_normalize(&[]).is_empty());
    let malformed = C::compressed_from_bytes(&vec![0xff; C::COMPRESSED_BYTES]);
    assert!(C::compressed_decompress(&malformed).is_none());
}

macro_rules! cycle_cases {
    ($msm:ident, $codec:ident, $cycle:ty) => {
        #[test]
        fn $msm() {
            msm_edges::<$cycle>();
        }
        #[test]
        fn $codec() {
            codec_edges::<$cycle>();
        }
    };
}
#[cfg(feature = "secp-secq")]
cycle_cases!(
    secq_msm_dispatch_preserves_group_arithmetic,
    secq_codec_preserves_identity_and_affine_points,
    super::secp::SecqCycle
);
#[cfg(feature = "jubjub-bls12-381")]
cycle_cases!(
    bls_msm_dispatch_preserves_group_arithmetic,
    bls_codec_preserves_identity_and_affine_points,
    super::cycle::Bls12_381G1Cycle
);

#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn bls_checked_codecs_match_the_independent_subgroup_decoder() {
    use super::cycle::Bls12_381G1Cycle as C;
    use bls12_381::G1Affine;

    let mut off_curve = [0; 48];
    off_curve[0] = 0x80;
    off_curve[47] = 2;
    let noncanonical_x = [
        0x9a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac,
        0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0,
        0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xaa, 0xab,
    ];
    let mut malformed_identity = [0; 48];
    malformed_identity[0] = 0xc0;
    malformed_identity[47] = 1;
    // (x=0, y=2) lies on y^2=x^3+4 and has order three. Unlike the old
    // random candidate test, this always exercises on-curve subgroup rejection.
    let mut torsion = [0; 48];
    torsion[0] = 0x80;
    let on_curve = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&torsion)).unwrap();
    assert!(!bool::from(on_curve.is_torsion_free()));
    for bytes in [off_curve, noncanonical_x, malformed_identity, torsion] {
        assert!(Option::<G1Affine>::from(G1Affine::from_compressed(&bytes)).is_none());
        assert!(C::compressed_decompress(&C::compressed_from_bytes(&bytes)).is_none());
    }
    // The optimized generator map must still emit points accepted by the
    // independent checked decoder used as a reference before the crate move.
    for seed in [[1; 64], [9; 64]] {
        let point = C::point_hash_from_uniform(&seed);
        assert_ne!(point, <C as Cycle>::Point::identity());
        let encoded = C::point_compress(&point);
        let bytes: &[u8; 48] = C::compressed_as_bytes(&encoded).try_into().unwrap();
        assert!(Option::<G1Affine>::from(G1Affine::from_compressed(bytes)).is_some());
    }
}
