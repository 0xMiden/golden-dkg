//! BLS12-381 G1 multi-scalar multiplication backed by `blst`.
//!
//! Stored affine bases already use `blst_p1_affine`, so [`msm`] passes them
//! directly to `MultiPoint::mult`. Projective inputs use `blstrs`' bridge to
//! blst's batch conversion and Pippenger implementation. Scalars stay in
//! `bls12_381::Scalar` because Jubjub and the R1CS field require that exact
//! type, and cross to blst through their canonical little-endian bytes.
//!
//! `MultiPoint::mult` runs on `blst`'s own internal thread pool (sized from
//! the host CPU count) whenever the `blst` crate's `no-threads` feature is
//! off, which it is in this workspace — independent of this workspace's own
//! `parallel` feature (`p3_maybe_rayon`). Every MSM through this module is
//! therefore multi-threaded regardless of `parallel`, including in a
//! "sequential" build or benchmark configuration. Benchmarks on the target
//! machine found that disabling this pool made representative large MSMs
//! more than three times slower, so blst remains the MSM parallelism owner.

use crate::BlsG1Projective;
use bls12_381::Scalar;
use blst::{blst_p1, blst_p1_affine, MultiPoint};
use group::Group;

/// Multi-scalar multiplication `sum(scalars[i] * bases[i])` over BLS12-381
/// G1, with bases already converted to `blst`'s native affine
/// representation. Panics if `scalars.len() != bases.len()`.
pub(crate) fn msm(scalars: &[Scalar], bases: &[blst_p1_affine]) -> BlsG1Projective {
    assert_eq!(scalars.len(), bases.len());
    if bases.is_empty() {
        return BlsG1Projective::identity();
    }

    let mut scalar_bytes = Vec::with_capacity(scalars.len() * 32);
    for scalar in scalars {
        scalar_bytes.extend_from_slice(&scalar.to_bytes());
    }
    let result: blst_p1 = bases.mult(&scalar_bytes, 255);
    BlsG1Projective(blstrs::G1Projective::from_raw_unchecked(
        result.x.into(),
        result.y.into(),
        result.z.into(),
    ))
}

/// Multi-scalar multiplication over projective inputs using `blstrs`' direct
/// bridge to `blst`'s projective-to-affine batch conversion and Pippenger.
pub(crate) fn msm_projective(scalars: &[Scalar], points: &[BlsG1Projective]) -> BlsG1Projective {
    assert_eq!(scalars.len(), points.len());
    if points.is_empty() {
        return BlsG1Projective::identity();
    }

    let scalars: Vec<_> = scalars
        .iter()
        .map(BlsG1Projective::scalar_to_blstrs)
        .collect();
    let points: Vec<_> = points.iter().map(|point| point.0).collect();
    BlsG1Projective(blstrs::G1Projective::multi_exp(&points, &scalars))
}

/// Normalize projective points through `blst`.
pub(crate) fn batch_normalize(points: &[BlsG1Projective]) -> Vec<blst_p1_affine> {
    let point_ptrs: Vec<*const blst_p1> = points
        .iter()
        .map(|point| point.0.as_ref() as *const blst_p1)
        .collect();
    let mut affine = vec![blst_p1_affine::default(); points.len()];

    // SAFETY: Every pointer refers to an element of `points`, which remains
    // alive and immutable for the call. `affine` has initialized storage for
    // every output. The input and output do not overlap. blst accepts an empty
    // input when `points.len()` is zero.
    #[allow(unsafe_code)]
    unsafe {
        blst::blst_p1s_to_affine(affine.as_mut_ptr(), point_ptrs.as_ptr(), points.len());
    }

    affine
}

/// Clear the BLS12-381 G1 cofactor with its 64-bit effective cofactor.
pub(crate) fn clear_cofactor(point: &blstrs::G1Projective) -> blstrs::G1Projective {
    const EFFECTIVE_COFACTOR: u64 = 0xd201_0000_0001_0001;
    let mut result = blst_p1::default();

    // SAFETY: Both point pointers are valid for the call and do not overlap.
    // The scalar buffer contains the requested 64 bits in blst's little-endian
    // format.
    #[allow(unsafe_code)]
    unsafe {
        blst::blst_p1_mult(
            &mut result,
            point.as_ref(),
            EFFECTIVE_COFACTOR.to_le_bytes().as_ptr(),
            64,
        );
    }

    blstrs::G1Projective::from_raw_unchecked(result.x.into(), result.y.into(), result.z.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ff::Field;
    use group::prime::PrimeCurveAffine;
    use group::{Curve, Group};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn naive_msm(scalars: &[Scalar], points: &[BlsG1Projective]) -> BlsG1Projective {
        let mut acc = BlsG1Projective::identity();
        for (s, p) in scalars.iter().zip(points) {
            acc += p * s;
        }
        acc
    }

    fn naive_msm_affine(scalars: &[Scalar], bases: &[blstrs::G1Affine]) -> BlsG1Projective {
        let points: Vec<_> = bases
            .iter()
            .map(|point| BlsG1Projective(blstrs::G1Projective::from(point)))
            .collect();
        naive_msm(scalars, &points)
    }

    fn raw_bases(bases: &[blstrs::G1Affine]) -> Vec<blst_p1_affine> {
        bases.iter().map(|base| *base.as_ref()).collect()
    }

    #[test]
    fn identity_bases_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let id = blstrs::G1Affine::identity();
        let p = blstrs::G1Projective::random(&mut rng).to_affine();
        let q = blstrs::G1Projective::random(&mut rng).to_affine();
        let s: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();

        for bases in [vec![id, p, q, id], vec![id, id, id, id], vec![p, id, q, p]] {
            assert_eq!(msm(&s, &raw_bases(&bases)), naive_msm_affine(&s, &bases));
        }
    }

    #[test]
    fn zero_scalars_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let bases: Vec<_> = (0..4)
            .map(|_| blstrs::G1Projective::random(&mut rng).to_affine())
            .collect();
        let scalars = vec![
            Scalar::ZERO,
            Scalar::random(&mut rng),
            Scalar::ZERO,
            Scalar::ZERO,
        ];
        assert_eq!(
            msm(&scalars, &raw_bases(&bases)),
            naive_msm_affine(&scalars, &bases)
        );

        let all_zero = vec![Scalar::ZERO; 4];
        assert_eq!(
            msm(&all_zero, &raw_bases(&bases)),
            BlsG1Projective::identity()
        );
    }

    #[test]
    fn result_can_be_the_identity() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let base = blstrs::G1Projective::random(&mut rng).to_affine();
        let s = Scalar::random(&mut rng);
        assert_eq!(
            msm(&[s, -s], &raw_bases(&[base, base])),
            BlsG1Projective::identity()
        );
    }

    #[test]
    fn matches_naive_sum_for_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for len in [0usize, 1, 2, 3, 5, 17, 64] {
            let scalars: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
            let points: Vec<_> = (0..len)
                .map(|_| BlsG1Projective::random(&mut rng))
                .collect();
            let affine: Vec<_> = points.iter().map(|point| point.0.to_affine()).collect();

            let got = msm(&scalars, &raw_bases(&affine));
            let want = naive_msm(&scalars, &points);
            assert_eq!(got, want, "mismatch at len={len}");
        }
    }

    #[test]
    fn empty_input_is_identity() {
        let out = msm(&[], &[]);
        assert_eq!(out, BlsG1Projective::identity());
    }

    #[test]
    fn single_base_matches_scalar_mul() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let scalar = Scalar::random(&mut rng);
        let point = BlsG1Projective::generator();
        let affine = *point.0.to_affine().as_ref();

        let got = msm(&[scalar], &[affine]);
        assert_eq!(got, point * scalar);
    }

    #[test]
    fn matches_naive_sum_with_repeated_and_negated_bases() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let base = blstrs::G1Projective::random(&mut rng).to_affine();
        let s = Scalar::random(&mut rng);
        let scalars = [s, -s, s, -s, s];
        let bases = [base; 5];

        let got = msm(&scalars, &raw_bases(&bases));
        let want = BlsG1Projective(blstrs::G1Projective::from(base)) * s;
        assert_eq!(got, want);
    }

    #[test]
    fn batch_normalize_matches_individual_normalization() {
        let generator = BlsG1Projective::generator();
        let points = [BlsG1Projective::identity(), generator, generator.double()];
        let expected: Vec<_> = points
            .iter()
            .map(|point| *point.0.to_affine().as_ref())
            .collect();

        assert_eq!(batch_normalize(&points), expected);
        assert!(batch_normalize(&[]).is_empty());
    }

    #[test]
    fn cofactor_clear_matches_scalar_multiplication() {
        const EFFECTIVE_COFACTOR: u64 = 0xd201_0000_0001_0001;
        let point = blstrs::G1Projective::generator().double();
        let expected = point * blstrs::Scalar::from(EFFECTIVE_COFACTOR);

        assert_eq!(clear_cofactor(&point), expected);
    }
}
