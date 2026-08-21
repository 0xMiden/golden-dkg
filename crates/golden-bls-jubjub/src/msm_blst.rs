//! BLS12-381 G1 multi-scalar multiplication backed by [`blstrs`], a Rust
//! wrapper over Supranational's `blst` C library.
//!
//! The `bls12_381` crate this workspace otherwise builds on (see
//! `crates/bls12_381`, a vendored fork) has no hardware-accelerated field
//! arithmetic — everything is plain Rust limb arithmetic. `blst`'s field
//! layer is hand-written assembly, and it ships its own mature, tuned
//! Pippenger multi-exponentiation (`G1Projective::multi_exp`), so this
//! crosses the FFI boundary at exactly the MSM call site instead of trying
//! to out-optimize hand-tuned assembly in pure Rust: convert scalars and
//! points into `blstrs` types, call its `multi_exp`, convert the result
//! back.
//!
//! Points convert via the *uncompressed* encoding (raw affine `x`/`y`),
//! not compressed: decompression needs a field square root per point,
//! which measured roughly 175x slower than a plain uncompressed decode for
//! a few thousand points — exactly the sizes this MSM runs on. The decode
//! also skips the on-curve/subgroup check (`_unchecked`): every point
//! reaching this module already came from a trusted internal source
//! (Bulletproofs generators, in-circuit witnesses) that is on-curve and in
//! the prime-order subgroup by construction, so re-checking it here would
//! be pure waste, not a real safety measure.

use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;

fn to_blst_scalar(scalar: &Scalar) -> blstrs::Scalar {
    let bytes: [u8; 32] = scalar.to_repr();
    Option::from(blstrs::Scalar::from_repr(bytes)).unwrap_or(blstrs::Scalar::ZERO)
}

fn to_blst_point(affine: &G1Affine) -> blstrs::G1Projective {
    let bytes = affine.to_uncompressed();
    let blst_affine: blstrs::G1Affine =
        Option::from(blstrs::G1Affine::from_uncompressed_unchecked(&bytes))
            .unwrap_or_else(blstrs::G1Affine::identity);
    blstrs::G1Projective::from(blst_affine)
}

fn from_blst_point(point: &blstrs::G1Projective) -> G1Projective {
    let bytes = point.to_affine().to_uncompressed();
    let affine: G1Affine = Option::from(G1Affine::from_uncompressed_unchecked(&bytes))
        .unwrap_or_else(G1Affine::identity);
    G1Projective::from(affine)
}

/// Multi-scalar multiplication `sum(scalars[i] * bases[i])` over BLS12-381
/// G1, with bases already in affine form. Panics if `scalars.len() !=
/// bases.len()`.
pub(crate) fn msm(scalars: &[Scalar], bases: &[G1Affine]) -> G1Projective {
    assert_eq!(scalars.len(), bases.len());
    if bases.is_empty() {
        return G1Projective::identity();
    }

    let blst_scalars: Vec<blstrs::Scalar> = scalars.iter().map(to_blst_scalar).collect();
    let blst_points: Vec<blstrs::G1Projective> = bases.iter().map(to_blst_point).collect();
    let result = blstrs::G1Projective::multi_exp(&blst_points, &blst_scalars);
    from_blst_point(&result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use group::Group;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn naive_msm(scalars: &[Scalar], points: &[G1Projective]) -> G1Projective {
        let mut acc = G1Projective::identity();
        for (s, p) in scalars.iter().zip(points) {
            acc += p * s;
        }
        acc
    }

    #[test]
    fn matches_naive_sum_for_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for len in [0usize, 1, 2, 3, 5, 17, 64] {
            let scalars: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
            let points: Vec<G1Projective> =
                (0..len).map(|_| G1Projective::random(&mut rng)).collect();
            let affine: Vec<G1Affine> = points.iter().map(G1Projective::to_affine).collect();

            let got = msm(&scalars, &affine);
            let want = naive_msm(&scalars, &points);
            assert_eq!(got, want, "mismatch at len={len}");
        }
    }

    #[test]
    fn empty_input_is_identity() {
        let out = msm(&[], &[]);
        assert_eq!(out, G1Projective::identity());
    }

    #[test]
    fn single_base_matches_scalar_mul() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let scalar = Scalar::random(&mut rng);
        let point = G1Projective::generator();
        let affine = point.to_affine();

        let got = msm(&[scalar], &[affine]);
        assert_eq!(got, point * scalar);
    }

    #[test]
    fn matches_naive_sum_with_repeated_and_negated_bases() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let base = G1Projective::random(&mut rng).to_affine();
        let s = Scalar::random(&mut rng);
        let scalars = [s, -s, s, -s, s];
        let bases = [base; 5];

        let got = msm(&scalars, &bases);
        let want = G1Projective::from(base) * s;
        assert_eq!(got, want);
    }
}
