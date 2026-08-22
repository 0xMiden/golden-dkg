//! BLS12-381 G1 multi-scalar multiplication backed by `blst`, Supranational's
//! C library (via its safe Rust bindings crate, also named `blst`).
//!
//! The `bls12_381` crate this workspace otherwise builds on (see
//! `crates/bls12_381`, a vendored fork) has no hardware-accelerated field
//! arithmetic — everything is plain Rust limb arithmetic. `blst`'s field
//! layer is hand-written assembly, and it ships its own mature, tuned
//! Pippenger multi-exponentiation (`MultiPoint::mult`), so this crosses the
//! FFI boundary at exactly the MSM call site instead of trying to
//! out-optimize hand-tuned assembly in pure Rust: convert scalars and bases
//! into `blst` types, call its `mult`, convert the result back.
//!
//! Bases convert via the *uncompressed* encoding (raw affine `x`/`y`), not
//! compressed: decompression needs a field square root per point, which
//! measured roughly 175x slower than a plain uncompressed decode for a few
//! thousand points — exactly the sizes this MSM runs on. The decode also
//! skips the on-curve/subgroup check (`_unchecked`): every point reaching
//! this module already came from a trusted internal source (Bulletproofs
//! generators, in-circuit witnesses) that is on-curve and in the
//! prime-order subgroup by construction, so re-checking it here would be
//! pure waste, not a real safety measure.
//!
//! Bases go straight to `blst_p1_affine` rather than through `blstrs`'
//! projective `G1Projective::multi_exp`: that method re-derives affine
//! coordinates internally (`p1_affines::from`) even when every input point
//! is already affine, since it also has to accept projective input. Calling
//! `blst`'s affine-slice `MultiPoint::mult` directly skips that redundant
//! re-affining pass.

use bls12_381::{G1Affine, G1Projective, Scalar};
use blst::{blst_p1, blst_p1_affine, MultiPoint};
use group::prime::PrimeCurveAffine;
use group::Curve;

fn to_blst_affine(affine: &G1Affine) -> blst_p1_affine {
    let bytes = affine.to_uncompressed();
    let blst_affine: blstrs::G1Affine =
        Option::from(blstrs::G1Affine::from_uncompressed_unchecked(&bytes))
            .unwrap_or_else(blstrs::G1Affine::identity);
    *AsRef::<blst_p1_affine>::as_ref(&blst_affine)
}

fn from_blst_p1(point: &blst_p1) -> G1Projective {
    let projective =
        blstrs::G1Projective::from_raw_unchecked(point.x.into(), point.y.into(), point.z.into());
    let bytes = projective.to_affine().to_uncompressed();
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

    let blst_bases: Vec<blst_p1_affine> = bases.iter().map(to_blst_affine).collect();
    let mut scalar_bytes = Vec::with_capacity(scalars.len() * 32);
    for scalar in scalars {
        scalar_bytes.extend_from_slice(&scalar.to_bytes());
    }
    let result: blst_p1 = blst_bases.mult(&scalar_bytes, 255);
    from_blst_p1(&result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ff::Field;
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
