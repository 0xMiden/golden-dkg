//! BLS12-381 G1 multi-scalar multiplication backed by `blst`, Supranational's
//! C library (via its safe Rust bindings crate, also named `blst`).
//!
//! The `bls12_381` crate this workspace otherwise builds on has no
//! hardware-accelerated field arithmetic — everything is plain Rust limb
//! arithmetic. `blst`'s field layer is hand-written assembly, and it ships
//! its own mature, tuned Pippenger multi-exponentiation (`MultiPoint::mult`),
//! so this crosses the FFI boundary at exactly the MSM call site instead of
//! trying to out-optimize hand-tuned assembly in pure Rust: convert scalars
//! and bases into `blst` types, call its `mult`, convert the result back.
//!
//! Bases convert via the *uncompressed* encoding (raw affine `x`/`y`), not
//! compressed: decompression needs a field square root per point, which
//! measured roughly 175x slower than a plain uncompressed decode for a few
//! thousand points — exactly the sizes this MSM runs on. The decode also
//! skips the subgroup check (`_unchecked`): every point reaching this
//! module already came from a trusted internal source (Bulletproofs
//! generators, in-circuit witnesses) that is in the prime-order subgroup by
//! construction, so re-checking that here would be pure waste. The on-curve
//! check is not skipped — `blst_p1_deserialize` performs it unconditionally
//! inside the FFI call, `_unchecked` only means "no subgroup check" for
//! `blst`, unlike `bls12_381`'s own `_unchecked` naming convention.
//!
//! Bases go straight to `blst_p1_affine` rather than through `blstrs`'
//! projective `G1Projective::multi_exp`: that method re-derives affine
//! coordinates internally (`p1_affines::from`) even when every input point
//! is already affine, since it also has to accept projective input. Calling
//! `blst`'s affine-slice `MultiPoint::mult` directly skips that redundant
//! re-affining pass.
//!
//! [`crate::cycle::Bls12_381G1Cycle::Affine`] is `blst_p1_affine` itself
//! (not `bls12_381::G1Affine`), so the decode this module's doc above
//! describes runs once, when a point becomes a stored generator or
//! commitment ([`to_blst_affine`]/[`from_blst_affine`]) — not on every MSM
//! call over the same generator vector. [`msm`] takes bases already in that
//! form and passes them to `blst` with no conversion at all.
//!
//! `MultiPoint::mult` runs on `blst`'s own internal thread pool (sized from
//! the host CPU count) whenever the `blst` crate's `no-threads` feature is
//! off, which it is in this workspace — independent of this workspace's own
//! `parallel` feature (`p3_maybe_rayon`). Every MSM through this module is
//! therefore multi-threaded regardless of `parallel`, including in a
//! "sequential" build/bench/CI configuration; under `parallel`, `blst`'s
//! pool and `p3_maybe_rayon`'s rayon workers are two independent thread
//! pools that can contend for CPU.

use bls12_381::{G1Affine, G1Projective, Scalar};
use blst::{blst_p1, blst_p1_affine, MultiPoint};
use group::Curve;

/// Convert a `bls12_381` affine point to `blst`'s native representation.
pub(crate) fn to_blst_affine(affine: &G1Affine) -> blst_p1_affine {
    let bytes = affine.to_uncompressed();
    // `bytes` is `bls12_381`'s own uncompressed encoding of an already
    // on-curve, in-subgroup point, and `blstrs` decodes the identical
    // standard uncompressed BLS12-381 encoding. A `None` here means the two
    // crates disagree about that encoding, a real bug worth a loud failure
    // rather than a silently wrong MSM result.
    let blst_affine: blstrs::G1Affine =
        Option::from(blstrs::G1Affine::from_uncompressed_unchecked(&bytes))
            .expect("bls12_381 and blstrs must agree on the uncompressed G1 encoding");
    *AsRef::<blst_p1_affine>::as_ref(&blst_affine)
}

/// Convert a `blst`-native affine point back to a `bls12_381` affine point.
/// Correctly round-trips the identity: `blst_p1_affine`'s all-zero encoding
/// is its own infinity sentinel, and `blst_p1_affine_serialize`
/// (`to_uncompressed`) sets the standard uncompressed encoding's infinity
/// flag for it, which `bls12_381::G1Affine::from_uncompressed_unchecked`
/// then decodes back to the identity — exercised by
/// `crate::cycle::tests::point_to_affine_and_back_round_trips_the_identity`.
pub(crate) fn from_blst_affine(affine: &blst_p1_affine) -> G1Affine {
    let blst_affine = blstrs::G1Affine::from_raw_unchecked(affine.x.into(), affine.y.into(), false);
    let bytes = blst_affine.to_uncompressed();
    Option::from(G1Affine::from_uncompressed_unchecked(&bytes))
        .expect("blstrs and bls12_381 must agree on the uncompressed G1 encoding")
}

fn from_blst_p1(point: &blst_p1) -> G1Projective {
    let projective =
        blstrs::G1Projective::from_raw_unchecked(point.x.into(), point.y.into(), point.z.into());
    let bytes = projective.to_affine().to_uncompressed();
    // Same cross-library round trip as `to_blst_affine`, in the opposite
    // direction: a `None` here means `blstrs`' MSM produced bytes
    // `bls12_381` cannot decode, a real bug worth a loud failure.
    let affine: G1Affine = Option::from(G1Affine::from_uncompressed_unchecked(&bytes))
        .expect("blstrs and bls12_381 must agree on the uncompressed G1 encoding");
    G1Projective::from(affine)
}

/// Multi-scalar multiplication `sum(scalars[i] * bases[i])` over BLS12-381
/// G1, with bases already converted to `blst`'s native affine
/// representation. Panics if `scalars.len() != bases.len()`.
pub(crate) fn msm(scalars: &[Scalar], bases: &[blst_p1_affine]) -> G1Projective {
    assert_eq!(scalars.len(), bases.len());
    if bases.is_empty() {
        return G1Projective::identity();
    }

    let mut scalar_bytes = Vec::with_capacity(scalars.len() * 32);
    for scalar in scalars {
        scalar_bytes.extend_from_slice(&scalar.to_bytes());
    }
    let result: blst_p1 = bases.mult(&scalar_bytes, 255);
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

    fn naive_msm_affine(scalars: &[Scalar], bases: &[G1Affine]) -> G1Projective {
        let points: Vec<G1Projective> = bases.iter().map(G1Projective::from).collect();
        naive_msm(scalars, &points)
    }

    fn blst_bases(bases: &[G1Affine]) -> Vec<blst_p1_affine> {
        bases.iter().map(to_blst_affine).collect()
    }

    #[test]
    fn identity_bases_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let id = G1Affine::identity();
        let p = G1Projective::random(&mut rng).to_affine();
        let q = G1Projective::random(&mut rng).to_affine();
        let s: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();

        for bases in [vec![id, p, q, id], vec![id, id, id, id], vec![p, id, q, p]] {
            assert_eq!(
                msm(&s, &blst_bases(&bases)),
                naive_msm_affine(&s, &bases),
                "bases {bases:?}"
            );
        }
    }

    #[test]
    fn zero_scalars_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let bases: Vec<G1Affine> = (0..4)
            .map(|_| G1Projective::random(&mut rng).to_affine())
            .collect();
        let blst = blst_bases(&bases);
        let scalars = vec![
            Scalar::ZERO,
            Scalar::random(&mut rng),
            Scalar::ZERO,
            Scalar::ZERO,
        ];
        assert_eq!(msm(&scalars, &blst), naive_msm_affine(&scalars, &bases));

        let all_zero = vec![Scalar::ZERO; 4];
        assert_eq!(msm(&all_zero, &blst), G1Projective::identity());
    }

    #[test]
    fn result_can_be_the_identity() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let base = to_blst_affine(&G1Projective::random(&mut rng).to_affine());
        let s = Scalar::random(&mut rng);
        assert_eq!(msm(&[s, -s], &[base, base]), G1Projective::identity());
    }

    #[test]
    fn matches_naive_sum_for_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for len in [0usize, 1, 2, 3, 5, 17, 64] {
            let scalars: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
            let points: Vec<G1Projective> =
                (0..len).map(|_| G1Projective::random(&mut rng)).collect();
            let affine: Vec<G1Affine> = points.iter().map(G1Projective::to_affine).collect();

            let got = msm(&scalars, &blst_bases(&affine));
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
        let affine = to_blst_affine(&point.to_affine());

        let got = msm(&[scalar], &[affine]);
        assert_eq!(got, point * scalar);
    }

    #[test]
    fn matches_naive_sum_with_repeated_and_negated_bases() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let base = to_blst_affine(&G1Projective::random(&mut rng).to_affine());
        let s = Scalar::random(&mut rng);
        let scalars = [s, -s, s, -s, s];
        let bases = [base; 5];

        let got = msm(&scalars, &bases);
        let want = G1Projective::from(from_blst_affine(&base)) * s;
        assert_eq!(got, want);
    }
}
