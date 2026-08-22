//! [`Cycle`] implementation for BLS12-381 G1, the Bulletproofs commitment
//! group (`Gout`) of the paper eVRF's BLS12-381/Jubjub instantiation. The
//! R1CS native field is BLS12-381's scalar field, which is also Jubjub's
//! base field (`jubjub::Fq` is a re-export of `bls12_381::Scalar`), so a
//! Jubjub-typed `Gin` witness value needs no field conversion to become an
//! R1CS coefficient.

use bls12_381::{G1Affine, G1Projective, Scalar};
use bulletproofs_cycle::Cycle;
use ff::Field;
use group::{Curve, GroupEncoding};
use sha2::{Digest, Sha256};
use subtle::CtOption;

/// Domain separator for [`Bls12_381G1Cycle::point_hash_from_uniform`]'s
/// try-and-increment candidate derivation.
const HASH_TO_CURVE_DOMAIN: &[u8] = b"golden-bulletproofs-bls12-381-g1-v1";

/// [`Cycle`] over BLS12-381 G1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bls12_381G1Cycle;

/// Map a domain-separated `(seed, counter)` pair to 48 pseudorandom bytes,
/// laid out as a candidate BLS12-381 G1 compressed point encoding: the
/// compression flag (bit 7 of byte 0) is forced on and the infinity flag
/// (bit 6) is forced off, so [`G1Affine::from_compressed_unchecked`] always
/// attempts a genuine x-coordinate recovery rather than returning the
/// identity.
fn candidate_compressed_bytes(seed: &[u8; 64], counter: u64) -> [u8; 48] {
    let mut out = [0u8; 48];

    let mut first = Sha256::new();
    first.update(HASH_TO_CURVE_DOMAIN);
    first.update(seed);
    first.update(counter.to_be_bytes());
    first.update(0u32.to_be_bytes());
    out[..32].copy_from_slice(&first.finalize());

    let mut second = Sha256::new();
    second.update(HASH_TO_CURVE_DOMAIN);
    second.update(seed);
    second.update(counter.to_be_bytes());
    second.update(1u32.to_be_bytes());
    out[32..].copy_from_slice(&second.finalize()[..16]);

    out[0] &= 0b0011_1111;
    out[0] |= 0b1000_0000;
    out
}

/// Map 64 uniform bytes to a near-uniform, cofactor-cleared BLS12-381 G1
/// point via try-and-increment: repeatedly derive a candidate compressed
/// encoding and attempt x-coordinate recovery, until one lands on the
/// curve. `bls12_381` ships no RFC 9380 hash-to-curve outside its
/// `experimental` feature (whose optional `digest 0.9` dependency conflicts
/// with this workspace's pinned `digest 0.10`), so this uses the classic
/// try-and-increment technique instead: each candidate succeeds with
/// probability roughly 1/2 (whether `x^3 + b` is a quadratic residue), so
/// this converges in a small constant number of iterations with overwhelming
/// probability. It is not constant-time, which matches this crate's
/// existing `Cycle` impls (`golden-halo2curves` documents the same
/// restriction) and is fine here: every caller uses this to derive public,
/// nothing-up-my-sleeve Bulletproofs generators, never secret data.
///
/// The x-coordinate recovery (a 381-bit field square root, the dominant
/// cost of each candidate) runs through `blstrs`' hand-written-assembly
/// field layer rather than `bls12_381`'s plain-Rust one; both crates decode
/// the same standard compressed BLS12-381 encoding, so this produces
/// identical candidate points to decoding directly with `bls12_381` — only
/// the arithmetic backend for the recovery differs.
fn hash_to_curve_try_and_increment(seed: &[u8; 64]) -> G1Projective {
    let mut counter: u64 = 0;
    loop {
        let candidate = candidate_compressed_bytes(seed, counter);
        let blst_affine: CtOption<blstrs::G1Affine> =
            blstrs::G1Affine::from_compressed_unchecked(&candidate);
        if let Some(blst_affine) = Option::<blstrs::G1Affine>::from(blst_affine) {
            let uncompressed = blst_affine.to_uncompressed();
            let affine: CtOption<G1Affine> = G1Affine::from_uncompressed_unchecked(&uncompressed);
            if let Some(affine) = Option::<G1Affine>::from(affine) {
                let point: G1Projective = G1Projective::from(affine).clear_cofactor();
                if !bool::from(point.is_identity()) {
                    return point;
                }
            }
        }
        counter += 1;
    }
}

impl Cycle for Bls12_381G1Cycle {
    type Scalar = Scalar;
    type Point = G1Projective;
    type Affine = G1Affine;
    type Compressed = <G1Projective as GroupEncoding>::Repr;
    const COMPRESSED_BYTES: usize = 48;

    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
        Scalar::from_bytes_wide(bytes)
    }

    fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Self::Scalar> {
        Option::from(Scalar::from_bytes(bytes))
    }

    fn scalar_to_canonical(scalar: &Self::Scalar) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        Option::from(Field::invert(scalar)).unwrap_or(Scalar::ZERO)
    }

    fn scalar_batch_invert(items: &mut [Self::Scalar]) -> Self::Scalar {
        // Montgomery batch invert with a single inversion. Precondition:
        // every entry is nonzero (see the `Cycle` trait doc for the same
        // contract on every other implementation in this workspace).
        let mut acc = Scalar::ONE;
        let mut scratch: Vec<Self::Scalar> = Vec::with_capacity(items.len());
        for x in items.iter() {
            scratch.push(acc);
            acc *= *x;
        }
        let acc_inv = Self::scalar_invert(&acc);
        let mut running = acc_inv;
        for i in (0..items.len()).rev() {
            let original = items[i];
            items[i] = running * scratch[i];
            running *= original;
        }
        acc_inv
    }

    fn point_compress(point: &Self::Point) -> Self::Compressed {
        GroupEncoding::to_bytes(point)
    }

    fn compressed_decompress(compressed: &Self::Compressed) -> Option<Self::Point> {
        Option::from(GroupEncoding::from_bytes(compressed))
    }

    fn compressed_identity() -> Self::Compressed {
        GroupEncoding::to_bytes(&G1Projective::identity())
    }

    fn compressed_is_identity(compressed: &Self::Compressed) -> bool {
        compressed.as_ref() == Self::compressed_identity().as_ref()
    }

    fn compressed_from_bytes(bytes: &[u8]) -> Self::Compressed {
        let mut repr = Self::Compressed::default();
        repr.as_mut()
            .copy_from_slice(&bytes[..Self::COMPRESSED_BYTES]);
        repr
    }

    fn compressed_as_bytes(compressed: &Self::Compressed) -> &[u8] {
        compressed.as_ref()
    }

    fn point_hash_from_uniform(bytes: &[u8; 64]) -> Self::Point {
        hash_to_curve_try_and_increment(bytes)
    }

    fn point_to_affine(point: &Self::Point) -> Self::Affine {
        point.to_affine()
    }

    fn affine_to_point(point: &Self::Affine) -> Self::Point {
        G1Projective::from(point)
    }

    fn batch_normalize(points: &[Self::Point]) -> Vec<Self::Affine> {
        let mut affine = vec![Self::Affine::default(); points.len()];
        G1Projective::batch_normalize(points, &mut affine);
        affine
    }

    fn affine_compress(point: &Self::Affine) -> Self::Compressed {
        GroupEncoding::to_bytes(point)
    }

    fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        let affine = Self::batch_normalize(points);
        crate::msm_blst::msm(scalars, &affine)
    }

    fn vartime_msm_affine(scalars: &[Self::Scalar], points: &[Self::Affine]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        crate::msm_blst::msm(scalars, points)
    }

    fn vartime_msm_optional(
        scalars: &[Self::Scalar],
        points: &[Option<Self::Point>],
    ) -> Option<Self::Point> {
        let identity = G1Projective::identity();
        let filtered: Vec<_> = scalars
            .iter()
            .zip(points.iter())
            .filter(|(_, p)| **p != Some(identity))
            .collect();
        if filtered.is_empty() {
            return Some(identity);
        }
        let filtered_scalars: Vec<_> = filtered.iter().map(|(s, _)| **s).collect();
        let filtered_points: Vec<Self::Point> = filtered
            .iter()
            .map(|(_, p)| **p)
            .collect::<Option<Vec<_>>>()?;
        Some(Self::vartime_msm(&filtered_scalars, &filtered_points))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use group::Group;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn point_hash_from_uniform_is_deterministic_and_in_prime_order_subgroup() {
        let bytes = [7u8; 64];
        let a = Bls12_381G1Cycle::point_hash_from_uniform(&bytes);
        let b = Bls12_381G1Cycle::point_hash_from_uniform(&bytes);
        assert_eq!(a, b);
        assert!(!bool::from(a.is_identity()));
        assert!(bool::from(G1Affine::from(a).is_torsion_free()));
    }

    #[test]
    fn point_hash_from_uniform_differs_across_inputs() {
        let a = Bls12_381G1Cycle::point_hash_from_uniform(&[1u8; 64]);
        let b = Bls12_381G1Cycle::point_hash_from_uniform(&[2u8; 64]);
        assert_ne!(a, b);
    }

    /// Decode a candidate's x-coordinate recovery entirely through
    /// `bls12_381`, independent of [`hash_to_curve_try_and_increment`]'s
    /// `blstrs` decode path, to confirm the two backends agree on which
    /// candidates land on the curve and on the resulting point.
    fn hash_to_curve_try_and_increment_reference(seed: &[u8; 64]) -> G1Projective {
        let mut counter: u64 = 0;
        loop {
            let candidate = candidate_compressed_bytes(seed, counter);
            let affine: Option<G1Affine> =
                Option::from(G1Affine::from_compressed_unchecked(&candidate));
            if let Some(affine) = affine {
                let point: G1Projective = G1Projective::from(affine).clear_cofactor();
                if !bool::from(point.is_identity()) {
                    return point;
                }
            }
            counter += 1;
        }
    }

    #[test]
    fn point_hash_from_uniform_matches_pure_bls12_381_reference_decode() {
        for i in 0u8..32 {
            let seed = [i; 64];
            assert_eq!(
                Bls12_381G1Cycle::point_hash_from_uniform(&seed),
                hash_to_curve_try_and_increment_reference(&seed),
            );
        }
    }

    #[test]
    fn compressed_round_trips() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let point = G1Projective::random(&mut rng);
        let compressed = Bls12_381G1Cycle::point_compress(&point);
        let decoded = Bls12_381G1Cycle::compressed_decompress(&compressed).unwrap();
        assert_eq!(point, decoded);
    }

    #[test]
    fn compressed_decompress_rejects_off_subgroup_point() {
        // Force the infinity flag off and reuse a candidate that is on the
        // curve but not necessarily in the prime-order subgroup, by
        // decoding via the unchecked path and re-encoding without cofactor
        // clearing, then confirming the checked path either agrees (if the
        // random point already lands in the subgroup) or rejects it.
        let candidate = candidate_compressed_bytes(&[9u8; 64], 0);
        let Some(affine) =
            Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&candidate))
        else {
            return;
        };
        let is_torsion_free = bool::from(affine.is_torsion_free());
        let checked = Bls12_381G1Cycle::compressed_decompress(&GroupEncoding::to_bytes(&affine));
        assert_eq!(checked.is_some(), is_torsion_free);
    }

    #[test]
    fn scalar_batch_invert_matches_individual_inversions() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut items: Vec<Scalar> = (0..8).map(|_| Scalar::random(&mut rng)).collect();
        let expected: Vec<Scalar> = items
            .iter()
            .map(|s| Option::from(Field::invert(s)).unwrap())
            .collect();
        Bls12_381G1Cycle::scalar_batch_invert(&mut items);
        assert_eq!(items, expected);
    }

    #[test]
    fn scalar_wide_and_canonical_round_trip() {
        let bytes = [5u8; 32];
        let scalar = Bls12_381G1Cycle::scalar_from_canonical(&bytes).unwrap();
        assert_eq!(Bls12_381G1Cycle::scalar_to_canonical(&scalar), bytes);
    }

    #[test]
    fn vartime_msm_matches_generator_mul_for_single_term() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let scalar = Scalar::random(&mut rng);
        let point = G1Projective::generator();
        let msm = Bls12_381G1Cycle::vartime_msm(&[scalar], &[point]);
        assert_eq!(msm, point * scalar);
    }
}
