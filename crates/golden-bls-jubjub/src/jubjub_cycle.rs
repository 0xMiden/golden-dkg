//! [`Cycle`] implementation for Jubjub, the identity-key / Diffie-Hellman
//! group (`Gin`) of the paper eVRF's BLS12-381/Jubjub instantiation.
//!
//! This is a separate `Cycle` impl from [`crate::cycle::Bls12_381G1Cycle`]:
//! `Gin` never backs Bulletproofs commitments, but the paper eVRF's
//! Chaum-Pedersen and constant-term proofs (native Schnorr-style proofs over
//! `Gin`, outside the R1CS) reuse the same `Cycle` machinery for point/scalar
//! transcript encoding that `golden-halo2curves` gives both Secp256k1 and
//! Secq256k1.

use bulletproofs_cycle::Cycle;
use ff::{Field, PrimeField};
use group::cofactor::CofactorGroup;
use group::{Curve, Group, GroupEncoding};
use jubjub::{AffinePoint, ExtendedPoint, Fr, SubgroupPoint};
use sha2::{Digest, Sha256};
use subtle::CtOption;

use crate::pippenger::multi_scalar_mul;

/// Domain separator for [`JubjubCycle::point_hash_from_uniform`]'s
/// try-and-increment candidate derivation.
const HASH_TO_CURVE_DOMAIN: &[u8] = b"golden-bulletproofs-jubjub-v1";

/// [`Cycle`] over Jubjub's prime-order subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JubjubCycle;

/// Map a domain-separated `(seed, counter)` pair to 32 pseudorandom bytes,
/// laid out as a candidate Jubjub affine-point encoding (see
/// `golden_group::candidate_bytes` for the same technique keyed by a
/// `(domain, message)` pair instead of a single 64-byte seed).
fn candidate_bytes(seed: &[u8; 64], counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_TO_CURVE_DOMAIN);
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Map 64 uniform bytes to a near-uniform, cofactor-cleared Jubjub point via
/// try-and-increment. See `Bls12_381G1Cycle::point_hash_from_uniform`'s doc
/// for the rationale (`jubjub` ships no RFC 9380 hash-to-curve; every caller
/// uses this to derive public Bulletproofs-unrelated transcript points, so
/// non-constant-time running time is not a concern).
fn hash_to_curve_try_and_increment(seed: &[u8; 64]) -> SubgroupPoint {
    let mut counter: u32 = 0;
    loop {
        let candidate = candidate_bytes(seed, counter);
        let affine: CtOption<AffinePoint> = AffinePoint::from_bytes(candidate);
        let affine: Option<AffinePoint> = Option::from(affine);
        if let Some(affine) = affine {
            let extended: ExtendedPoint = affine.into();
            let point = extended.clear_cofactor();
            if !bool::from(point.is_identity()) {
                return point;
            }
        }
        counter += 1;
    }
}

impl Cycle for JubjubCycle {
    type Scalar = Fr;
    type Point = SubgroupPoint;
    type Affine = AffinePoint;
    type Compressed = <SubgroupPoint as GroupEncoding>::Repr;
    const COMPRESSED_BYTES: usize = 32;

    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
        Fr::from_bytes_wide(bytes)
    }

    fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Self::Scalar> {
        Option::from(Fr::from_bytes(bytes))
    }

    fn scalar_to_canonical(scalar: &Self::Scalar) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        Option::from(Field::invert(scalar)).unwrap_or(Fr::ZERO)
    }

    fn scalar_batch_invert(items: &mut [Self::Scalar]) -> Self::Scalar {
        // Montgomery batch invert with a single inversion. Precondition:
        // every entry is nonzero (see the `Cycle` trait doc for the same
        // contract on every other implementation in this workspace).
        let mut acc = Fr::ONE;
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
        GroupEncoding::to_bytes(&SubgroupPoint::identity())
    }

    fn compressed_is_identity(compressed: &Self::Compressed) -> bool {
        compressed == &Self::compressed_identity()
    }

    fn compressed_from_bytes(bytes: &[u8]) -> Self::Compressed {
        let mut repr = Self::Compressed::default();
        repr.copy_from_slice(&bytes[..Self::COMPRESSED_BYTES]);
        repr
    }

    fn compressed_as_bytes(compressed: &Self::Compressed) -> &[u8] {
        compressed.as_slice()
    }

    fn point_hash_from_uniform(bytes: &[u8; 64]) -> Self::Point {
        hash_to_curve_try_and_increment(bytes)
    }

    fn point_to_affine(point: &Self::Point) -> Self::Affine {
        let extended: ExtendedPoint = (*point).into();
        extended.to_affine()
    }

    fn affine_to_point(point: &Self::Affine) -> Self::Point {
        // `from_raw_unchecked` is O(1) (a plain reinterpretation of the
        // coordinates); `clear_cofactor()`/`into_subgroup()` would instead
        // pay a real scalar multiplication or a torsion-free check. Every
        // `Self::Affine` this crate produces already comes from a
        // prime-order-subgroup point (via `point_to_affine`, or via
        // Bulletproofs generators derived through
        // `point_hash_from_uniform`/`batch_normalize`, both subgroup-valued),
        // so no check is needed here — exactly the "hard-coding constants"
        // contract `SubgroupPoint::from_raw_unchecked` documents.
        SubgroupPoint::from_raw_unchecked(point.get_u(), point.get_v())
    }

    fn batch_normalize(points: &[Self::Point]) -> Vec<Self::Affine> {
        let mut extended: Vec<ExtendedPoint> = points.iter().map(|p| (*p).into()).collect();
        jubjub::batch_normalize(&mut extended).collect()
    }

    fn affine_compress(point: &Self::Affine) -> Self::Compressed {
        GroupEncoding::to_bytes(point)
    }

    fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        let bytes: Vec<[u8; 32]> = scalars.iter().map(|s| s.to_repr()).collect();
        multi_scalar_mul(&bytes, points, Fr::NUM_BITS)
    }

    fn vartime_msm_affine(scalars: &[Self::Scalar], points: &[Self::Affine]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        let projective: Vec<Self::Point> = points.iter().map(Self::affine_to_point).collect();
        Self::vartime_msm(scalars, &projective)
    }

    fn vartime_msm_optional(
        scalars: &[Self::Scalar],
        points: &[Option<Self::Point>],
    ) -> Option<Self::Point> {
        let identity = SubgroupPoint::identity();
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
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn point_hash_from_uniform_is_deterministic_and_in_prime_order_subgroup() {
        let bytes = [7u8; 64];
        let a = JubjubCycle::point_hash_from_uniform(&bytes);
        let b = JubjubCycle::point_hash_from_uniform(&bytes);
        assert_eq!(a, b);
        assert!(!bool::from(a.is_identity()));
    }

    #[test]
    fn point_hash_from_uniform_differs_across_inputs() {
        let a = JubjubCycle::point_hash_from_uniform(&[1u8; 64]);
        let b = JubjubCycle::point_hash_from_uniform(&[2u8; 64]);
        assert_ne!(a, b);
    }

    #[test]
    fn compressed_round_trips() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let point = SubgroupPoint::random(&mut rng);
        let compressed = JubjubCycle::point_compress(&point);
        let decoded = JubjubCycle::compressed_decompress(&compressed).unwrap();
        assert_eq!(point, decoded);
    }

    #[test]
    fn scalar_batch_invert_matches_individual_inversions() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut items: Vec<Fr> = (0..8).map(|_| Fr::random(&mut rng)).collect();
        let expected: Vec<Fr> = items
            .iter()
            .map(|s| Option::from(Field::invert(s)).unwrap())
            .collect();
        JubjubCycle::scalar_batch_invert(&mut items);
        assert_eq!(items, expected);
    }

    #[test]
    fn vartime_msm_matches_generator_mul_for_single_term() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let scalar = Fr::random(&mut rng);
        let point = SubgroupPoint::generator();
        let msm = JubjubCycle::vartime_msm(&[scalar], &[point]);
        assert_eq!(msm, point * scalar);
    }

    #[test]
    fn affine_to_point_is_the_inverse_of_point_to_affine() {
        let mut rng = ChaCha20Rng::seed_from_u64(31);
        for _ in 0..8 {
            let p = SubgroupPoint::random(&mut rng);
            let a = JubjubCycle::point_to_affine(&p);
            assert_eq!(JubjubCycle::affine_to_point(&a), p);
        }
    }

    #[test]
    fn vartime_msm_affine_matches_vartime_msm() {
        let mut rng = ChaCha20Rng::seed_from_u64(32);
        let points: Vec<SubgroupPoint> = (0..4).map(|_| SubgroupPoint::random(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..4).map(|_| Fr::random(&mut rng)).collect();
        let affine = JubjubCycle::batch_normalize(&points);
        assert_eq!(
            JubjubCycle::vartime_msm_affine(&scalars, &affine),
            JubjubCycle::vartime_msm(&scalars, &points)
        );
    }

    #[test]
    fn batch_normalize_matches_point_to_affine() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let points: Vec<SubgroupPoint> = (0..5).map(|_| SubgroupPoint::random(&mut rng)).collect();
        let batch = JubjubCycle::batch_normalize(&points);
        for (point, affine) in points.iter().zip(batch.iter()) {
            assert_eq!(*affine, JubjubCycle::point_to_affine(point));
        }
    }
}
