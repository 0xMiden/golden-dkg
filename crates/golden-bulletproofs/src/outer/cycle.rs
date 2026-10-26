//! [`Cycle`] implementation for BLS12-381 G1, the Bulletproofs commitment
//! group (`Gout`) of the paper eVRF's BLS12-381/Jubjub instantiation. The
//! R1CS native field is BLS12-381's scalar field, which is also Jubjub's
//! base field (`jubjub::Fq` is a re-export of `bls12_381::Scalar`), so a
//! Jubjub-typed `Gin` witness value needs no field conversion to become an
//! R1CS coefficient.

use super::g1::BlsG1Projective;
use bls12_381::Scalar;
use bulletproofs_cycle::Cycle;
use ff::Field;
use group::{Group, GroupEncoding};
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
/// probability. This map is not constant-time: it derives public deterministic
/// Bulletproofs generators and never processes secret data.
///
/// The x-coordinate recovery (a 381-bit field square root, the dominant
/// cost of each candidate) runs through `blstrs`' hand-written-assembly
/// field layer rather than `bls12_381`'s plain-Rust one; both crates decode
/// the same standard compressed BLS12-381 encoding, so this produces
/// identical candidate points to decoding directly with `bls12_381` — only
/// the arithmetic backend for the recovery differs.
fn hash_to_curve_try_and_increment(seed: &[u8; 64]) -> BlsG1Projective {
    let mut counter: u64 = 0;
    loop {
        let candidate = candidate_compressed_bytes(seed, counter);
        let affine: CtOption<blstrs::G1Affine> =
            blstrs::G1Affine::from_compressed_unchecked(&candidate);
        if let Some(affine) = Option::<blstrs::G1Affine>::from(affine) {
            let point = blstrs::G1Projective::from(affine);
            let cleared = super::msm_blst::clear_cofactor(&point);
            if !bool::from(cleared.is_identity()) {
                return BlsG1Projective(cleared);
            }
        }
        counter += 1;
    }
}

fn checked_affine(point: &blst::blst_p1_affine) -> blstrs::G1Affine {
    let affine = blstrs::G1Affine::from_raw_unchecked(point.x.into(), point.y.into(), false);
    assert!(
        bool::from(affine.is_on_curve() & affine.is_torsion_free()),
        "affine point must be in the BLS12-381 G1 prime-order subgroup"
    );
    affine
}

impl Cycle for Bls12_381G1Cycle {
    type Scalar = Scalar;
    type Point = BlsG1Projective;
    // `blst`'s native affine representation, not `bls12_381::G1Affine`: see
    // `super::msm_blst`'s module doc for why. Converting to/from it happens
    // once per stored generator or commitment (here and in
    // `batch_normalize`/`affine_compress`), not once per MSM call.
    type Affine = blst::blst_p1_affine;
    type Compressed = <blstrs::G1Projective as GroupEncoding>::Repr;
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
        GroupEncoding::to_bytes(&point.0)
    }

    fn compressed_decompress(compressed: &Self::Compressed) -> Option<Self::Point> {
        Option::<blstrs::G1Projective>::from(GroupEncoding::from_bytes(compressed))
            .map(BlsG1Projective)
    }

    fn compressed_identity() -> Self::Compressed {
        GroupEncoding::to_bytes(&blstrs::G1Projective::identity())
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
        *blstrs::G1Affine::from(point.0).as_ref()
    }

    fn affine_to_point(point: &Self::Affine) -> Self::Point {
        BlsG1Projective(blstrs::G1Projective::from(checked_affine(point)))
    }

    fn batch_normalize(points: &[Self::Point]) -> Vec<Self::Affine> {
        super::msm_blst::batch_normalize(points)
    }

    fn affine_compress(point: &Self::Affine) -> Self::Compressed {
        GroupEncoding::to_bytes(&checked_affine(point))
    }

    fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        super::msm_blst::msm_projective(scalars, points)
    }

    fn vartime_msm_affine(scalars: &[Self::Scalar], points: &[Self::Affine]) -> Self::Point {
        assert_eq!(scalars.len(), points.len());
        super::msm_blst::msm(scalars, points)
    }

    fn vartime_msm_mixed(
        affine_batches: &[(&[Self::Scalar], &[Self::Affine])],
        dynamic_scalars: &[Self::Scalar],
        dynamic_points: &[Self::Point],
    ) -> Self::Point {
        super::msm_blst::msm_mixed(affine_batches, dynamic_scalars, dynamic_points)
    }

    fn vartime_msm_optional(
        scalars: &[Self::Scalar],
        points: &[Option<Self::Point>],
    ) -> Option<Self::Point> {
        let identity = BlsG1Projective::identity();
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
