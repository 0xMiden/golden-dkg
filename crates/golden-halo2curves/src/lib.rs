//! [`bulletproofs_cycle::Cycle`] implementations for the `halo2curves`
//! Secp/Secq curve cycle.
//!
//! Each curve implements `Cycle` with its own scalar field as the R1CS field
//! and its own projective group as the commitment group. The two curves form a
//! 2-cycle: the scalar field of one is the base field of the other, so a
//! Golden relation whose witness values live in one field can commit in the
//! other without foreign-field arithmetic in the Bulletproofs layer.

#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(feature = "halo2curves-secp256k1")]
pub mod golden_group;

use bulletproofs_cycle::Cycle;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{Group, GroupEncoding};
use halo2curves::CurveExt;
use subtle::CtOption;

/// Implement [`Cycle`] for a `halo2curves` projective curve.
macro_rules! impl_cycle {
    ($wrapper:ident, $curve:ty, $scalar:ty, $compressed_bytes:literal, $domain:literal) => {
        /// Concrete [`Cycle`] over a single `halo2curves` curve.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $wrapper;

        impl Cycle for $wrapper {
            type Scalar = $scalar;
            type Point = $curve;
            type Affine = <$curve as halo2curves::CurveExt>::AffineExt;
            type Compressed = <$curve as GroupEncoding>::Repr;
            const COMPRESSED_BYTES: usize = $compressed_bytes;

            fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
                <Self::Scalar as FromUniformBytes<64>>::from_uniform_bytes(bytes)
            }

            fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Self::Scalar> {
                let repr = <Self::Scalar as PrimeField>::Repr::from(*bytes);
                <Self::Scalar as PrimeField>::from_repr_vartime(repr)
            }

            fn scalar_to_canonical(scalar: &Self::Scalar) -> [u8; 32] {
                *scalar.to_repr().inner()
            }

            fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
                let ct: CtOption<Self::Scalar> = Field::invert(scalar);
                Option::from(ct).unwrap_or(Self::Scalar::ZERO)
            }

            fn scalar_batch_invert(items: &mut [Self::Scalar]) -> Self::Scalar {
                // Montgomery batch invert with a single inversion. Precondition:
                // every entry is nonzero. A single zero entry collapses the
                // running accumulator to zero, after which every output is
                // overwritten with zero (not just the zero entry) and the
                // returned product is zero. Callers in this crate only feed
                // transcript challenges, which are nonzero with overwhelming
                // probability.
                let mut acc = Self::Scalar::ONE;
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
                let ct: CtOption<Self::Point> = GroupEncoding::from_bytes(compressed);
                Option::from(ct)
            }

            fn compressed_identity() -> Self::Compressed {
                // Native halo2curves encoding of the identity, used by the
                // Bulletproofs layer for its own generators. This is **not**
                // the same byte layout as the `[0u8; 33]` convention used by
                // `golden_group::GoldenGroup::encode_element` for the
                // GoldenGroup trait surface: halo2curves sets a flag bit on
                // the leading byte to mark the identity rather than emitting
                // all zeros. The two APIs do not cross (Cycle drives the
                // Bulletproofs IPP; GoldenGroup drives DKG transcripts), so
                // the disagreement is fine as long as callers do not mix
                // them. If you need to pass an identity between layers,
                // re-encode through the target trait's API.
                GroupEncoding::to_bytes(&<Self::Point as Group>::identity())
            }

            fn compressed_is_identity(compressed: &Self::Compressed) -> bool {
                compressed.as_ref() == Self::compressed_identity().as_ref()
            }

            fn compressed_from_bytes(bytes: &[u8]) -> Self::Compressed {
                let mut repr = <Self::Compressed as Default>::default();
                repr.as_mut()
                    .copy_from_slice(&bytes[..Self::COMPRESSED_BYTES]);
                repr
            }

            fn compressed_as_bytes(compressed: &Self::Compressed) -> &[u8] {
                compressed.as_ref()
            }

            fn point_hash_from_uniform(bytes: &[u8; 64]) -> Self::Point {
                let hash = <Self::Point as CurveExt>::hash_to_curve($domain);
                hash(&bytes[..])
            }

            fn point_to_affine(point: &Self::Point) -> Self::Affine {
                use group::Curve;
                point.to_affine()
            }

            fn affine_to_point(point: &Self::Affine) -> Self::Point {
                use group::prime::PrimeCurveAffine;
                point.to_curve()
            }

            fn batch_normalize(points: &[Self::Point]) -> Vec<Self::Affine> {
                use group::Curve;

                let mut affine = vec![Self::Affine::default(); points.len()];
                <Self::Point as Curve>::batch_normalize(points, &mut affine);
                affine
            }

            fn affine_compress(point: &Self::Affine) -> Self::Compressed {
                use group::GroupEncoding;
                point.to_bytes()
            }

            fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
                // Use a two-point path for IPA folds, and Pippenger for
                // larger MSMs.
                //
                // Drop identity points before Pippenger: its bucket logic does
                // not handle the point-at-infinity affine representation.
                use group::Curve;
                use group::Group;
                use halo2curves::msm::msm_best;

                type Affine = <$curve as halo2curves::CurveExt>::AffineExt;
                let identity = <Self::Point as Group>::identity();

                if points.len() == 2 && points[0] != identity && points[1] != identity {
                    let p = points[0];
                    let q = points[1];

                    let mut table = [identity; 15];
                    table[3] = p; // P
                    table[0] = q; // Q
                    table[7] = table[3].double(); // 2P
                    table[1] = table[0].double(); // 2Q
                    table[11] = table[7] + p; // 3P
                    table[2] = table[1] + q; // 3Q

                    // table[i * 4 + j - 1] = i*P + j*Q for 0 <= i,j <= 3.
                    table[4] = table[3] + q;
                    table[5] = table[4] + q;
                    table[6] = table[5] + q;
                    table[8] = table[7] + q;
                    table[9] = table[8] + q;
                    table[10] = table[9] + q;
                    table[12] = table[11] + q;
                    table[13] = table[12] + q;
                    table[14] = table[13] + q;

                    let mut affine_table = [Affine::default(); 15];
                    <Self::Point as Curve>::batch_normalize(&table, &mut affine_table);

                    let s1 = scalars[0].to_repr();
                    let s2 = scalars[1].to_repr();
                    let mut acc = identity;
                    for (b1, b2) in s1.as_ref().iter().rev().zip(s2.as_ref().iter().rev()) {
                        for i in (0..8u32).rev().step_by(2) {
                            acc = acc.double().double();
                            let w1 = (((b1 >> i) & 1) << 1) | ((b1 >> (i - 1)) & 1);
                            let w2 = (((b2 >> i) & 1) << 1) | ((b2 >> (i - 1)) & 1);
                            let idx = (w1 as usize) * 4 + (w2 as usize);
                            if idx != 0 {
                                acc += affine_table[idx - 1];
                            }
                        }
                    }
                    return acc;
                }

                if !points.iter().any(|p| *p == identity) {
                    let mut bases = vec![Affine::default(); points.len()];
                    <Self::Point as Curve>::batch_normalize(points, &mut bases);
                    return msm_best::<Affine>(scalars, &bases);
                }

                let filtered: Vec<_> = scalars
                    .iter()
                    .zip(points.iter())
                    .filter(|(_, p)| **p != identity)
                    .collect();
                if filtered.is_empty() {
                    return identity;
                }
                let scalars: Vec<_> = filtered.iter().map(|(s, _)| **s).collect();
                let filtered_points: Vec<Self::Point> = filtered.iter().map(|(_, p)| **p).collect();
                let mut bases = vec![Affine::default(); filtered_points.len()];
                <Self::Point as Curve>::batch_normalize(&filtered_points, &mut bases);
                msm_best::<Affine>(&scalars, &bases)
            }

            fn vartime_msm_affine(
                scalars: &[Self::Scalar],
                points: &[Self::Affine],
            ) -> Self::Point {
                use halo2curves::msm::msm_best;

                assert_eq!(scalars.len(), points.len());
                msm_best::<Self::Affine>(scalars, points)
            }

            fn vartime_msm_optional(
                scalars: &[Self::Scalar],
                points: &[Option<Self::Point>],
            ) -> Option<Self::Point> {
                use group::Curve;
                use group::Group;
                use halo2curves::msm::msm_best;

                type Affine = <$curve as halo2curves::CurveExt>::AffineExt;
                let identity = <Self::Point as Group>::identity();
                let filtered: Vec<_> = scalars
                    .iter()
                    .zip(points.iter())
                    .filter(|(_, p)| **p != Some(identity))
                    .collect();
                if filtered.is_empty() {
                    return Some(identity);
                }
                let scalars: Vec<_> = filtered.iter().map(|(s, _)| **s).collect();
                let filtered_points: Vec<Self::Point> = filtered
                    .iter()
                    .map(|(_, p)| **p)
                    .collect::<Option<Vec<_>>>()?;
                let mut bases = vec![Affine::default(); filtered_points.len()];
                <Self::Point as Curve>::batch_normalize(&filtered_points, &mut bases);
                Some(msm_best::<Affine>(&scalars, &bases))
            }
        }
    };
}

impl_cycle!(
    Secp256k1Cycle,
    halo2curves::secp256k1::Secp256k1,
    halo2curves::secp256k1::Fq,
    33,
    "golden-bulletproofs-secp256k1"
);

impl_cycle!(
    Secq256k1Cycle,
    halo2curves::secq256k1::Secq256k1,
    halo2curves::secq256k1::Fq,
    33,
    "golden-bulletproofs-secq256k1"
);
