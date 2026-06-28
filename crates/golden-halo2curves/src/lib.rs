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

            fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
                // Use halo2curves' Pippenger MSM (msm_best) instead of a naive
                // acc += p*s loop. The conversion to affine is O(n) inversions
                // but pays for itself many times over on every Bulletproofs
                // prove/verify, where each MSM is over thousands of points.
                //
                // Drop (scalar, point) pairs whose point is the identity before
                // handing to msm_best: Pippenger's bucket logic doesn't handle
                // the point-at-infinity affine representation, and an identity
                // point contributes nothing to the sum anyway.
                use group::Group;
                use halo2curves::msm::msm_best;

                type Affine = <$curve as halo2curves::CurveExt>::AffineExt;
                let identity = <Self::Point as Group>::identity();
                let filtered: Vec<_> = scalars
                    .iter()
                    .zip(points.iter())
                    .filter(|(_, p)| **p != identity)
                    .collect();
                if filtered.is_empty() {
                    return identity;
                }
                let scalars: Vec<_> = filtered.iter().map(|(s, _)| **s).collect();
                let bases: Vec<Affine> = filtered.iter().map(|(_, p)| (**p).into()).collect();
                msm_best::<Affine>(&scalars, &bases)
            }

            fn vartime_msm_optional(
                scalars: &[Self::Scalar],
                points: &[Option<Self::Point>],
            ) -> Option<Self::Point> {
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
                let bases: Vec<Affine> = filtered
                    .iter()
                    .map(|(_, p)| (*p).map(|proj| proj.into()))
                    .collect::<Option<Vec<_>>>()?;
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
