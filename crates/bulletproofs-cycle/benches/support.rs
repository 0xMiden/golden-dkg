//! Benchmark-only [`Cycle`] impls over the upstream `halo2curves` secp256k1 /
//! secq256k1 curves (privacy-ethereum/halo2curves).
//!
//! These live in the bench harness — not in `golden-halo2curves` — so that
//! `bulletproofs-cycle` can be benchmarked against `halo2curves` directly,
//! with no dependency on the golden project. The impls mirror the production
//! adapters in `golden-halo2curves` (same `msm_best` Pippenger MSM, same
//! `hash_to_curve` domain separators) so the numbers reflect the real curve
//! backend.
//!
//! Each bench binary pulls this in via `#[path = "support.rs"] mod support;`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use bulletproofs_cycle::Cycle;
use ff::{Field, FromUniformBytes, PrimeField};
use group::{Group, GroupEncoding};
use halo2curves::CurveExt;
use subtle::CtOption;

/// Implement [`Cycle`] for a single `halo2curves` projective curve.
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
                // Montgomery batch invert; precondition: every entry is nonzero.
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
                // halo2curves Pippenger MSM. Identity points are dropped first:
                // Pippenger's bucket logic doesn't handle the point-at-infinity
                // affine representation, and they contribute nothing anyway.
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
