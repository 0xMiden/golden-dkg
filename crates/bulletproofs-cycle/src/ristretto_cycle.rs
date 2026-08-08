//! [`Cycle`] implementation for the Ristretto255 group over Curve25519.
//!
//! Ristretto is not part of any curve cycle on its own, but it is the native
//! commitment group of upstream `zkcrypto/bulletproofs`. Wiring it through the
//! same `Cycle` trait as the Secp/Secq cycle proves the abstraction is
//! backend-pluggable rather than halo2curves-specific, and it unlocks
//! byte-for-byte compatibility with upstream proof fixtures for future
//! cross-validation work.
//!
//! The impl lives behind the `ristretto` cargo feature because pulling in
//! `curve25519-dalek` is opt-in: the crate's primary target is the Secp/Secq
//! cycle, and downstream users who never touch Ristretto should not pay for
//! the dalek dependency.

use crate::Cycle;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use group::Group;

/// Concrete [`Cycle`] over Ristretto255.
///
/// `Scalar` is `curve25519_dalek::scalar::Scalar` (the Ristretto scalar field,
/// `l = 2^252 + 27742317777372353535851937790883648493`), and `Point` is the
/// prime-order `RistrettoPoint` group. Compressed points are 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoCycle;

impl Cycle for RistrettoCycle {
    type Scalar = Scalar;
    type Point = RistrettoPoint;
    type Affine = RistrettoPoint;
    type Compressed = CompressedRistretto;
    const COMPRESSED_BYTES: usize = 32;

    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
        Scalar::from_bytes_mod_order_wide(bytes)
    }

    fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Self::Scalar> {
        // dalek's from_canonical_bytes returns CtOption<Scalar>; the
        // Cycle trait wants Option<Scalar>. subtle's blanket From impl
        // does the conversion in constant time.
        Option::from(Scalar::from_canonical_bytes(*bytes))
    }

    fn scalar_to_canonical(scalar: &Self::Scalar) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        // dalek 4.x Scalar::invert returns Scalar directly (0 for 0), so the
        // Cycle trait's "Field::ZERO for non-invertible inputs" contract is
        // satisfied without a CtOption unwrap.
        Scalar::invert(scalar)
    }

    fn scalar_batch_invert(items: &mut [Self::Scalar]) -> Self::Scalar {
        // dalek 4.x Scalar::batch_invert returns Scalar directly (0 if any
        // input is 0). The Cycle trait's precondition is that every entry is
        // nonzero, so the zero-return-on-zero path is unreachable in callers.
        Scalar::batch_invert(items)
    }

    fn point_compress(point: &Self::Point) -> Self::Compressed {
        point.compress()
    }

    fn compressed_decompress(compressed: &Self::Compressed) -> Option<Self::Point> {
        compressed.decompress()
    }

    fn compressed_identity() -> Self::Compressed {
        RistrettoPoint::identity().compress()
    }

    fn compressed_is_identity(compressed: &Self::Compressed) -> bool {
        compressed.as_bytes() == Self::compressed_identity().as_bytes()
    }

    fn compressed_from_bytes(bytes: &[u8]) -> Self::Compressed {
        // Precondition: bytes.len() >= COMPRESSED_BYTES. See Cycle::compressed_from_bytes.
        // CompressedRistretto is a public tuple struct around [u8; 32], so
        // constructing directly avoids the Result-returning from_slice path.
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[..Self::COMPRESSED_BYTES]);
        CompressedRistretto(buf)
    }

    fn compressed_as_bytes(compressed: &Self::Compressed) -> &[u8] {
        compressed.as_bytes()
    }

    fn point_hash_from_uniform(bytes: &[u8; 64]) -> Self::Point {
        RistrettoPoint::from_uniform_bytes(bytes)
    }

    fn point_to_affine(point: &Self::Point) -> Self::Affine {
        *point
    }

    fn affine_to_point(point: &Self::Affine) -> Self::Point {
        *point
    }

    fn batch_normalize(points: &[Self::Point]) -> Vec<Self::Affine> {
        points.to_vec()
    }

    fn affine_compress(point: &Self::Affine) -> Self::Compressed {
        point.compress()
    }

    fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point {
        // RistrettoPoint: VartimeMultiscalarMul takes owned iterators. The
        // Cycle signature hands us slices of references, so collect once to
        // bridge into dalek's iterator API.
        RistrettoPoint::vartime_multiscalar_mul(scalars.to_vec(), points.to_vec())
    }

    fn vartime_msm_affine(scalars: &[Self::Scalar], points: &[Self::Affine]) -> Self::Point {
        RistrettoPoint::vartime_multiscalar_mul(scalars.to_vec(), points.to_vec())
    }

    fn vartime_msm_optional(
        scalars: &[Self::Scalar],
        points: &[Option<Self::Point>],
    ) -> Option<Self::Point> {
        let mut acc = RistrettoPoint::identity();
        for (s, p) in scalars.iter().zip(points.iter()) {
            let p = (*p)?;
            acc += p * *s;
        }
        Some(acc)
    }
}
