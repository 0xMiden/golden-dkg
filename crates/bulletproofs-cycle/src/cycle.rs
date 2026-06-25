//! Curve-cycle abstraction used by the Bulletproofs R1CS port.
//!
//! The original `zkcrypto/bulletproofs` crate is monomorphic over Ristretto.
//! This trait captures the smallest set of operations the R1CS path needs so
//! the same code runs over any zkcrypto-compatible curve whose scalar field
//! backs the R1CS coefficients and whose group carries the Pedersen and
//! Bulletproofs commitments.
//!
//! Scalar arithmetic (`+`, `-`, `*`, negation, `ZERO`, `ONE`) comes from
//! [`ff::Field`]. Group arithmetic (`+`, `-`, negation, scalar multiplication,
//! `identity`, `generator`) comes from [`group::Group`]. The remaining
//! operations that the zkcrypto traits do not expose in a uniform way are
//! provided as methods on [`Cycle`].

use core::fmt::Debug;

use ff::{Field, PrimeField};
use group::Group;
use rand_core::CryptoRngCore;

/// Bulletproofs commitment group plus its scalar field.
///
/// `Scalar` is the R1CS coefficient field and `Point` is the projective group
/// whose scalar field is `Scalar`. `Compressed` is the fixed-width encoding of
/// a group element used in proof transcripts and serialized proofs.
pub trait Cycle: Clone + Eq + Debug + 'static {
    /// R1CS coefficient field, also the scalar field of [`Cycle::Point`].
    type Scalar: Field + PrimeField + Copy + Default + Eq + Debug + 'static;
    /// Projective group element used for Pedersen and Bulletproofs commitments.
    type Point: Group<Scalar = Self::Scalar> + Copy + Eq + Debug + 'static;
    /// Fixed-width compressed encoding of a [`Cycle::Point`].
    type Compressed: Clone + Debug + 'static;

    /// Number of bytes in a compressed point encoding.
    const COMPRESSED_BYTES: usize;

    /// Reduce 64 uniform bytes into a scalar via a wide reduction.
    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar;

    /// Decode a scalar from its canonical 32-byte encoding, returning `None`
    /// when the bytes are not a canonical representative.
    fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Self::Scalar>;

    /// Canonical 32-byte encoding of a scalar.
    fn scalar_to_canonical(scalar: &Self::Scalar) -> [u8; 32];

    /// Multiplicative inverse of a scalar.
    ///
    /// Returns [`Field::ZERO`] for non-invertible inputs (i.e. zero). This is a
    /// trait-surface contract, not a recovery: callers must ensure inputs are
    /// nonzero, or handle the zero return explicitly. Transcript-derived
    /// challenge scalars are nonzero with overwhelming probability.
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// Batch-invert a slice in place, returning the product of all inverses.
    ///
    /// **Precondition: every entry is nonzero.** Unlike
    /// `curve25519_dalek::scalar::Scalar::batch_invert`, this method returns a
    /// bare `Scalar` (not `Option<Scalar>`), so a zero input is not signalled.
    /// If any entry is zero, the Montgomery accumulator collapses to zero and
    /// every output is silently corrupted to zero, not just the zero entry.
    /// The returned product is also zero in that case. Callers in this crate
    /// only feed transcript challenges, which are nonzero with overwhelming
    /// probability.
    fn scalar_batch_invert(items: &mut [Self::Scalar]) -> Self::Scalar;

    /// Compress a projective point to its fixed-width encoding.
    fn point_compress(point: &Self::Point) -> Self::Compressed;

    /// Decompress a fixed-width encoding, returning `None` if it is invalid.
    fn compressed_decompress(compressed: &Self::Compressed) -> Option<Self::Point>;

    /// Encoding of the group identity element.
    fn compressed_identity() -> Self::Compressed;

    /// Whether a compressed encoding is the identity element.
    fn compressed_is_identity(compressed: &Self::Compressed) -> bool;

    /// Construct a compressed encoding directly from its byte representation.
    ///
    /// **Precondition: `bytes.len() >= Self::COMPRESSED_BYTES`.** The
    /// implementation indexes `bytes[..COMPRESSED_BYTES]` without a bounds
    /// check, so a short slice panics. Current callers in
    /// `inner_product_proof::from_bytes` and `r1cs::proof::from_bytes` slice
    /// from a pre-length-checked buffer, so the panic is unreachable in
    /// production; future callers must do the same.
    fn compressed_from_bytes(bytes: &[u8]) -> Self::Compressed;

    /// Byte slice view of a compressed encoding.
    fn compressed_as_bytes(compressed: &Self::Compressed) -> &[u8];

    /// Map 64 uniform bytes to a near-uniform group element. Used to derive
    /// independent Bulletproofs generators from a SHAKE256 stream.
    fn point_hash_from_uniform(bytes: &[u8; 64]) -> Self::Point;

    /// Variable-time multiscalar multiplication of `scalars` and `points`.
    ///
    /// Panics if the slice lengths differ. The first milestone does not require
    /// constant-time multiplication.
    fn vartime_msm(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point;

    /// Variable-time multiscalar multiplication where each point may be
    /// missing. Returns `None` if any required point is `None`.
    fn vartime_msm_optional(
        scalars: &[Self::Scalar],
        points: &[Option<Self::Point>],
    ) -> Option<Self::Point>;
}

/// Helper: random scalar drawn from a cryptographic RNG.
pub fn random_scalar<C: Cycle>(rng: &mut impl CryptoRngCore) -> C::Scalar {
    C::Scalar::random(rng)
}
