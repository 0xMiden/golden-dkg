//! Native arithmetic and strict protocol codecs for the fixed Golden relation.

use core::fmt::Debug;

use ff::PrimeField;
use group::prime::PrimeGroup;

use crate::Result;

/// Byte order of a native base-field representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldByteOrder {
    /// Most-significant byte first.
    BigEndian,
    /// Least-significant byte first.
    LittleEndian,
}

/// A prime-order identity group used by the fixed Main Golden relation.
///
/// Arithmetic uses the native `ff` and `group` types. These hooks supply the
/// protocol encodings and curve operations those traits do not describe.
/// This is the inner identity/DH group, independently of a proof system's
/// outer commitment group. Implementations for the same mathematical group
/// must use the same protocol bytes and [`Self::GROUP_ID`].
pub trait DkgGroup: Clone + Debug + Eq + Send + Sync + 'static {
    /// Native scalar field of the prime-order identity group.
    type Scalar: PrimeField;
    /// Native prime-order identity/DH points.
    type Point: PrimeGroup<Scalar = Self::Scalar>;
    /// Native field containing the point's affine coordinates.
    type BaseField: PrimeField;

    /// Stable mathematical group identifier, independent of arithmetic/proof backend.
    const GROUP_ID: &'static str;
    /// Exact byte length of every protocol point, including the identity.
    const POINT_BYTES: usize;

    /// Encode a point in the group's canonical protocol representation.
    fn encode_point(point: &Self::Point) -> Vec<u8>;

    /// Strictly decode exactly one canonical subgroup point.
    ///
    /// Reject incorrect lengths, alternate encodings and points outside the
    /// prime-order subgroup. Decoding must never clear the cofactor. The
    /// identity has one stable encoding; its admissibility belongs to the
    /// protocol field that contains it.
    fn decode_point(bytes: &[u8]) -> Result<Self::Point>;

    /// Encode a scalar as a canonical 32-byte little-endian integer.
    fn encode_scalar(scalar: &Self::Scalar) -> [u8; 32];

    /// Strictly decode a canonical 32-byte little-endian scalar.
    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar>;

    /// Byte order of the native representation for [`Self::BaseField`].
    fn base_field_byte_order() -> FieldByteOrder;

    /// Map a domain-separated input to a nonidentity prime-order point.
    ///
    /// Cofactor clearing may form part of this map, unlike point decoding.
    fn hash_to_point(domain: &[u8], input: &[u8]) -> Result<Self::Point>;

    /// Extract an affine x-coordinate; for Jubjub this is Edwards `u`.
    ///
    /// The identity and unavailable coordinates must fail closed.
    fn affine_x(point: &Self::Point) -> Result<Self::BaseField>;

    /// Reduce the canonical base-field integer modulo the scalar order.
    ///
    /// This is integer reduction, including the full base/scalar modulus gap;
    /// it is not a checked reinterpretation or equality in the base field.
    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar;

    /// Multiply the canonical generator by a scalar.
    ///
    /// Adapters retain their constant-time public fixed-base tables here.
    fn mul_generator(scalar: &Self::Scalar) -> Self::Point;
}
