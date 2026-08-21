//! Minimal scalar and group traits used by the Golden algebraic core.

use core::fmt::Debug;

use ff::PrimeField;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::{Error, Result};

/// Byte order used by a public field-element representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldByteOrder {
    /// Most-significant byte first.
    BigEndian,
    /// Least-significant byte first.
    LittleEndian,
}

/// Scalar field operations needed by Shamir sharing and interpolation.
pub trait GoldenScalar: Clone + Debug + Eq + ConstantTimeEq + Sized {
    /// Canonical scalar byte representation.
    type Repr: AsRef<[u8]> + Clone + Debug + Eq + TryFrom<Vec<u8>>;

    /// Length in bytes of [`Self::Repr`].
    const REPR_BYTES: usize;

    /// Return the additive identity.
    fn zero() -> Self;

    /// Return the multiplicative identity.
    fn one() -> Self;

    /// Sample a random scalar.
    fn random(rng: &mut impl CryptoRngCore) -> Self;

    /// Convert a public `u64` into a scalar.
    ///
    /// Reduction is by the field modulus; this is infallible for every
    /// concrete `GoldenScalar` in the workspace today, so the `Result` is
    /// reserved for future fields that may reject inputs outside a canonical
    /// range (e.g. a field whose modulus is below `u64::MAX` and where a
    /// caller wants reduction-by-construction rather than wrapping). Callers
    /// can `.expect(...)` on the result when the input is known small.
    fn from_u64(value: u64) -> Result<Self>;

    /// Add two scalars.
    fn add(&self, rhs: &Self) -> Self;

    /// Subtract two scalars.
    fn sub(&self, rhs: &Self) -> Self;

    /// Multiply two scalars.
    fn mul(&self, rhs: &Self) -> Self;

    /// Return the additive inverse.
    fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    /// Invert a scalar. Return `None` for zero.
    fn invert(&self) -> Option<Self>;

    /// Return whether the scalar is zero.
    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::zero())
    }

    /// Encode a scalar in canonical form.
    fn to_repr(&self) -> Self::Repr;

    /// Decode a scalar from canonical form.
    fn from_repr(repr: &Self::Repr) -> Result<Self>;

    /// Return the scalar field modulus in the same byte order as [`Self::Repr`].
    ///
    /// This value is not itself a canonical scalar encoding, because canonical
    /// scalar encodings are strictly less than the modulus.
    fn modulus() -> Self::Repr;

    /// Return the byte order used by [`Self::Repr`].
    fn repr_byte_order() -> FieldByteOrder;

    /// Derive a nonzero scalar by rejection sampling SHA-256 output.
    fn hash_to_scalar(domain: &[u8], message: &[u8]) -> Result<Self> {
        for counter in 0u32..u32::MAX {
            let mut bytes = Vec::with_capacity(Self::REPR_BYTES);
            let mut block = 0u32;

            while bytes.len() < Self::REPR_BYTES {
                let mut hasher = Sha256::new();
                hasher.update(b"golden-scalar-v1");
                hasher.update((domain.len() as u64).to_be_bytes());
                hasher.update(domain);
                hasher.update((message.len() as u64).to_be_bytes());
                hasher.update(message);
                hasher.update(counter.to_be_bytes());
                hasher.update(block.to_be_bytes());
                bytes.extend_from_slice(&hasher.finalize());
                block += 1;
            }

            bytes.truncate(Self::REPR_BYTES);
            let repr = Self::Repr::try_from(bytes).map_err(|_| Error::InvalidEncoding)?;
            if let Ok(scalar) = Self::from_repr(&repr) {
                if !bool::from(scalar.is_zero()) {
                    return Ok(scalar);
                }
            }
        }

        Err(Error::InvalidEncoding)
    }
}

/// Prime order discrete log group operations needed by Feldman commitments.
pub trait GoldenGroup: Clone + Debug + Sized {
    /// Scalar field for this group.
    type Scalar: GoldenScalar;

    /// Group element type.
    type Element: Clone + Debug + Eq + ConstantTimeEq;

    /// Canonical group element byte representation.
    type ElementRepr: AsRef<[u8]> + Clone + Debug + Eq;

    /// Length in bytes of [`Self::ElementRepr`].
    const ELEMENT_REPR_BYTES: usize;

    /// Stable backend identifier for transcript binding.
    const BACKEND_ID: &'static str;

    /// Return the group generator.
    fn generator() -> Self::Element;

    /// Return the group identity.
    fn identity() -> Self::Element;

    /// Add two group elements.
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Subtract two group elements.
    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Multiply a group element by a scalar.
    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element;

    /// Multiply the group generator by a scalar.
    fn mul_generator(scalar: &Self::Scalar) -> Self::Element {
        Self::mul(&Self::generator(), scalar)
    }

    /// Return whether the point is the identity.
    fn is_identity(point: &Self::Element) -> Choice;

    /// Encode a group element in canonical form.
    fn encode_element(point: &Self::Element) -> Self::ElementRepr;

    /// Decode a group element from canonical form.
    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element>;
}

/// Random-oracle-to-group operation for prime-order output groups.
///
/// This is smaller than [`GoldenCurve`]: protocol output groups and
/// Bulletproofs generator groups need independent hash-to-group points, but do
/// not necessarily need affine coordinates for the input-curve exponentiation
/// gadgets.
pub trait GoldenHashToGroup: GoldenGroup {
    /// Hash a domain-separated message to a non-identity group element.
    ///
    /// `domain` is the application-specific prefix. Curve adapters append the
    /// ciphersuite's fixed RFC 9380 domain suffix before hashing.
    fn hash_to_group(domain: &[u8], message: &[u8]) -> Result<Self::Element>;
}

/// Curve operations needed to evaluate the fixed Main Golden relation.
///
/// This is deliberately separate from [`GoldenGroup`]: Shamir sharing and
/// Feldman commitments only need prime-order group arithmetic, while Main
/// Golden also needs full base-field arithmetic and affine x-coordinates.
pub trait GoldenCurve: GoldenHashToGroup {
    /// Base field containing affine coordinates and the setup coefficient.
    type BaseField: PrimeField;

    /// Return the byte order used by [`PrimeField::Repr`] for the base field.
    fn base_field_byte_order() -> FieldByteOrder;

    /// Return the affine x-coordinate of a non-identity group element.
    ///
    /// Implementations must fail closed for the identity and for any point
    /// whose affine representation is unavailable. They must not substitute
    /// zero for a missing coordinate.
    fn affine_x(point: &Self::Element) -> Result<Self::BaseField>;

    /// Interpret a base-field element as its canonical integer and reduce that
    /// integer modulo the group scalar order.
    ///
    /// This conversion is exact and infallible for every canonical base-field
    /// element; it is not a fallible cross-field decoding operation.
    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar;
}
