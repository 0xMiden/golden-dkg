//! [`golden_core::GoldenGroup`] adapter for `jubjub`.
//!
//! The DKG layer speaks the `GoldenGroup` trait over a prime-order group.
//! This module exposes `JubjubGoldenGroup`, whose scalar field is the Jubjub
//! scalar field `Fr` and whose element type is `jubjub::SubgroupPoint` (the
//! cofactor-cleared prime-order subgroup, encoded in the type itself). The
//! paper eVRF backend in `golden-evrf` consumes this adapter as `Gin`; its
//! base field `jubjub::Fq` is a re-export of `bls12_381::Scalar`, the same
//! type used as the R1CS field for the `Gout` Bulletproofs commitment group
//! (see `crate::cycle::Bls12_381G1Cycle`), so no field conversion is needed
//! between the two.

use core::fmt;

use ff::{Field, PrimeField};
use golden_core::{
    Error, FieldByteOrder, GoldenEvrfCurve, GoldenGroup, GoldenHashToGroup, GoldenScalar, Result,
};
use group::cofactor::CofactorGroup;
use group::{Group, GroupEncoding};
use jubjub::{AffinePoint, ExtendedPoint, Fq, Fr, SubgroupPoint};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// Jubjub scalar-field (`Fr`) modulus, little-endian canonical bytes.
/// `r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`.
const JUBJUB_FR_MODULUS_LE: [u8; 32] = [
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
];

/// Jubjub base-field (`Fq`, i.e. `bls12_381::Scalar`) modulus, little-endian
/// canonical bytes.
/// `q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
const JUBJUB_FQ_MODULUS_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
    0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
];

/// Domain separator prefix for [`JubjubGoldenGroup::hash_to_group`]'s
/// try-and-increment candidate derivation.
const HASH_TO_CURVE_PREFIX: &[u8] = b"golden-jubjub-h2c-v1";

/// Wrapper around the Jubjub scalar field `Fr`.
#[derive(Clone, Copy, Default)]
pub struct JubjubScalar(pub Fr);

impl fmt::Debug for JubjubScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("JubjubScalar").field(&"<redacted>").finish()
    }
}

impl PartialEq for JubjubScalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for JubjubScalar {}

impl ConstantTimeEq for JubjubScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl GoldenScalar for JubjubScalar {
    type Repr = [u8; 32];

    const REPR_BYTES: usize = 32;

    fn zero() -> Self {
        Self(Fr::zero())
    }

    fn one() -> Self {
        Self(Fr::one())
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Fr::random(rng))
    }

    fn from_u64(value: u64) -> Result<Self> {
        Ok(Self(Fr::from(value)))
    }

    fn add(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }

    fn sub(&self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }

    fn mul(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    fn neg(&self) -> Self {
        Self(-self.0)
    }

    fn invert(&self) -> Option<Self> {
        Option::<Fr>::from(self.0.invert()).map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn from_repr(repr: &Self::Repr) -> Result<Self> {
        Option::<Fr>::from(Fr::from_repr(*repr))
            .map(Self)
            .ok_or(Error::InvalidEncoding)
    }

    fn modulus() -> Self::Repr {
        JUBJUB_FR_MODULUS_LE
    }

    fn repr_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }
}

/// Wrapper around a Jubjub prime-order-subgroup point.
#[derive(Clone, Copy, Default)]
pub struct JubjubElement(pub SubgroupPoint);

impl fmt::Debug for JubjubElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = JubjubGoldenGroup::encode_element(self);
        f.debug_tuple("JubjubElement")
            .field(&encoded.as_ref())
            .finish()
    }
}

impl PartialEq for JubjubElement {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for JubjubElement {}

impl ConstantTimeEq for JubjubElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let a: ExtendedPoint = self.0.into();
        let b: ExtendedPoint = other.0.into();
        a.ct_eq(&b)
    }
}

/// Golden group marker for Jubjub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JubjubGoldenGroup {}

impl GoldenGroup for JubjubGoldenGroup {
    type Scalar = JubjubScalar;
    type Element = JubjubElement;
    type ElementRepr = [u8; 33];

    const ELEMENT_REPR_BYTES: usize = 33;

    const BACKEND_ID: &'static str = "jubjub-v1";

    fn generator() -> Self::Element {
        JubjubElement(SubgroupPoint::generator())
    }

    fn identity() -> Self::Element {
        JubjubElement(SubgroupPoint::identity())
    }

    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element {
        JubjubElement(a.0 + b.0)
    }

    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        JubjubElement(a.0 - b.0)
    }

    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        JubjubElement(point.0 * scalar.0)
    }

    fn is_identity(point: &Self::Element) -> Choice {
        point.0.is_identity()
    }

    /// Encodes to a 33-byte representation (a leading `0x00` tag byte plus
    /// Jubjub's native 32-byte encoding) so the identity has a fixed-width
    /// all-zero encoding distinct from any non-identity point, mirroring
    /// `Secp256k1GoldenGroup::encode_element`. Jubjub's own 32-byte
    /// `GroupEncoding` already gives the identity a unique canonical
    /// encoding (`(0, 1)`, all-zero `u`-coordinate byte with sign bit 0), so
    /// the tag byte is redundant for canonicality but kept for a uniform
    /// `ELEMENT_REPR_BYTES` across `GoldenGroup` backends in this workspace.
    fn encode_element(point: &Self::Element) -> Self::ElementRepr {
        let mut out = [0u8; 33];
        out[1..].copy_from_slice(&GroupEncoding::to_bytes(&point.0));
        out
    }

    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element> {
        if repr[0] != 0 {
            return Err(Error::InvalidEncoding);
        }
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&repr[1..]);
        let ct: subtle::CtOption<SubgroupPoint> = GroupEncoding::from_bytes(&inner);
        Option::<SubgroupPoint>::from(ct)
            .map(JubjubElement)
            .ok_or(Error::InvalidEncoding)
    }
}

/// Map a domain-separated `(domain, message, counter)` triple to 32
/// pseudorandom bytes, laid out as a candidate Jubjub affine-point encoding
/// (`AffinePoint::to_bytes` layout: `v`-coordinate with the `u`-coordinate
/// sign folded into the top bit of the last byte).
fn candidate_bytes(domain: &[u8], message: &[u8], counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_TO_CURVE_PREFIX);
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.update(counter.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

impl GoldenHashToGroup for JubjubGoldenGroup {
    /// Hash a domain-separated message to a non-identity Jubjub point via
    /// try-and-increment (see `crate::cycle`'s
    /// `hash_to_curve_try_and_increment` for the rationale: `jubjub` ships
    /// no RFC 9380 hash-to-curve, and this crate's use of hash-to-group is
    /// always for public transcript-bound values, never secret data, so
    /// try-and-increment's non-constant-time running time is not a concern).
    fn hash_to_group(domain: &[u8], message: &[u8]) -> Result<Self::Element> {
        for counter in 0u32..u32::MAX {
            let candidate = candidate_bytes(domain, message, counter);
            let affine: subtle::CtOption<AffinePoint> = AffinePoint::from_bytes(candidate);
            let affine: Option<AffinePoint> = Option::from(affine);
            if let Some(affine) = affine {
                let extended: ExtendedPoint = affine.into();
                let point = extended.clear_cofactor();
                if !bool::from(point.is_identity()) {
                    return Ok(JubjubElement(point));
                }
            }
        }
        Err(Error::InvalidEncoding)
    }
}

impl GoldenEvrfCurve for JubjubGoldenGroup {
    type BaseFieldRepr = [u8; 32];

    fn affine_coordinates(
        point: &Self::Element,
    ) -> Result<(Self::BaseFieldRepr, Self::BaseFieldRepr)> {
        if bool::from(Self::is_identity(point)) {
            return Err(Error::InvalidEncoding);
        }
        let extended: ExtendedPoint = point.0.into();
        let affine = AffinePoint::from(extended);
        let u: Fq = affine.get_u();
        let v: Fq = affine.get_v();
        Ok((u.to_bytes(), v.to_bytes()))
    }

    fn base_field_modulus() -> Self::BaseFieldRepr {
        JUBJUB_FQ_MODULUS_LE
    }

    fn base_field_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scalar_encoding_round_trips() {
        let s = JubjubScalar(Fr::from(42u64));
        let repr = s.to_repr();
        assert_eq!(JubjubScalar::from_repr(&repr).unwrap(), s);
    }

    #[test]
    fn element_encoding_round_trips() {
        let p = JubjubGoldenGroup::mul_generator(&JubjubScalar(Fr::from(7u64)));
        let repr = JubjubGoldenGroup::encode_element(&p);
        assert_eq!(JubjubGoldenGroup::decode_element(&repr).unwrap(), p);
    }

    #[test]
    fn identity_encoding_is_fixed_width_and_zero_tagged() {
        let repr = JubjubGoldenGroup::encode_element(&JubjubGoldenGroup::identity());
        assert_eq!(repr[0], 0);
    }

    #[test]
    fn decode_element_rejects_nonzero_tag_byte() {
        let mut repr = JubjubGoldenGroup::encode_element(&JubjubGoldenGroup::generator());
        repr[0] = 1;
        assert!(JubjubGoldenGroup::decode_element(&repr).is_err());
    }

    #[test]
    fn hash_to_group_is_deterministic_and_non_identity() {
        let a = JubjubGoldenGroup::hash_to_group(b"dom", b"msg").unwrap();
        let b = JubjubGoldenGroup::hash_to_group(b"dom", b"msg").unwrap();
        assert_eq!(a, b);
        assert!(!bool::from(JubjubGoldenGroup::is_identity(&a)));
    }

    #[test]
    fn hash_to_group_differs_across_messages() {
        let a = JubjubGoldenGroup::hash_to_group(b"dom", b"one").unwrap();
        let b = JubjubGoldenGroup::hash_to_group(b"dom", b"two").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn affine_coordinates_round_trip_through_generator() {
        let g = JubjubGoldenGroup::generator();
        let (u, v) = JubjubGoldenGroup::affine_coordinates(&g).unwrap();
        let expected = AffinePoint::from(ExtendedPoint::from(g.0));
        assert_eq!(u, expected.get_u().to_bytes());
        assert_eq!(v, expected.get_v().to_bytes());
    }

    #[test]
    fn affine_coordinates_rejects_identity() {
        assert!(JubjubGoldenGroup::affine_coordinates(&JubjubGoldenGroup::identity()).is_err());
    }

    #[test]
    fn base_field_modulus_matches_jubjub_fq() {
        let expected = hex_modulus_to_le(<Fq as PrimeField>::MODULUS);
        assert_eq!(JubjubGoldenGroup::base_field_modulus(), expected);
    }

    #[test]
    fn scalar_modulus_matches_jubjub_fr() {
        let expected = hex_modulus_to_le(<Fr as PrimeField>::MODULUS);
        assert_eq!(JubjubScalar::modulus(), expected);
    }

    /// Parse a hex modulus string from `ff::PrimeField::MODULUS` into a
    /// little-endian byte array, independent of the adapter's own constants.
    fn hex_modulus_to_le(hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]);
            let lo = hex_nibble(chunk[1]);
            bytes[31 - i] = (hi << 4) | lo;
        }
        bytes
    }

    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
}
