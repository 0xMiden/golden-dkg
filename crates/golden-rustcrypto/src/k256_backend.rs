//! secp256k1 backend built on RustCrypto.

use core::fmt;

use golden_core::{
    Error, FieldByteOrder, GoldenCurve, GoldenGroup, GoldenHashToGroup, GoldenScalar, Result,
};
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ff::Field;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::PrimeField;
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar, Secp256k1,
};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

const K256_SCALAR_FIELD_MODULUS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const HASH_TO_CURVE_SUITE_DOMAIN: &[u8] = b"secp256k1_XMD:SHA-256_SSWU_RO_";

/// secp256k1 scalar wrapper.
///
/// Public tuple field, same rationale as [`P256Scalar`](crate::P256Scalar):
/// the inner `Scalar` is reachable for callers that need `k256`'s own API,
/// but the supported path is [`GoldenScalar`]. Reaching into `.0` ties your
/// code to `k256`'s scalar type and layout.
#[derive(Clone, Default)]
pub struct K256Scalar(pub Scalar);

impl fmt::Debug for K256Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("K256Scalar").field(&"<redacted>").finish()
    }
}

impl PartialEq for K256Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for K256Scalar {}

impl ConstantTimeEq for K256Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Zeroize for K256Scalar {
    fn zeroize(&mut self) {
        // Delegate to k256's Scalar::zeroize so the underlying FieldBytes are
        // explicitly overwritten, rather than relying on assignment lowering
        // to wipe the previous bytes.
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for K256Scalar {}

impl Drop for K256Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GoldenScalar for K256Scalar {
    type Repr = [u8; 32];

    const REPR_BYTES: usize = 32;

    fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    fn one() -> Self {
        Self(Scalar::ONE)
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::random(rng))
    }

    fn from_u64(value: u64) -> Result<Self> {
        Ok(Self(Scalar::from(value)))
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
        Option::<Scalar>::from(self.0.invert()).map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        let repr = self.0.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_ref());
        out
    }

    fn from_repr(repr: &Self::Repr) -> Result<Self> {
        let bytes = FieldBytes::from(*repr);
        Option::<Scalar>::from(Scalar::from_repr(bytes))
            .map(Self)
            .ok_or(Error::InvalidEncoding)
    }

    fn modulus() -> Self::Repr {
        K256_SCALAR_FIELD_MODULUS
    }

    fn repr_byte_order() -> FieldByteOrder {
        FieldByteOrder::BigEndian
    }
}

/// secp256k1 group element wrapper.
///
/// Public tuple field, same rationale as [`K256Scalar`]: the supported path
/// is [`GoldenGroup`]; reaching into `.0` ties your code to `k256`.
#[derive(Clone, Copy, Default)]
pub struct K256Element(pub ProjectivePoint);

impl fmt::Debug for K256Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("K256Element")
            .field(&K256Backend::encode_element(self).as_ref())
            .finish()
    }
}

impl PartialEq for K256Element {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for K256Element {}

impl ConstantTimeEq for K256Element {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// secp256k1 backend marker.
///
/// Like the other backend types in this crate this is an empty enum used as
/// the concrete `Self` for `impl GoldenGroup for K256Backend`. There is never
/// a value of this type; it exists to carry the associated types and
/// `BACKEND_ID` constant that scope a backend's wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum K256Backend {}

impl GoldenGroup for K256Backend {
    type Scalar = K256Scalar;
    type Element = K256Element;
    type ElementRepr = [u8; 33];

    const ELEMENT_REPR_BYTES: usize = 33;

    const BACKEND_ID: &'static str = "rustcrypto-k256-v1";

    fn generator() -> Self::Element {
        K256Element(ProjectivePoint::GENERATOR)
    }

    fn identity() -> Self::Element {
        K256Element(ProjectivePoint::IDENTITY)
    }

    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element {
        K256Element(a.0 + b.0)
    }

    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        K256Element(a.0 - b.0)
    }

    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        K256Element(point.0 * scalar.0)
    }

    fn is_identity(point: &Self::Element) -> Choice {
        point.0.is_identity()
    }

    /// Encode a non-identity point as 33-byte SEC1 compressed, and the
    /// identity as the all-zero 33-byte array.
    ///
    /// See [`P256Backend::encode_element`](crate::P256Backend::encode_element)
    /// for the rationale of the fixed-width identity encoding: every
    /// 33-byte short-Weierstrass backend in the workspace commits to the
    /// same `[u8; 33]` wire format for the point at infinity.
    fn encode_element(point: &Self::Element) -> Self::ElementRepr {
        if bool::from(Self::is_identity(point)) {
            return [0u8; 33];
        }
        let affine = AffinePoint::from(point.0);
        let encoded = affine.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// Decode a 33-byte repr produced by [`encode_element`](GoldenGroup::encode_element).
    ///
    /// See [`P256Backend::decode_element`](crate::P256Backend::decode_element);
    /// the same acceptance/rejection rules apply.
    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element> {
        if repr == &[0u8; 33] {
            return Ok(Self::identity());
        }
        let encoded = EncodedPoint::from_bytes(repr).map_err(|_| Error::InvalidEncoding)?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or(Error::InvalidEncoding)?;
        Ok(K256Element(ProjectivePoint::from(affine)))
    }
}

impl GoldenHashToGroup for K256Backend {
    fn hash_to_group(domain: &[u8], message: &[u8]) -> Result<Self::Element> {
        let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[message],
            &[domain, HASH_TO_CURVE_SUITE_DOMAIN],
        )
        .map_err(|_| Error::InvalidEncoding)?;
        let element = K256Element(point);
        if bool::from(Self::is_identity(&element)) {
            return Err(Error::InvalidEncoding);
        }
        Ok(element)
    }
}

impl GoldenCurve for K256Backend {
    type BaseField = FieldElement;

    fn base_field_byte_order() -> FieldByteOrder {
        FieldByteOrder::BigEndian
    }

    fn affine_x(point: &Self::Element) -> Result<Self::BaseField> {
        if bool::from(Self::is_identity(point)) {
            return Err(Error::InvalidEncoding);
        }

        let x = AffinePoint::from(point.0).x();
        Option::<FieldElement>::from(FieldElement::from_repr(x)).ok_or(Error::InvalidEncoding)
    }

    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar {
        K256Scalar(<Scalar as Reduce<U256>>::reduce_bytes(&value.to_repr()))
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::*;
    use golden_core::{
        lagrange_interpolate_at_zero, FeldmanCommitment, ParticipantIndex, Polynomial,
    };

    fn participants(values: &[u32]) -> Vec<ParticipantIndex> {
        values
            .iter()
            .map(|value| ParticipantIndex::new(*value).expect("nonzero participant"))
            .collect()
    }

    #[test]
    fn k256_scalar_encoding_round_trips_and_rejects_noncanonical() {
        let scalar = K256Scalar::from_u64(42).unwrap();
        let repr = scalar.to_repr();
        assert_eq!(K256Scalar::from_repr(&repr).unwrap(), scalar);
        assert!(K256Scalar::from_repr(&[0xff; 32]).is_err());
        assert_eq!(
            K256Scalar::modulus(),
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
                0xd0, 0x36, 0x41, 0x41
            ]
        );
    }

    #[test]
    fn k256_modulus_constant_matches_k256_source_of_truth() {
        // The hardcoded K256_SCALAR_FIELD_MODULUS array duplicates k256's own
        // scalar field modulus. Cross-check directly against
        // `<Scalar as PrimeField>::MODULUS`, which k256 exposes on the public
        // Scalar type, so a hand-edit to either copy drifts relative to the
        // other. The base-field modulus was tracked here previously but was
        // only used by the deleted GoldenEvrfCurve impl; it has been removed.
        let scalar_hex = <Scalar as k256::elliptic_curve::PrimeField>::MODULUS;
        assert_eq!(
            hex_be_to_be_bytes(scalar_hex),
            K256_SCALAR_FIELD_MODULUS,
            "scalar field modulus drifted from k256::Scalar::MODULUS"
        );
    }

    fn hex_be_to_be_bytes(hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        assert_eq!(hex.len(), 64, "expected 32-byte modulus, got {hex}");
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]);
            let lo = hex_nibble(chunk[1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            // Input is k256::Scalar::MODULUS, a compile-time hex constant.
            // A non-hex char would be a k256 bug; fall through to 0 so the
            // resulting bytes mismatch and the assertion fails loudly.
            _ => 0,
        }
    }

    #[test]
    fn k256_scalar_zeroizes_and_is_marked_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<K256Scalar>();
        let mut scalar = K256Scalar::from_u64(42).unwrap();
        scalar.zeroize();
        assert_eq!(scalar, K256Scalar::zero());
    }

    #[test]
    fn k256_element_encoding_round_trips_and_rejects_malformed_bytes() {
        let point = K256Backend::mul_generator(&K256Scalar::from_u64(9).unwrap());
        let repr = K256Backend::encode_element(&point);
        assert_eq!(K256Backend::decode_element(&repr).unwrap(), point);
        assert!(K256Backend::decode_element(&[1u8; 33]).is_err());
    }

    #[test]
    fn k256_identity_encoding_is_fixed_width_and_round_trips() {
        let repr = K256Backend::encode_element(&K256Backend::identity());

        assert_eq!(repr, [0u8; 33]);
        assert_eq!(
            K256Backend::decode_element(&repr).unwrap(),
            K256Backend::identity()
        );
    }

    #[test]
    fn k256_affine_x_returns_the_generator_coordinate_and_rejects_identity() {
        let x = K256Backend::affine_x(&K256Backend::generator())
            .expect("generator has affine coordinates");

        assert_eq!(
            x.to_repr(),
            FieldBytes::from([
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98,
            ])
        );
        assert!(K256Backend::affine_x(&K256Backend::identity()).is_err());
    }

    #[test]
    fn k256_reduces_the_full_base_field_integer() {
        let p_minus_one =
            Option::<FieldElement>::from(FieldElement::from_repr(FieldBytes::from([
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                0xff, 0xff, 0xfc, 0x2e,
            ])))
            .expect("p - 1 is canonical");

        assert_eq!(
            K256Backend::reduce_base_field(&p_minus_one).to_repr(),
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72,
                0x2f, 0xc9, 0xba, 0xed,
            ]
        );
    }

    #[test]
    fn k256_evrf_hash_to_group_is_domain_separated_and_non_identity() {
        let first = K256Backend::hash_to_group(b"golden-evrf-h1", b"message").unwrap();
        let again = K256Backend::hash_to_group(b"golden-evrf-h1", b"message").unwrap();
        let other_domain = K256Backend::hash_to_group(b"golden-evrf-h2", b"message").unwrap();

        assert_eq!(first, again);
        assert_ne!(first, other_domain);
        assert!(!bool::from(K256Backend::is_identity(&first)));
    }

    #[test]
    fn k256_shamir_reconstructs_threshold_subset() {
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
        let secret = K256Scalar::random(&mut rng);
        let poly = Polynomial::random_with_secret(secret.clone(), 3, &mut rng).unwrap();
        let shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        assert_eq!(lagrange_interpolate_at_zero(&shares[0..3]).unwrap(), secret);
    }

    #[test]
    fn k256_feldman_verifies_valid_shares_and_rejects_altered_share() {
        let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
        let secret = K256Scalar::random(&mut rng);
        let poly = Polynomial::random_with_secret(secret.clone(), 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<K256Backend>::commit(&poly).unwrap();
        let mut shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        for share in &shares {
            assert!(commitment.verify_share(share).unwrap());
        }

        shares[0].value = shares[0].value.add(&K256Scalar::one());
        assert!(!commitment.verify_share(&shares[0]).unwrap());
    }

    #[test]
    fn k256_public_key_matches_generator_times_secret() {
        let secret = K256Scalar::from_u64(123).unwrap();
        let poly = Polynomial::from_coefficients(vec![secret.clone()]).unwrap();
        let commitment = FeldmanCommitment::<K256Backend>::commit(&poly).unwrap();

        assert_eq!(commitment.public_key(), K256Backend::mul_generator(&secret));
    }
}
