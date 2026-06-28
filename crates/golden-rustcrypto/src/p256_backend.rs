//! P-256 backend built on RustCrypto.

use core::fmt;

use golden_core::{Error, FieldByteOrder, GoldenGroup, GoldenHashToGroup, GoldenScalar, Result};
use p256::elliptic_curve::ff::Field;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Group;
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, EncodedPoint, FieldBytes, NistP256, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

const P256_SCALAR_FIELD_MODULUS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// P-256 scalar wrapper.
///
/// The inner `Scalar` is exposed as a public tuple field so that callers that
/// need direct access to the underlying `p256` API (e.g. for hashing into the
/// scalar field via a crate-native API the `GoldenScalar` trait does not
/// cover) can reach it without re-deriving the type. The trait surface in
/// [`GoldenScalar`] is the supported path; reaching into `.0` ties your code
/// to `p256`'s API and to the exact scalar layout used here.
#[derive(Clone, Default)]
pub struct P256Scalar(pub Scalar);

impl fmt::Debug for P256Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P256Scalar").field(&"<redacted>").finish()
    }
}

impl PartialEq for P256Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for P256Scalar {}

impl ConstantTimeEq for P256Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Zeroize for P256Scalar {
    fn zeroize(&mut self) {
        // Delegate to p256's Scalar::zeroize so the underlying FieldBytes are
        // explicitly overwritten, rather than relying on assignment lowering
        // to wipe the previous bytes.
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for P256Scalar {}

impl Drop for P256Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GoldenScalar for P256Scalar {
    type Repr = [u8; 32];

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
        P256_SCALAR_FIELD_MODULUS
    }

    fn repr_byte_order() -> FieldByteOrder {
        FieldByteOrder::BigEndian
    }
}

/// P-256 group element wrapper.
///
/// Public tuple field, same rationale as [`P256Scalar`]: the inner
/// `ProjectivePoint` is reachable for callers that need the underlying
/// `p256` API, but the supported path is [`GoldenGroup`].
#[derive(Clone, Copy, Default)]
pub struct P256Element(pub ProjectivePoint);

impl fmt::Debug for P256Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P256Element")
            .field(&P256Backend::encode_element(self).as_ref())
            .finish()
    }
}

impl PartialEq for P256Element {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for P256Element {}

impl ConstantTimeEq for P256Element {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// P-256 backend marker.
///
/// Empty enum, used as the concrete `Self` for `impl GoldenGroup for
/// P256Backend`. See [`crate::K256Backend`] for the rationale; the same applies
/// here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P256Backend {}

impl GoldenGroup for P256Backend {
    type Scalar = P256Scalar;
    type Element = P256Element;
    type ElementRepr = [u8; 33];

    const BACKEND_ID: &'static str = "rustcrypto-p256-v1";

    fn generator() -> Self::Element {
        P256Element(ProjectivePoint::GENERATOR)
    }

    fn identity() -> Self::Element {
        P256Element(ProjectivePoint::IDENTITY)
    }

    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element {
        P256Element(a.0 + b.0)
    }

    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        P256Element(a.0 - b.0)
    }

    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        P256Element(point.0 * scalar.0)
    }

    fn is_identity(point: &Self::Element) -> Choice {
        point.0.is_identity()
    }

    /// Encode a non-identity point as 33-byte SEC1 compressed, and the
    /// identity as the all-zero 33-byte array.
    ///
    /// This is **not** the SEC1 identity encoding (SEC1 uses a single
    /// `0x00` byte for the point at infinity). The fixed-width `[0u8; 33]`
    /// convention is chosen so that [`ElementRepr`](GoldenGroup::ElementRepr)
    /// is a fixed-width `[u8; 33]` and every byte vector round-trips through
    /// [`decode_element`](GoldenGroup::decode_element) without a length tag.
    /// Every 33-byte short-Weierstrass backend in the workspace
    /// (`k256_backend`, `golden-halo2curves::golden_group`) shares this
    /// convention so transcripts commit to a canonical byte layout for a
    /// given curve.
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
    /// Accepts the all-zero identity encoding (see [`encode_element`](GoldenGroup::encode_element)
    /// for why we deviate from SEC1 here) and any valid 33-byte SEC1
    /// compressed point. Returns [`Error::InvalidEncoding`] for any other
    /// input, including valid but uncompressed 65-byte encodings.
    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element> {
        if repr == &[0u8; 33] {
            return Ok(Self::identity());
        }
        let encoded = EncodedPoint::from_bytes(repr).map_err(|_| Error::InvalidEncoding)?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or(Error::InvalidEncoding)?;
        Ok(P256Element(ProjectivePoint::from(affine)))
    }
}

impl GoldenHashToGroup for P256Backend {
    fn hash_to_group(domain: &[u8], message: &[u8]) -> Result<Self::Element> {
        let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[message], &[domain])
            .map_err(|_| Error::InvalidEncoding)?;
        let element = P256Element(point);
        if bool::from(Self::is_identity(&element)) {
            return Err(Error::InvalidEncoding);
        }
        Ok(element)
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
    fn p256_scalar_encoding_round_trips_and_rejects_noncanonical() {
        let scalar = P256Scalar::from_u64(42).unwrap();
        let repr = scalar.to_repr();
        assert_eq!(P256Scalar::from_repr(&repr).unwrap(), scalar);
        assert!(P256Scalar::from_repr(&[0xff; 32]).is_err());
        assert_eq!(
            P256Scalar::modulus(),
            [
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                0xfc, 0x63, 0x25, 0x51
            ]
        );
    }

    #[test]
    fn p256_scalar_zeroizes_and_is_marked_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<P256Scalar>();
        let mut scalar = P256Scalar::from_u64(42).unwrap();
        scalar.zeroize();
        assert_eq!(scalar, P256Scalar::zero());
    }

    #[test]
    fn p256_element_encoding_round_trips_and_rejects_malformed_bytes() {
        let point = P256Backend::mul_generator(&P256Scalar::from_u64(9).unwrap());
        let repr = P256Backend::encode_element(&point);
        assert_eq!(P256Backend::decode_element(&repr).unwrap(), point);
        assert!(P256Backend::decode_element(&[1u8; 33]).is_err());
    }

    #[test]
    fn p256_identity_encoding_is_fixed_width_and_round_trips() {
        let repr = P256Backend::encode_element(&P256Backend::identity());

        assert_eq!(repr, [0u8; 33]);
        assert_eq!(
            P256Backend::decode_element(&repr).unwrap(),
            P256Backend::identity()
        );
    }

    #[test]
    fn p256_evrf_hash_to_group_is_domain_separated_and_non_identity() {
        let first = P256Backend::hash_to_group(b"golden-evrf-h1", b"message").unwrap();
        let again = P256Backend::hash_to_group(b"golden-evrf-h1", b"message").unwrap();
        let other_domain = P256Backend::hash_to_group(b"golden-evrf-h2", b"message").unwrap();

        assert_eq!(first, again);
        assert_ne!(first, other_domain);
        assert!(!bool::from(P256Backend::is_identity(&first)));
    }

    #[test]
    fn p256_shamir_reconstructs_threshold_subset() {
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let secret = P256Scalar::random(&mut rng);
        let poly = Polynomial::random_with_secret(secret.clone(), 3, &mut rng).unwrap();
        let shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        assert_eq!(lagrange_interpolate_at_zero(&shares[0..3]).unwrap(), secret);
    }

    #[test]
    fn p256_feldman_verifies_valid_shares_and_rejects_altered_share() {
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let secret = P256Scalar::random(&mut rng);
        let poly = Polynomial::random_with_secret(secret.clone(), 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<P256Backend>::commit(&poly).unwrap();
        let mut shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        for share in &shares {
            assert!(commitment.verify_share(share).unwrap());
        }

        shares[0].value = shares[0].value.add(&P256Scalar::one());
        assert!(!commitment.verify_share(&shares[0]).unwrap());
    }

    #[test]
    fn p256_public_key_matches_generator_times_secret() {
        let secret = P256Scalar::from_u64(123).unwrap();
        let poly = Polynomial::from_coefficients(vec![secret.clone()]).unwrap();
        let commitment = FeldmanCommitment::<P256Backend>::commit(&poly).unwrap();

        assert_eq!(commitment.public_key(), P256Backend::mul_generator(&secret));
    }
}
