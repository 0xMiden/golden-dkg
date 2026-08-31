//! [`golden_core::GoldenGroup`] adapter for `halo2curves::secp256k1`.
//!
//! The DKG layer speaks the `GoldenGroup` trait over a prime-order group. This
//! module exposes `Secp256k1GoldenGroup`, whose scalar field is the Secp256k1
//! scalar field `Fq` and whose element type is the Secp256k1 projective group.
//! The Main Golden proof system in `golden-evrf` consumes this adapter and
//! downcasts to the concrete `halo2curves` types when it builds the R1CS
//! statement.

use core::fmt;

use ff::{Field, FromUniformBytes, PrimeField};
use golden_core::{
    Error, FieldByteOrder, GoldenCurve, GoldenGroup, GoldenHashToGroup, GoldenScalar, Result,
};
use group::{Curve, Group, GroupEncoding};
use halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2curves::serde::Repr;
use halo2curves::{Coordinates, CurveAffine, CurveExt};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};

/// Secp256k1 base-field modulus, little-endian canonical bytes.
/// `p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`.
#[cfg(test)]
const SECP256K1_FP_MODULUS_LE: [u8; 32] = [
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Secp256k1 scalar-field modulus, little-endian canonical bytes.
/// `n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`.
const SECP256K1_FQ_MODULUS_LE: [u8; 32] = [
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Wrapper around the Secp256k1 scalar field `Fq`.
#[derive(Clone, Copy, Default)]
pub struct Secp256k1Scalar(pub Fq);

impl fmt::Debug for Secp256k1Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secp256k1Scalar")
            .field(&"<redacted>")
            .finish()
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Secp256k1Scalar {}

impl ConstantTimeEq for Secp256k1Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl GoldenScalar for Secp256k1Scalar {
    type Repr = [u8; 32];

    const REPR_BYTES: usize = 32;

    fn zero() -> Self {
        Self(Fq::ZERO)
    }

    fn one() -> Self {
        Self(Fq::ONE)
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Fq::random(rng))
    }

    fn from_u64(value: u64) -> Result<Self> {
        Ok(Self(Fq::from(value)))
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
        Option::<Fq>::from(self.0.invert()).map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        let repr = self.0.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_ref());
        out
    }

    fn from_repr(repr: &Self::Repr) -> Result<Self> {
        let fq_repr = Repr::<32>::from(*repr);
        Option::<Fq>::from(Fq::from_repr(fq_repr))
            .map(Self)
            .ok_or(Error::InvalidEncoding)
    }

    fn modulus() -> Self::Repr {
        SECP256K1_FQ_MODULUS_LE
    }

    fn repr_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }
}

/// Wrapper around the Secp256k1 projective group element.
#[derive(Clone, Copy, Default)]
pub struct Secp256k1Element(pub Secp256k1);

impl fmt::Debug for Secp256k1Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = Secp256k1GoldenGroup::encode_element(self);
        f.debug_tuple("Secp256k1Element")
            .field(&encoded.as_ref())
            .finish()
    }
}

impl PartialEq for Secp256k1Element {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Secp256k1Element {}

impl ConstantTimeEq for Secp256k1Element {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Golden group marker for Secp256k1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Secp256k1GoldenGroup {}

impl GoldenGroup for Secp256k1GoldenGroup {
    type Scalar = Secp256k1Scalar;
    type Element = Secp256k1Element;
    type ElementRepr = [u8; 33];

    const ELEMENT_REPR_BYTES: usize = 33;

    const BACKEND_ID: &'static str = "halo2curves-secp256k1-v1";
    const CURVE_ID: &'static str = "secp256k1-v1";

    fn generator() -> Self::Element {
        Secp256k1Element(Secp256k1::generator())
    }

    fn identity() -> Self::Element {
        Secp256k1Element(Secp256k1::identity())
    }

    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Secp256k1Element(a.0 + b.0)
    }

    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Secp256k1Element(a.0 - b.0)
    }

    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        Secp256k1Element(point.0 * scalar.0)
    }

    fn is_identity(point: &Self::Element) -> Choice {
        point.0.is_identity()
    }

    fn encode_element(point: &Self::Element) -> Self::ElementRepr {
        if bool::from(Self::is_identity(point)) {
            return [0u8; 33];
        }

        let halo_encoding = GroupEncoding::to_bytes(&point.0);
        let mut out = [0u8; 33];
        out[0] = 2 | ((halo_encoding.as_ref()[0] >> 7) & 1);
        for (output, input) in out[1..]
            .iter_mut()
            .zip(halo_encoding.as_ref()[1..].iter().rev())
        {
            *output = *input;
        }
        out
    }

    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element> {
        if repr == &[0u8; 33] {
            return Ok(Self::identity());
        }
        if !matches!(repr[0], 2 | 3) {
            return Err(Error::InvalidEncoding);
        }

        let mut halo_encoding = [0u8; 33];
        halo_encoding[0] = (repr[0] & 1) << 7;
        for (output, input) in halo_encoding[1..].iter_mut().zip(repr[1..].iter().rev()) {
            *output = *input;
        }
        let compressed = Repr::<33>::from(halo_encoding);
        let point = GroupEncoding::from_bytes(&compressed);
        Option::<Secp256k1>::from(point)
            .map(Secp256k1Element)
            .ok_or(Error::InvalidEncoding)
    }
}

impl GoldenHashToGroup for Secp256k1GoldenGroup {
    /// Hash a domain-separated message to a non-identity Secp256k1 point.
    ///
    /// **Backend restriction:** `halo2curves::CurveExt::hash_to_curve`
    /// takes the domain separation tag as `&str` (it is forwarded to the
    /// underlying RFC 9380 suite as a UTF-8 string), so this implementation
    /// rejects non-UTF-8 `domain` inputs. The trait signature stays
    /// `&[u8]` for consistency with the k256/p256 backends, but a non-UTF-8
    /// domain will fail here while succeeding on the RustCrypto backends.
    /// Callers that want backend portability should restrict domain tags
    /// to printable ASCII.
    ///
    /// Returns [`Error::InvalidEncoding`] for non-UTF-8 domains, for the
    /// (probability-zero) identity hash output, or for any curve decoding
    /// failure. The error variant is shared across those failure modes
    /// because [`GoldenHashToGroup`] does not surface a finer-grained
    /// variant; callers that need to distinguish UTF-8 rejection from
    /// identity hashes should pre-validate the domain as UTF-8.
    fn hash_to_group(domain: &[u8], message: &[u8]) -> Result<Self::Element> {
        let domain_str = core::str::from_utf8(domain).map_err(|_| Error::InvalidEncoding)?;
        let hash = <Secp256k1 as CurveExt>::hash_to_curve(domain_str);
        let point = hash(message);
        if bool::from(Self::is_identity(&Secp256k1Element(point))) {
            return Err(Error::InvalidEncoding);
        }
        Ok(Secp256k1Element(point))
    }
}

impl GoldenCurve for Secp256k1GoldenGroup {
    type BaseField = Fp;

    fn base_field_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }

    fn affine_x(point: &Self::Element) -> Result<Self::BaseField> {
        if bool::from(Self::is_identity(point)) {
            return Err(Error::InvalidEncoding);
        }
        let aff = point.0.to_affine();
        let coords = aff.coordinates();
        let opt: Option<Coordinates<Secp256k1Affine>> = Option::from(coords);
        let c = opt.ok_or(Error::InvalidEncoding)?;
        Ok(*c.x())
    }

    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(value.to_repr().as_ref());
        Secp256k1Scalar(Fq::from_uniform_bytes(&wide))
    }
}

/// Convert a DKG scalar (`G::Scalar = Secp256k1Scalar`, the Secp256k1 scalar
/// field `Fq`) into the R1CS field `Fp` (the Secp256k1 base field) by
/// re-interpreting the canonical little-endian bytes. Returns `None` if the
/// scalar's canonical integer is not a valid `Fp` element (i.e. `>= p`).
///
/// The paper eVRF `beta` is an `Fp` element multiplying `T_1.x` (also `Fp`),
/// while the DKG stores `beta` as `G::Scalar = Fq`.
///
/// **Reachability of `None`:** for Secp256k1 the base field modulus `p` is
/// strictly larger than the scalar field modulus `q`, so every canonical
/// `Fq` encoding lives in `[0, q)` with `q < p` and always round-trips into
/// `Fp`. The `None` branch is therefore unreachable through any `Fq`-typed
/// input on this curve. The round-trip canonicality check below still runs
/// to defend against a future curve switch where the modulus ordering flips
/// (and against any upstream `Fp::from_repr` regression that stops enforcing
/// canonicality): after `Fp::from_repr` we re-encode and compare; any
/// mismatch means the input was non-canonical and we return `None` rather
/// than handing back a silently wrapped value.
pub fn scalar_to_r1cs_field(scalar: &Secp256k1Scalar) -> Option<Fp> {
    let bytes = scalar.0.to_repr();
    let arr: [u8; 32] = *bytes.inner();
    let fp_repr = Repr::<32>::from(arr);
    let fp = Option::<Fp>::from(Fp::from_repr(fp_repr))?;
    let roundtrip = fp.to_repr();
    if roundtrip.inner() != &arr {
        return None;
    }
    Some(fp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use golden_core::{
        deal, DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig,
        ParticipantIndex, ParticipantRegistry, SessionId,
    };
    use golden_rustcrypto::{K256Backend, K256Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    const FIXED_TEST_PROOF: &[u8] = &[0x5a, 0xa5];

    #[derive(Default)]
    struct CapturingProofSystem {
        dealer_message_root: Mutex<Option<[u8; 32]>>,
    }

    impl CapturingProofSystem {
        fn dealer_message_root(&self) -> [u8; 32] {
            self.dealer_message_root.lock().unwrap().unwrap()
        }
    }

    impl<G: GoldenCurve> DealerProofSystem<G> for CapturingProofSystem {
        fn prove(
            &self,
            _config: &DkgConfig<G>,
            statement: &DealerProofStatement<G>,
            _witness: &DealerProofWitness<G>,
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            *self.dealer_message_root.lock().unwrap() = Some(statement.dealer_message_root());
            Ok(FIXED_TEST_PROOF.to_vec())
        }

        fn verify(
            &self,
            _config: &DkgConfig<G>,
            _statement: &DealerProofStatement<G>,
            proof: &[u8],
        ) -> Result<()> {
            if proof == FIXED_TEST_PROOF {
                Ok(())
            } else {
                Err(Error::ProofVerificationFailed)
            }
        }
    }

    #[test]
    fn scalar_encoding_round_trips() {
        let s = Secp256k1Scalar(Fq::from(42u64));
        let repr = s.to_repr();
        assert_eq!(Secp256k1Scalar::from_repr(&repr).unwrap(), s);
    }

    #[test]
    fn element_encoding_round_trips() {
        let p = Secp256k1GoldenGroup::mul_generator(&Secp256k1Scalar(Fq::from(7u64)));
        let repr = Secp256k1GoldenGroup::encode_element(&p);
        assert_eq!(Secp256k1GoldenGroup::decode_element(&repr).unwrap(), p);
    }

    #[test]
    fn identity_encoding_is_fixed_width() {
        let repr = Secp256k1GoldenGroup::encode_element(&Secp256k1GoldenGroup::identity());
        assert_eq!(repr, [0u8; 33]);
    }

    #[test]
    fn secp256k1_protocol_identity_is_adapter_independent() {
        let dealer = ParticipantIndex::new(1).unwrap();
        let receiver = ParticipantIndex::new(2).unwrap();
        let halo_dealer_secret = Secp256k1Scalar::from_u64(7).unwrap();
        let halo_receiver_secret = Secp256k1Scalar::from_u64(11).unwrap();
        let rustcrypto_dealer_secret = K256Scalar::from_u64(7).unwrap();
        let rustcrypto_receiver_secret = K256Scalar::from_u64(11).unwrap();
        let halo_registry: ParticipantRegistry<Secp256k1GoldenGroup> =
            ParticipantRegistry::new(vec![
                (
                    dealer,
                    Secp256k1GoldenGroup::mul_generator(&halo_dealer_secret),
                ),
                (
                    receiver,
                    Secp256k1GoldenGroup::mul_generator(&halo_receiver_secret),
                ),
            ])
            .unwrap();
        let rustcrypto_registry: ParticipantRegistry<K256Backend> = ParticipantRegistry::new(vec![
            (
                dealer,
                K256Backend::mul_generator(&rustcrypto_dealer_secret),
            ),
            (
                receiver,
                K256Backend::mul_generator(&rustcrypto_receiver_secret),
            ),
        ])
        .unwrap();
        let halo_config = DkgConfig::new_zero(1, SessionId([0x42; 32]), halo_registry).unwrap();
        let rustcrypto_config =
            DkgConfig::new_zero(1, SessionId([0x42; 32]), rustcrypto_registry).unwrap();

        assert_ne!(Secp256k1GoldenGroup::BACKEND_ID, K256Backend::BACKEND_ID);
        assert_eq!(Secp256k1GoldenGroup::CURVE_ID, K256Backend::CURVE_ID);
        assert_ne!(
            halo_dealer_secret.to_repr(),
            rustcrypto_dealer_secret.to_repr()
        );
        assert_eq!(halo_config.root(), rustcrypto_config.root());

        let mut halo_rng = ChaCha20Rng::from_seed([0x24; 32]);
        let mut rustcrypto_rng = ChaCha20Rng::from_seed([0x24; 32]);
        let halo_proof_system = CapturingProofSystem::default();
        let rustcrypto_proof_system = CapturingProofSystem::default();
        let halo_dealing = deal(
            &halo_proof_system,
            &halo_config,
            dealer,
            &halo_dealer_secret,
            &mut halo_rng,
        )
        .unwrap();
        let rustcrypto_dealing = deal(
            &rustcrypto_proof_system,
            &rustcrypto_config,
            dealer,
            &rustcrypto_dealer_secret,
            &mut rustcrypto_rng,
        )
        .unwrap();

        assert_eq!(
            halo_proof_system.dealer_message_root(),
            rustcrypto_proof_system.dealer_message_root()
        );
        assert_eq!(halo_dealing.dealer_message_bytes().len(), 180);
        assert!(halo_dealing
            .dealer_message_bytes()
            .ends_with(FIXED_TEST_PROOF));
        assert_eq!(
            halo_dealing.dealer_message_bytes(),
            rustcrypto_dealing.dealer_message_bytes()
        );
    }

    #[test]
    fn scalar_to_r1cs_field_round_trips_for_small_beta() {
        let beta_fq = Secp256k1Scalar(Fq::from(123u64));
        let beta_fp = scalar_to_r1cs_field(&beta_fq).expect("small beta fits in Fp");
        assert_eq!(beta_fp, Fp::from(123u64));
    }

    #[test]
    fn scalar_to_r1cs_field_rejects_scalars_above_p() {
        // The dream audit flagged that only the Some(_) branch of
        // scalar_to_r1cs_field was tested. For Secp256k1 the Fp modulus
        // p (base field) is strictly larger than the Fq modulus q (scalar
        // field), so every canonical Fq scalar lives in [0, q) with q < p
        // and always round-trips into Fp. The `None` branch of
        // scalar_to_r1cs_field is therefore unreachable through any
        // Fq-typed input on this curve; we assert the modulus ordering
        // (via the big-endian hex strings from ff, which compare as
        // unsigned integers) that makes it unreachable, so the contract
        // stays honest if the curve ever changes.
        let p_hex = <Fp as PrimeField>::MODULUS;
        let q_hex = <Fq as PrimeField>::MODULUS;
        assert!(
            p_hex > q_hex,
            "secp256k1 base field p ({p_hex}) must exceed scalar field q ({q_hex})"
        );

        // Fp::from_repr already enforces canonicality for the Secp256k1
        // base field in halo2curves 0.10, so feeding it the modulus bytes
        // (an integer equal to p, which is 0 mod p but not canonical) is
        // rejected at that layer. The round-trip guard in
        // scalar_to_r1cs_field is belt-and-braces for the same property.
        let p_bytes = SECP256K1_FP_MODULUS_LE;
        let fp_repr = Repr::<32>::from(p_bytes);
        assert!(
            Option::<Fp>::from(Fp::from_repr(fp_repr)).is_none(),
            "Fp::from_repr must reject non-canonical modulus bytes"
        );
    }

    #[test]
    fn affine_x_returns_the_generator_coordinate_and_rejects_identity() {
        let x = Secp256k1GoldenGroup::affine_x(&Secp256k1GoldenGroup::generator())
            .expect("generator has affine coordinates");

        assert_eq!(
            x.to_repr().inner(),
            &[
                0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc,
                0x9b, 0x02, 0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9,
                0x7e, 0x66, 0xbe, 0x79,
            ]
        );
        assert!(Secp256k1GoldenGroup::affine_x(&Secp256k1GoldenGroup::identity()).is_err());
    }

    #[test]
    fn scalar_modulus_matches_secp256k1_n() {
        let expected = hex_modulus_to_le(<Fq as PrimeField>::MODULUS);
        assert_eq!(Secp256k1Scalar::modulus(), expected);
    }

    /// Parse a hex modulus string from `ff::PrimeField::MODULUS` into a
    /// little-endian byte array, independent of the adapter's own constants.
    fn hex_modulus_to_le(hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]);
            let lo = hex_nibble(chunk[1]);
            // hex string is big-endian (MSB first), so byte 0 is the MSB.
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
