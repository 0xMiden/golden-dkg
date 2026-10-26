//! Cross-layer native adapter invariants, shared by both supported groups.
#![cfg(any(feature = "secp256k1", feature = "jubjub"))]
#![allow(clippy::unwrap_used)]

use ff::{Field, PrimeField};
use golden_core::{DkgGroup, Error, FeldmanCommitment, ParticipantIndex, Polynomial, Share};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn check_adapter<G: DkgGroup>(max_reduction_quotient: u8, hash_vector: &[u8]) {
    let mut rng = ChaCha20Rng::from_seed([0x47; 32]);
    let mut scalars = vec![G::Scalar::ZERO, G::Scalar::ONE, -G::Scalar::ONE];
    let mut power = G::Scalar::ONE;
    for _ in 0..G::Scalar::NUM_BITS {
        scalars.extend([
            power - G::Scalar::ONE,
            power,
            power + G::Scalar::ONE,
            -power,
        ]);
        power = power.double();
    }
    scalars.extend((0..32).map(|_| G::Scalar::random(&mut rng)));
    for scalar in scalars {
        let point = G::mul_generator(&scalar);
        assert_eq!(point, G::Point::generator() * scalar);
        let bytes = G::encode_point(&point);
        assert_eq!(bytes.len(), G::POINT_BYTES);
        assert_eq!(G::decode_point(&bytes).unwrap(), point);
        let scalar_bytes = G::encode_scalar(&scalar);
        assert_eq!(G::decode_scalar(&scalar_bytes).unwrap(), scalar);
    }

    let mut scalar_modulus = G::encode_scalar(&(-G::Scalar::ONE));
    adjust_integer(&mut scalar_modulus, 1);
    assert_eq!(
        G::decode_scalar(&scalar_modulus),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(G::decode_scalar(&[0; 31]), Err(Error::InvalidEncoding));
    assert_eq!(G::decode_scalar(&[0; 33]), Err(Error::InvalidEncoding));
    let mut overlong = G::encode_point(&G::Point::generator());
    overlong.push(0);
    assert_eq!(G::decode_point(&overlong), Err(Error::InvalidEncoding));
    assert_eq!(G::decode_point(&[]), Err(Error::InvalidEncoding));
    assert_eq!(
        G::decode_point(&vec![255; G::POINT_BYTES]),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        G::affine_x(&G::Point::identity()),
        Err(Error::InvalidEncoding)
    );

    // Expected values follow integer quotient/remainder, independently of
    // the adapter's Horner reduction. Include the widest Jubjub gap, 8r.
    for quotient in 0..=max_reduction_quotient {
        for delta in [-1, 0, 1] {
            if quotient == 0 && delta == -1 {
                continue;
            }
            let mut bytes = multiply_integer(&scalar_modulus, quotient);
            adjust_integer(&mut bytes, delta);
            let mut repr = <G::BaseField as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            let value = Option::<G::BaseField>::from(G::BaseField::from_repr(repr)).unwrap();
            let expected = match delta {
                -1 => -G::Scalar::ONE,
                0 => G::Scalar::ZERO,
                _ => G::Scalar::ONE,
            };
            assert_eq!(G::reduce_base_field(&value), expected);
        }
    }
    // Independent integer subtraction exercises the largest canonical base value.
    let maximum = -G::BaseField::ONE;
    let mut remainder = maximum.to_repr();
    for _ in 0..max_reduction_quotient {
        let mut borrow = 0i16;
        for (byte, modulus_byte) in remainder.as_mut().iter_mut().zip(scalar_modulus) {
            let difference = i16::from(*byte) - i16::from(modulus_byte) - borrow;
            *byte = difference as u8;
            borrow = i16::from(difference < 0);
        }
        assert_eq!(borrow, 0);
    }
    assert_eq!(
        G::reduce_base_field(&maximum),
        G::decode_scalar(remainder.as_ref()).unwrap()
    );
    // Pinned against the preserved native mappings at baseline 0e3168f,
    // with the new protocol point encodings (SEC1 / native Jubjub).
    assert_eq!(
        G::encode_point(&G::hash_to_point(b"adapter-map-vector", b"one").unwrap()),
        hash_vector
    );
    assert_ne!(
        G::hash_to_point(b"adapter-map-vector", b"one").unwrap(),
        G::hash_to_point(b"adapter-map-vector", b"two").unwrap()
    );

    for constant in [G::Scalar::ZERO, G::Scalar::from(42)] {
        let polynomial =
            Polynomial::from_coefficients(&[constant, G::Scalar::from(3), G::Scalar::from(7)])
                .unwrap();
        let commitment = FeldmanCommitment::<G>::commit(&polynomial).unwrap();
        assert_eq!(commitment.public_key(), G::mul_generator(&constant));
        for index in [1, 2, 16, u32::MAX] {
            let participant = ParticipantIndex::new(index).unwrap();
            let share = polynomial.evaluate(participant).unwrap();
            assert!(commitment.verify_share(&share).unwrap());
            assert_eq!(
                commitment.public_key_share(participant).unwrap(),
                G::mul_generator(share.value())
            );
            let changed = Share::new(participant, *share.value() + G::Scalar::ONE);
            assert!(!commitment.verify_share(&changed).unwrap());
        }
    }
}

fn multiply_integer(bytes: &[u8; 32], multiplier: u8) -> [u8; 32] {
    let mut result = [0; 32];
    let mut carry = 0u16;
    for (input, output) in bytes.iter().zip(result.iter_mut()) {
        carry += u16::from(*input) * u16::from(multiplier);
        *output = carry as u8;
        carry >>= 8;
    }
    assert_eq!(carry, 0);
    result
}

fn adjust_integer(bytes: &mut [u8; 32], delta: i8) {
    if delta == 0 {
        return;
    }
    let mut carry = true;
    for byte in bytes {
        if !carry {
            break;
        }
        let (value, overflow) = if delta > 0 {
            byte.overflowing_add(1)
        } else {
            byte.overflowing_sub(1)
        };
        *byte = value;
        carry = overflow;
    }
    assert!(!carry, "test integer overflow");
}

#[cfg(feature = "secp256k1")]
#[test]
fn secp_native_arithmetic_codecs_reduction_and_feldman_agree() {
    check_adapter::<golden_curves::Secp256k1Group>(
        1,
        &[
            3, 226, 145, 171, 35, 136, 153, 101, 118, 17, 105, 137, 44, 16, 214, 218, 43, 50, 136,
            44, 48, 15, 188, 2, 47, 199, 38, 95, 90, 199, 90, 151, 86,
        ],
    );
}

#[cfg(feature = "jubjub")]
#[test]
fn jubjub_native_arithmetic_codecs_reduction_and_feldman_agree() {
    check_adapter::<golden_curves::JubjubGroup>(
        8,
        &[
            213, 181, 179, 103, 190, 172, 57, 69, 121, 208, 142, 148, 220, 89, 115, 210, 45, 107,
            30, 143, 114, 107, 10, 54, 60, 204, 88, 118, 253, 129, 95, 87,
        ],
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn secp_protocol_uses_sec1_with_its_distinct_zero_identity() {
    use golden_curves::secp256k1::{Point, Secp256k1Group as G};
    use group::GroupEncoding;
    let generator = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    assert_eq!(G::encode_point(&Point::generator()), generator);
    assert_eq!(G::decode_point(&generator).unwrap(), Point::generator());
    assert_eq!(G::encode_point(&Point::identity()), [0; 33]);
    assert_eq!(G::decode_point(&[0; 33]).unwrap(), Point::identity());
    // Native halo2curves compressed flags/LE x are not protocol SEC1 bytes.
    assert!(G::decode_point(Point::generator().to_bytes().as_ref()).is_err());
    assert!(G::decode_point(Point::identity().to_bytes().as_ref()).is_err());
}

#[cfg(feature = "jubjub")]
#[test]
fn jubjub_decoding_rejects_torsion_and_noncanonical_identity() {
    use golden_curves::jubjub::{BaseField, JubjubGroup as G, Point};
    let mut identity = [0; 32];
    identity[0] = 1;
    assert_eq!(G::encode_point(&Point::identity()), identity);
    assert_eq!(G::decode_point(&identity).unwrap(), Point::identity());
    let torsion = (-BaseField::ONE).to_repr(); // Edwards (u=0, v=-1), order two.
    assert!(G::decode_point(torsion.as_ref()).is_err());
    identity[31] = 0x80; // Negative zero in the u-coordinate sign bit.
    assert!(G::decode_point(&identity).is_err());
}
