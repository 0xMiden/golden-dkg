//! Public conformance tests for the Secp256k1 Main Golden curve adapter.

#![cfg(feature = "halo2curves-secp256k1")]
#![allow(clippy::unwrap_used)]

use ff::PrimeField;
use golden_core::main_golden::{beta, effective_message, h1, h2, receiver_pad};
use golden_core::{
    DealerMessageNonce, DkgInstanceKind, EvrfMessage, FieldByteOrder, GoldenCurve, GoldenGroup,
    GoldenHashToGroup, GoldenScalar, ParticipantIndex,
};
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use golden_rustcrypto::{K256Backend, K256Scalar};
use halo2curves::secp256k1::Fp;

type Curve = Secp256k1GoldenGroup;

#[test]
fn secp256k1_exposes_the_main_golden_curve_capabilities() {
    fn requires_golden_curve<C: GoldenCurve<BaseField = Fp>>() {}
    requires_golden_curve::<Curve>();

    assert_eq!(Curve::base_field_byte_order(), FieldByteOrder::LittleEndian);

    // SEC 2, section 2.7.1, gives the secp256k1 generator x-coordinate as
    // 79BE667E...16F81798. halo2curves uses a little-endian field repr.
    let generator_x = Curve::affine_x(&Curve::generator()).expect("generator is affine");
    assert_eq!(
        canonical_bytes(&generator_x),
        [
            0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc,
            0x9b, 0x02, 0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9,
            0x7e, 0x66, 0xbe, 0x79,
        ]
    );

    // This is (p - 1) mod n, independently calculated from the published
    // secp256k1 base-field and scalar-field moduli. It exercises a full-field
    // input that cannot be represented by the scalar field without reduction.
    let p_minus_one = Fp::from_repr_vartime(<Fp as PrimeField>::Repr::from([
        0x2e, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ]))
    .expect("p - 1 is a canonical base-field element");
    let reduced = Curve::reduce_base_field(&p_minus_one);
    assert_eq!(
        reduced.to_repr(),
        [
            0xed, 0xba, 0xc9, 0x2f, 0x72, 0xa1, 0x2d, 0x40, 0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23,
            0x51, 0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    );
}

#[test]
fn main_golden_beta_matches_the_fixed_protocol_vector() {
    let coefficient = beta::<Curve>().expect("fixed beta derivation succeeds");

    // Independent SHA-256 calculation for attempt=0, block=0 using the
    // specification's exact framing. The accepted big-endian candidate is
    // 25797001c27a2d7d6c6f51c284c926635b94dde798cf6df6f8a1aab39792cfb6;
    // halo2curves exposes the canonical Fp representation little-endian.
    assert_eq!(
        canonical_bytes(&coefficient),
        [
            0xb6, 0xcf, 0x92, 0x97, 0xb3, 0xaa, 0xa1, 0xf8, 0xf6, 0x6d, 0xcf, 0x98, 0xe7, 0xdd,
            0x94, 0x5b, 0x63, 0x26, 0xc9, 0x84, 0xc2, 0x51, 0x6f, 0x6c, 0x7d, 0x2d, 0x7a, 0xc2,
            0x01, 0x70, 0x79, 0x25,
        ]
    );
}

#[test]
fn effective_message_binds_the_configured_instance_kind() {
    let configuration_root = [0x42; 32];
    let dealer = ParticipantIndex::new(7).expect("nonzero participant");
    let nonce = DealerMessageNonce([0xa5; 32]);

    let random = effective_message(
        configuration_root,
        dealer,
        3,
        DkgInstanceKind::Random,
        nonce,
    );
    let zero = effective_message(configuration_root, dealer, 3, DkgInstanceKind::Zero, nonce);

    assert_eq!(
        random.0,
        [
            0x60, 0x23, 0x14, 0xe1, 0x42, 0xa2, 0x9f, 0xf5, 0xd7, 0xde, 0x27, 0x0d, 0xc9, 0xfd,
            0x8a, 0x3b, 0x9f, 0x22, 0x32, 0x4b, 0x9d, 0x70, 0x66, 0xbd, 0xe1, 0x5c, 0xbc, 0xaa,
            0x6f, 0x96, 0x61, 0x23,
        ]
    );

    assert_ne!(
        random, zero,
        "changing only Random/Zero policy must change the effective message"
    );
}

#[test]
fn h1_and_h2_order_identity_keys_canonically_and_bind_both_keys() {
    let message = EvrfMessage([0x3c; 32]);
    let key_a = public_key(3);
    let key_b = public_key(7);
    let replacement = public_key(11);

    let h1_ab = h1::<Curve>(message, &key_a, &key_b).expect("H1 accepts valid keys");
    let h2_ab = h2::<Curve>(message, &key_a, &key_b).expect("H2 accepts valid keys");

    assert_eq!(
        h1_ab,
        h1::<Curve>(message, &key_b, &key_a).expect("H1 accepts reversed keys")
    );
    assert_eq!(
        h2_ab,
        h2::<Curve>(message, &key_b, &key_a).expect("H2 accepts reversed keys")
    );
    assert_ne!(h1_ab, h2_ab, "H1 and H2 must use distinct domains");

    assert_ne!(
        h1_ab,
        h1::<Curve>(message, &replacement, &key_b).expect("H1 accepts replacement key"),
        "H1 must bind the first identity key"
    );
    assert_ne!(
        h1_ab,
        h1::<Curve>(message, &key_a, &replacement).expect("H1 accepts replacement key"),
        "H1 must bind the second identity key"
    );
    assert_ne!(
        h2_ab,
        h2::<Curve>(message, &replacement, &key_b).expect("H2 accepts replacement key"),
        "H2 must bind the first identity key"
    );
    assert_ne!(
        h2_ab,
        h2::<Curve>(message, &key_a, &replacement).expect("H2 accepts replacement key"),
        "H2 must bind the second identity key"
    );
    assert_ne!(
        h1_ab,
        h1::<Curve>(EvrfMessage([0x3d; 32]), &key_a, &key_b)
            .expect("H1 accepts another effective message"),
        "H1 must bind the effective message"
    );
    assert_ne!(
        h2_ab,
        h2::<Curve>(EvrfMessage([0x3d; 32]), &key_a, &key_b)
            .expect("H2 accepts another effective message"),
        "H2 must bind the effective message"
    );
}

#[test]
fn identity_coordinates_and_identity_dh_outputs_fail_closed() {
    assert!(
        Curve::affine_x(&Curve::identity()).is_err(),
        "the identity has no affine x-coordinate"
    );

    let message = EvrfMessage([0x7e; 32]);
    let peer_public_key = public_key(7);
    assert!(
        receiver_pad::<Curve>(message, &Secp256k1Scalar::zero(), &peer_public_key).is_err(),
        "an identity DH result must not be replaced with a zero coordinate"
    );
}

#[test]
fn secp256k1_adapters_agree_on_main_golden_coordinates_and_pad() {
    let message = EvrfMessage([0x63; 32]);
    let halo_secret = Secp256k1Scalar::from_u64(3).expect("small integer is a scalar");
    let halo_peer = public_key(7);
    let rustcrypto_secret = K256Scalar::from_u64(3).expect("small integer is a scalar");
    let rustcrypto_own = K256Backend::mul_generator(&rustcrypto_secret);
    let rustcrypto_peer =
        K256Backend::mul_generator(&K256Scalar::from_u64(7).expect("small integer is a scalar"));

    let halo_own = Curve::mul_generator(&halo_secret);
    let halo_h1 = h1::<Curve>(message, &halo_own, &halo_peer).expect("valid H1");
    let halo_h2 = h2::<Curve>(message, &halo_own, &halo_peer).expect("valid H2");
    let rustcrypto_h1 =
        h1::<K256Backend>(message, &rustcrypto_own, &rustcrypto_peer).expect("valid H1");
    let rustcrypto_h2 =
        h2::<K256Backend>(message, &rustcrypto_own, &rustcrypto_peer).expect("valid H2");
    let mut halo_h1_x = canonical_bytes(&Curve::affine_x(&halo_h1).expect("H1 is affine"));
    let mut halo_h2_x = canonical_bytes(&Curve::affine_x(&halo_h2).expect("H2 is affine"));
    let rustcrypto_h1_x: [u8; 32] = K256Backend::affine_x(&rustcrypto_h1)
        .expect("H1 is affine")
        .to_repr()
        .into();
    let rustcrypto_h2_x: [u8; 32] = K256Backend::affine_x(&rustcrypto_h2)
        .expect("H2 is affine")
        .to_repr()
        .into();
    halo_h1_x.reverse();
    halo_h2_x.reverse();
    assert_eq!(
        halo_h1_x,
        [
            0x27, 0x1b, 0xb4, 0x4b, 0x61, 0x13, 0xcd, 0x0f, 0x5f, 0xac, 0x1c, 0xa7, 0xc5, 0xdd,
            0x9e, 0x62, 0xfe, 0xd5, 0xc3, 0x56, 0xc0, 0xc3, 0xf8, 0xf5, 0x7b, 0xff, 0xdf, 0x3d,
            0xe9, 0x2b, 0xa5, 0x46,
        ]
    );
    assert_eq!(
        halo_h2_x,
        [
            0x59, 0x9f, 0xd2, 0x1f, 0xe8, 0xc7, 0xee, 0x0b, 0x6d, 0x99, 0x8d, 0xba, 0xcb, 0x62,
            0xbe, 0x86, 0xd5, 0x2c, 0x9d, 0x93, 0xf0, 0x2c, 0x53, 0xe2, 0xe1, 0xd2, 0x0b, 0x4a,
            0xce, 0xf2, 0x78, 0x30,
        ]
    );
    assert_eq!(halo_h1_x, rustcrypto_h1_x);
    assert_eq!(halo_h2_x, rustcrypto_h2_x);
    let halo_h1_encoding = Curve::encode_element(&halo_h1);
    let halo_h2_encoding = Curve::encode_element(&halo_h2);
    let rustcrypto_h1_encoding = K256Backend::encode_element(&rustcrypto_h1);
    let rustcrypto_h2_encoding = K256Backend::encode_element(&rustcrypto_h2);
    assert_eq!(
        halo_h1_encoding,
        [
            0x03, 0x27, 0x1b, 0xb4, 0x4b, 0x61, 0x13, 0xcd, 0x0f, 0x5f, 0xac, 0x1c, 0xa7, 0xc5,
            0xdd, 0x9e, 0x62, 0xfe, 0xd5, 0xc3, 0x56, 0xc0, 0xc3, 0xf8, 0xf5, 0x7b, 0xff, 0xdf,
            0x3d, 0xe9, 0x2b, 0xa5, 0x46,
        ]
    );
    assert_eq!(halo_h1_encoding, rustcrypto_h1_encoding);
    assert_eq!(halo_h2_encoding, rustcrypto_h2_encoding);
    assert_eq!(
        Curve::decode_element(&rustcrypto_h1_encoding).expect("odd SEC1 point decodes"),
        halo_h1
    );

    let halo_pad = receiver_pad::<Curve>(message, &halo_secret, &halo_peer)
        .expect("valid pad")
        .to_repr();
    assert_eq!(
        halo_pad,
        [
            0xf8, 0x90, 0x54, 0x13, 0x49, 0x80, 0xb0, 0x4d, 0x67, 0xa7, 0x81, 0x19, 0x1a, 0x72,
            0xbb, 0xf7, 0xb1, 0x26, 0xd6, 0x61, 0x68, 0x06, 0xb6, 0x8a, 0x85, 0x91, 0x40, 0x5a,
            0x35, 0x3d, 0x5e, 0xdb,
        ]
    );
    let reverse_halo_pad = receiver_pad::<Curve>(
        message,
        &Secp256k1Scalar::from_u64(7).expect("small integer is a scalar"),
        &halo_own,
    )
    .expect("roles may be reversed")
    .to_repr();
    assert_eq!(halo_pad, reverse_halo_pad);

    let mut halo_pad_be = halo_pad;
    halo_pad_be.reverse();
    assert_eq!(
        halo_pad_be,
        receiver_pad::<K256Backend>(message, &rustcrypto_secret, &rustcrypto_peer)
            .expect("valid pad")
            .to_repr()
    );

    let mut legacy_padded_message = [0u8; 64];
    legacy_padded_message[..32].copy_from_slice(&message.0);
    let legacy_h1 = Curve::hash_to_group(b"golden-paper-evrf-H-Gin-1-v1", &legacy_padded_message)
        .expect("legacy input hashes to a point");
    let legacy_h2 = Curve::hash_to_group(b"golden-paper-evrf-H-Gin-2-v1", &legacy_padded_message)
        .expect("legacy input hashes to a point");
    assert_ne!(
        Curve::affine_x(&halo_h1).expect("H1 is affine"),
        Curve::affine_x(&legacy_h1).expect("legacy H1 is affine")
    );
    assert_ne!(
        Curve::affine_x(&halo_h2).expect("H2 is affine"),
        Curve::affine_x(&legacy_h2).expect("legacy H2 is affine")
    );
}

fn public_key(secret: u64) -> <Curve as GoldenGroup>::Element {
    Curve::mul_generator(&Secp256k1Scalar::from_u64(secret).expect("small integer is a scalar"))
}

fn canonical_bytes(value: &Fp) -> [u8; 32] {
    value
        .to_repr()
        .as_ref()
        .try_into()
        .expect("Secp256k1 base-field representations are 32 bytes")
}
