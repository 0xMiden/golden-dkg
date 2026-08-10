//! Public API tests for the paper Secp/Secq backend.
//!
//! These tests exercise exported backend surfaces directly and do not rely on
//! private helpers from `paper.rs`.

#![allow(clippy::unwrap_used)]

use golden_core::{
    DealerMessageNonce, Error, EvrfProofBackend, EvrfStatement, GoldenGroup, GoldenScalar,
    ParticipantIndex, SessionId, PROTOCOL_VERSION,
};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};

const PROOF_ID_LEN_BYTES: usize = 4;
const NESTED_LEN_BYTES: usize = 8;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn minimal_evrf_statement() -> EvrfStatement<Secp256k1GoldenGroup> {
    let dealer = idx(1);
    let receiver = idx(2);
    let dealer_secret = Secp256k1Scalar::from_u64(3).unwrap();
    let receiver_secret = Secp256k1Scalar::from_u64(5).unwrap();
    let share = Secp256k1Scalar::from_u64(13).unwrap();
    let pad = Secp256k1Scalar::from_u64(7).unwrap();
    let receiver_public_key = Secp256k1GoldenGroup::mul_generator(&receiver_secret);

    EvrfStatement {
        protocol_version: PROTOCOL_VERSION,
        backend_id: <Secp256k1GoldenGroup as GoldenGroup>::BACKEND_ID,
        session_id: SessionId([1u8; 32]),
        registry_root: [2u8; 32],
        threshold: 1,
        dealer,
        receiver,
        msg_i: DealerMessageNonce([9u8; 32]),
        beta: Secp256k1Scalar::from_u64(17).unwrap(),
        dealer_public_key: Secp256k1GoldenGroup::mul_generator(&dealer_secret),
        receiver_public_key,
        commitment_coefficients: vec![Secp256k1GoldenGroup::mul_generator(&share)],
        share_commitment: Secp256k1GoldenGroup::mul_generator(&share),
        pad_commitment: Secp256k1GoldenGroup::mul_generator(&pad),
        dh_commitment: Secp256k1GoldenGroup::mul(&receiver_public_key, &pad),
        encrypted_share: Secp256k1Scalar::add(&share, &pad),
        transcript_root: [3u8; 32],
    }
}

#[test]
fn batched_backend_uses_v3_proof_protocol_identifier() {
    assert_eq!(
        <SecpSecqBackend as EvrfProofBackend<Secp256k1GoldenGroup>>::PROOF_ID,
        b"golden-paper-evrf-batched-v3"
    );
}

#[test]
fn backend_rejects_malformed_proof_stream_framing() {
    let statement = minimal_evrf_statement();
    let proof_id = <SecpSecqBackend as EvrfProofBackend<Secp256k1GoldenGroup>>::PROOF_ID;
    let mut prefix = u32::try_from(proof_id.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    prefix.extend_from_slice(proof_id);

    let mut wrong_id = prefix.clone();
    wrong_id[PROOF_ID_LEN_BYTES] ^= 0x01;
    let missing_nested_length = prefix.clone();
    let mut truncated_nested_length = prefix.clone();
    truncated_nested_length.extend_from_slice(&[0u8; NESTED_LEN_BYTES - 1]);
    let mut overflowing_nested_length = prefix.clone();
    overflowing_nested_length.extend_from_slice(&u64::MAX.to_be_bytes());
    let mut truncated_nested_payload = prefix;
    truncated_nested_payload.extend_from_slice(&1u64.to_be_bytes());

    for bytes in [
        wrong_id,
        missing_nested_length,
        truncated_nested_length,
        overflowing_nested_length,
        truncated_nested_payload,
    ] {
        assert_eq!(
            SecpSecqBackend::verify_batch(core::slice::from_ref(&statement), &bytes).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }
}
