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
fn backend_rejects_malformed_proof_bytes() {
    let statement = minimal_evrf_statement();
    let malformed = [vec![0u8; 7], vec![0u8; 8], {
        let mut bytes = vec![0u8; 8];
        bytes.push(0);
        bytes
    }];

    for bytes in malformed {
        assert_eq!(
            SecpSecqBackend::verify_batch(core::slice::from_ref(&statement), &bytes).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }
}
