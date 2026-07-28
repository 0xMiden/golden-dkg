//! Public DKG integration tests for the curve-generic prototype backend.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, verify_dealing,
    wire::{from_wire_bytes, to_wire_bytes},
    DealerMessage, DkgConfig, DkgDealing, Error, EvrfProofBackend, GoldenGroup, GoldenScalar,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn participants() -> [ParticipantIndex; 4] {
    [idx(1), idx(2), idx(3), idx(4)]
}

fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
    P256Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config() -> DkgConfig<P256Backend> {
    let registry = ParticipantRegistry::new(
        participants()
            .into_iter()
            .map(|participant| {
                (
                    participant,
                    P256Backend::mul_generator(&identity_secret(participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        3,
        SessionId([42u8; 32]),
        P256Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn create_dealing_fixture(seed: u8) -> (DkgConfig<P256Backend>, DkgDealing<P256Backend>) {
    let config = config();
    let dealer = idx(1);
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    (config, dealing)
}

fn proof_header_len(proof: &[u8]) -> usize {
    let encoded_id_len = u32::from_be_bytes(proof[..4].try_into().unwrap()) as usize;
    let proof_id = <ShareOpeningBackend as EvrfProofBackend<P256Backend>>::PROOF_ID;
    assert_eq!(encoded_id_len, proof_id.len());
    assert_eq!(&proof[4..4 + encoded_id_len], proof_id);
    4 + encoded_id_len
}

fn proof_record_len() -> usize {
    3 * P256Backend::ELEMENT_REPR_BYTES + 2 * P256Scalar::REPR_BYTES
}

fn assert_proof_rejected(seed: u8, mutate: impl FnOnce(&mut Vec<u8>)) {
    let (config, mut dealing) = create_dealing_fixture(seed);
    verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config).unwrap();
    mutate(&mut dealing.message.proof);
    assert_eq!(
        verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config).unwrap_err(),
        Error::ProofVerificationFailed
    );
}

#[test]
fn create_wire_roundtrip_verify_and_complete_uses_opaque_proof_bytes() {
    let config = config();
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let mut dealings: BTreeMap<ParticipantIndex, DkgDealing<P256Backend>> = config
        .registry
        .indexes()
        .map(|dealer| {
            let mut dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            let encoded = to_wire_bytes(&dealing.message);
            let decoded = from_wire_bytes::<DealerMessage<P256Backend>>(&encoded).unwrap();
            assert_eq!(to_wire_bytes(&decoded), encoded);
            verify_dealing::<P256Backend, ShareOpeningBackend>(&decoded, &config).unwrap();
            dealing.message = decoded;
            (dealer, dealing)
        })
        .collect();

    let receiver = idx(2);
    let own_dealing = dealings.remove(&receiver).unwrap();
    let peer_dealings = dealings
        .into_iter()
        .map(|(dealer, dealing)| (dealer, dealing.message))
        .collect();
    let output = complete::<P256Backend, ShareOpeningBackend>(
        receiver,
        &identity_secret(receiver),
        &own_dealing,
        &peer_dealings,
        &config,
    )
    .unwrap();

    assert_eq!(
        output.public_key_shares[&receiver],
        P256Backend::mul_generator(&output.secret_share.value)
    );
    assert_eq!(output.public_key_shares.len(), participants().len());
}

#[test]
fn dkg_rejects_each_tampered_nonce_and_response() {
    let point_bytes = P256Backend::ELEMENT_REPR_BYTES;
    let scalar_bytes = P256Scalar::REPR_BYTES;
    let field_offsets = [
        0,
        point_bytes,
        2 * point_bytes,
        3 * point_bytes,
        3 * point_bytes + scalar_bytes,
    ];
    for (case, field_offset) in field_offsets.into_iter().enumerate() {
        assert_proof_rejected(2 + u8::try_from(case).unwrap(), |proof| {
            let byte = proof_header_len(proof) + field_offset;
            proof[byte] ^= 1;
        });
    }
}

#[test]
fn dkg_rejects_omitted_proof_record() {
    assert_proof_rejected(3, |proof| {
        let record_len = proof_record_len();
        proof.truncate(proof.len() - record_len);
    });
}

#[test]
fn dkg_rejects_extra_proof_record() {
    assert_proof_rejected(4, |proof| {
        let header_len = proof_header_len(proof);
        let record_len = proof_record_len();
        let extra = proof[header_len..header_len + record_len].to_vec();
        proof.extend_from_slice(&extra);
    });
}

#[test]
fn dkg_rejects_reordered_proof_records() {
    assert_proof_rejected(5, |proof| {
        let header_len = proof_header_len(proof);
        let record_len = proof_record_len();
        let first = proof[header_len..header_len + record_len].to_vec();
        let second = proof[header_len + record_len..header_len + 2 * record_len].to_vec();
        proof[header_len..header_len + record_len].copy_from_slice(&second);
        proof[header_len + record_len..header_len + 2 * record_len].copy_from_slice(&first);
    });
}

#[test]
fn dkg_rejects_truncated_proof_bytes() {
    assert_proof_rejected(6, |proof| {
        proof.pop();
    });
}

#[test]
fn dkg_rejects_trailing_proof_bytes() {
    assert_proof_rejected(7, |proof| proof.push(0));
}

#[test]
fn dkg_rejects_wrong_proof_id() {
    assert_proof_rejected(8, |proof| {
        let header_len = proof_header_len(proof);
        assert!(header_len > 4);
        proof[4] ^= 1;
    });
}

#[test]
fn dealer_message_wire_decode_accepts_malformed_inner_proof_bytes() {
    let (config, mut dealing) = create_dealing_fixture(9);
    dealing.message.proof = vec![1, 2, 3, 5, 8];

    let encoded = to_wire_bytes(&dealing.message);
    let decoded = from_wire_bytes::<DealerMessage<P256Backend>>(&encoded)
        .expect("generic dealer-message decoding must treat proof bytes as opaque");

    assert_eq!(decoded.proof, dealing.message.proof);
    assert_eq!(
        verify_dealing::<P256Backend, ShareOpeningBackend>(&decoded, &config).unwrap_err(),
        Error::ProofVerificationFailed
    );
}
