//! Public DKG integration tests for the curve-generic prototype backend.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, verify_dealing,
    wire::{from_wire_bytes, to_wire_bytes},
    DealerMessage, DkgConfig, DkgDealing, Error, EvrfProofBackend, EvrfStatement, GoldenGroup,
    GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId, PROTOCOL_VERSION,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use merlin::Transcript;
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
    2 * P256Backend::ELEMENT_REPR_BYTES + 2 * P256Scalar::REPR_BYTES
}

fn proof_statements(
    dealing: &DkgDealing<P256Backend>,
    config: &DkgConfig<P256Backend>,
) -> Vec<EvrfStatement<P256Backend>> {
    let dealer = dealing.message.dealer;
    config
        .registry
        .indexes()
        .filter(|receiver| *receiver != dealer)
        .map(|receiver| {
            let encrypted_share = dealing.message.encrypted_shares[&receiver].clone();
            EvrfStatement {
                protocol_version: PROTOCOL_VERSION,
                backend_id: P256Backend::BACKEND_ID,
                session_id: config.session_id,
                registry_root: config.registry.root(),
                threshold: config.threshold,
                dealer,
                receiver,
                msg_i: dealing.message.msg_i,
                beta: config.beta.clone(),
                dealer_public_key: *config.registry.public_key(dealer).unwrap(),
                receiver_public_key: *config.registry.public_key(receiver).unwrap(),
                commitment_coefficients: dealing.message.commitment.coefficients().to_vec(),
                share_commitment: dealing
                    .message
                    .commitment
                    .public_key_share(receiver)
                    .unwrap(),
                pad_commitment: encrypted_share.pad_commitment,
                encrypted_share: encrypted_share.encrypted_share,
                transcript_root: dealing.message.transcript_root,
            }
        })
        .collect()
}

fn prototype_challenge_checkpoints(
    statements: &[EvrfStatement<P256Backend>],
    proof: &[u8],
) -> Vec<[u8; 32]> {
    let proof_id = <ShareOpeningBackend as EvrfProofBackend<P256Backend>>::PROOF_ID;
    let mut transcript = Transcript::new(proof_id);
    transcript.append_message(b"group-backend", P256Backend::BACKEND_ID.as_bytes());
    transcript.append_message(
        b"statement-count",
        &u64::try_from(statements.len()).unwrap().to_be_bytes(),
    );
    for statement in statements {
        transcript.append_message(b"statement-root", &statement.root());
    }

    let mut cursor = proof_header_len(proof);
    let mut checkpoints = Vec::with_capacity(statements.len());
    for _ in statements {
        for label in [b"share-nonce-point".as_slice(), b"pad-nonce-point"] {
            let end = cursor + P256Backend::ELEMENT_REPR_BYTES;
            transcript.append_message(label, &proof[cursor..end]);
            cursor = end;
        }
        let mut challenge = [0u8; 32];
        transcript.challenge_bytes(b"opening-challenge", &mut challenge);
        checkpoints.push(challenge);
        for label in [b"share-response".as_slice(), b"pad-response"] {
            let end = cursor + P256Scalar::REPR_BYTES;
            transcript.append_message(label, &proof[cursor..end]);
            cursor = end;
        }
    }
    assert_eq!(cursor, proof.len());
    checkpoints
}

fn assert_proof_rejected(seed: u8, mutate: impl FnOnce(&mut Vec<u8>)) {
    let (config, mut dealing) = create_dealing_fixture(seed);
    verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config).unwrap();
    let transcript_root = dealing.message.transcript_root;
    mutate(&mut dealing.message.proof);
    assert_eq!(dealing.message.transcript_root, transcript_root);
    assert_eq!(dealing.message.recompute_transcript_root(), transcript_root);
    assert_eq!(
        verify_dealing::<P256Backend, ShareOpeningBackend>(&dealing.message, &config).unwrap_err(),
        Error::ProofVerificationFailed
    );
}

#[test]
fn deterministic_prototype_proof_stream_matches_v3_vector() {
    let (config, dealing) = create_dealing_fixture(10);

    assert_eq!(
        dealing.message.proof.as_slice(),
        include_bytes!("vectors/prototype-share-opening-v3.bin")
    );
    assert_eq!(
        prototype_challenge_checkpoints(
            &proof_statements(&dealing, &config),
            &dealing.message.proof
        ),
        vec![
            [
                110, 162, 168, 92, 153, 134, 208, 169, 69, 65, 191, 158, 163, 176, 106, 22, 211,
                41, 78, 102, 61, 86, 164, 208, 248, 62, 19, 250, 135, 165, 30, 124,
            ],
            [
                40, 120, 209, 8, 247, 242, 111, 162, 24, 101, 143, 255, 237, 182, 219, 188, 159,
                133, 122, 213, 116, 76, 113, 137, 148, 134, 199, 43, 49, 77, 233, 147,
            ],
            [
                122, 20, 204, 11, 11, 35, 13, 135, 234, 194, 6, 69, 194, 167, 30, 24, 169, 224,
                215, 141, 69, 199, 98, 241, 113, 199, 132, 217, 175, 235, 158, 222,
            ],
        ]
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
        2 * point_bytes,
        2 * point_bytes + scalar_bytes,
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
