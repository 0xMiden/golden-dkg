//! Public DKG integration tests for the curve-generic prototype backend.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, verify_dealing,
    wire::{from_wire_bytes, to_wire_bytes},
    DealerMessage, DkgConfig, DkgDealing, DkgInstanceKind, EvrfDealingStatement,
    EvrfDealingWitness, EvrfMessage, EvrfProofBackend, EvrfReceiverStatement, EvrfReceiverWitness,
    EvrfStatement, EvrfWitness, FeldmanCommitment, GoldenGroup, GoldenScalar, ParticipantIndex,
    ParticipantRegistry, SessionId,
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

fn legacy_beta() -> P256Scalar {
    P256Scalar::from_u64(77).unwrap()
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
        registry,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
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
        &legacy_beta(),
        &mut rng,
    )
    .unwrap();
    (config, dealing)
}

fn nested_backend_fixture() -> (EvrfStatement<P256Backend>, EvrfWitness<P256Backend>) {
    let dealer = idx(1);
    let dealer_secret = identity_secret(dealer);
    let mut public_dealings = Vec::new();
    let mut private_dealings = Vec::new();

    for position in 0..2u64 {
        let constant = P256Scalar::from_u64(10 + position).unwrap();
        let linear = P256Scalar::from_u64(3 + position).unwrap();
        let commitment_coefficients = vec![
            P256Backend::mul_generator(&constant),
            P256Backend::mul_generator(&linear),
        ];
        let mut public_receivers = Vec::new();
        let mut private_receivers = Vec::new();
        for receiver in [idx(2), idx(3)] {
            let x = P256Scalar::from_u64(u64::from(receiver.get())).unwrap();
            let share = constant.add(&linear.mul(&x));
            let pad = P256Scalar::from_u64(30 + position + u64::from(receiver.get())).unwrap();
            public_receivers.push(EvrfReceiverStatement {
                receiver,
                receiver_public_key: P256Backend::mul_generator(&identity_secret(receiver)),
                share_commitment: P256Backend::mul_generator(&share),
                pad_commitment: P256Backend::mul_generator(&pad),
                encrypted_share: share.add(&pad),
            });
            private_receivers.push(EvrfReceiverWitness { share, pad });
        }
        public_dealings.push(EvrfDealingStatement {
            message: EvrfMessage([u8::try_from(10 + position).unwrap(); 32]),
            commitment: FeldmanCommitment::from_coefficients(commitment_coefficients).unwrap(),
            receivers: public_receivers,
        });
        private_dealings.push(EvrfDealingWitness {
            polynomial_constant: Some(constant),
            receivers: private_receivers,
        });
    }

    (
        EvrfStatement {
            dealer_public_key: P256Backend::mul_generator(&dealer_secret),
            beta: P256Scalar::from_u64(77).unwrap(),
            dealer_message_root: [5; 32],
            dealings: public_dealings,
        },
        EvrfWitness {
            identity_secret: dealer_secret,
            dealings: private_dealings,
        },
    )
}

fn prove_nested(
    statement: &EvrfStatement<P256Backend>,
    witness: &EvrfWitness<P256Backend>,
    seed: u8,
) -> golden_core::Result<Vec<u8>> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    ShareOpeningBackend::prove_batch(statement, witness, &mut rng)
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

fn assert_proof_rejected(seed: u8, mutate: impl FnOnce(&mut Vec<u8>)) {
    let (config, dealing) = create_dealing_fixture(seed);
    let mut message = dealing.message().clone();
    verify_dealing::<P256Backend, ShareOpeningBackend>(&message, &config, &legacy_beta()).unwrap();
    let root = message.root();
    mutate(&mut message.proof);
    assert_eq!(message.root(), root);
    assert!(
        verify_dealing::<P256Backend, ShareOpeningBackend>(&message, &config, &legacy_beta())
            .is_err()
    );
}

#[test]
fn prototype_emits_one_joint_proof_for_mixed_batch() {
    let (config, dealing) = create_dealing_fixture(10);
    let message = dealing.message();
    let (_, repeated) = create_dealing_fixture(10);
    let receiver_count = participants().len() - 1;

    assert_eq!(
        <ShareOpeningBackend as EvrfProofBackend<P256Backend>>::PROOF_ID,
        b"golden-evrf/prototype-share-opening/v4"
    );

    assert_eq!(
        config.instances(),
        [DkgInstanceKind::Random, DkgInstanceKind::Zero]
    );
    assert_eq!(message.dealings.len(), 2);
    assert_eq!(message.proof, repeated.message().proof);
    assert_eq!(
        message.proof.len(),
        proof_header_len(&message.proof) + 2 * receiver_count * proof_record_len()
    );
    verify_dealing::<P256Backend, ShareOpeningBackend>(message, &config, &legacy_beta()).unwrap();
}

#[test]
fn nested_backend_rejects_misaligned_witness_and_wrong_dealer_secret() {
    let (statement, witness) = nested_backend_fixture();
    for case in 0..3 {
        let mut changed = witness.clone();
        match case {
            0 => {
                changed.dealings.pop();
            }
            1 => {
                changed.dealings[0].receivers.pop();
            }
            2 => {
                changed.identity_secret = changed.identity_secret.add(&P256Scalar::one());
            }
            _ => unreachable!(),
        }
        assert!(prove_nested(&statement, &changed, 20 + case).is_err());
    }
}

#[test]
fn nested_backend_binds_openings_and_statement_root() {
    let (statement, witness) = nested_backend_fixture();
    let proof = prove_nested(&statement, &witness, 24).unwrap();
    ShareOpeningBackend::verify_batch(&statement, &proof).unwrap();

    for case in 0..2 {
        let mut changed = witness.clone();
        let receiver = &mut changed.dealings[0].receivers[0];
        if case == 0 {
            receiver.share = receiver.share.add(&P256Scalar::one());
        } else {
            receiver.pad = receiver.pad.add(&P256Scalar::one());
        }
        let changed_proof = prove_nested(&statement, &changed, 25 + case).unwrap();
        assert!(ShareOpeningBackend::verify_batch(&statement, &changed_proof).is_err());
    }

    let mut changed_statement = statement.clone();
    changed_statement.dealer_message_root[0] ^= 1;
    assert!(ShareOpeningBackend::verify_batch(&changed_statement, &proof).is_err());
}

#[test]
fn nested_backend_default_cross_proof_fallback_checks_each_proof() {
    let (statement, witness) = nested_backend_fixture();
    let proof = prove_nested(&statement, &witness, 28).unwrap();
    let valid = [
        (&statement, proof.as_slice()),
        (&statement, proof.as_slice()),
    ];
    <ShareOpeningBackend as EvrfProofBackend<P256Backend>>::verify_proof_batch(&valid).unwrap();

    let mut invalid_proof = proof.clone();
    let first_record = proof_header_len(&invalid_proof);
    invalid_proof[first_record] ^= 1;
    let invalid = [
        (&statement, proof.as_slice()),
        (&statement, invalid_proof.as_slice()),
    ];
    assert!(
        <ShareOpeningBackend as EvrfProofBackend<P256Backend>>::verify_proof_batch(&invalid)
            .is_err()
    );
}

#[test]
fn create_wire_roundtrip_verify_and_complete_uses_opaque_proof_bytes() {
    let config = config();
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let dealings: BTreeMap<ParticipantIndex, DkgDealing<P256Backend>> = config
        .registry()
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &legacy_beta(),
                &mut rng,
            )
            .unwrap();
            let encoded = to_wire_bytes(dealing.message());
            let decoded = from_wire_bytes::<DealerMessage<P256Backend>>(&encoded).unwrap();
            assert_eq!(to_wire_bytes(&decoded), encoded);
            assert_eq!(&decoded, dealing.message());
            verify_dealing::<P256Backend, ShareOpeningBackend>(&decoded, &config, &legacy_beta())
                .unwrap();
            (dealer, dealing)
        })
        .collect();

    let receiver = idx(2);
    let own_dealing = dealings.get(&receiver).unwrap();
    let peer_dealings = dealings
        .iter()
        .filter(|(dealer, _)| **dealer != receiver)
        .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
        .collect();
    let output = complete::<P256Backend, ShareOpeningBackend>(
        receiver,
        &identity_secret(receiver),
        own_dealing,
        &peer_dealings,
        &config,
        &legacy_beta(),
    )
    .unwrap();

    assert_eq!(output.configuration_root(), config.root());
    assert_eq!(output.instances().len(), config.instances().len());
    for instance in output.instances() {
        assert_eq!(
            instance.public_key_shares()[&receiver],
            P256Backend::mul_generator(&instance.secret_share().value)
        );
        assert_eq!(instance.public_key_shares().len(), participants().len());
    }
    assert!(bool::from(P256Backend::is_identity(
        output.instances()[1].public_key()
    )));
}

#[test]
fn dkg_rejects_each_tampered_nonce_and_response() {
    let point_bytes = P256Backend::ELEMENT_REPR_BYTES;
    let scalar_bytes = P256Scalar::REPR_BYTES;
    let field_offsets = [
        0,
        point_bytes,
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
    let (config, dealing) = create_dealing_fixture(9);
    let mut message = dealing.message().clone();
    message.proof = vec![1, 2, 3, 5, 8];

    let encoded = to_wire_bytes(&message);
    let decoded = from_wire_bytes::<DealerMessage<P256Backend>>(&encoded)
        .expect("generic dealer-message decoding must treat proof bytes as opaque");

    assert_eq!(decoded.proof, message.proof);
    assert!(
        verify_dealing::<P256Backend, ShareOpeningBackend>(&decoded, &config, &legacy_beta())
            .is_err()
    );
}
