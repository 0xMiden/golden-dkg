//! End-to-end DKG integration tests against the paper Secp/Secq backend.
//!
//! These drive the public batch-native DKG lifecycle and tamper only cloned
//! network messages. Most tests are ignored because each dealer proof builds a
//! full Secp/Secq R1CS instance; run them via `cargo nextest --run-ignored only`.
//! The single-participant test runs unignored because there are no receiver
//! relations to prove.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete_legacy as complete, create_dealing, verify_dealing,
    wire::{from_wire_bytes, to_wire_bytes},
    DealerMessage, DkgConfig, DkgDealing, DkgInstanceKind, GoldenGroup, GoldenScalar,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const PROOF_ID_LEN_BYTES: usize = 4;
const NESTED_LEN_BYTES: usize = 8;

type Group = Secp256k1GoldenGroup;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn legacy_beta() -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(77).unwrap()
}

fn config(
    participants: &[ParticipantIndex],
    threshold: usize,
    instances: Vec<DkgInstanceKind>,
) -> DkgConfig<Group> {
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|participant| {
                (
                    *participant,
                    Group::mul_generator(&identity_secret(*participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(threshold, SessionId([42u8; 32]), registry, instances).unwrap()
}

fn random_config() -> DkgConfig<Group> {
    config(&[idx(1), idx(2), idx(3)], 2, vec![DkgInstanceKind::Random])
}

fn mixed_config() -> DkgConfig<Group> {
    config(
        &[idx(1), idx(2)],
        1,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
}

fn zero_config() -> DkgConfig<Group> {
    config(&[idx(1), idx(2)], 1, vec![DkgInstanceKind::Zero])
}

fn single_participant_config() -> DkgConfig<Group> {
    config(
        &[idx(1)],
        1,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
}

fn tamper_element(point: &<Group as GoldenGroup>::Element) -> <Group as GoldenGroup>::Element {
    Group::add(point, &Group::generator())
}

fn tamper_scalar(scalar: &Secp256k1Scalar) -> Secp256k1Scalar {
    Secp256k1Scalar::add(scalar, &Secp256k1Scalar::one())
}

fn all_dealings(
    config: &DkgConfig<Group>,
    rng: &mut ChaCha20Rng,
) -> BTreeMap<ParticipantIndex, DkgDealing<Group>> {
    config
        .registry()
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<Group, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                &legacy_beta(),
                rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn assert_dkg_completes(config: DkgConfig<Group>, decode_messages: bool) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let dealings = all_dealings(&config, &mut rng);
    let messages = dealings
        .iter()
        .map(|(dealer, dealing)| {
            let message = if decode_messages {
                let encoded = to_wire_bytes(dealing.message());
                let decoded = from_wire_bytes::<DealerMessage<Group>>(&encoded).unwrap();
                assert_eq!(to_wire_bytes(&decoded), encoded);
                decoded
            } else {
                dealing.message().clone()
            };
            (*dealer, message)
        })
        .collect::<BTreeMap<_, _>>();

    for message in messages.values() {
        verify_dealing::<Group, SecpSecqBackend>(message, &config, &legacy_beta()).unwrap();
    }

    let receiver = idx(2);
    let peer_dealings = messages
        .iter()
        .filter_map(|(dealer, message)| (*dealer != receiver).then_some((*dealer, message.clone())))
        .collect();
    let output = complete::<Group, SecpSecqBackend>(
        receiver,
        &identity_secret(receiver),
        dealings.get(&receiver).unwrap(),
        &peer_dealings,
        &config,
        &legacy_beta(),
    )
    .unwrap();

    assert_eq!(output.configuration_root(), config.root());
    assert_eq!(output.instances().len(), config.instances().len());
    for (kind, instance) in config.instances().iter().zip(output.instances()) {
        assert_eq!(
            instance.public_key_shares()[&receiver],
            Group::mul_generator(instance.secret_share())
        );
        assert_eq!(instance.public_key_shares().len(), config.registry().len());
        if *kind == DkgInstanceKind::Zero {
            assert!(bool::from(Group::is_identity(instance.public_key())));
        }
    }
}

#[test]
fn single_participant_dkg_completes_without_proving() {
    let config = single_participant_config();
    let dealer = idx(1);
    let mut rng = ChaCha20Rng::from_seed([7; 32]);

    let dealing = create_dealing::<Group, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &legacy_beta(),
        &mut rng,
    )
    .unwrap();
    assert!(dealing.message().proof.is_empty());
    assert!(dealing
        .message()
        .dealings
        .iter()
        .all(|body| body.encrypted_shares.is_empty()));

    verify_dealing::<Group, SecpSecqBackend>(dealing.message(), &config, &legacy_beta()).unwrap();

    let output = complete::<Group, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &dealing,
        &BTreeMap::new(),
        &config,
        &legacy_beta(),
    )
    .unwrap();
    assert_eq!(output.instances().len(), 2);
    for instance in output.instances() {
        assert_eq!(
            instance.public_key(),
            &Group::mul_generator(instance.secret_share())
        );
    }
    assert!(bool::from(Group::is_identity(
        output.instances()[1].public_key()
    )));
}

#[test]
#[ignore = "slow: proves one mixed ordered DKG batch per dealer"]
fn mixed_dkg_completes_with_batched_evrf_backend() {
    assert_dkg_completes(mixed_config(), false);
}

#[test]
#[ignore = "slow: completes a zero-sharing paper DKG from decoded peer messages"]
fn zero_dkg_completes_with_decoded_peer_messages() {
    assert_dkg_completes(zero_config(), true);
}

#[test]
#[ignore = "slow: reuses one proof across public-message tamper cases"]
fn dkg_rejects_tampered_public_fields() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = random_config();
    let dealer = idx(1);
    let dealing = create_dealing::<Group, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &legacy_beta(),
        &mut rng,
    )
    .unwrap();
    let message = dealing.message();
    verify_dealing::<Group, SecpSecqBackend>(message, &config, &legacy_beta()).unwrap();

    let receiver = idx(2);
    let mut wrong_pad = message.clone();
    let encrypted = wrong_pad.dealings[0]
        .encrypted_shares
        .get_mut(&receiver)
        .unwrap();
    encrypted.pad_commitment = tamper_element(&encrypted.pad_commitment);

    let mut wrong_encrypted_share = message.clone();
    let encrypted = wrong_encrypted_share.dealings[0]
        .encrypted_shares
        .get_mut(&receiver)
        .unwrap();
    encrypted.encrypted_share = tamper_scalar(&encrypted.encrypted_share);

    let mut wrong_commitment = message.clone();
    let mut coefficients = wrong_commitment.dealings[0]
        .commitment
        .coefficients()
        .to_vec();
    coefficients[0] = tamper_element(&coefficients[0]);
    wrong_commitment.dealings[0].commitment =
        golden_core::FeldmanCommitment::from_coefficients(coefficients).unwrap();

    let mut wrong_configuration = message.clone();
    wrong_configuration.configuration_root[0] ^= 1;

    let mut swapped_receivers = message.clone();
    let first = swapped_receivers.dealings[0]
        .encrypted_shares
        .get(&idx(2))
        .cloned()
        .unwrap();
    let second = swapped_receivers.dealings[0]
        .encrypted_shares
        .get(&idx(3))
        .cloned()
        .unwrap();
    swapped_receivers.dealings[0]
        .encrypted_shares
        .insert(idx(2), second);
    swapped_receivers.dealings[0]
        .encrypted_shares
        .insert(idx(3), first);

    let mut missing_receiver = message.clone();
    missing_receiver.dealings[0]
        .encrypted_shares
        .remove(&idx(3));

    let mut extra_self_receiver = message.clone();
    let placeholder = extra_self_receiver.dealings[0]
        .encrypted_shares
        .get(&receiver)
        .cloned()
        .unwrap();
    extra_self_receiver.dealings[0]
        .encrypted_shares
        .insert(dealer, placeholder);

    // Preserve the public encrypted-share equation while changing the claimed
    // paper eVRF pad, so rejection must come from proof verification.
    let mut wrong_proof_pad = message.clone();
    let encrypted = wrong_proof_pad.dealings[0]
        .encrypted_shares
        .get_mut(&receiver)
        .unwrap();
    encrypted.pad_commitment = tamper_element(&encrypted.pad_commitment);
    encrypted.encrypted_share = tamper_scalar(&encrypted.encrypted_share);

    for tampered in [
        wrong_pad,
        wrong_encrypted_share,
        wrong_commitment,
        wrong_configuration,
        swapped_receivers,
        missing_receiver,
        extra_self_receiver,
        wrong_proof_pad,
    ] {
        let result = verify_dealing::<Group, SecpSecqBackend>(&tampered, &config, &legacy_beta());
        assert!(
            result.is_err(),
            "tampered dealer message must be rejected, got {result:?}"
        );
    }
}

#[test]
#[ignore = "slow: builds and verifies one full paper dealer proof"]
fn dkg_rejects_malformed_or_replayed_proofs() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config(&[idx(1), idx(2)], 1, vec![DkgInstanceKind::Zero]);
    let dealer = idx(1);
    let dealing = create_dealing::<Group, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &legacy_beta(),
        &mut rng,
    )
    .unwrap();
    let message = dealing.message();
    verify_dealing::<Group, SecpSecqBackend>(message, &config, &legacy_beta()).unwrap();

    let proof_id_len =
        u32::from_be_bytes(message.proof[..PROOF_ID_LEN_BYTES].try_into().unwrap()) as usize;
    let nested_len_offset = PROOF_ID_LEN_BYTES + proof_id_len;
    let payload_start = nested_len_offset + NESTED_LEN_BYTES;
    let payload_len = u64::from_be_bytes(
        message.proof[nested_len_offset..payload_start]
            .try_into()
            .unwrap(),
    ) as usize;
    // A zero dealing ends with the nested R1CS frame: there is no trailing
    // constant-term Schnorr record.
    assert_eq!(payload_start + payload_len, message.proof.len());

    let mut wrong_id = message.clone();
    wrong_id.proof[PROOF_ID_LEN_BYTES] ^= 0x01;
    let mut malformed_length = message.clone();
    malformed_length.proof[nested_len_offset..payload_start]
        .copy_from_slice(&u64::MAX.to_be_bytes());
    let mut truncated = message.clone();
    truncated.proof.pop();
    let mut trailing = message.clone();
    trailing.proof.push(0);
    let mut corrupted_payload = message.clone();
    corrupted_payload.proof[payload_start + payload_len / 2] ^= 0x01;
    let mut noncanonical_nested = message.clone();
    noncanonical_nested.proof[nested_len_offset..payload_start]
        .copy_from_slice(&u64::try_from(payload_len + 1).unwrap().to_be_bytes());
    noncanonical_nested.proof.push(0);

    for invalid in [
        wrong_id,
        malformed_length,
        truncated,
        trailing,
        corrupted_payload,
        noncanonical_nested,
    ] {
        assert!(
            verify_dealing::<Group, SecpSecqBackend>(&invalid, &config, &legacy_beta()).is_err()
        );
    }

    let mut replayed = message.clone();
    replayed.dealings[0].nonce.0[0] ^= 0x01;
    assert!(
        verify_dealing::<Group, SecpSecqBackend>(&replayed, &config, &legacy_beta()).is_err(),
        "proof replay under a different dealing nonce must be rejected"
    );
}
