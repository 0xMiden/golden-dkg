//! End-to-end DKG integration tests against the paper Secp/Secq backend.
//!
//! Drives the public `golden_core::{create_dealing, verify_dealing, complete}`
//! surface bound to `SecpSecqBackend`, then tampers with the dealer message
//! to pin rejection of malformed ciphertexts, commitments, and proof bytes.
//! Most tests are `#[ignore]` because the backend proves a full R1CS instance
//! per dealing; run via `cargo nextest --run-ignored only`.
//! `single_participant_dkg_completes_without_proving` is the exception: a
//! single-participant (n=1) dealing has no eVRF statement to prove, so it
//! runs unignored.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, verify_dealing,
    wire::{from_wire_bytes, to_wire_bytes},
    DealerMessage, DkgConfig, EvrfProofBackend, EvrfStatement, GoldenGroup, GoldenScalar,
    ParticipantIndex, ParticipantRegistry, SessionId, PROTOCOL_VERSION,
};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const PROOF_ID_LEN_BYTES: usize = 4;
const NESTED_LEN_BYTES: usize = 8;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config() -> DkgConfig<Secp256k1GoldenGroup> {
    let participants = [idx(1), idx(2), idx(3)];
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|p| {
                (
                    *p,
                    Secp256k1GoldenGroup::mul_generator(&identity_secret(*p)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        2,
        SessionId([42u8; 32]),
        Secp256k1Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn two_participant_config() -> DkgConfig<Secp256k1GoldenGroup> {
    let registry = ParticipantRegistry::new(
        [idx(1), idx(2)]
            .into_iter()
            .map(|participant| {
                (
                    participant,
                    Secp256k1GoldenGroup::mul_generator(&identity_secret(participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        1,
        SessionId([42u8; 32]),
        Secp256k1Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn single_participant_config() -> DkgConfig<Secp256k1GoldenGroup> {
    let registry = ParticipantRegistry::new(vec![(
        idx(1),
        Secp256k1GoldenGroup::mul_generator(&identity_secret(idx(1))),
    )])
    .unwrap();
    DkgConfig::new(
        1,
        SessionId([42u8; 32]),
        Secp256k1Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn tamper_element(
    point: &<Secp256k1GoldenGroup as GoldenGroup>::Element,
) -> <Secp256k1GoldenGroup as GoldenGroup>::Element {
    Secp256k1GoldenGroup::add(point, &Secp256k1GoldenGroup::generator())
}

fn tamper_scalar(s: &Secp256k1Scalar) -> Secp256k1Scalar {
    Secp256k1Scalar::add(s, &Secp256k1Scalar::one())
}

/// Run `verify_dealing` against `config` for a single dealer after applying
/// `tamper` to the freshly built dealer message.
fn assert_dealing_rejected<F>(tamper: F)
where
    F: FnOnce(&mut DealerMessage<Secp256k1GoldenGroup>),
{
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();
    let dealer = idx(1);
    let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();
    tamper(&mut dealing.message);
    let result = verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
    assert!(
        result.is_err(),
        "tampered dealing must be rejected, got {result:?}"
    );
}

/// Build the `EvrfStatement` list exactly as `verify_dealing` does, so the
/// backend's `verify_batch` can be invoked directly with a tampered
/// statement.
fn build_statements(
    dealing: &golden_core::DkgDealing<Secp256k1GoldenGroup>,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    dealer: ParticipantIndex,
) -> Vec<EvrfStatement<Secp256k1GoldenGroup>> {
    let mut statements = Vec::new();
    for receiver in config.registry.indexes() {
        if receiver == dealer {
            continue;
        }
        let share_commitment = dealing
            .message
            .commitment
            .public_key_share(receiver)
            .unwrap();
        let encrypted_share = dealing
            .message
            .encrypted_shares
            .get(&receiver)
            .cloned()
            .unwrap();
        statements.push(EvrfStatement {
            protocol_version: PROTOCOL_VERSION,
            backend_id: <Secp256k1GoldenGroup as GoldenGroup>::BACKEND_ID,
            session_id: config.session_id,
            registry_root: config.registry.root(),
            threshold: config.threshold,
            dealer,
            receiver,
            msg_i: dealing.message.msg_i,
            beta: config.beta,
            dealer_public_key: *config.registry.public_key(dealer).unwrap(),
            receiver_public_key: *config.registry.public_key(receiver).unwrap(),
            commitment_coefficients: dealing.message.commitment.coefficients().to_vec(),
            share_commitment,
            pad_commitment: encrypted_share.pad_commitment,
            encrypted_share: encrypted_share.encrypted_share,
            transcript_root: dealing.message.transcript_root,
        });
    }
    statements
}

fn assert_dkg_completes(config: DkgConfig<Secp256k1GoldenGroup>, decode_messages: bool) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let mut dealings: BTreeMap<_, _> = config
        .registry
        .indexes()
        .map(|dealer| {
            (
                dealer,
                create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                    dealer,
                    &identity_secret(dealer),
                    &config,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect();

    for dealing in dealings.values_mut() {
        if decode_messages {
            let encoded = to_wire_bytes(&dealing.message);
            let decoded = from_wire_bytes::<DealerMessage<Secp256k1GoldenGroup>>(&encoded).unwrap();
            assert_eq!(to_wire_bytes(&decoded), encoded);
            dealing.message = decoded;
        }
        verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();
    }

    let participant_count = config.registry.indexes().count();
    let receiver = idx(2);
    let own_dealing = dealings.get(&receiver).unwrap();
    let peer_dealings = dealings
        .iter()
        .filter_map(|(dealer, dealing)| {
            if *dealer == receiver {
                None
            } else {
                Some((*dealer, dealing.message.clone()))
            }
        })
        .collect();
    let output = complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
        receiver,
        &identity_secret(receiver),
        own_dealing,
        &peer_dealings,
        &config,
    )
    .unwrap();

    assert_eq!(
        output.public_key_shares[&receiver],
        Secp256k1GoldenGroup::mul_generator(&output.secret_share.value)
    );
    assert_eq!(output.public_key_shares.len(), participant_count);
}

#[test]
fn single_participant_dkg_completes_without_proving() {
    let config = single_participant_config();
    let dealer = idx(1);
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    assert!(dealing.message.proof.is_empty());
    assert!(dealing.message.encrypted_shares.is_empty());

    verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();

    let output = complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &dealing,
        &BTreeMap::new(),
        &config,
    )
    .unwrap();
    assert_eq!(
        output.public_key,
        Secp256k1GoldenGroup::mul_generator(&output.secret_share.value)
    );
    assert_eq!(output.public_key_shares.len(), 1);
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_completes_with_batched_evrf_backend() {
    assert_dkg_completes(config(), false);
}

#[test]
#[ignore = "slow: completes the real paper DKG from decoded peer messages"]
fn dkg_completes_with_decoded_peer_messages() {
    assert_dkg_completes(two_participant_config(), true);
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_pad_commitment() {
    assert_dealing_rejected(|msg| {
        let receiver = idx(2);
        let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
        entry.pad_commitment = tamper_element(&entry.pad_commitment);
    });
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_encrypted_share() {
    assert_dealing_rejected(|msg| {
        let receiver = idx(2);
        let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
        entry.encrypted_share = tamper_scalar(&entry.encrypted_share);
    });
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_share_commitment() {
    assert_dealing_rejected(|msg| {
        let mut coeffs = msg.commitment.coefficients().to_vec();
        let last = coeffs.last_mut().unwrap();
        *last = tamper_element(last);
        msg.commitment = golden_core::FeldmanCommitment::from_coefficients(coeffs).unwrap();
    });
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_transcript_root() {
    assert_dealing_rejected(|msg| {
        msg.transcript_root[0] ^= 0x01;
    });
}

#[test]
#[ignore = "slow: builds and verifies the full batched dealer proof"]
fn dkg_accepts_the_deterministic_dealing_and_rejects_malformed_or_replayed_proofs() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let participants = [idx(1), idx(2)];
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|participant| {
                (
                    *participant,
                    Secp256k1GoldenGroup::mul_generator(&identity_secret(*participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    let config = DkgConfig::new(
        1,
        SessionId([42u8; 32]),
        Secp256k1Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap();
    let dealer = idx(1);
    let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();

    let proof_id_len = u32::from_be_bytes(
        dealing.message.proof[..PROOF_ID_LEN_BYTES]
            .try_into()
            .unwrap(),
    ) as usize;
    let nested_len_offset = PROOF_ID_LEN_BYTES + proof_id_len;
    let payload_start = nested_len_offset + NESTED_LEN_BYTES;
    let payload_len = u64::from_be_bytes(
        dealing.message.proof[nested_len_offset..payload_start]
            .try_into()
            .unwrap(),
    ) as usize;
    // The nested frame contains only the R1CS proof. Protocol v7 appends a
    // native constant-term proof, encoded as one point and one scalar. The old
    // assertion treated the nested frame as the complete stream and stopped
    // this test before it could exercise the malformed and replayed proofs.
    let constant_term_proof_len = <Secp256k1GoldenGroup as GoldenGroup>::ELEMENT_REPR_BYTES
        + <Secp256k1Scalar as GoldenScalar>::REPR_BYTES;
    assert_eq!(
        payload_start + payload_len + constant_term_proof_len,
        dealing.message.proof.len()
    );

    let mut wrong_id = dealing.message.clone();
    wrong_id.proof[PROOF_ID_LEN_BYTES] ^= 0x01;

    let mut malformed_length = dealing.message.clone();
    malformed_length.proof[nested_len_offset..payload_start]
        .copy_from_slice(&u64::MAX.to_be_bytes());

    let mut truncated = dealing.message.clone();
    truncated.proof.pop();

    let mut trailing = dealing.message.clone();
    trailing.proof.push(0);

    let mut corrupted_nested_payload = dealing.message.clone();
    corrupted_nested_payload.proof[payload_start + payload_len / 2] ^= 0x01;

    let mut noncanonical_nested = dealing.message.clone();
    noncanonical_nested.proof[nested_len_offset..payload_start]
        .copy_from_slice(&u64::try_from(payload_len + 1).unwrap().to_be_bytes());
    noncanonical_nested.proof.push(0);

    for message in [
        wrong_id,
        malformed_length,
        truncated,
        trailing,
        corrupted_nested_payload,
        noncanonical_nested,
    ] {
        assert!(
            verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&message, &config).is_err(),
            "invalid proof stream must be rejected"
        );
    }

    let mut replayed_statement = dealing.message.clone();
    replayed_statement.msg_i.0[0] ^= 0x01;
    replayed_statement.transcript_root = replayed_statement.recompute_transcript_root();
    assert!(
        verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&replayed_statement, &config,)
            .is_err(),
        "proof replay under a different dealer statement must be rejected"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_swapped_encrypted_shares() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();
    let dealer = idx(1);
    let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();
    let a = dealing
        .message
        .encrypted_shares
        .get(&idx(2))
        .cloned()
        .unwrap();
    let b = dealing
        .message
        .encrypted_shares
        .get(&idx(3))
        .cloned()
        .unwrap();
    dealing.message.encrypted_shares.insert(idx(2), b);
    dealing.message.encrypted_shares.insert(idx(3), a);
    let result = verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
    assert!(
        result.is_err(),
        "swapped encrypted shares must be rejected, got {result:?}"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_missing_encrypted_share() {
    assert_dealing_rejected(|msg| {
        msg.encrypted_shares.remove(&idx(3));
    });
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_extra_self_receiver() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();
    let dealer = idx(1);
    let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();
    let placeholder = dealing
        .message
        .encrypted_shares
        .get(&idx(2))
        .cloned()
        .unwrap();
    dealing.message.encrypted_shares.insert(dealer, placeholder);
    dealing.message.transcript_root = dealing.message.recompute_transcript_root();
    let result = verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
    assert!(
        matches!(result, Err(golden_core::Error::UnexpectedShare(d)) if d == dealer.get()),
        "self-receiver must be rejected with UnexpectedShare({}), got {result:?}",
        dealer.get()
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn backend_rejects_pad_commitment_not_opened_by_proof_pad() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();
    let dealer = idx(1);
    let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    let mut statements = build_statements(&dealing, &config, dealer);
    SecpSecqBackend::verify_batch(&statements, &dealing.message.proof).unwrap();
    statements[0].pad_commitment = tamper_element(&statements[0].pad_commitment);
    let result = SecpSecqBackend::verify_batch(&statements, &dealing.message.proof);
    assert!(
        result.is_err(),
        "backend must reject pad_commitment not opened by proof pad, got {result:?}"
    );
}
