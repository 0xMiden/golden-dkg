//! End-to-end DKG integration tests against the paper Secp/Secq backend.
//!
//! Drives the public `golden_core::{create_dealing, verify_dealing, complete}`
//! surface bound to `SecpSecqBackend`, then tampers with the dealer message
//! to pin rejection of malformed ciphertexts, commitments, and proof bytes.
//! All tests are `#[ignore]` because the backend proves a full R1CS instance
//! per dealing; run via `cargo nextest --run-ignored only`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, verify_dealing, DealerMessage, DkgConfig, EvrfProofBackend,
    EvrfStatement, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
    PROTOCOL_VERSION,
};
use golden_evrf::paper::secp_secq::{SecpSecqBackend, SecpSecqProof};
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

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
    F: FnOnce(&mut DealerMessage<Secp256k1GoldenGroup, SecpSecqProof>),
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
    dealing: &golden_core::DkgDealing<Secp256k1GoldenGroup, SecpSecqProof>,
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
            dealer,
            receiver,
            msg_i: dealing.message.msg_i,
            beta: config.beta,
            dealer_public_key: *config.registry.public_key(dealer).unwrap(),
            receiver_public_key: *config.registry.public_key(receiver).unwrap(),
            share_commitment,
            pad_commitment: encrypted_share.pad_commitment,
            dh_commitment: encrypted_share.dh_commitment,
            encrypted_share: encrypted_share.encrypted_share,
            transcript_root: dealing.message.transcript_root,
        });
    }
    statements
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_completes_with_batched_evrf_backend() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();

    let dealings: BTreeMap<_, _> = config
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

    for dealing in dealings.values() {
        verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config).unwrap();
    }

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
    assert_eq!(output.public_key_shares.len(), 3);
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
fn dkg_rejects_tampered_dh_commitment() {
    assert_dealing_rejected(|msg| {
        let receiver = idx(2);
        let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
        entry.dh_commitment = tamper_element(&entry.dh_commitment);
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
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_proof_bytes() {
    assert_dealing_rejected(|msg| {
        if msg.proof.0.is_empty() {
            msg.proof.0.push(0);
        }
        msg.proof.0[0] ^= 0x01;
    });
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

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn backend_rejects_dh_commitment_not_opened_by_proof_pad() {
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
    statements[0].dh_commitment = tamper_element(&statements[0].dh_commitment);
    let result = SecpSecqBackend::verify_batch(&statements, &dealing.message.proof);
    assert!(
        result.is_err(),
        "backend must reject dh_commitment not opened by proof pad, got {result:?}"
    );
}
