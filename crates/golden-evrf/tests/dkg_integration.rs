//! Public end-to-end coverage for the production Secp/Secq DKG proof system.
//!
//! Full proof tests are ignored because preparing generators and building the
//! Main Golden circuit is expensive. They remain explicitly runnable with
//! `cargo nextest run -p golden-evrf --test dkg_integration --features
//! halo2curves-secp256k1 --run-ignored only`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, deal, DkgConfig, DkgInstanceKind, Error, GoldenGroup, GoldenScalar, OwnDealing,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type Group = Secp256k1GoldenGroup;

const DEALER_MESSAGE_MAGIC: &[u8] = b"golden-dkg-dealer";

fn participant(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config(instances: Vec<DkgInstanceKind>) -> DkgConfig<Group> {
    config_with_participants(2, instances)
}

fn config_with_participants(
    participant_count: u32,
    instances: Vec<DkgInstanceKind>,
) -> DkgConfig<Group> {
    let registry = ParticipantRegistry::new(
        (1..=participant_count)
            .map(participant)
            .map(|participant| {
                (
                    participant,
                    Group::mul_generator(&identity_secret(participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(1, SessionId([42; 32]), registry, instances).unwrap()
}

fn all_dealings(
    proof_system: &SecpSecqBulletproofs,
    config: &DkgConfig<Group>,
    seed: u8,
) -> BTreeMap<ParticipantIndex, OwnDealing<Group>> {
    config
        .registry()
        .indexes()
        .map(|dealer| {
            let mut rng = ChaCha20Rng::from_seed(
                [seed.wrapping_add(u8::try_from(dealer.get()).unwrap()); 32],
            );
            let dealing = deal(
                proof_system,
                config,
                dealer,
                &identity_secret(dealer),
                &mut rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn peer_candidates(
    dealings: &BTreeMap<ParticipantIndex, OwnDealing<Group>>,
    receiver: ParticipantIndex,
) -> Vec<(ParticipantIndex, Vec<u8>)> {
    dealings
        .iter()
        .filter(|(dealer, _)| **dealer != receiver)
        .map(|(dealer, dealing)| (*dealer, dealing.dealer_message_bytes().to_vec()))
        .collect()
}

fn header_len() -> usize {
    DEALER_MESSAGE_MAGIC.len()
        + 4 // dealer-message codec version
        + 4 // Golden protocol version
        + 8 // curve identifier length
        + Group::CURVE_ID.len()
        + 32 // configuration root
        + 4 // encoded dealer
}

fn proof_offset(config: &DkgConfig<Group>) -> usize {
    let receiver_count = config.registry().len() - 1;
    config.instances().iter().fold(header_len(), |len, kind| {
        let physical_coefficients = match kind {
            DkgInstanceKind::Random => config.threshold(),
            DkgInstanceKind::Zero => config.threshold() - 1,
        };
        len + 32
            + physical_coefficients * Group::ELEMENT_REPR_BYTES
            + receiver_count * (Group::ELEMENT_REPR_BYTES + Secp256k1Scalar::REPR_BYTES)
    })
}

fn complete_for(
    proof_system: &SecpSecqBulletproofs,
    config: &DkgConfig<Group>,
    dealings: &BTreeMap<ParticipantIndex, OwnDealing<Group>>,
    receiver: ParticipantIndex,
) -> golden_core::Result<golden_core::DkgOutput<Group>> {
    complete(
        proof_system,
        config,
        &identity_secret(receiver),
        &dealings[&receiver],
        &peer_candidates(dealings, receiver),
    )
}

#[test]
fn single_participant_uses_the_zero_capacity_empty_proof_path() {
    let config = config_with_participants(1, vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let dealer = participant(1);
    let secret = identity_secret(dealer);
    let mut rng = ChaCha20Rng::from_seed([7; 32]);

    let own_dealing = deal(&proof_system, &config, dealer, &secret, &mut rng).unwrap();
    assert_eq!(
        own_dealing.dealer_message_bytes().len(),
        proof_offset(&config)
    );

    let output = complete(&proof_system, &config, &secret, &own_dealing, &[]).unwrap();
    assert_eq!(output.participant(), dealer);
    assert_eq!(output.configuration_root(), config.root());
    assert_eq!(output.instances().len(), 2);
    assert!(bool::from(Group::is_identity(
        output.instance(1).unwrap().public_key()
    )));
}

#[test]
#[ignore = "slow: builds two full one-instance Main Golden dealer proofs"]
fn one_instance_one_receiver_bytes_are_canonical_framed_and_bound() {
    let config = config(vec![DkgInstanceKind::Random]);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let dealings = all_dealings(&proof_system, &config, 20);
    let receiver = participant(1);
    let peer = participant(2);

    let expected = complete_for(&proof_system, &config, &dealings, receiver).unwrap();
    assert_eq!(expected.participant(), receiver);
    assert_eq!(expected.configuration_root(), config.root());
    assert_eq!(expected.instances().len(), 1);
    assert_eq!(
        expected.instance(0).unwrap().public_key_shares()[&receiver],
        Group::mul_generator(expected.instance(0).unwrap().secret_share())
    );

    let body_len = proof_offset(&config);
    let own_bytes = dealings[&receiver].dealer_message_bytes();
    let peer_bytes = dealings[&peer].dealer_message_bytes();
    assert!(body_len < own_bytes.len());
    assert!(body_len < peer_bytes.len());

    let mut changed_message = peer_bytes.to_vec();
    changed_message[header_len()] ^= 1;

    let mut changed_proof_header = peer_bytes.to_vec();
    changed_proof_header[body_len] ^= 1;

    let mut truncated_proof = peer_bytes.to_vec();
    truncated_proof.pop();

    let mut trailing_proof = peer_bytes.to_vec();
    trailing_proof.push(0);

    let mut replayed_for_another_dealer = peer_bytes[..body_len].to_vec();
    replayed_for_another_dealer.extend_from_slice(&own_bytes[body_len..]);

    for (case, bytes) in [
        ("changed effective message", changed_message),
        ("changed proof header", changed_proof_header),
        ("truncated proof", truncated_proof),
        ("trailing proof", trailing_proof),
        (
            "proof replayed across dealer keys",
            replayed_for_another_dealer,
        ),
    ] {
        let error = complete(
            &proof_system,
            &config,
            &identity_secret(receiver),
            &dealings[&receiver],
            &[(peer, bytes)],
        )
        .unwrap_err();
        assert_eq!(
            error,
            Error::InvalidDealerProofs {
                dealers: vec![peer],
            },
            "{case}"
        );
    }

    let retried = complete_for(&proof_system, &config, &dealings, receiver).unwrap();
    assert_eq!(retried.completion_root(), expected.completion_root());
}

#[test]
#[ignore = "slow: builds the ordered Random/Zero Main Golden proof for both dealers"]
fn mixed_random_zero_production_dkg_completes_for_every_participant() {
    let config = config(vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let dealings = all_dealings(&proof_system, &config, 40);
    let outputs = config
        .registry()
        .indexes()
        .map(|receiver| complete_for(&proof_system, &config, &dealings, receiver).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(outputs.len(), 2);
    for output in &outputs {
        assert_eq!(output.configuration_root(), config.root());
        assert_eq!(output.instances().len(), 2);
        assert!(bool::from(Group::is_identity(
            output.instance(1).unwrap().public_key()
        )));
        for instance in output.instances() {
            assert_eq!(
                instance.public_key_shares()[&output.participant()],
                Group::mul_generator(instance.secret_share())
            );
        }
    }
    assert_eq!(outputs[0].completion_root(), outputs[1].completion_root());
    for position in 0..2 {
        assert_eq!(
            outputs[0].instance(position).unwrap().public_key(),
            outputs[1].instance(position).unwrap().public_key()
        );
        assert_eq!(
            outputs[0].instance(position).unwrap().public_key_shares(),
            outputs[1].instance(position).unwrap().public_key_shares()
        );
    }
}
