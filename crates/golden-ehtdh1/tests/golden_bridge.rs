//! Golden DKG to EHTDH1 bridge tests.

#![cfg(feature = "halo2curves-secp256k1")]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, deal, DkgConfig, DkgInstanceKind, DkgOutput, GoldenGroup, GoldenScalar, OwnDealing,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    material_from_dkg_output, Ciphertext, Combiner, DecryptionShare, Error, PublicKeySet,
    SealingKey, SecretShare, SetupContext, UnsealingShare,
};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, CryptoRngCore, Error as RandError, RngCore, SeedableRng};

type G = Secp256k1GoldenGroup;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn scalar(value: u64) -> Secp256k1Scalar {
    Secp256k1Scalar::from_u64(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
    scalar(100 + u64::from(participant.get()))
}

fn config(
    participants: &[ParticipantIndex],
    threshold: usize,
    session_id: SessionId,
    instances: Vec<DkgInstanceKind>,
) -> DkgConfig<G> {
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|participant| {
                (
                    *participant,
                    G::mul_generator(&identity_secret(*participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(threshold, session_id, registry, instances).unwrap()
}

fn ehtdh1_config(
    participants: &[ParticipantIndex],
    threshold: usize,
    session_id: SessionId,
) -> DkgConfig<G> {
    config(
        participants,
        threshold,
        session_id,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
}

fn own_dealings(
    proof_system: &SecpSecqBulletproofs,
    config: &DkgConfig<G>,
    rng: &mut impl CryptoRngCore,
) -> BTreeMap<ParticipantIndex, OwnDealing<G>> {
    config
        .registry()
        .indexes()
        .map(|dealer| {
            let dealing =
                deal(proof_system, config, dealer, &identity_secret(dealer), rng).unwrap();
            assert_eq!(dealing.participant(), dealer);
            assert!(!dealing.dealer_message_bytes().is_empty());
            (dealer, dealing)
        })
        .collect()
}

fn outputs(
    proof_system: &SecpSecqBulletproofs,
    config: &DkgConfig<G>,
    rng: &mut impl CryptoRngCore,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let dealings = own_dealings(proof_system, config, rng);
    config
        .registry()
        .indexes()
        .map(|receiver| {
            let peers = dealings
                .iter()
                .filter_map(|(dealer, dealing)| {
                    (*dealer != receiver)
                        .then_some((*dealer, dealing.dealer_message_bytes().to_vec()))
                })
                .collect::<Vec<_>>();
            let output = complete(
                proof_system,
                config,
                &identity_secret(receiver),
                dealings.get(&receiver).unwrap(),
                &peers,
            )
            .unwrap();
            (receiver, output)
        })
        .collect()
}

fn single_output(
    session_id: SessionId,
    instances: Vec<DkgInstanceKind>,
    rng: &mut impl CryptoRngCore,
) -> (DkgConfig<G>, DkgOutput<G>) {
    let participant = idx(1);
    let config = config(&[participant], 1, session_id, instances);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let output = outputs(&proof_system, &config, rng)
        .remove(&participant)
        .unwrap();
    (config, output)
}

/// Test-only entropy failure that forces the Random aggregate constant to zero.
#[derive(Debug, Default)]
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ZeroRng {}

#[test]
#[ignore = "slow: proves and verifies the Secp/Secq Main Golden DKG bridge"]
fn opaque_secp_batch_opens_ehtdh1_payload_and_preserves_wire_behavior() {
    let participants = [idx(1), idx(2)];
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let config = ehtdh1_config(&participants, 2, SessionId([42u8; 32]));
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    assert_eq!(
        config.instances(),
        [DkgInstanceKind::Random, DkgInstanceKind::Zero]
    );
    let outputs = outputs(&proof_system, &config, &mut rng);
    let epoch = [8u8; 32];
    let materials = participants
        .iter()
        .map(|participant| {
            let output = outputs.get(participant).unwrap();
            let material = material_from_dkg_output(&config, output, epoch).unwrap();
            let decryption = output.instance(0).unwrap();
            let context = output.instance(1).unwrap();

            assert!(!bool::from(G::is_identity(decryption.public_key())));
            assert!(bool::from(G::is_identity(context.public_key())));
            assert_eq!(
                material.sealing_key.joint_public_key(),
                decryption.public_key()
            );
            assert_eq!(
                material.public_key_set.joint_public_key,
                *decryption.public_key()
            );
            assert_eq!(material.secret_share.participant, *participant);
            assert_eq!(material.secret_share.decryption, *decryption.secret_share());
            assert_eq!(material.secret_share.context, *context.secret_share());
            assert_eq!(
                material
                    .public_key_set
                    .public_share(*participant)
                    .unwrap()
                    .decryption,
                decryption.public_key_shares()[participant]
            );
            assert_eq!(
                material
                    .public_key_set
                    .public_share(*participant)
                    .unwrap()
                    .context,
                context.public_key_shares()[participant]
            );
            assert_eq!(material.setup_context.session_id, config.session_id());
            assert_eq!(material.setup_context.configuration_root, config.root());
            assert_eq!(
                material.setup_context.completion_root,
                output.completion_root()
            );

            (*participant, material)
        })
        .collect::<BTreeMap<_, _>>();
    let first = materials.get(&idx(1)).unwrap();
    for material in materials.values() {
        assert_eq!(material.sealing_key, first.sealing_key);
        assert_eq!(material.public_key_set, first.public_key_set);
        assert_eq!(material.setup_context, first.setup_context);
    }

    let setup_context =
        from_wire_bytes::<SetupContext>(&to_wire_bytes(&first.setup_context)).unwrap();
    let public_key_set =
        from_wire_bytes::<PublicKeySet<G>>(&to_wire_bytes(&first.public_key_set)).unwrap();
    let sealing_key = from_wire_bytes::<SealingKey<G>>(&to_wire_bytes(&first.sealing_key)).unwrap();
    assert_eq!(setup_context, first.setup_context);
    assert_eq!(public_key_set, first.public_key_set);
    assert_eq!(sealing_key, first.sealing_key);

    for material in materials.values() {
        let secret_share =
            from_wire_bytes::<SecretShare<G>>(&to_wire_bytes(&material.secret_share)).unwrap();
        assert_eq!(secret_share.participant, material.secret_share.participant);
        assert_eq!(secret_share.decryption, material.secret_share.decryption);
        assert_eq!(secret_share.context, material.secret_share.context);
    }

    let mut seal_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let message = sealing_key
        .seal_bytes_with_associated_data(&mut seal_rng, b"vault payload", b"ad")
        .unwrap();
    let message = from_wire_bytes::<Ciphertext<G>>(&to_wire_bytes(&message)).unwrap();
    message.verify_with_associated_data(b"ad").unwrap();
    assert_eq!(
        message.verify_with_associated_data(b"wrong-ad"),
        Err(Error::AssociatedDataMismatch)
    );
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let shares = materials
        .values()
        .map(|material| {
            let share = UnsealingShare::new(material.secret_share.clone())
                .decrypt_share(&mut share_rng, &setup_context, &message, b"dc")
                .unwrap();
            from_wire_bytes::<DecryptionShare<G>>(&to_wire_bytes(&share)).unwrap()
        })
        .collect::<Vec<_>>();

    let combiner = Combiner::new(public_key_set, setup_context).unwrap();
    assert!(combiner
        .combine_exact(&message, b"dc", &shares[..1])
        .is_err());
    assert!(combiner
        .combine_exact(&message, b"wrong-dc", &shares)
        .is_err());
    let opened = combiner.combine_exact(&message, b"dc", &shares).unwrap();

    assert_eq!(opened, b"vault payload");
}

#[test]
fn bridge_requires_random_then_zero_configuration_order() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let (config, output) = single_output(
        SessionId([43u8; 32]),
        vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
        &mut rng,
    );

    let result = material_from_dkg_output(&config, &output, [9u8; 32]);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("expected [Random, Zero] batch")
    );
}

#[test]
fn bridge_rejects_output_from_another_configuration() {
    let participant = idx(1);
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let (output_config, output) = single_output(
        SessionId([44u8; 32]),
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        &mut rng,
    );
    let bridge_config = ehtdh1_config(&[participant], 1, SessionId([45u8; 32]));
    assert_ne!(output_config.root(), bridge_config.root());

    let result = material_from_dkg_output(&bridge_config, &output, [10u8; 32]);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("configuration root mismatch")
    );
}

#[test]
fn bridge_rejects_identity_decryption_aggregate_key() {
    let (config, output) = single_output(
        SessionId([46u8; 32]),
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        &mut ZeroRng,
    );
    assert!(bool::from(G::is_identity(
        output.instance(0).unwrap().public_key()
    )));

    let result = material_from_dkg_output(&config, &output, [11u8; 32]);

    assert_eq!(result.unwrap_err(), Error::InvalidJointPublicKey);
}

#[test]
fn every_setup_context_field_affects_its_root() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let (config, output) = single_output(
        SessionId([47u8; 32]),
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        &mut rng,
    );
    let material = material_from_dkg_output(&config, &output, [12u8; 32]).unwrap();
    let original = material.setup_context.root();
    type Mutation = (&'static str, fn(&mut SetupContext));
    let mutations: [Mutation; 8] = [
        ("backend id", |context| context.backend_id.push('x')),
        ("threshold", |context| context.threshold += 1),
        ("registry root", |context| context.registry_root[0] ^= 1),
        ("participant list", |context| {
            context.participants[0] = idx(2);
        }),
        ("session id", |context| context.session_id.0[0] ^= 1),
        ("configuration root", |context| {
            context.configuration_root[0] ^= 1;
        }),
        ("completion root", |context| {
            context.completion_root[0] ^= 1;
        }),
        ("epoch", |context| context.epoch[0] ^= 1),
    ];

    for (field, mutate) in mutations {
        let mut changed = material.setup_context.clone();
        mutate(&mut changed);
        assert_ne!(changed.root(), original, "{field} must affect the root");
    }
}
