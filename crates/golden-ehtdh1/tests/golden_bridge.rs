//! Golden DKG to EHTDH1 bridge tests.

#![cfg(any(feature = "prototype-bridge", feature = "halo2curves-secp256k1"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, DealerMessage, DkgConfig, DkgDealing, DkgInstanceKind, DkgOutput,
    GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_ehtdh1::{material_from_dkg_output, Combiner, Error, SetupContext, UnsealingShare};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type G = P256Backend;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn scalar(value: u64) -> P256Scalar {
    P256Scalar::from_u64(value).unwrap()
}

fn participants() -> [ParticipantIndex; 3] {
    [idx(1), idx(2), idx(3)]
}

fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
    scalar(100 + u64::from(participant.get()))
}

fn config(session_id: SessionId, instances: Vec<DkgInstanceKind>) -> DkgConfig<G> {
    let registry = ParticipantRegistry::new(
        participants()
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
    DkgConfig::batch(2, session_id, scalar(77), registry, instances).unwrap()
}

fn ehtdh1_config(session_id: SessionId) -> DkgConfig<G> {
    config(
        session_id,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
}

fn dealings(
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
) -> BTreeMap<ParticipantIndex, DkgDealing<G>> {
    config
        .registry()
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<G, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn peer_dealings(
    receiver: ParticipantIndex,
    dealings: &BTreeMap<ParticipantIndex, DkgDealing<G>>,
) -> BTreeMap<ParticipantIndex, DealerMessage<G>> {
    dealings
        .iter()
        .filter_map(|(dealer, dealing)| {
            (*dealer != receiver).then_some((*dealer, dealing.message().clone()))
        })
        .collect()
}

fn outputs(
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let dealings = dealings(config, rng);
    config
        .registry()
        .indexes()
        .map(|receiver| {
            let output = complete::<G, ShareOpeningBackend>(
                receiver,
                &identity_secret(receiver),
                dealings.get(&receiver).unwrap(),
                &peer_dealings(receiver, &dealings),
                config,
            )
            .unwrap();
            (receiver, output)
        })
        .collect()
}

#[test]
fn golden_batch_outputs_open_ehtdh1_payload_and_preserve_share_meaning() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let config = ehtdh1_config(SessionId([42u8; 32]));
    let outputs = outputs(&config, &mut rng);
    let epoch = [8u8; 32];
    let materials = participants()
        .iter()
        .map(|participant| {
            let output = outputs.get(participant).unwrap();
            let material = material_from_dkg_output(&config, output, epoch).unwrap();
            let decryption = &output.instances()[0];
            let context = &output.instances()[1];

            assert_eq!(
                material.sealing_key.joint_public_key(),
                decryption.public_key()
            );
            assert_eq!(
                material.public_key_set.joint_public_key,
                *decryption.public_key()
            );
            assert_eq!(material.secret_share.participant, *participant);
            assert_eq!(
                material.secret_share.decryption,
                decryption.secret_share().value
            );
            assert_eq!(material.secret_share.context, context.secret_share().value);
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

    let mut seal_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let message = first
        .sealing_key
        .seal_bytes_with_associated_data(&mut seal_rng, b"vault payload", b"ad")
        .unwrap();
    message.verify_with_associated_data(b"ad").unwrap();
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let shares = materials
        .values()
        .map(|material| {
            UnsealingShare::new(material.secret_share.clone())
                .decrypt_share(&mut share_rng, &material.setup_context, &message, b"dc")
                .unwrap()
        })
        .collect::<Vec<_>>();

    let opened = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())
        .unwrap()
        .combine_exact(&message, b"dc", &shares[..2])
        .unwrap();

    assert_eq!(opened, b"vault payload");
}

#[test]
fn bridge_requires_random_then_zero_configuration_order() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let config = config(
        SessionId([43u8; 32]),
        vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
    );
    let outputs = outputs(&config, &mut rng);

    let result = material_from_dkg_output(&config, outputs.get(&idx(1)).unwrap(), [9u8; 32]);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("expected [Random, Zero] batch")
    );
}

#[test]
fn bridge_rejects_output_from_another_configuration() {
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let output_config = ehtdh1_config(SessionId([44u8; 32]));
    let bridge_config = ehtdh1_config(SessionId([45u8; 32]));
    let outputs = outputs(&output_config, &mut rng);

    let result =
        material_from_dkg_output(&bridge_config, outputs.get(&idx(1)).unwrap(), [10u8; 32]);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("configuration root mismatch")
    );
}

#[test]
fn every_setup_context_field_affects_its_root() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let config = ehtdh1_config(SessionId([46u8; 32]));
    let outputs = outputs(&config, &mut rng);
    let material =
        material_from_dkg_output(&config, outputs.get(&idx(1)).unwrap(), [11u8; 32]).unwrap();
    let original = material.setup_context.root();
    type Mutation = (&'static str, fn(&mut SetupContext));
    let mutations: [Mutation; 8] = [
        ("backend id", |context| context.backend_id.push('x')),
        ("threshold", |context| context.threshold += 1),
        ("registry root", |context| context.registry_root[0] ^= 1),
        ("participant list", |context| context.participants.reverse()),
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

#[cfg(feature = "halo2curves-secp256k1")]
mod secp_secq {
    use std::collections::BTreeMap;

    use golden_core::{
        complete, create_dealing, DealerMessage, DkgConfig, DkgDealing, DkgInstanceKind, DkgOutput,
        GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
    };
    use golden_ehtdh1::{material_from_dkg_output, Combiner, UnsealingShare};
    use golden_evrf::paper::secp_secq::SecpSecqBackend;
    use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    type PaperGroup = Secp256k1GoldenGroup;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> Secp256k1Scalar {
        Secp256k1Scalar::from_u64(value).unwrap()
    }

    fn participants() -> [ParticipantIndex; 2] {
        [idx(1), idx(2)]
    }

    fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
        scalar(100 + u64::from(participant.get()))
    }

    fn config() -> DkgConfig<PaperGroup> {
        let registry = ParticipantRegistry::new(
            participants()
                .iter()
                .map(|participant| {
                    (
                        *participant,
                        PaperGroup::mul_generator(&identity_secret(*participant)),
                    )
                })
                .collect(),
        )
        .unwrap();
        DkgConfig::batch(
            2,
            SessionId([55u8; 32]),
            scalar(77),
            registry,
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap()
    }

    fn outputs(
        config: &DkgConfig<PaperGroup>,
        rng: &mut ChaCha20Rng,
    ) -> BTreeMap<ParticipantIndex, DkgOutput<PaperGroup>> {
        let dealings = config
            .registry()
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing::<PaperGroup, SecpSecqBackend>(
                    dealer,
                    &identity_secret(dealer),
                    config,
                    rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect::<BTreeMap<ParticipantIndex, DkgDealing<PaperGroup>>>();

        config
            .registry()
            .indexes()
            .map(|receiver| {
                let peers = dealings
                    .iter()
                    .filter_map(|(dealer, dealing)| {
                        (*dealer != receiver).then_some((*dealer, dealing.message().clone()))
                    })
                    .collect::<BTreeMap<ParticipantIndex, DealerMessage<PaperGroup>>>();
                let output = complete::<PaperGroup, SecpSecqBackend>(
                    receiver,
                    &identity_secret(receiver),
                    dealings.get(&receiver).unwrap(),
                    &peers,
                    config,
                )
                .unwrap();
                (receiver, output)
            })
            .collect()
    }

    #[test]
    #[ignore = "slow: proves paper Secp/Secq eVRF dealings"]
    fn paper_backend_batch_output_opens_ehtdh1_payload() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let config = config();
        let outputs = outputs(&config, &mut rng);
        let materials = participants()
            .iter()
            .map(|participant| {
                (
                    *participant,
                    material_from_dkg_output(
                        &config,
                        outputs.get(participant).unwrap(),
                        [12u8; 32],
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let first = materials.get(&idx(1)).unwrap();
        let mut seal_rng = ChaCha20Rng::from_seed([13u8; 32]);
        let message = first
            .sealing_key
            .seal_bytes(&mut seal_rng, b"paper")
            .unwrap();
        let mut share_rng = ChaCha20Rng::from_seed([14u8; 32]);
        let shares = materials
            .values()
            .map(|material| {
                UnsealingShare::new(material.secret_share.clone())
                    .decrypt_share(&mut share_rng, &material.setup_context, &message, b"dc")
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let opened = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())
            .unwrap()
            .combine_exact(&message, b"dc", &shares)
            .unwrap();

        assert_eq!(opened, b"paper");
    }
}
