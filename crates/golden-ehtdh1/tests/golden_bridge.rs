//! Golden DKG to EHTDH1 bridge tests.

#![cfg(any(feature = "prototype-bridge", feature = "halo2curves-secp256k1"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing_with_secret, DealerMessage, DkgConfig, DkgDealing, DkgOutput,
    GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_ehtdh1::{
    derive_context_session_id, material_from_dkg_outputs, Combiner, Error, UnsealingShare,
};
use golden_evrf::prototype::{ShareOpeningBackend, ShareOpeningBatchedProof};
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type G = P256Backend;
type Proof = ShareOpeningBatchedProof<G>;

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

fn config(session_id: SessionId) -> DkgConfig<G> {
    config_with_identity_offset(session_id, 0)
}

fn config_with_identity_offset(session_id: SessionId, offset: u64) -> DkgConfig<G> {
    let registry = ParticipantRegistry::new(
        participants()
            .iter()
            .map(|participant| {
                (
                    *participant,
                    G::mul_generator(&scalar(100 + offset + u64::from(participant.get()))),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(2, session_id, scalar(77), registry).unwrap()
}

fn dealings(
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
    secret_for_dealer: impl Fn(ParticipantIndex) -> P256Scalar,
) -> BTreeMap<ParticipantIndex, DkgDealing<G, Proof>> {
    config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing_with_secret::<G, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                secret_for_dealer(dealer),
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
    dealings: &BTreeMap<ParticipantIndex, DkgDealing<G, Proof>>,
) -> BTreeMap<ParticipantIndex, DealerMessage<G, Proof>> {
    dealings
        .iter()
        .filter_map(|(dealer, dealing)| {
            (*dealer != receiver).then_some((*dealer, dealing.message.clone()))
        })
        .collect()
}

fn outputs(
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
    secret_for_dealer: impl Fn(ParticipantIndex) -> P256Scalar,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let dealings = dealings(config, rng, secret_for_dealer);
    config
        .registry
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
fn golden_outputs_open_ehtdh1_payload() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let decryption_config = config(SessionId([42u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(20 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());
    let epoch = [8u8; 32];
    let materials = participants()
        .iter()
        .map(|participant| {
            (
                *participant,
                material_from_dkg_outputs(
                    &decryption_config,
                    decryption_outputs.get(participant).unwrap(),
                    &context_config,
                    context_outputs.get(participant).unwrap(),
                    epoch,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let first = materials.get(&idx(1)).unwrap();
    let mut seal_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let message = first
        .sealing_key
        .seal_bytes_with_associated_data(&mut seal_rng, b"vault payload", b"ad")
        .unwrap();
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
fn bridge_rejects_nonzero_context_sharing() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let decryption_config = config(SessionId([43u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(30 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| scalar(1));

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [9u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("zero-sharing public key is not identity")
    );
}

#[test]
fn bridge_rejects_identity_decryption_public_key() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let decryption_config = config(SessionId([49u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |_| P256Scalar::zero());
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [15u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("decryption public key is identity")
    );
}

#[test]
fn bridge_requires_derived_context_session() {
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let decryption_config = config(SessionId([44u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let wrong_context_config = config(SessionId([99u8; 32]));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(40 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [10u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("context session mismatch")
    );
}

#[test]
fn bridge_rejects_threshold_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let decryption_config = config(SessionId([45u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let mut wrong_context_config = context_config.clone();
    wrong_context_config.threshold = 3;
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(50 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [11u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("threshold mismatch")
    );
}

#[test]
fn bridge_rejects_registry_root_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let decryption_config = config(SessionId([46u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let wrong_context_config = config_with_identity_offset(
        derive_context_session_id(decryption_config.session_id),
        1_000,
    );
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(60 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [12u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("registry root mismatch")
    );
}

#[test]
fn bridge_rejects_local_participant_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let decryption_config = config(SessionId([47u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(70 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(2)).unwrap(),
        [13u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("local participant mismatch")
    );
}

#[test]
fn dkg_transcript_roots_affect_setup_context_root() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let decryption_config = config(SessionId([48u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(80 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());
    let material = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [14u8; 32],
    )
    .unwrap();
    let original = material.setup_context.root();
    let mut changed_decryption = material.setup_context.clone();
    changed_decryption.decryption_transcript_root[0] ^= 1;
    let mut changed_context = material.setup_context.clone();
    changed_context.context_transcript_root[0] ^= 1;

    assert_ne!(changed_decryption.root(), original);
    assert_ne!(changed_context.root(), original);
}

#[cfg(feature = "halo2curves-secp256k1")]
mod secp_secq {
    use std::collections::BTreeMap;

    use golden_core::{
        complete, create_dealing_with_secret, DealerMessage, DkgConfig, DkgDealing, DkgOutput,
        GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
    };
    use golden_ehtdh1::{
        derive_context_session_id, material_from_dkg_outputs, Combiner, UnsealingShare,
    };
    use golden_evrf::paper::secp_secq::{SecpSecqBackend, SecpSecqProof};
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

    fn config(session_id: SessionId) -> DkgConfig<PaperGroup> {
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
        // A threshold-one zero sharing is the constant-zero polynomial, whose
        // identity share commitments are rejected by the paper backend.
        DkgConfig::new(2, session_id, scalar(77), registry).unwrap()
    }

    fn dealings(
        config: &DkgConfig<PaperGroup>,
        rng: &mut ChaCha20Rng,
        secret_for_dealer: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
    ) -> BTreeMap<ParticipantIndex, DkgDealing<PaperGroup, SecpSecqProof>> {
        config
            .registry
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing_with_secret::<PaperGroup, SecpSecqBackend>(
                    dealer,
                    &identity_secret(dealer),
                    secret_for_dealer(dealer),
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
        dealings: &BTreeMap<ParticipantIndex, DkgDealing<PaperGroup, SecpSecqProof>>,
    ) -> BTreeMap<ParticipantIndex, DealerMessage<PaperGroup, SecpSecqProof>> {
        dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                (*dealer != receiver).then_some((*dealer, dealing.message.clone()))
            })
            .collect()
    }

    fn outputs(
        config: &DkgConfig<PaperGroup>,
        rng: &mut ChaCha20Rng,
        secret_for_dealer: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
    ) -> BTreeMap<ParticipantIndex, DkgOutput<PaperGroup>> {
        let dealings = dealings(config, rng, secret_for_dealer);
        config
            .registry
            .indexes()
            .map(|receiver| {
                let output = complete::<PaperGroup, SecpSecqBackend>(
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
    #[ignore = "slow: proves paper Secp/Secq eVRF dealings"]
    fn paper_backend_outputs_open_ehtdh1_payload() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let decryption_config = config(SessionId([55u8; 32]));
        let context_config = config(derive_context_session_id(decryption_config.session_id));
        let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
            scalar(60 + u64::from(dealer.get()))
        });
        let context_outputs = outputs(&context_config, &mut rng, |_| Secp256k1Scalar::zero());
        let materials = participants()
            .iter()
            .map(|participant| {
                (
                    *participant,
                    material_from_dkg_outputs(
                        &decryption_config,
                        decryption_outputs.get(participant).unwrap(),
                        &context_config,
                        context_outputs.get(participant).unwrap(),
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
