//! Reshare dealing, public validation and predecessor binding on both native adapters.

use ff::Field;
use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, complete_reshare, deal, deal_reshare, verify_dealer_message,
    verify_dealer_messages, DealerMessageRef, DkgGroup,
    DkgInstanceKind::{Reshare, Zero},
    DkgOutput, DkgPublicOutput, Error, OwnDealing, ParticipantIndex,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::sync::Mutex;

use super::support::{board, credential, participant, Capture, Generation, PROOFS};

/// Offset of the configuration root in a broadcast, after the framed wire magic.
const ROOT: usize = 8 + b"golden-dkg-wire-v4".len();

/// `bytes` with its configuration root replaced by `root`.
fn with_root(bytes: &[u8], root: [u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[ROOT..ROOT + 32].copy_from_slice(&root);
    out
}

fn wire_and_logical_binding<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    let predecessor = plain.predecessor();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    for (receivers, threshold) in [(&[1, 2, 3, 4][..], 3), (&[1][..], 1)] {
        let config = plain.reshare_config_in(5, &[1, 2], receivers, threshold, vec![Reshare, Zero]);
        assert_eq!(config.receiver_count(), config.registry().len());
        let proofs = Capture(Mutex::new(Vec::new()));
        let own = plain.dealings(&proofs, &config, &mut rng);
        let statements = proofs.0.into_inner().unwrap();
        assert_eq!(statements.len(), own.len());
        for (dealing, statement) in own.iter().zip(&statements) {
            let dealer = dealing.participant();
            assert_eq!(statement.dealer(), dealer);
            let reshared = statement.instance(0).unwrap();
            let zero = statement.instance(1).unwrap();
            assert_eq!((reshared.kind(), zero.kind()), (Reshare, Zero));
            assert_eq!(
                reshared.commitment_coefficients().first(),
                predecessor.public_key_share(dealer)
            );
            assert!(bool::from(zero.commitment_coefficients()[0].is_identity()));

            let bytes = dealing.broadcast_bytes();
            let mut offset = ROOT + 32 + 4;
            for instance in statement.instances() {
                assert_eq!(instance.commitment_coefficients().len(), threshold);
                assert!(instance
                    .receivers()
                    .map(|receiver| receiver.participant())
                    .eq(config.registry().indexes()));
                offset += 32;
                let wire: Vec<u8> = instance.commitment_coefficients()[1..]
                    .iter()
                    .flat_map(G::encode_point)
                    .collect();
                assert_eq!(wire.len(), (threshold - 1) * G::POINT_BYTES);
                assert_eq!(bytes[offset..offset + wire.len()], wire);
                offset += wire.len() + config.receiver_count() * (G::POINT_BYTES + 32);
            }
            let proof = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
            assert_eq!(bytes.len(), offset + 8 + usize::try_from(proof).unwrap());

            let mut coefficients = u32::try_from(threshold).unwrap().to_be_bytes().to_vec();
            for coefficient in reshared.commitment_coefficients() {
                coefficients.extend_from_slice(&G::encode_point(coefficient));
            }
            assert!(statement
                .logical_bytes()
                .windows(coefficients.len())
                .any(|window| window == coefficients));
        }
    }
}
both!(
    reshare_wire_omits_and_logical_payload_binds_pinned_constant,
    wire_and_logical_binding
);

fn dealer_checks_precede_sampling<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    let config = plain.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let proofs = InsecureRevealedWitnessProof;
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let dealer = participant(1);
    let share = plain.share(dealer);
    let mut attempt = |dealer: ParticipantIndex, identity: G::Scalar, share: G::Scalar| {
        deal_reshare(&proofs, &config, dealer, &identity, &share, &mut rng).err()
    };
    for wrong in [
        share + G::Scalar::ONE,
        -share,
        G::Scalar::ZERO,
        plain.share(participant(2)),
    ] {
        assert_eq!(
            attempt(dealer, credential::<G>(0, dealer), wrong),
            Some(Error::PredecessorShareMismatch)
        );
    }
    for identity in [
        credential::<G>(0, participant(2)),
        credential::<G>(1, dealer),
    ] {
        assert_eq!(
            attempt(dealer, identity, G::Scalar::ZERO),
            Some(Error::IdentityKeyMismatch)
        );
    }
    for outsider in [3, 4] {
        let id = participant(outsider);
        assert_eq!(
            attempt(id, credential::<G>(0, id), share),
            Some(Error::UnknownParticipant(outsider))
        );
    }
    assert_eq!(rng.get_word_pos(), 0);
}
both!(
    reshare_dealer_checks_precede_sampling,
    dealer_checks_precede_sampling
);

fn replay_and_column_binding<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    let other = Generation::<G>::plain(&[1, 2, 3], 2, 2);
    let config = plain.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let rival = other.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let fresh = plain.reshare_config_in(6, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    assert_ne!(
        plain.predecessor().public_key_share(participant(1)),
        other.predecessor().public_key_share(participant(1))
    );
    let proofs = InsecureRevealedWitnessProof;
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let own = plain.dealings(&proofs, &config, &mut rng);
    let dealer = own[0].participant();
    let bytes = own[0].broadcast_bytes();
    let invalid = Some(Error::InvalidDealerMessages {
        dealers: vec![dealer],
    });

    for (target, candidate) in [
        (&plain.config, bytes.to_vec()),
        (&plain.config, with_root(bytes, plain.config.root())),
        (&rival, bytes.to_vec()),
        (&rival, with_root(bytes, rival.root())),
    ] {
        assert_eq!(
            verify_dealer_message(&proofs, target, dealer, &candidate).err(),
            invalid
        );
    }
    assert_eq!(
        verify_dealer_message(&proofs, &fresh, dealer, &with_root(bytes, fresh.root())).err(),
        Some(Error::InvalidDealerProofs {
            dealers: vec![dealer]
        })
    );
    assert_eq!(
        deal_reshare(
            &proofs,
            &rival,
            dealer,
            &credential::<G>(0, dealer),
            &plain.share(dealer),
            &mut rng
        )
        .err(),
        Some(Error::PredecessorShareMismatch)
    );
}
both!(
    reshare_dealings_bind_configuration_and_predecessor_column,
    replay_and_column_binding
);

fn cross_kind<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    let config = plain.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let swapped = plain.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Zero, Reshare]);
    let own = plain.dealings(&PROOFS, &config, &mut ChaCha20Rng::from_seed([6; 32]));
    let plain_board = board(&plain.own);
    let board = board(&own);
    let me = participant(1);
    let other = participant(2);
    assert_eq!(
        (
            plain.own[0].participant(),
            own[0].participant(),
            own[1].participant()
        ),
        (me, me, other)
    );
    let receiver = credential::<G>(1, me);
    let mismatch = Some(Error::ConfigurationKindMismatch);
    let invalid = |dealer| {
        Some(Error::InvalidDealerMessages {
            dealers: vec![dealer],
        })
    };
    let invalid_state = Some(Error::InvalidPersistedState);

    let mut untouched = ChaCha20Rng::from_seed([7; 32]);
    let share = plain.share(me);
    for (dealer, identity) in [
        (me, credential::<G>(0, me)),
        (participant(9), G::Scalar::ONE),
    ] {
        assert_eq!(
            deal(&PROOFS, &config, dealer, &identity, &mut untouched).err(),
            mismatch
        );
        assert_eq!(
            deal_reshare(
                &PROOFS,
                &plain.config,
                dealer,
                &identity,
                &share,
                &mut untouched
            )
            .err(),
            mismatch
        );
    }
    assert_eq!(untouched.get_word_pos(), 0);
    let identity = credential::<G>(0, me);
    assert_eq!(
        complete(
            &PROOFS,
            &config,
            &identity,
            &plain.own[0],
            &plain_board[1..]
        )
        .err(),
        mismatch
    );
    assert_eq!(
        complete_reshare(&PROOFS, &plain.config, &receiver, me, &board).err(),
        mismatch
    );

    assert_eq!(
        verify_dealer_message(&PROOFS, &config, me, plain.own[0].broadcast_bytes()).err(),
        invalid(me)
    );
    let replayed = with_root(plain.own[0].broadcast_bytes(), config.root());
    assert_eq!(
        verify_dealer_message(&PROOFS, &config, me, &replayed).err(),
        invalid(me)
    );
    let relaid = with_root(own[0].broadcast_bytes(), swapped.root());
    assert_eq!(
        verify_dealer_message(&PROOFS, &swapped, me, &relaid).err(),
        invalid(me)
    );
    assert_eq!(
        OwnDealing::from_bytes(&config, me, &plain.own[0].to_bytes().unwrap()).err(),
        invalid_state
    );
    assert_eq!(
        DkgPublicOutput::from_bytes(&config, &plain.public.to_bytes().unwrap()).err(),
        invalid_state
    );
    assert_eq!(
        DkgOutput::from_bytes(&config, me, &plain.outputs[&me].to_bytes().unwrap()).err(),
        invalid_state
    );
    let unexpected = Some(Error::UnexpectedDealer {
        dealer: participant(3),
    });
    assert_eq!(
        verify_dealer_messages(&PROOFS, &config, &plain_board).err(),
        unexpected
    );
    assert_eq!(
        aggregate_public(&PROOFS, &config, &plain_board).err(),
        unexpected
    );

    // The `Reshare` and `Zero` blocks have equal sizes, so swapping them leaves a well-formed
    // broadcast whose constants are pinned to the other kind.
    let header = ROOT + 32 + 4;
    let block = 32
        + (config.threshold() - 1) * G::POINT_BYTES
        + config.receiver_count() * (G::POINT_BYTES + 32);
    let mut blocks = own[1].broadcast_bytes().to_vec();
    let proof = header + 2 * block;
    let length = u64::from_be_bytes(blocks[proof..proof + 8].try_into().unwrap());
    assert_eq!(blocks.len(), proof + 8 + usize::try_from(length).unwrap());
    let (first, rest) = blocks.split_at_mut(header + block);
    first[header..].swap_with_slice(&mut rest[..block]);
    let tampered = [
        board[0],
        DealerMessageRef {
            expected_dealer: other,
            bytes: &blocks,
        },
    ];
    assert_eq!(
        verify_dealer_messages(&PROOFS, &config, &tampered).err(),
        invalid(other)
    );
    assert_eq!(
        aggregate_public(&PROOFS, &config, &tampered).err(),
        invalid(other)
    );
    assert_eq!(
        complete_reshare(&PROOFS, &config, &receiver, me, &tampered).err(),
        invalid(other)
    );
}
both!(
    plain_and_reshare_operations_reject_the_other_kind,
    cross_kind
);
