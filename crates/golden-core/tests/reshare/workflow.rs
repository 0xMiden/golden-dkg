//! End-to-end reshares of completed sharings on both native adapters.

use golden_core::{
    aggregate_public, complete_reshare, verify_dealer_message, verify_dealer_messages,
    DealerMessageRef, DkgGroup,
    DkgInstanceKind::{self, Reshare, Zero},
    Error,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use super::support::{board, check_reshare, credential, participant, Generation, PROOFS};

/// One reshare: the plain committee and its threshold, then the dealers, the receivers, their
/// threshold and the instance layout.
type Row = (
    &'static [u32],
    usize,
    &'static [u32],
    &'static [u32],
    usize,
    &'static [DkgInstanceKind],
);
const GROW: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3, 4], 3, &[Reshare, Zero]);
const GROW_RESHARE_ONLY: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3, 4], 3, &[Reshare]);
const GROW_BETWEEN_ZEROS: Row = (
    &[1, 2, 3],
    2,
    &[1, 2],
    &[1, 2, 3, 4],
    3,
    &[Zero, Reshare, Zero],
);
const SHRINK: Row = (
    &[1, 2, 3, 4],
    3,
    &[1, 2, 4],
    &[1, 2, 3],
    2,
    &[Zero, Reshare],
);
const DISJOINT: Row = (&[1, 2, 3], 2, &[2, 3], &[11, 12, 13], 2, &[Reshare]);
const OVERLAP: Row = (
    &[1, 2, 3],
    2,
    &[1, 2, 3],
    &[2, 3, 4, 5],
    2,
    &[Reshare, Zero, Zero],
);
const THRESHOLD_ONE_RESHARE_ONLY: Row = (&[1, 2, 3], 2, &[1, 2, 3], &[1, 2], 1, &[Reshare]);
const THRESHOLD_ONE: Row = (&[1, 2, 3], 2, &[1, 2, 3], &[1, 2], 1, &[Reshare, Zero]);
const THRESHOLD_ONE_BETWEEN_ZEROS: Row = (
    &[1, 2, 3],
    2,
    &[1, 2, 3],
    &[1, 2],
    1,
    &[Zero, Reshare, Zero],
);
const OUTSIDER: Row = (&[1, 2, 3], 2, &[1, 3], &[7], 1, &[Reshare, Zero]);
const NON_DEALER_RESHARE_ONLY: Row = (&[1, 2, 3], 2, &[2, 3], &[1], 1, &[Reshare]);
const NON_DEALER: Row = (&[1, 2, 3], 2, &[2, 3], &[1], 1, &[Reshare, Zero]);
const NON_DEALER_BETWEEN_ZEROS: Row = (&[1, 2, 3], 2, &[2, 3], &[1], 1, &[Zero, Reshare, Zero]);
const RAISE: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3], 3, &[Reshare, Zero]);
const REFRESH: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3], 2, &[Reshare, Zero]);
const REFRESH_BY_OTHER_DEALERS: Row = (&[1, 2, 3], 2, &[2, 3], &[1, 2, 3], 2, &[Reshare, Zero]);

fn topology<G: DkgGroup>((committee, threshold, dealers, receivers, new_threshold, layout): Row) {
    let plain = Generation::<G>::plain(committee, threshold, 1);
    let config = plain.reshare_config(dealers, receivers, new_threshold, layout.to_vec());
    assert_eq!(config.receiver_count(), receivers.len());
    for (dealer, key) in config.dealers().entries() {
        assert_ne!(config.identity_public_key(dealer), Some(key));
    }
    let own = plain.dealings(&PROOFS, &config, &mut ChaCha20Rng::from_seed([2; 32]));
    let board = board(&own);
    for dealing in &own {
        assert_eq!(dealing.config_root(), config.root());
        let (dealer, bytes) = (dealing.participant(), dealing.broadcast_bytes());
        verify_dealer_message(&PROOFS, &config, dealer, bytes).unwrap();
    }
    verify_dealer_messages(&PROOFS, &config, &board).unwrap();
    verify_dealer_messages(&PROOFS, &config, &board[1..]).unwrap();

    let mut forged = own[0].broadcast_bytes().to_vec();
    *forged.last_mut().unwrap() ^= 1;
    let mut tampered = board.clone();
    tampered[0].bytes = &forged;
    assert_eq!(
        verify_dealer_messages(&PROOFS, &config, &tampered).err(),
        Some(Error::InvalidDealerProofs {
            dealers: vec![own[0].participant()]
        })
    );

    let next = Generation::complete(plain.number + 1, config, own);
    check_reshare(&plain, &next);
}
both!(reshare_grows_the_committee_and_threshold, topology, GROW);
both!(
    reshare_grows_the_committee_with_only_a_reshare_column,
    topology,
    GROW_RESHARE_ONLY
);
both!(
    reshare_grows_the_committee_between_zero_columns,
    topology,
    GROW_BETWEEN_ZEROS
);
both!(
    reshare_shrinks_the_committee_and_threshold,
    topology,
    SHRINK
);
both!(
    reshare_moves_the_key_to_a_disjoint_committee,
    topology,
    DISJOINT
);
both!(
    reshare_by_every_dealer_to_an_overlapping_committee,
    topology,
    OVERLAP
);
both!(
    reshare_lowers_the_threshold_to_one_with_only_a_reshare_column,
    topology,
    THRESHOLD_ONE_RESHARE_ONLY
);
both!(reshare_lowers_the_threshold_to_one, topology, THRESHOLD_ONE);
both!(
    reshare_lowers_the_threshold_to_one_between_zero_columns,
    topology,
    THRESHOLD_ONE_BETWEEN_ZEROS
);
both!(
    reshare_hands_the_key_to_a_single_outsider,
    topology,
    OUTSIDER
);
both!(
    reshare_hands_the_key_to_a_non_dealing_member_with_only_a_reshare_column,
    topology,
    NON_DEALER_RESHARE_ONLY
);
both!(
    reshare_hands_the_key_to_a_non_dealing_member,
    topology,
    NON_DEALER
);
both!(
    reshare_hands_the_key_to_a_non_dealing_member_between_zero_columns,
    topology,
    NON_DEALER_BETWEEN_ZEROS
);
both!(
    reshare_raises_the_threshold_of_the_same_holders,
    topology,
    RAISE
);
both!(reshare_refreshes_the_same_holders, topology, REFRESH);
both!(
    reshare_refreshes_the_same_holders_through_other_dealers,
    topology,
    REFRESH_BY_OTHER_DEALERS
);

/// One predecessor reshared as `first` and as `second`, which differ only in their dealers,
/// keeps its key under different roots, shares and public shares.
fn dealer_sets<G: DkgGroup>(first: Row, second: Row) {
    let (committee, threshold, ..) = first;
    assert_eq!((committee, threshold), (second.0, second.1));
    let plain = Generation::<G>::plain(committee, threshold, 1);
    let [first, second] =
        [(first, 2), (second, 3)].map(|((_, _, dealers, receivers, threshold, layout), seed)| {
            plain.reshare(
                plain.reshare_config(dealers, receivers, threshold, layout.to_vec()),
                seed,
            )
        });
    assert_ne!(first.config.root(), second.config.root());
    assert_eq!(first.key(), second.key());
    for receiver in first.config.registry().indexes() {
        assert_ne!(first.share(receiver), second.share(receiver));
        assert_ne!(
            first.public_share(receiver.get()),
            second.public_share(receiver.get())
        );
    }
}
both!(
    reshare_through_other_dealers_keeps_the_key_and_changes_every_share,
    dealer_sets,
    REFRESH,
    REFRESH_BY_OTHER_DEALERS
);

fn chained_reshares<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 3);
    let first = plain.reshare(
        plain.reshare_config(&[1, 3], &[1, 2, 3, 4], 3, vec![Reshare, Zero]),
        4,
    );
    check_reshare(&plain, &first);
    let predecessor = first.predecessor();
    assert_eq!(predecessor.threshold(), 3);
    assert_eq!(predecessor.public_key(), &plain.key());
    assert_eq!(predecessor.config_root(), first.config.root());
    assert_eq!(
        predecessor.completion_root(),
        first.public.completion_root()
    );
    let second = first.reshare(
        first.reshare_config(&[2, 3, 4], &[5, 6], 2, vec![Zero, Reshare]),
        5,
    );
    assert_eq!(second.config.predecessor(), Some(&predecessor));
    check_reshare(&first, &second);
    assert_eq!(second.key(), plain.key());
    assert_eq!(second.secret(), plain.secret());
}
both!(reshare_of_reshare_output, chained_reshares);

fn declared_dealers_are_required<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 9);
    let config = plain.reshare_config(&[1, 2, 3], &[1, 2], 2, vec![Reshare, Zero]);
    let own = plain.dealings(&PROOFS, &config, &mut ChaCha20Rng::from_seed([10; 32]));
    let board = board(&own);
    let receiver = participant(1);
    let identity = credential::<G>(1, receiver);
    for absent in &own {
        let partial: Vec<_> = board
            .iter()
            .copied()
            .filter(|item| item.expected_dealer != absent.participant())
            .collect();
        verify_dealer_messages(&PROOFS, &config, &partial).unwrap();
        let missing = Some(Error::MissingDealer {
            dealer: absent.participant(),
        });
        assert_eq!(
            complete_reshare(&PROOFS, &config, &identity, receiver, &partial).err(),
            missing
        );
        assert_eq!(aggregate_public(&PROOFS, &config, &partial).err(), missing);
    }
    let mut stranger = board.clone();
    stranger.push(DealerMessageRef {
        expected_dealer: participant(4),
        bytes: own[0].broadcast_bytes(),
    });
    assert_eq!(
        complete_reshare(&PROOFS, &config, &identity, receiver, &stranger).err(),
        Some(Error::UnexpectedDealer {
            dealer: participant(4)
        })
    );
    let output = complete_reshare(&PROOFS, &config, &identity, receiver, &board).unwrap();
    assert_eq!(
        output.completion_root(),
        aggregate_public(&PROOFS, &config, &board)
            .unwrap()
            .completion_root()
    );
}
both!(
    reshare_completion_requires_every_declared_dealer,
    declared_dealers_are_required
);

fn completion_rejections<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 11);
    let config = plain.reshare_config(&[1, 2], &[2, 3, 4], 2, vec![Reshare, Zero]);
    let own = plain.dealings(&PROOFS, &config, &mut ChaCha20Rng::from_seed([12; 32]));
    let board = board(&own);
    let member = participant(2);
    for (receiver, identity) in [
        (member, credential::<G>(0, member)),
        (member, credential::<G>(1, participant(3))),
        (participant(1), credential::<G>(1, participant(1))),
        (participant(1), credential::<G>(0, participant(1))),
    ] {
        for messages in [&board[..], &[][..]] {
            assert_eq!(
                complete_reshare(&PROOFS, &config, &identity, receiver, messages).err(),
                Some(Error::IdentityKeyMismatch)
            );
        }
    }
    let identity = credential::<G>(1, member);
    let empty = Some(Error::EmptyBoard);
    assert_eq!(verify_dealer_messages(&PROOFS, &config, &[]).err(), empty);
    assert_eq!(aggregate_public(&PROOFS, &config, &[]).err(), empty);
    assert_eq!(
        complete_reshare(&PROOFS, &config, &identity, member, &[]).err(),
        empty
    );

    let mut forged = own[0].broadcast_bytes().to_vec();
    *forged.last_mut().unwrap() ^= 1;
    let mut tampered = board.clone();
    tampered[0].bytes = &forged;
    let dealers = vec![own[0].participant()];
    assert_eq!(
        complete_reshare(&PROOFS, &config, &identity, member, &tampered).err(),
        Some(Error::InvalidDealerProofs { dealers })
    );
}
both!(
    reshare_completion_rejects_wrong_credentials_and_boards,
    completion_rejections
);
