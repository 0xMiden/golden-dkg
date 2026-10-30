//! Group-key reshares across committee topologies on P-256 with the prototype
//! share-opening backend.
//!
//! Each topology runs a fresh plain DKG, reshares its key from a declared
//! dealer set to a new committee, and checks every receiver's output against
//! the public aggregation and the predecessor's secret.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    aggregate_reshare_public, complete, complete_reshare, create_dealing, create_reshare_dealing,
    lagrange_interpolate_at_zero, reconstruct_secret, verify_reshare_dealing,
    verify_reshare_dealing_for_receiver, verify_reshare_dealings, DealerMessage, DkgConfig,
    DkgOutput, Error, FeldmanCommitment, GoldenGroup, GoldenScalar, IdentityKeyProof,
    ParticipantIndex, ParticipantRegistry, ReshareConfig, ResharePredecessor, SessionId, Share,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type Board = BTreeMap<ParticipantIndex, DealerMessage<P256Backend>>;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

/// Identity secret of member `index` of committee generation `generation`.
/// Every generation holds distinct keys, so a member of both committees of one
/// reshare deals and receives under different keys.
fn credential(generation: u64, index: ParticipantIndex) -> P256Scalar {
    P256Scalar::from_u64(1000 * generation + u64::from(index.get()) + 10).unwrap()
}

fn registry(generation: u64, indexes: &[u32]) -> ParticipantRegistry<P256Backend> {
    ParticipantRegistry::new(
        indexes
            .iter()
            .map(|index| {
                let secret = credential(generation, idx(*index));
                (
                    idx(*index),
                    P256Backend::mul_generator(&secret),
                    IdentityKeyProof::prove(&secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn beta() -> P256Scalar {
    P256Scalar::from_u64(77).unwrap()
}

fn rng(seed: u8, stream: u64) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    rng.set_stream(stream);
    rng
}

fn messages(board: &Board) -> Vec<&DealerMessage<P256Backend>> {
    board.values().collect()
}

/// Every `size`-element subset of `items`, in order.
fn subsets<T: Copy>(items: &[T], size: usize) -> Vec<Vec<T>> {
    (0u32..1 << items.len())
        .filter(|mask| mask.count_ones() as usize == size)
        .map(|mask| {
            items
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask >> bit & 1 == 1)
                .map(|(_, item)| *item)
                .collect()
        })
        .collect()
}

/// One completed sharing of a group key by committee generation `number`:
/// every holder's output and the key set a reshare preserves.
struct Generation {
    number: u64,
    threshold: usize,
    predecessor: ResharePredecessor<P256Backend>,
    outputs: BTreeMap<ParticipantIndex, DkgOutput<P256Backend>>,
}

impl Generation {
    /// An honest plain DKG among `committee`, completed by every member.
    fn plain(committee: &[u32], threshold: usize, seed: u8) -> Self {
        let config = DkgConfig::new(
            threshold,
            SessionId([seed; 32]),
            beta(),
            registry(0, committee),
        )
        .unwrap();
        let mut rng = rng(seed, 0);
        let dealings: BTreeMap<_, _> = config
            .registry
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
                    dealer,
                    &credential(0, dealer),
                    &config,
                    &mut rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect();
        let outputs: BTreeMap<_, _> = config
            .registry
            .indexes()
            .map(|holder| {
                let peers = dealings
                    .iter()
                    .filter(|(dealer, _)| **dealer != holder)
                    .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
                    .collect();
                let output = complete::<P256Backend, ShareOpeningBackend>(
                    holder,
                    &credential(0, holder),
                    &dealings[&holder],
                    &peers,
                    &config,
                )
                .unwrap();
                (holder, output)
            })
            .collect();
        let predecessors: Vec<_> = outputs
            .values()
            .map(|output| ResharePredecessor::from_dkg_output(&config, output).unwrap())
            .collect();
        assert!(predecessors.windows(2).all(|pair| pair[0] == pair[1]));
        Self {
            number: 0,
            threshold,
            predecessor: predecessors[0].clone(),
            outputs,
        }
    }

    fn key(&self) -> &<P256Backend as GoldenGroup>::Element {
        self.predecessor.public_key()
    }

    fn share(&self, holder: ParticipantIndex) -> &Share<P256Scalar> {
        &self.outputs[&holder].secret_share
    }

    /// The group secret, interpolated from the first threshold holders' shares.
    fn secret(&self) -> P256Scalar {
        let shares: Vec<_> = self
            .outputs
            .values()
            .take(self.threshold)
            .map(|output| output.secret_share.clone())
            .collect();
        reconstruct_secret(&shares, self.threshold).unwrap()
    }

    /// Reshare from this generation's `dealers` to the next generation's
    /// `receivers` under session `[session; 32]`, declaring the largest
    /// corruption bound the threshold and committee size allow.
    fn reshare_config(
        &self,
        session: u8,
        dealers: &[u32],
        receivers: &[u32],
        threshold: usize,
    ) -> ReshareConfig<P256Backend> {
        let max_corrupt_receivers = (threshold - 1).min(receivers.len() - threshold);
        ReshareConfig::new(
            threshold,
            max_corrupt_receivers,
            SessionId([session; 32]),
            beta(),
            registry(self.number, dealers),
            registry(self.number + 1, receivers),
            self.predecessor.clone(),
        )
        .unwrap()
    }

    /// Every declared dealer's dealing of `config`, keyed by dealer.
    fn dealings(&self, config: &ReshareConfig<P256Backend>, rng: &mut ChaCha20Rng) -> Board {
        config
            .dealers()
            .indexes()
            .map(|dealer| {
                let message = create_reshare_dealing::<P256Backend, ShareOpeningBackend>(
                    dealer,
                    &credential(self.number, dealer),
                    self.share(dealer),
                    config,
                    rng,
                )
                .unwrap();
                (dealer, message)
            })
            .collect()
    }

    /// Every receiver's completion of `config` from `board`. Each output
    /// equals the public aggregation, opens its public share and yields the
    /// same chained predecessor.
    fn complete(&self, config: &ReshareConfig<P256Backend>, board: &Board) -> Self {
        let public =
            aggregate_reshare_public::<P256Backend, ShareOpeningBackend>(board, config).unwrap();
        let outputs: BTreeMap<_, _> = config
            .receivers()
            .indexes()
            .map(|receiver| {
                let output = complete_reshare::<P256Backend, ShareOpeningBackend>(
                    receiver,
                    &credential(self.number + 1, receiver),
                    board,
                    config,
                )
                .unwrap();
                assert_eq!(output.secret_share.participant, receiver);
                assert_eq!(output.public_key, public.public_key);
                assert_eq!(output.public_key_shares, public.public_key_shares);
                assert_eq!(output.transcript_root, public.transcript_root);
                assert_eq!(
                    public.public_key_shares[&receiver],
                    P256Backend::mul_generator(&output.secret_share.value)
                );
                (receiver, output)
            })
            .collect();
        let predecessors: Vec<_> = outputs
            .values()
            .map(|output| ResharePredecessor::from_reshare_output(config, output).unwrap())
            .collect();
        assert!(predecessors.windows(2).all(|pair| pair[0] == pair[1]));
        Self {
            number: self.number + 1,
            threshold: config.threshold(),
            predecessor: predecessors[0].clone(),
            outputs,
        }
    }
}

/// Check that `next`, a reshare of `previous`, keeps the group key, that every
/// threshold subset of its shares reconstructs `previous`'s secret, and that
/// one share fewer does not.
fn check_reshare(previous: &Generation, next: &Generation) {
    let secret = previous.secret();
    assert_eq!(P256Backend::mul_generator(&secret), *previous.key());
    assert_eq!(next.key(), previous.key());
    let holders: Vec<_> = next.outputs.keys().copied().collect();
    let shares = |subset: &[ParticipantIndex]| -> Vec<_> {
        subset
            .iter()
            .map(|holder| next.share(*holder).clone())
            .collect()
    };
    for subset in subsets(&holders, next.threshold) {
        assert_eq!(
            reconstruct_secret(&shares(&subset), next.threshold).unwrap(),
            secret
        );
    }
    if next.threshold > 1 {
        for subset in subsets(&holders, next.threshold - 1) {
            assert_ne!(
                lagrange_interpolate_at_zero(&shares(&subset)).unwrap(),
                secret
            );
        }
    }
}

/// `board` with one proof byte of `dealer`'s dealing flipped.
fn tamper(board: &Board, dealer: ParticipantIndex) -> Board {
    let mut tampered = board.clone();
    *tampered.get_mut(&dealer).unwrap().proof.last_mut().unwrap() ^= 1;
    tampered
}

/// One reshare: the plain committee and its threshold, then the dealers, the
/// receivers and their threshold.
type Row = (&'static [u32], usize, &'static [u32], &'static [u32], usize);

const GROW: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3, 4], 3);
const SHRINK: Row = (&[1, 2, 3, 4], 3, &[1, 2, 4], &[1, 2, 3], 2);
const DISJOINT: Row = (&[1, 2, 3], 2, &[2, 3], &[11, 12, 13], 2);
const OVERLAP: Row = (&[1, 2, 3], 2, &[1, 2, 3], &[2, 3, 4, 5], 2);
const RAISE: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3], 3);
const REFRESH: Row = (&[1, 2, 3], 2, &[1, 2], &[1, 2, 3], 2);
const REFRESH_BY_OTHER_DEALERS: Row = (&[1, 2, 3], 2, &[2, 3], &[1, 2, 3], 2);
const THRESHOLD_ONE: Row = (&[1, 2, 3], 2, &[1, 2, 3], &[1, 2], 1);
const OUTSIDER: Row = (&[1, 2, 3], 2, &[1, 3], &[7], 1);
const NON_DEALER: Row = (&[1, 2, 3], 2, &[2, 3], &[1], 1);

fn topology((committee, threshold, dealers, receivers, new_threshold): Row, seed: u8) {
    let plain = Generation::plain(committee, threshold, seed);
    let config = plain.reshare_config(seed + 100, dealers, receivers, new_threshold);
    let board = plain.dealings(&config, &mut rng(seed, 1));
    for message in board.values() {
        assert_eq!(message.registry_root, config.root());
        assert!(message
            .encrypted_shares
            .keys()
            .copied()
            .eq(config.receivers().indexes()));
        verify_reshare_dealing::<P256Backend, ShareOpeningBackend>(message, &config).unwrap();
        for receiver in config.receivers().indexes() {
            verify_reshare_dealing_for_receiver::<P256Backend, ShareOpeningBackend>(
                receiver,
                &credential(1, receiver),
                message,
                &config,
            )
            .unwrap();
        }
    }
    let all = messages(&board);
    verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&all, &config).unwrap();
    verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&all[1..], &config).unwrap();

    let blamed = *board.keys().last().unwrap();
    let tampered = tamper(&board, blamed);
    let blame = Error::DealerProofVerificationFailed(blamed.get());
    assert_eq!(
        verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&messages(&tampered), &config),
        Err(blame.clone())
    );
    assert_eq!(
        aggregate_reshare_public::<P256Backend, ShareOpeningBackend>(&tampered, &config)
            .unwrap_err(),
        blame
    );
    let receiver = config.receivers().indexes().next().unwrap();
    assert_eq!(
        complete_reshare::<P256Backend, ShareOpeningBackend>(
            receiver,
            &credential(1, receiver),
            &tampered,
            &config,
        )
        .unwrap_err(),
        blame
    );

    let next = plain.complete(&config, &board);
    check_reshare(&plain, &next);
}

#[test]
fn reshare_grows_the_committee_and_threshold() {
    topology(GROW, 1);
}

#[test]
fn reshare_shrinks_the_committee_and_threshold() {
    topology(SHRINK, 2);
}

#[test]
fn reshare_moves_the_key_to_a_disjoint_committee() {
    topology(DISJOINT, 3);
}

#[test]
fn reshare_by_every_dealer_to_an_overlapping_committee() {
    topology(OVERLAP, 4);
}

#[test]
fn reshare_raises_the_threshold_of_the_same_holders() {
    topology(RAISE, 5);
}

#[test]
fn reshare_refreshes_the_same_holders() {
    topology(REFRESH, 6);
}

#[test]
fn reshare_refreshes_the_same_holders_through_other_dealers() {
    topology(REFRESH_BY_OTHER_DEALERS, 7);
}

#[test]
fn reshare_lowers_the_threshold_to_one() {
    topology(THRESHOLD_ONE, 8);
}

#[test]
fn reshare_hands_the_key_to_a_single_outsider() {
    topology(OUTSIDER, 9);
}

#[test]
fn reshare_hands_the_key_to_a_non_dealing_member() {
    topology(NON_DEALER, 10);
}

/// One predecessor reshared by two dealer sets to the same committee under the
/// same session keeps its key under different roots, shares and public shares.
#[test]
fn reshare_through_other_dealers_keeps_the_key_and_changes_every_share() {
    let plain = Generation::plain(&[1, 2, 3], 2, 11);
    let [(first_config, first), (second_config, second)] =
        [(REFRESH, 1), (REFRESH_BY_OTHER_DEALERS, 2)].map(
            |((_, _, dealers, receivers, threshold), stream)| {
                let config = plain.reshare_config(111, dealers, receivers, threshold);
                let board = plain.dealings(&config, &mut rng(11, stream));
                let next = plain.complete(&config, &board);
                check_reshare(&plain, &next);
                (config, next)
            },
        );
    assert_eq!(first_config.session_id(), second_config.session_id());
    assert_ne!(first_config.root(), second_config.root());
    assert_eq!(first.key(), second.key());
    assert_ne!(
        first.predecessor.completion_root(),
        second.predecessor.completion_root()
    );
    for receiver in first_config.receivers().indexes() {
        assert_ne!(first.share(receiver), second.share(receiver));
        assert_ne!(
            first.predecessor.public_key_share(receiver),
            second.predecessor.public_key_share(receiver)
        );
    }
}

#[test]
fn reshare_of_reshare_output() {
    let plain = Generation::plain(&[1, 2, 3], 2, 12);
    let first_config = plain.reshare_config(112, &[1, 3], &[1, 2, 3, 4], 3);
    let first = plain.complete(
        &first_config,
        &plain.dealings(&first_config, &mut rng(12, 1)),
    );
    check_reshare(&plain, &first);
    let predecessor = &first.predecessor;
    assert_eq!(predecessor.threshold(), 3);
    assert_eq!(predecessor.public_key(), plain.key());
    assert_eq!(
        predecessor.completion_root(),
        first.outputs[&idx(1)].transcript_root
    );
    assert!(predecessor
        .public_key_shares()
        .keys()
        .copied()
        .eq(first_config.receivers().indexes()));

    let second_config = first.reshare_config(212, &[2, 3, 4], &[5, 6], 2);
    assert_eq!(second_config.predecessor(), predecessor);
    let second = first.complete(
        &second_config,
        &first.dealings(&second_config, &mut rng(12, 2)),
    );
    check_reshare(&first, &second);
    assert_eq!(second.key(), plain.key());
    assert_eq!(second.secret(), plain.secret());
}

#[test]
fn reshare_completion_requires_every_declared_dealer() {
    let plain = Generation::plain(&[1, 2, 3], 2, 13);
    let config = plain.reshare_config(113, &[1, 2, 3], &[1, 2], 2);
    let board = plain.dealings(&config, &mut rng(13, 1));
    let receiver = idx(1);
    let identity = credential(1, receiver);
    let complete_with = |board: &Board| {
        complete_reshare::<P256Backend, ShareOpeningBackend>(receiver, &identity, board, &config)
            .map(|output| output.transcript_root)
    };
    let aggregate_with = |board: &Board| {
        aggregate_reshare_public::<P256Backend, ShareOpeningBackend>(board, &config)
            .map(|public| public.transcript_root)
    };

    for absent in board.keys() {
        let mut partial = board.clone();
        partial.remove(absent);
        verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&messages(&partial), &config)
            .unwrap();
        let missing = Err(Error::MissingDealing(absent.get()));
        assert_eq!(complete_with(&partial), missing);
        assert_eq!(aggregate_with(&partial), missing);
    }

    let mut stranger = board.clone();
    let mut message = board[&idx(1)].clone();
    message.dealer = idx(4);
    stranger.insert(idx(4), message);
    assert_eq!(complete_with(&stranger), Err(Error::UnknownParticipant(4)));
    assert_eq!(aggregate_with(&stranger), Err(Error::UnknownParticipant(4)));

    let mut mislabeled = board.clone();
    mislabeled.insert(idx(4), board[&idx(1)].clone());
    let mismatch = Err(Error::DealerKeyMismatch {
        map_key: 4,
        message_dealer: 1,
    });
    assert_eq!(complete_with(&mislabeled), mismatch);
    assert_eq!(aggregate_with(&mislabeled), mismatch);

    assert_eq!(
        complete_with(&board).unwrap(),
        aggregate_with(&board).unwrap()
    );
}

#[test]
fn reshare_completion_rejects_wrong_credentials_and_boards() {
    let plain = Generation::plain(&[1, 2, 3], 2, 14);
    let config = plain.reshare_config(114, &[1, 2], &[2, 3, 4], 2);
    let board = plain.dealings(&config, &mut rng(14, 1));
    let member = idx(2);

    for (receiver, identity) in [
        (member, credential(0, member)),
        (member, credential(1, idx(3))),
        (idx(1), credential(1, idx(1))),
        (idx(1), credential(0, idx(1))),
    ] {
        for dealings in [&board, &Board::new()] {
            assert_eq!(
                complete_reshare::<P256Backend, ShareOpeningBackend>(
                    receiver, &identity, dealings, &config,
                )
                .unwrap_err(),
                Error::IdentityKeyMismatch
            );
        }
        assert_eq!(
            verify_reshare_dealing_for_receiver::<P256Backend, ShareOpeningBackend>(
                receiver,
                &identity,
                &board[&idx(1)],
                &config,
            )
            .unwrap_err(),
            Error::IdentityKeyMismatch
        );
    }

    let identity = credential(1, member);
    let complete_with = |board: &Board| {
        complete_reshare::<P256Backend, ShareOpeningBackend>(member, &identity, board, &config)
            .unwrap_err()
    };
    assert_eq!(
        verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&[], &config).unwrap_err(),
        Error::ProofVerificationFailed
    );
    assert_eq!(
        aggregate_reshare_public::<P256Backend, ShareOpeningBackend>(&Board::new(), &config)
            .unwrap_err(),
        Error::MissingDealing(1)
    );
    assert_eq!(complete_with(&Board::new()), Error::MissingDealing(1));

    let other_session = plain.reshare_config(214, &[1, 2], &[2, 3, 4], 2);
    assert_ne!(other_session.root(), config.root());
    let other_receivers = plain.reshare_config(114, &[1, 2], &[2, 3, 5], 2);
    assert_eq!(
        complete_with(&plain.dealings(&other_session, &mut rng(14, 2))),
        Error::SessionMismatch
    );
    assert_eq!(
        complete_with(&plain.dealings(&other_receivers, &mut rng(14, 3))),
        Error::RegistryMismatch
    );

    assert_eq!(
        complete_with(&tamper(&board, idx(1))),
        Error::DealerProofVerificationFailed(1)
    );

    // A constant other than Y_1 under a matching dealing root reaches the
    // C_0 comparison.
    let dealer = idx(1);
    let mut shifted = board.clone();
    let message = shifted.get_mut(&dealer).unwrap();
    let mut coefficients = message.commitment.coefficients().to_vec();
    coefficients[0] = P256Backend::add(&coefficients[0], &P256Backend::generator());
    message.commitment = FeldmanCommitment::from_coefficients(coefficients).unwrap();
    message.transcript_root = message.recompute_transcript_root();
    let mismatch = Error::ReshareConstantMismatch(dealer.get());
    assert_eq!(
        verify_reshare_dealing::<P256Backend, ShareOpeningBackend>(&shifted[&dealer], &config)
            .unwrap_err(),
        mismatch
    );
    assert_eq!(
        verify_reshare_dealings::<P256Backend, ShareOpeningBackend>(&messages(&shifted), &config)
            .unwrap_err(),
        mismatch
    );
    assert_eq!(complete_with(&shifted), mismatch);
}
