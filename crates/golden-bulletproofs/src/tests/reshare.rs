//! Reshare shapes, the single-receiver proof guard and the reshare cases of the real-workflow gate.
use super::{reject_publicly_valid_mutations, Capture, WIRE_HEADER};
use crate::driver::Backend;
use crate::prepared::Prepared;
use crate::shape::{multiplier_count, required_capacity};
use ff::{Field, PrimeField};
use golden_core::{
    aggregate_public, complete_reshare, deal_reshare, lagrange_interpolate_at_zero, main_golden,
    verify_dealer_message, verify_dealer_messages, DealerMessageRef, DealerProofRef,
    DealerProofSystem, DkgConfig, DkgGroup,
    DkgInstanceKind::{Random, Reshare, Zero},
    DkgOutput, DkgPublicOutput, Error, OwnDealing, ParticipantIndex, ParticipantRegistry,
    ResharePredecessor, SessionId, Share,
};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::{CryptoRng, RngCore};
use std::sync::Mutex;

fn participant(index: u32) -> ParticipantIndex {
    ParticipantIndex::new(index).unwrap()
}
/// Predecessor identity credential, reused as the reshare dealer credential.
fn dealer_credential<G: DkgGroup>(index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(u64::from(index.get()) + 10)
}
/// Reshare receiver credential, distinct from every dealer credential.
fn receiver_credential<G: DkgGroup>(index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(u64::from(index.get()) + 200)
}
fn registry<G: DkgGroup>(
    indexes: impl IntoIterator<Item = u32>,
    credential: fn(ParticipantIndex) -> G::Scalar,
) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        indexes
            .into_iter()
            .map(|index| {
                let id = participant(index);
                (id, G::mul_generator(&credential(id)))
            })
            .collect(),
    )
    .unwrap()
}
fn board<G: DkgGroup>(own: &[OwnDealing<G>]) -> Vec<DealerMessageRef<'_>> {
    own.iter()
        .map(|dealing| DealerMessageRef {
            expected_dealer: dealing.participant(),
            bytes: dealing.broadcast_bytes(),
        })
        .collect()
}
/// `[Reshare, Zero]` from predecessor dealers 1 and 3 to `receivers`, tolerating
/// `threshold - 1` corrupt receivers.
fn reshare_config<G: DkgGroup>(
    predecessor: ResharePredecessor<G>,
    receivers: &[u32],
    threshold: usize,
) -> DkgConfig<G> {
    DkgConfig::new_reshare(
        threshold,
        threshold - 1,
        SessionId([71; 32]),
        registry([1, 3], dealer_credential::<G>),
        registry(receivers.iter().copied(), receiver_credential::<G>),
        predecessor,
        vec![Reshare, Zero],
    )
    .unwrap()
}

/// Threshold-2 key set of committee `1..=3` on the line `5 + 7x`.
fn known_predecessor<G: DkgGroup>() -> ResharePredecessor<G> {
    let point = |x: u32| G::mul_generator(&G::Scalar::from(5 + 7 * u64::from(x)));
    ResharePredecessor::new(
        2,
        point(0),
        (1..=3)
            .map(|index| (participant(index), point(index)))
            .collect(),
        [1; 32],
        [2; 32],
    )
    .unwrap()
}

fn reshare_capacity<C: Backend>() {
    let singleton = DkgConfig::new(
        1,
        SessionId([72; 32]),
        registry([1], receiver_credential::<C::Dkg>),
        vec![Random, Zero],
    )
    .unwrap();
    let empty = Prepared::<C>::prepare_for(&singleton).unwrap();
    assert_eq!(empty.capacity, 0);
    for receivers in 1..=4u32 {
        let indexes = (1..=receivers).collect::<Vec<_>>();
        let config = reshare_config::<C::Dkg>(known_predecessor(), &indexes, 1);
        let plain = DkgConfig::new(
            1,
            SessionId([73; 32]),
            registry(1..=receivers + 1, receiver_credential::<C::Dkg>),
            vec![Random, Zero],
        )
        .unwrap();
        let count = indexes.len();
        assert_eq!(config.receiver_count(), count);
        assert_eq!(plain.receiver_count(), count);
        let required = required_capacity::<C>(&config).unwrap();
        assert!(required > 0);
        assert_eq!(
            required,
            multiplier_count::<C>(2 * count)
                .unwrap()
                .next_power_of_two()
        );
        assert_eq!(required, required_capacity::<C>(&plain).unwrap());
        let insufficient = Err(Error::InsufficientProofCapacity {
            required,
            available: 0,
        });
        assert_eq!(empty.check_capacity(&config), insufficient);
        assert_eq!(
            crate::driver::verify_batch::<C>(&empty, &config, &[]),
            insufficient
        );
    }
}
#[cfg(feature = "secp-secq")]
#[test]
fn secp_reshare_capacity_counts_every_receiver() {
    reshare_capacity::<crate::outer::secp::SecqCycle>();
}
#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn jubjub_reshare_capacity_counts_every_receiver() {
    reshare_capacity::<crate::outer::cycle::Bls12_381G1Cycle>();
}

/// Reshare the line `5 + 7x` from dealers 1 and 3, holding shares 12 and 26, to receiver 1 alone
/// at threshold 1. Every dealer still proves its single slot per instance, and an empty proof
/// is rejected.
fn single_receiver_reshare<G: DkgGroup, P: DealerProofSystem<G>>(
    capture: &Capture<G, P>,
    config: &DkgConfig<G>,
) -> [OwnDealing<G>; 2] {
    assert_eq!(config.receiver_count(), 1);
    let mut rng = ChaCha20Rng::from_seed([77; 32]);
    let dealings = [1, 3].map(|index| {
        let dealer = participant(index);
        let share = G::Scalar::from(5 + 7 * u64::from(index));
        let identity = dealer_credential::<G>(dealer);
        deal_reshare(capture, config, dealer, &identity, &share, &mut rng).unwrap()
    });
    let board = board(&dealings);
    {
        let captured = capture.proofs.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let empty = captured
            .iter()
            .map(|(statement, _)| DealerProofRef {
                statement,
                proof: &[],
            })
            .collect::<Vec<_>>();
        assert_eq!(
            capture.verify_batch(config, &empty),
            Err(Error::InvalidProof)
        );
        for (statement, proof) in captured.iter() {
            assert!(!proof.is_empty());
            assert_eq!(
                capture.verify(config, statement, &[]),
                Err(Error::InvalidProof)
            );
        }
    }
    verify_dealer_messages(capture, config, &board).unwrap();

    let receiver = participant(1);
    let identity = receiver_credential::<G>(receiver);
    let output = complete_reshare(capture, config, &identity, receiver, &board).unwrap();
    assert_eq!(output.secret_share(0), Some(&G::Scalar::from(5)));
    assert_eq!(output.secret_share(1), Some(&G::Scalar::ZERO));
    dealings
}
/// The receiverless proof bypass is backend-generic driver code, so one backend guards it.
#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn single_receiver_reshare_requires_proofs() {
    let config = reshare_config(known_predecessor(), &[1], 1);
    let capture = Capture {
        inner: crate::BlsJubjubBulletproofs::prepare_for(&config).unwrap(),
        proofs: Mutex::new(Vec::new()),
    };
    single_receiver_reshare(&capture, &config);
}

/// Reshare cases of the real-workflow gate. The restored artifact `small`, of `small_capacity`,
/// serves single-receiver reshares, and `prepare` makes the one artifact for three receivers.
pub(super) fn reshare_cases<G: DkgGroup, P: DealerProofSystem<G>>(
    small: P,
    small_capacity: usize,
    prepare: impl Fn(&DkgConfig<G>) -> (P, Vec<u8>, usize),
) {
    let small = Capture {
        inner: small,
        proofs: Mutex::new(Vec::new()),
    };
    let config = reshare_config(known_predecessor(), &[1], 1);
    let dealings = single_receiver_reshare(&small, &config);
    reject_publicly_valid_mutations(
        &small,
        &config,
        participant(1),
        dealings[0].broadcast_bytes(),
    );
    let large = three_receiver_reshare(&small.inner, small_capacity, prepare);
    forced_zero_share(&large);
}

/// Reshare the line `5 + 7x` from dealers 1 and 3 to receivers 1, 2 and 4, raising the threshold
/// from 2 to 3, on the one artifact from `prepare`. The `small` artifact of `small_capacity`
/// can neither prove nor verify it.
fn three_receiver_reshare<G: DkgGroup, P: DealerProofSystem<G>>(
    small: &P,
    small_capacity: usize,
    prepare: impl Fn(&DkgConfig<G>) -> (P, Vec<u8>, usize),
) -> Capture<G, P> {
    let config = reshare_config(known_predecessor(), &[1, 2, 4], 3);
    assert_eq!(config.receiver_count(), 3);
    let key = *config.predecessor().unwrap().public_key();
    let share = |index: u32| G::Scalar::from(5 + 7 * u64::from(index));
    let (proofs, _, capacity) = prepare(&config);
    assert!(small_capacity < capacity);
    let insufficient = Error::InsufficientProofCapacity {
        required: capacity,
        available: small_capacity,
    };
    let mut rng = ChaCha20Rng::from_seed([76; 32]);
    let one = participant(1);
    let small_dealing = deal_reshare(
        small,
        &config,
        one,
        &dealer_credential::<G>(one),
        &share(1),
        &mut rng,
    );
    assert_eq!(small_dealing.unwrap_err(), insufficient);

    let capture = Capture {
        inner: proofs,
        proofs: Mutex::new(Vec::new()),
    };
    let dealings = [1, 3].map(|index| {
        let dealer = participant(index);
        let identity = dealer_credential::<G>(dealer);
        let share = share(index);
        deal_reshare(&capture, &config, dealer, &identity, &share, &mut rng).unwrap()
    });
    let board = board(&dealings);
    {
        let captured = capture.proofs.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let batch = captured
            .iter()
            .map(|(statement, proof)| DealerProofRef { statement, proof })
            .collect::<Vec<_>>();
        capture.verify_batch(&config, &batch).unwrap();
        for (statement, proof) in captured.iter() {
            for instance in statement.instances() {
                let receivers = instance.receivers().map(|receiver| receiver.participant());
                assert!(receivers.eq(config.registry().indexes()));
            }
            capture.verify(&config, statement, proof).unwrap();
            assert_eq!(
                small.verify(&config, statement, proof),
                Err(insufficient.clone())
            );
        }
    }
    assert_eq!(
        verify_dealer_messages(small, &config, &board),
        Err(insufficient)
    );
    verify_dealer_messages(&capture, &config, &board).unwrap();
    for item in &board {
        verify_dealer_message(&capture, &config, item.expected_dealer, item.bytes).unwrap();
    }

    let public = aggregate_public(&capture, &config, &board).unwrap();
    assert_eq!(*public.instance(0).unwrap().public_key(), key);
    assert!(bool::from(
        public.instance(1).unwrap().public_key().is_identity()
    ));
    let mut reshared = Vec::new();
    let mut zero = Vec::new();
    for receiver in config.registry().indexes() {
        let identity = receiver_credential::<G>(receiver);
        let output = complete_reshare(&capture, &config, &identity, receiver, &board).unwrap();
        assert_eq!(output.completion_root(), public.completion_root());
        for position in 0..config.instances().len() {
            assert_eq!(
                G::mul_generator(output.secret_share(position).unwrap()),
                *public
                    .instance(position)
                    .unwrap()
                    .public_key_share(receiver)
                    .unwrap(),
            );
        }
        reshared.push(Share::new(receiver, *output.secret_share(0).unwrap()));
        zero.push(Share::new(receiver, *output.secret_share(1).unwrap()));
    }
    assert_eq!(lagrange_interpolate_at_zero(&reshared).unwrap(), share(0));
    assert!(bool::from(
        lagrange_interpolate_at_zero(&zero).unwrap().is_zero()
    ));

    reject_publicly_valid_mutations(&capture, &config, one, dealings[0].broadcast_bytes());
    reject_tampered_dealer(&capture, &config, &board);
    capture
}

/// With honest dealer 1 on the board, a publicly valid change to dealer 3's nonce is named at
/// the proof boundary.
fn reject_tampered_dealer<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    board: &[DealerMessageRef<'_>],
) {
    let three = participant(3);
    assert_eq!(board.len(), 2);
    let (honest, dealer) = (board[0], board[1]);
    assert_eq!(dealer.expected_dealer, three);
    let receiver = participant(4);
    let identity = receiver_credential::<G>(receiver);

    let mut forged = dealer.bytes.to_vec();
    forged[WIRE_HEADER] ^= 1;
    let tampered = [
        honest,
        DealerMessageRef {
            expected_dealer: three,
            bytes: &forged,
        },
    ];
    let invalid = Some(Error::InvalidDealerProofs {
        dealers: vec![three],
    });
    assert_eq!(
        verify_dealer_messages(proofs, config, &tampered).err(),
        invalid
    );
    assert_eq!(
        complete_reshare(proofs, config, &identity, receiver, &tampered).err(),
        invalid
    );
}

/// Serves `chosen` as the first 64-byte wide scalar sample and fresh randomness otherwise, so a
/// corrupt dealer picks the first sampled coefficient of its polynomial.
struct ChosenScalar<F> {
    chosen: Option<F>,
    rest: ChaCha20Rng,
}
impl<F: PrimeField> RngCore for ChosenScalar<F> {
    fn next_u32(&mut self) -> u32 {
        self.rest.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.rest.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        if bytes.len() == 64 {
            if let Some(scalar) = self.chosen.take() {
                let repr = scalar.to_repr();
                bytes.fill(0);
                bytes[..repr.as_ref().len()].copy_from_slice(repr.as_ref());
                return;
            }
        }
        self.rest.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl<F: PrimeField> CryptoRng for ChosenScalar<F> {}

/// Every receiver's completion of the threshold-2 reshare `board`. The board verifies, the
/// predecessor key is kept, each output opens its public shares, every pair of shares
/// reconstructs `secret`, and the restored public output is a predecessor.
fn complete_every_receiver<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    board: &[DealerMessageRef<'_>],
    secret: G::Scalar,
) -> (ResharePredecessor<G>, Vec<DkgOutput<G>>) {
    assert_eq!(config.threshold(), 2);
    verify_dealer_messages(proofs, config, board).unwrap();
    let public = aggregate_public(proofs, config, board).unwrap();
    let key = config.predecessor().unwrap().public_key();
    assert_eq!(public.instance(0).unwrap().public_key(), key);
    let outputs = config
        .registry()
        .indexes()
        .map(|receiver| {
            let identity = receiver_credential::<G>(receiver);
            let output = complete_reshare(proofs, config, &identity, receiver, board).unwrap();
            assert_eq!(output.completion_root(), public.completion_root());
            assert_eq!(
                G::mul_generator(output.secret_share(0).unwrap()),
                *public
                    .instance(0)
                    .unwrap()
                    .public_key_share(receiver)
                    .unwrap(),
            );
            output
        })
        .collect::<Vec<_>>();
    for (index, first) in outputs.iter().enumerate() {
        for second in &outputs[index + 1..] {
            let pair = [first, second]
                .map(|output| Share::new(output.participant(), *output.secret_share(0).unwrap()));
            assert_eq!(lagrange_interpolate_at_zero(&pair).unwrap(), secret);
        }
    }
    let restored = DkgPublicOutput::from_bytes(config, &public.to_bytes().unwrap()).unwrap();
    assert_eq!(restored.completion_root(), public.completion_root());
    let predecessor = ResharePredecessor::from_output(config, &restored, 0).unwrap();
    assert_eq!(predecessor.public_key(), key);
    (predecessor, outputs)
}

/// Dealers 1 and 2, with weights 2 and -1 at zero, reshare the line `5 + 7x` to receivers 1, 2
/// and 3 at threshold 2. Corrupt dealer 2, rushing with corrupt receiver 1, picks
/// `f_2(1) = 2·f_1(1)`, so receiver 1's share is zero and its public share the identity. The
/// output is a predecessor and seeds a reshare from receivers 1 and 3, in which receiver 1 deals
/// its zero share under an identity pinned constant.
fn forced_zero_share<G: DkgGroup, P: DealerProofSystem<G>>(capture: &Capture<G, P>) {
    let config = DkgConfig::new_reshare(
        2,
        1,
        SessionId([78; 32]),
        registry([1, 2], dealer_credential::<G>),
        registry([1, 2, 3], receiver_credential::<G>),
        known_predecessor(),
        vec![Reshare, Zero],
    )
    .unwrap();
    let share = |index: u64| G::Scalar::from(5 + 7 * index);
    let (one, two) = (participant(1), participant(2));
    let mut rng = ChaCha20Rng::from_seed([78; 32]);
    let honest = deal_reshare(
        capture,
        &config,
        one,
        &dealer_credential::<G>(one),
        &share(1),
        &mut rng,
    )
    .unwrap();
    let received = {
        let captured = capture.proofs.lock().unwrap();
        let (statement, _) = captured.last().unwrap();
        let instance = statement.instance(0).unwrap();
        let slot = instance
            .receivers()
            .find(|slot| slot.participant() == one)
            .unwrap();
        let pad = main_golden::receiver_pad::<G>(
            instance.effective_message(),
            &receiver_credential::<G>(one),
            statement.dealer_public_key(),
        )
        .unwrap();
        let received = *slot.encrypted_share() - pad;
        assert_eq!(G::mul_generator(&received), *slot.share_commitment());
        received
    };
    let slope = received.double() - share(2);
    let mut chosen = ChosenScalar {
        chosen: Some(slope),
        rest: ChaCha20Rng::from_seed([79; 32]),
    };
    let corrupt = deal_reshare(
        capture,
        &config,
        two,
        &dealer_credential::<G>(two),
        &share(2),
        &mut chosen,
    )
    .unwrap();
    let dealings = [honest, corrupt];
    let secret = share(0);
    let (predecessor, outputs) =
        complete_every_receiver(capture, &config, &board(&dealings), secret);
    assert_eq!(outputs[0].participant(), one);
    assert_eq!(outputs[0].secret_share(0), Some(&G::Scalar::ZERO));
    assert!(bool::from(
        predecessor.public_key_share(one).unwrap().is_identity()
    ));

    let next = reshare_config(predecessor, &[1, 2, 3], 2);
    let pinned = next.predecessor().unwrap().public_key_share(one).unwrap();
    assert!(bool::from(pinned.is_identity()));
    let mut rng = ChaCha20Rng::from_seed([80; 32]);
    let dealings = [&outputs[0], &outputs[2]].map(|output| {
        let dealer = output.participant();
        let identity = dealer_credential::<G>(dealer);
        let share = output.secret_share(0).unwrap();
        deal_reshare(capture, &next, dealer, &identity, share, &mut rng).unwrap()
    });
    complete_every_receiver(capture, &next, &board(&dealings), secret);
}
