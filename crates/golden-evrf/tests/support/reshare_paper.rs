//! Real-proof reshares shared by the Secp/Secq and BLS12-381/Jubjub suites.
//!
//! Every reshare preserves the threshold-2 key set of committee `1..=3` on the
//! line `5 + 7x`, so the group secret is 5 and old member i holds `5 + 7i`.

use std::collections::BTreeMap;

use golden_core::{
    aggregate_reshare_public, complete_reshare, create_reshare_dealing,
    lagrange_interpolate_at_zero, verify_reshare_dealing, verify_reshare_dealing_for_receiver,
    verify_reshare_dealings, DealerMessage, DkgOutput, Error, EvrfProofBackend, FeldmanCommitment,
    GoldenGroup, GoldenScalar, IdentityKeyProof, ParticipantIndex, ParticipantRegistry,
    ReshareConfig, ResharePredecessor, Result, SessionId, Share,
};
use rand_chacha::{
    rand_core::{CryptoRng, Error as RandError, RngCore, SeedableRng},
    ChaCha20Rng,
};

type Board<G> = BTreeMap<ParticipantIndex, DealerMessage<G>>;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn scalar<G: GoldenGroup>(value: u64) -> G::Scalar {
    G::Scalar::from_u64(value).unwrap()
}

/// Share of old member `index` on the line `5 + 7x`; index 0 is the secret.
fn line<G: GoldenGroup>(index: u32) -> G::Scalar {
    scalar::<G>(5 + 7 * u64::from(index))
}

/// Identity secret of member `index` of committee generation `generation`.
fn credential<G: GoldenGroup>(generation: u64, index: ParticipantIndex) -> G::Scalar {
    scalar::<G>(1000 * generation + u64::from(index.get()) + 10)
}

fn registry<G: GoldenGroup>(generation: u64, indexes: &[u32]) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        indexes
            .iter()
            .map(|index| {
                let secret = credential::<G>(generation, idx(*index));
                (
                    idx(*index),
                    G::mul_generator(&secret),
                    IdentityKeyProof::prove(&secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}

/// Threshold-2 key set of committee `1..=3` on the line `5 + 7x`.
fn known_predecessor<G: GoldenGroup>() -> ResharePredecessor<G> {
    ResharePredecessor::new(
        2,
        G::mul_generator(&line::<G>(0)),
        (1..=3)
            .map(|index| (idx(index), G::mul_generator(&line::<G>(index))))
            .collect(),
        [1; 32],
    )
    .unwrap()
}

/// Reshare `predecessor` from generation `generation`'s `dealers` to the next
/// generation's `receivers`.
fn reshare_config<G: GoldenGroup>(
    predecessor: ResharePredecessor<G>,
    generation: u64,
    dealers: &[u32],
    receivers: &[u32],
    threshold: usize,
    max_corrupt_receivers: usize,
    session: u8,
) -> ReshareConfig<G> {
    ReshareConfig::new(
        threshold,
        max_corrupt_receivers,
        SessionId([session; 32]),
        scalar::<G>(77),
        registry(generation, dealers),
        registry(generation + 1, receivers),
        predecessor,
    )
    .unwrap()
}

fn deal<G, B>(
    config: &ReshareConfig<G>,
    generation: u64,
    share: &Share<G::Scalar>,
    rng: &mut (impl RngCore + CryptoRng),
) -> DealerMessage<G>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let dealer = share.participant;
    create_reshare_dealing::<G, B>(
        dealer,
        &credential::<G>(generation, dealer),
        share,
        config,
        rng,
    )
    .unwrap()
}

fn messages<G: GoldenGroup>(board: &Board<G>) -> Vec<&DealerMessage<G>> {
    board.values().collect()
}

/// Every `size`-element subset of `items`, in order.
fn subsets<T: Clone>(items: &[T], size: usize) -> Vec<Vec<T>> {
    (0u32..1 << items.len())
        .filter(|mask| mask.count_ones() as usize == size)
        .map(|mask| {
            items
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask >> bit & 1 == 1)
                .map(|(_, item)| item.clone())
                .collect()
        })
        .collect()
}

/// Every receiver's completion of `board`, holding generation `generation`'s
/// keys. The board verifies, every output equals the public aggregation and
/// opens its public share, and every threshold subset of shares reconstructs
/// `secret` while one share fewer does not.
fn complete_every_receiver<G, B>(
    config: &ReshareConfig<G>,
    generation: u64,
    board: &Board<G>,
    secret: &G::Scalar,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    verify_reshare_dealings::<G, B>(&messages(board), config).unwrap();
    let public = aggregate_reshare_public::<G, B>(board, config).unwrap();
    assert_eq!(&public.public_key, config.predecessor().public_key());
    let outputs: BTreeMap<_, _> = config
        .receivers()
        .indexes()
        .map(|receiver| {
            let output = complete_reshare::<G, B>(
                receiver,
                &credential::<G>(generation, receiver),
                board,
                config,
            )
            .unwrap();
            (receiver, output)
        })
        .collect();
    for (receiver, output) in &outputs {
        assert_eq!(output.public_key, public.public_key);
        assert_eq!(output.public_key_shares, public.public_key_shares);
        assert_eq!(output.transcript_root, public.transcript_root);
        assert_eq!(
            public.public_key_shares[receiver],
            G::mul_generator(&output.secret_share.value)
        );
    }
    let shares: Vec<_> = outputs
        .values()
        .map(|output| output.secret_share.clone())
        .collect();
    let threshold = config.threshold();
    for subset in subsets(&shares, threshold) {
        assert_eq!(&lagrange_interpolate_at_zero(&subset).unwrap(), secret);
    }
    if threshold > 1 {
        for subset in subsets(&shares, threshold - 1) {
            assert_ne!(&lagrange_interpolate_at_zero(&subset).unwrap(), secret);
        }
    }
    outputs
}

/// Changes to `message` that pass every public check are rejected by the
/// proof, and a changed pinned constant is rejected before it.
fn reject_publicly_valid_mutations<G, B>(config: &ReshareConfig<G>, message: &DealerMessage<G>)
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    verify_reshare_dealing::<G, B>(message, config).unwrap();
    let mut mutations = Vec::new();

    let mut nonce = message.clone();
    nonce.msg_i.0[0] ^= 1;
    mutations.push(("nonce", nonce));

    let mut paired = message.clone();
    let encrypted = paired.encrypted_shares.values_mut().next().unwrap();
    let delta = scalar::<G>(1);
    encrypted.pad_commitment = G::add(&encrypted.pad_commitment, &G::mul_generator(&delta));
    encrypted.encrypted_share = encrypted.encrypted_share.add(&delta);
    mutations.push(("paired pad/ciphertext", paired));

    // Adding g to A_k adds j^k to receiver j's Feldman evaluation; shifting
    // each ciphertext by the same amount keeps the public equation.
    let degree = message.commitment.coefficients().len() - 1;
    if degree > 0 {
        let mut shifted = message.clone();
        let mut coefficients = shifted.commitment.coefficients().to_vec();
        coefficients[degree] = G::add(&coefficients[degree], &G::generator());
        shifted.commitment = FeldmanCommitment::from_coefficients(coefficients).unwrap();
        for (receiver, encrypted) in &mut shifted.encrypted_shares {
            let step = u64::from(receiver.get()).pow(u32::try_from(degree).unwrap());
            encrypted.encrypted_share = encrypted.encrypted_share.add(&scalar::<G>(step));
        }
        mutations.push(("top coefficient/ciphertexts", shifted));
    }

    for (name, mut mutated) in mutations {
        mutated.transcript_root = mutated.recompute_transcript_root();
        assert_eq!(
            verify_reshare_dealing::<G, B>(&mutated, config),
            Err(Error::ProofVerificationFailed),
            "{name}"
        );
    }

    let mut proof = message.clone();
    let middle = proof.proof.len() / 2;
    proof.proof[middle] ^= 1;
    assert_eq!(
        verify_reshare_dealing::<G, B>(&proof, config),
        Err(Error::ProofVerificationFailed)
    );

    let mut constant = message.clone();
    let mut coefficients = constant.commitment.coefficients().to_vec();
    coefficients[0] = G::add(&coefficients[0], &G::generator());
    constant.commitment = FeldmanCommitment::from_coefficients(coefficients).unwrap();
    constant.transcript_root = constant.recompute_transcript_root();
    assert_eq!(
        verify_reshare_dealing::<G, B>(&constant, config),
        Err(Error::ReshareConstantMismatch(message.dealer.get()))
    );
}

/// Reshare dealers 1 and 3 to receiver 1 alone at threshold 1. Every dealing
/// still proves its single slot, and an empty proof is rejected.
pub fn single_receiver_reshare_requires_proofs<G, B>()
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let config = reshare_config(known_predecessor::<G>(), 0, &[1, 3], &[1], 1, 0, 71);
    let mut rng = ChaCha20Rng::from_seed([71; 32]);
    let board: Board<G> = [1, 3]
        .map(|index| {
            let share = Share {
                participant: idx(index),
                value: line::<G>(index),
            };
            (idx(index), deal::<G, B>(&config, 0, &share, &mut rng))
        })
        .into_iter()
        .collect();

    for message in board.values() {
        assert!(!message.proof.is_empty());
        assert_eq!(message.encrypted_shares.len(), 1);
        verify_reshare_dealing::<G, B>(message, &config).unwrap();
        verify_reshare_dealing_for_receiver::<G, B>(
            idx(1),
            &credential::<G>(1, idx(1)),
            message,
            &config,
        )
        .unwrap();
        let mut empty = message.clone();
        empty.proof.clear();
        assert_eq!(
            verify_reshare_dealing::<G, B>(&empty, &config),
            Err(Error::ProofVerificationFailed)
        );
    }
    let mut empty = board.clone();
    empty.get_mut(&idx(3)).unwrap().proof.clear();
    assert_eq!(
        verify_reshare_dealings::<G, B>(&messages(&empty), &config),
        Err(Error::DealerProofVerificationFailed(3))
    );

    let outputs = complete_every_receiver::<G, B>(&config, 1, &board, &line::<G>(0));
    assert_eq!(outputs[&idx(1)].secret_share.value, line::<G>(0));
    reject_publicly_valid_mutations::<G, B>(&config, &board[&idx(1)]);
}

/// Reshare dealers 1 and 3 to receivers 1, 2 and 4, raising the threshold
/// from 2 to 3. Every proof has the reshare shape (t_new, n_new) = (3, 3),
/// whose wire length `wire_len` gives.
pub fn three_receiver_reshare_raises_the_threshold<G, B>(
    wire_len: fn(usize, usize) -> Result<usize>,
) where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let config = reshare_config(known_predecessor::<G>(), 0, &[1, 3], &[1, 2, 4], 3, 0, 76);
    let mut rng = ChaCha20Rng::from_seed([76; 32]);
    let board: Board<G> = [1, 3]
        .map(|index| {
            let share = Share {
                participant: idx(index),
                value: line::<G>(index),
            };
            (idx(index), deal::<G, B>(&config, 0, &share, &mut rng))
        })
        .into_iter()
        .collect();

    let reshare_shape = wire_len(config.threshold(), config.receivers().len()).unwrap();
    for message in board.values() {
        assert_eq!(message.proof.len(), reshare_shape);
        assert_eq!(message.commitment.coefficients().len(), 3);
        assert!(message
            .encrypted_shares
            .keys()
            .copied()
            .eq(config.receivers().indexes()));
        verify_reshare_dealing::<G, B>(message, &config).unwrap();
        for receiver in config.receivers().indexes() {
            verify_reshare_dealing_for_receiver::<G, B>(
                receiver,
                &credential::<G>(1, receiver),
                message,
                &config,
            )
            .unwrap();
        }
    }
    complete_every_receiver::<G, B>(&config, 1, &board, &line::<G>(0));
    reject_publicly_valid_mutations::<G, B>(&config, &board[&idx(1)]);

    let mut tampered = board.clone();
    let forged = tampered.get_mut(&idx(3)).unwrap();
    forged.msg_i.0[0] ^= 1;
    forged.transcript_root = forged.recompute_transcript_root();
    let blame = Error::DealerProofVerificationFailed(3);
    assert_eq!(
        verify_reshare_dealings::<G, B>(&messages(&tampered), &config),
        Err(blame.clone())
    );
    assert_eq!(
        complete_reshare::<G, B>(idx(4), &credential::<G>(1, idx(4)), &tampered, &config)
            .unwrap_err(),
        blame
    );
}

/// Serves `slope`, little-endian, as the first 64-byte sample and `rest`
/// otherwise. Both paper scalar fields sample by reducing 64 little-endian
/// bytes, so a dealer at threshold 2 takes `slope` as its linear coefficient.
struct ChosenSlope {
    slope: Option<u64>,
    rest: ChaCha20Rng,
}

impl RngCore for ChosenSlope {
    fn next_u32(&mut self) -> u32 {
        self.rest.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rest.next_u64()
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        if bytes.len() == 64 {
            if let Some(slope) = self.slope.take() {
                bytes.fill(0);
                bytes[..8].copy_from_slice(&slope.to_le_bytes());
                return;
            }
        }
        self.rest.fill_bytes(bytes);
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), RandError> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

impl CryptoRng for ChosenSlope {}

/// Dealers 1 and 2, with weights 2 and -1 at zero, reshare the line `5 + 7x`
/// to receivers 1, 2 and 3 at threshold 2. Dealer 1 draws slope 1, so
/// f_1(1) = 13, which corrupt receiver 1 decrypts; corrupt dealer 2 then picks
/// slope 7, so f_2(1) = 26 = 2·f_1(1) and receiver 1's share is zero. The
/// output is a predecessor with an identity public share, and seeds a reshare
/// from receivers 1 and 3 in which receiver 1 deals its zero share under an
/// identity pinned constant.
pub fn forced_zero_share_chains<G, B>()
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let config = reshare_config(known_predecessor::<G>(), 0, &[1, 2], &[1, 2, 3], 2, 1, 78);
    let board: Board<G> = [(1, 1, 78), (2, 7, 79)]
        .map(|(index, slope, seed)| {
            let share = Share {
                participant: idx(index),
                value: line::<G>(index),
            };
            let mut rng = ChosenSlope {
                slope: Some(slope),
                rest: ChaCha20Rng::from_seed([seed; 32]),
            };
            let message = deal::<G, B>(&config, 0, &share, &mut rng);
            assert_eq!(
                message.commitment.coefficients()[1],
                G::mul_generator(&scalar::<G>(slope))
            );
            (idx(index), message)
        })
        .into_iter()
        .collect();
    let outputs = complete_every_receiver::<G, B>(&config, 1, &board, &line::<G>(0));
    assert_eq!(outputs[&idx(1)].secret_share.value, G::Scalar::zero());
    let predecessor = ResharePredecessor::from_reshare_output(&config, &outputs[&idx(1)]).unwrap();
    assert!(bool::from(G::is_identity(
        predecessor.public_key_share(idx(1)).unwrap()
    )));

    let next = reshare_config(predecessor, 1, &[1, 3], &[1, 2, 3], 2, 1, 80);
    let mut rng = ChaCha20Rng::from_seed([80; 32]);
    let board: Board<G> = [1, 3]
        .map(|index| {
            let share = &outputs[&idx(index)].secret_share;
            (idx(index), deal::<G, B>(&next, 1, share, &mut rng))
        })
        .into_iter()
        .collect();
    assert!(bool::from(G::is_identity(
        &board[&idx(1)].commitment.coefficients()[0]
    )));
    complete_every_receiver::<G, B>(&next, 2, &board, &line::<G>(0));
}
