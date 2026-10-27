//! Committees, proof capture and completed sharings for the reshare tests.

use ff::{Field, PrimeField};
use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, complete_reshare, deal, deal_reshare, lagrange_interpolate_at_zero,
    main_golden, reconstruct_secret, DealerMessageRef, DealerProofStatement, DealerProofSystem,
    DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Reshare, Zero},
    DkgOutput, DkgPublicOutput, OwnDealing, ParticipantIndex, ParticipantRegistry,
    ResharePredecessor, Result, SessionId, Share,
};
use group::Group;
use rand_chacha::{
    rand_core::{CryptoRng, CryptoRngCore, RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

pub(crate) const PROOFS: InsecureRevealedWitnessProof = InsecureRevealedWitnessProof;

pub(crate) fn participant(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}
/// Identity credential of member `index` of committee generation `generation`. Every member
/// holds a distinct key per generation, so a member of both committees of one reshare deals
/// and receives under different keys.
pub(crate) fn credential<G: DkgGroup>(generation: u64, index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(1000 * generation + u64::from(index.get()) + 10)
}
fn registry<G: DkgGroup>(generation: u64, indexes: &[u32]) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        indexes
            .iter()
            .map(|index| {
                let id = participant(*index);
                (id, G::mul_generator(&credential::<G>(generation, id)))
            })
            .collect(),
    )
    .unwrap()
}
pub(crate) fn board<G: DkgGroup>(own: &[OwnDealing<G>]) -> Vec<DealerMessageRef<'_>> {
    own.iter()
        .map(|dealing| DealerMessageRef {
            expected_dealer: dealing.participant(),
            bytes: dealing.broadcast_bytes(),
        })
        .collect()
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

/// Delegates to the insecure proof and records every proven statement.
pub(crate) struct Capture<G: DkgGroup>(pub(crate) Mutex<Vec<DealerProofStatement<G>>>);
impl<G: DkgGroup> DealerProofSystem<G> for Capture<G> {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.0.lock().unwrap().push(statement.clone());
        PROOFS.prove(config, statement, witness, rng)
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        PROOFS.verify(config, statement, proof)
    }
}
/// `receiver`'s share in the instance at `position` of a captured dealing, decrypted with
/// `receiver`'s credential.
pub(crate) fn decrypt<G: DkgGroup>(
    statement: &DealerProofStatement<G>,
    position: usize,
    receiver: ParticipantIndex,
    identity_secret: &G::Scalar,
) -> G::Scalar {
    let instance = statement.instance(position).unwrap();
    let slot = instance
        .receivers()
        .find(|slot| slot.participant() == receiver)
        .unwrap();
    let pad = main_golden::receiver_pad::<G>(
        instance.effective_message(),
        identity_secret,
        statement.dealer_public_key(),
    )
    .unwrap();
    let share = *slot.encrypted_share() - pad;
    assert_eq!(G::mul_generator(&share), *slot.share_commitment());
    share
}

/// Serves each queued scalar as the next 64-byte wide scalar sample and fresh randomness
/// otherwise, so a corrupt dealer chooses its polynomial coefficients.
pub(crate) struct ChosenScalars<F> {
    queued: VecDeque<F>,
    rest: ChaCha20Rng,
}
impl<F: PrimeField> ChosenScalars<F> {
    pub(crate) fn new(scalars: Vec<F>, seed: u8) -> Self {
        Self {
            queued: scalars.into(),
            rest: ChaCha20Rng::from_seed([seed; 32]),
        }
    }
}
impl<F: PrimeField> RngCore for ChosenScalars<F> {
    fn next_u32(&mut self) -> u32 {
        self.rest.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.rest.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        if bytes.len() == 64 {
            if let Some(scalar) = self.queued.pop_front() {
                let repr = scalar.to_repr();
                bytes.fill(0);
                bytes[..repr.as_ref().len()].copy_from_slice(repr.as_ref());
                return;
            }
        }
        self.rest.fill_bytes(bytes);
    }
    fn try_fill_bytes(
        &mut self,
        bytes: &mut [u8],
    ) -> core::result::Result<(), rand_chacha::rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl<F: PrimeField> CryptoRng for ChosenScalars<F> {}

/// One completed sharing of a group key: its configuration, dealings, public result and every
/// share holder's local output, all of committee generation `number`.
pub(crate) struct Generation<G: DkgGroup> {
    pub(crate) number: u64,
    pub(crate) config: DkgConfig<G>,
    pub(crate) own: Vec<OwnDealing<G>>,
    pub(crate) public: DkgPublicOutput<G>,
    pub(crate) outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
}
impl<G: DkgGroup> Generation<G> {
    /// Every share holder's completion of `config` from the dealings `own`.
    pub(crate) fn complete(number: u64, config: DkgConfig<G>, own: Vec<OwnDealing<G>>) -> Self {
        let board = board(&own);
        let public = aggregate_public(&PROOFS, &config, &board).unwrap();
        let outputs = config
            .registry()
            .indexes()
            .map(|holder| {
                let identity = credential::<G>(number, holder);
                let output = if config.predecessor().is_some() {
                    complete_reshare(&PROOFS, &config, &identity, holder, &board)
                } else {
                    let dealing = own.iter().find(|own| own.participant() == holder);
                    let peers: Vec<_> = board
                        .iter()
                        .copied()
                        .filter(|item| item.expected_dealer != holder)
                        .collect();
                    complete(&PROOFS, &config, &identity, dealing.unwrap(), &peers)
                };
                (holder, output.unwrap())
            })
            .collect();
        Self {
            number,
            config,
            own,
            public,
            outputs,
        }
    }
    /// The plain `[Random, Zero]` configuration of generation zero among `indexes`.
    pub(crate) fn plain_config(indexes: &[u32], threshold: usize, seed: u8) -> DkgConfig<G> {
        DkgConfig::new(
            threshold,
            SessionId([seed; 32]),
            registry(0, indexes),
            vec![Random, Zero],
        )
        .unwrap()
    }
    /// An honest plain `[Random, Zero]` DKG among `indexes`.
    pub(crate) fn plain(indexes: &[u32], threshold: usize, seed: u8) -> Self {
        let config = Self::plain_config(indexes, threshold, seed);
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let own = config
            .registry()
            .indexes()
            .map(|id| deal(&PROOFS, &config, id, &credential::<G>(0, id), &mut rng).unwrap())
            .collect();
        Self::complete(0, config, own)
    }
    /// Position of the column holding the group key.
    pub(crate) fn column(&self) -> usize {
        self.config
            .instances()
            .iter()
            .position(|kind| matches!(*kind, Random | Reshare))
            .unwrap()
    }
    pub(crate) fn key(&self) -> G::Point {
        *self.public.instance(self.column()).unwrap().public_key()
    }
    pub(crate) fn public_share(&self, holder: u32) -> G::Point {
        *self
            .public
            .instance(self.column())
            .unwrap()
            .public_key_share(participant(holder))
            .unwrap()
    }
    /// `holder`'s share of the group key.
    pub(crate) fn share(&self, holder: ParticipantIndex) -> G::Scalar {
        *self.outputs[&holder].secret_share(self.column()).unwrap()
    }
    /// The group secret, interpolated from the first threshold holders' shares.
    pub(crate) fn secret(&self) -> G::Scalar {
        let shares: Vec<_> = self
            .outputs
            .keys()
            .take(self.config.threshold())
            .map(|holder| Share::new(*holder, self.share(*holder)))
            .collect();
        reconstruct_secret(&shares, self.config.threshold()).unwrap()
    }
    /// The group key's predecessor, derived from the restored public output.
    pub(crate) fn predecessor(&self) -> ResharePredecessor<G> {
        let restored =
            DkgPublicOutput::from_bytes(&self.config, &self.public.to_bytes().unwrap()).unwrap();
        ResharePredecessor::from_output(&self.config, &restored, self.column()).unwrap()
    }
    /// Reshare from this generation's `dealers` to the next generation's `receivers`,
    /// tolerating `threshold - 1` corrupt receivers.
    pub(crate) fn reshare_config(
        &self,
        dealers: &[u32],
        receivers: &[u32],
        threshold: usize,
        instances: Vec<DkgInstanceKind>,
    ) -> DkgConfig<G> {
        let session = u8::try_from(self.number).unwrap() + 100;
        self.reshare_config_in(session, dealers, receivers, threshold, instances)
    }
    /// [`Self::reshare_config`] under session `[session; 32]`.
    pub(crate) fn reshare_config_in(
        &self,
        session: u8,
        dealers: &[u32],
        receivers: &[u32],
        threshold: usize,
        instances: Vec<DkgInstanceKind>,
    ) -> DkgConfig<G> {
        DkgConfig::new_reshare(
            threshold,
            threshold - 1,
            SessionId([session; 32]),
            registry(self.number, dealers),
            registry(self.number + 1, receivers),
            self.predecessor(),
            instances,
        )
        .unwrap()
    }
    /// The dealing of reshare `config` by `dealer` with its share of the group key.
    pub(crate) fn dealing(
        &self,
        proofs: &impl DealerProofSystem<G>,
        config: &DkgConfig<G>,
        dealer: u32,
        rng: &mut impl CryptoRngCore,
    ) -> OwnDealing<G> {
        let dealer = participant(dealer);
        let identity = credential::<G>(self.number, dealer);
        deal_reshare(proofs, config, dealer, &identity, &self.share(dealer), rng).unwrap()
    }
    /// Every declared dealer's dealing of reshare `config`, in index order.
    pub(crate) fn dealings(
        &self,
        proofs: &impl DealerProofSystem<G>,
        config: &DkgConfig<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<OwnDealing<G>> {
        config
            .dealers()
            .indexes()
            .map(|dealer| self.dealing(proofs, config, dealer.get(), rng))
            .collect()
    }
    /// Every declared dealer's honest dealing of `config`, completed by every receiver.
    pub(crate) fn reshare(&self, config: DkgConfig<G>, seed: u8) -> Self {
        let own = self.dealings(&PROOFS, &config, &mut ChaCha20Rng::from_seed([seed; 32]));
        Self::complete(self.number + 1, config, own)
    }
}

/// Check `next`, a reshare of `previous`: it keeps the group key, its public output restores
/// and is a valid predecessor, every receiver's output equals the public aggregation and
/// restores, its shares open their public shares, every threshold subset of `Reshare` shares
/// reconstructs `previous`'s secret under its key, and every `Zero` column shares zero under
/// the identity. One share fewer than the threshold reconstructs neither.
pub(crate) fn check_reshare<G: DkgGroup>(previous: &Generation<G>, next: &Generation<G>) {
    let secret = previous.secret();
    assert_eq!(G::mul_generator(&secret), previous.key());
    assert_eq!(next.key(), previous.key());
    let public_state = next.public.to_bytes().unwrap();
    let restored = DkgPublicOutput::from_bytes(&next.config, &public_state).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), public_state);
    assert_eq!(restored.completion_root(), next.public.completion_root());
    ResharePredecessor::from_output(&next.config, &restored, next.column()).unwrap();
    assert!(next
        .outputs
        .keys()
        .copied()
        .eq(next.config.registry().indexes()));
    for (receiver, output) in &next.outputs {
        assert_eq!(output.participant(), *receiver);
        assert_eq!(output.config_root(), next.config.root());
        assert_eq!(output.completion_root(), next.public.completion_root());
        assert_eq!(output.public().to_bytes().unwrap(), public_state);
        let restored =
            DkgOutput::from_bytes(&next.config, *receiver, &output.to_bytes().unwrap()).unwrap();
        for (position, instance) in next.public.instances().enumerate() {
            let share = output.secret_share(position).unwrap();
            assert_eq!(
                Some(&G::mul_generator(share)),
                instance.public_key_share(*receiver)
            );
            assert_eq!(restored.secret_share(position), Some(share));
        }
    }
    let holders: Vec<_> = next.outputs.keys().copied().collect();
    let threshold = next.config.threshold();
    for (position, kind) in next.config.instances().iter().enumerate() {
        let (key, expected) = if *kind == Reshare {
            (previous.key(), secret)
        } else {
            (G::Point::identity(), G::Scalar::ZERO)
        };
        assert_eq!(*next.public.instance(position).unwrap().public_key(), key);
        let shares = |subset: &[ParticipantIndex]| -> Vec<_> {
            subset
                .iter()
                .map(|holder| {
                    Share::new(
                        *holder,
                        *next.outputs[holder].secret_share(position).unwrap(),
                    )
                })
                .collect()
        };
        for subset in subsets(&holders, threshold) {
            assert_eq!(
                reconstruct_secret(&shares(&subset), threshold).unwrap(),
                expected
            );
        }
        if threshold > 1 {
            for subset in subsets(&holders, threshold - 1) {
                assert_ne!(
                    lagrange_interpolate_at_zero(&shares(&subset)).unwrap(),
                    expected
                );
            }
        }
    }
}
