//! Immutable configurations and canonical participant registries.
use crate::wire::{count, framed};
use crate::{DkgGroup, Error, ParticipantIndex, Result, TranscriptRoot};
use group::Group;
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};

/// Main Golden protocol version.
pub const PROTOCOL_VERSION: u32 = 3;
/// Dealer nonce/effective-message size.
pub const DEALER_MESSAGE_NONCE_BYTES: usize = 32;
/// Application-agreed replay-protection session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 32]);
impl SessionId {
    /// Generate an independent session identifier.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
/// An independently generated raw instance nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerMessageNonce(pub [u8; 32]);
impl DealerMessageNonce {
    /// Generate an instance nonce.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
/// Core-derived instance message for Main Golden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvrfMessage(pub [u8; 32]);

/// Canonical nonempty mapping from interpolation indexes to identity keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRegistry<G: DkgGroup> {
    participants: BTreeMap<ParticipantIndex, G::Point>,
}
impl<G: DkgGroup> ParticipantRegistry<G> {
    /// Validate indexes, nonidentity keys, and unique canonical key encodings.
    pub fn new(entries: Vec<(ParticipantIndex, G::Point)>) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::EmptyParticipantRegistry);
        }
        u32::try_from(entries.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut participants = BTreeMap::new();
        let mut public_keys = BTreeMap::<Vec<u8>, ParticipantIndex>::new();
        for (participant, key) in entries {
            participant.to_scalar::<G::Scalar>()?;
            if participants.contains_key(&participant) {
                return Err(Error::DuplicateParticipantIndex(participant.get()));
            }
            if bool::from(key.is_identity()) {
                return Err(Error::InvalidEncoding);
            }
            let encoded = G::encode_point(&key);
            if G::decode_point(&encoded)? != key {
                return Err(Error::InvalidEncoding);
            }
            if let Some(first) = public_keys.insert(encoded, participant) {
                return Err(Error::DuplicateParticipantPublicKey {
                    first: first.get(),
                    second: participant.get(),
                });
            }
            participants.insert(participant, key);
        }
        Ok(Self { participants })
    }
    /// Participant count.
    pub fn len(&self) -> usize {
        self.participants.len()
    }
    /// Whether this registry is empty (validated registries are never empty).
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
    /// Registered key.
    pub fn public_key(&self, participant: ParticipantIndex) -> Result<&G::Point> {
        self.participants
            .get(&participant)
            .ok_or(Error::UnknownParticipant(participant.get()))
    }
    /// Canonical participant order.
    pub fn indexes(&self) -> impl ExactSizeIterator<Item = ParticipantIndex> + '_ {
        self.participants.keys().copied()
    }
    /// Canonical participant/key entries.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (ParticipantIndex, &G::Point)> + '_ {
        self.participants.iter().map(|(index, key)| (*index, key))
    }
}

/// Constant-term policy of one ordered sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgInstanceKind {
    /// Independently sampled coefficients, including a possibly zero constant.
    Random,
    /// A fixed zero constant, physically omitted from broadcasts.
    Zero,
}
impl DkgInstanceKind {
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Random => 0,
            Self::Zero => 1,
        }
    }
    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Random),
            1 => Ok(Self::Zero),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

/// Immutable, fully validated public protocol configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig<G: DkgGroup> {
    threshold: usize,
    session_id: SessionId,
    registry: ParticipantRegistry<G>,
    instances: Vec<DkgInstanceKind>,
    canonical: Vec<u8>,
    root: TranscriptRoot,
}
impl<G: DkgGroup> DkgConfig<G> {
    /// Construct a nonempty ordered batch; reconstruction threshold is in `1..=n`.
    pub fn new(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
        instances: Vec<DkgInstanceKind>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > registry.len() {
            return Err(Error::InvalidThreshold {
                threshold,
                participants: registry.len(),
            });
        }
        if instances.is_empty() {
            return Err(Error::EmptyDkgBatch);
        }
        u32::try_from(instances.len()).map_err(|_| Error::ArithmeticOverflow)?;
        instances
            .len()
            .checked_mul(registry.len())
            .and_then(|v| v.checked_mul(threshold))
            .ok_or(Error::ArithmeticOverflow)?;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        framed(&mut canonical, G::GROUP_ID.as_bytes())?;
        count(&mut canonical, threshold)?;
        canonical.extend_from_slice(&session_id.0);
        count(&mut canonical, registry.len())?;
        for (participant, key) in registry.entries() {
            canonical.extend_from_slice(&participant.get().to_be_bytes());
            canonical.extend_from_slice(&G::encode_point(key));
        }
        count(&mut canonical, instances.len())?;
        canonical.extend(instances.iter().map(|kind| kind.tag()));
        let root = crate::transcript::hash_payload(b"golden-dkg/config-root/v3", &canonical)?;
        Ok(Self {
            threshold,
            session_id,
            registry,
            instances,
            canonical,
            root,
        })
    }
    /// Reconstruction threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    /// Agreed session identifier.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Canonical participant registry.
    pub fn registry(&self) -> &ParticipantRegistry<G> {
        &self.registry
    }
    /// Registered identity key, if present.
    pub fn identity_public_key(&self, participant: ParticipantIndex) -> Option<&G::Point> {
        self.registry.participants.get(&participant)
    }
    /// Canonical dealer registry.
    pub fn dealers(&self) -> &ParticipantRegistry<G> {
        &self.registry
    }
    /// Registered dealer identity key, if present.
    pub fn dealer_public_key(&self, dealer: ParticipantIndex) -> Option<&G::Point> {
        self.registry.participants.get(&dealer)
    }
    /// Canonical receivers of one dealer's sharings, excluding that dealer.
    pub fn receivers(
        &self,
        dealer: ParticipantIndex,
    ) -> impl Iterator<Item = (ParticipantIndex, &G::Point)> + '_ {
        self.registry
            .entries()
            .filter(move |(participant, _)| *participant != dealer)
    }
    /// Receiver count of every dealer's sharings.
    pub fn receiver_count(&self) -> usize {
        self.registry.len() - 1
    }
    /// Instance kinds in configuration order.
    pub fn instances(&self) -> &[DkgInstanceKind] {
        &self.instances
    }
    /// Kind at a zero-based configuration position.
    pub fn instance(&self, position: usize) -> Option<DkgInstanceKind> {
        self.instances.get(position).copied()
    }
    /// Proof-independent configuration identity.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }
    /// Exact canonical C payload bound by proof transcripts.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

pub(crate) fn associate<'a, G: DkgGroup>(
    config: &DkgConfig<G>,
    candidates: &[crate::DealerMessageRef<'a>],
    full: bool,
) -> Result<BTreeMap<ParticipantIndex, &'a [u8]>> {
    if candidates.is_empty() {
        return Err(Error::EmptyBoard);
    }
    let mut board = BTreeMap::new();
    let mut unexpected = BTreeSet::new();
    let mut duplicate = BTreeSet::new();
    for candidate in candidates {
        let dealer = candidate.expected_dealer;
        if config.dealer_public_key(dealer).is_none() {
            unexpected.insert(dealer);
        }
        if board.insert(dealer, candidate.bytes).is_some() {
            duplicate.insert(dealer);
        }
    }
    if let Some(dealer) = unexpected.first() {
        return Err(Error::UnexpectedDealer { dealer: *dealer });
    }
    if let Some(dealer) = duplicate.first() {
        return Err(Error::DuplicateDealer { dealer: *dealer });
    }
    if full {
        for dealer in config.dealers().indexes() {
            if !board.contains_key(&dealer) {
                return Err(Error::MissingDealer { dealer });
            }
        }
    }
    Ok(board)
}
