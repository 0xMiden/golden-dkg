//! Immutable configurations and canonical participant registries.
use crate::error::normalize_validation_error;
use crate::output::on_polynomial;
use crate::wire::{count, framed, reserve};
use crate::{DkgGroup, DkgPublicOutput, Error, ParticipantIndex, Result, TranscriptRoot};
use group::Group;
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};

/// Main Golden protocol version.
pub const PROTOCOL_VERSION: u32 = 3;
/// Dealer nonce/effective-message size.
pub const DEALER_MESSAGE_NONCE_BYTES: usize = 32;
pub(crate) const RESHARE_LABEL: &[u8] = b"golden-dkg/reshare";
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
            let encoded = canonical_encoding::<G>(&key)?;
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
    /// The dealer's predecessor share, pinned to its public predecessor share and physically
    /// omitted from broadcasts.
    Reshare,
}
impl DkgInstanceKind {
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Random => 0,
            Self::Zero => 1,
            Self::Reshare => 2,
        }
    }
    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Random),
            1 => Ok(Self::Zero),
            2 => Ok(Self::Reshare),
            _ => Err(Error::InvalidEncoding),
        }
    }
    /// Whether the constant is pinned, omitted from broadcasts and never opened.
    pub(crate) fn pins_constant(self) -> bool {
        match self {
            Self::Random => false,
            Self::Zero | Self::Reshare => true,
        }
    }
}

/// Public key set of the predecessor committee whose sharing a reshare continues.
/// Applications establish its authenticity, for example from a trusted completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResharePredecessor<G: DkgGroup> {
    threshold: usize,
    public_key: G::Point,
    public_key_shares: BTreeMap<ParticipantIndex, G::Point>,
    config_root: TranscriptRoot,
    completion_root: TranscriptRoot,
}
impl<G: DkgGroup> ResharePredecessor<G> {
    /// Validate canonical shares on one degree-`threshold - 1` polynomial whose constant is the
    /// nonidentity `public_key`. A share may be the identity.
    pub fn new(
        threshold: usize,
        public_key: G::Point,
        public_key_shares: Vec<(ParticipantIndex, G::Point)>,
        config_root: TranscriptRoot,
        completion_root: TranscriptRoot,
    ) -> Result<Self> {
        let public_key_shares = predecessor_shares::<G>(threshold, &public_key, public_key_shares)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPredecessor))?;
        Ok(Self {
            threshold,
            public_key,
            public_key_shares,
            config_root,
            completion_root,
        })
    }
    /// Key set of a `Random` or `Reshare` instance of an output that validates against `config`.
    pub fn from_output(
        config: &DkgConfig<G>,
        output: &DkgPublicOutput<G>,
        position: usize,
    ) -> Result<Self> {
        crate::output::validate_public(config, output)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPredecessor))?;
        let instance = output.instance(position).ok_or(Error::InvalidPredecessor)?;
        if !matches!(
            instance.kind(),
            DkgInstanceKind::Random | DkgInstanceKind::Reshare
        ) {
            return Err(Error::InvalidPredecessor);
        }
        let mut shares = reserve(instance.public_key_shares().len())?;
        shares.extend(
            instance
                .public_key_shares()
                .map(|(participant, point)| (participant, *point)),
        );
        Self::new(
            config.threshold(),
            *instance.public_key(),
            shares,
            config.root(),
            output.completion_root(),
        )
    }
    /// Predecessor reconstruction threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    /// Group key that the reshare preserves.
    pub fn public_key(&self) -> &G::Point {
        &self.public_key
    }
    /// One predecessor participant's public share.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Option<&G::Point> {
        self.public_key_shares.get(&participant)
    }
    /// Canonical predecessor public shares.
    pub fn public_key_shares(
        &self,
    ) -> impl ExactSizeIterator<Item = (ParticipantIndex, &G::Point)> {
        self.public_key_shares
            .iter()
            .map(|(participant, point)| (*participant, point))
    }
    /// Predecessor configuration identity.
    pub fn config_root(&self) -> TranscriptRoot {
        self.config_root
    }
    /// Predecessor completion identity.
    pub fn completion_root(&self) -> TranscriptRoot {
        self.completion_root
    }
}
fn predecessor_shares<G: DkgGroup>(
    threshold: usize,
    public_key: &G::Point,
    entries: Vec<(ParticipantIndex, G::Point)>,
) -> Result<BTreeMap<ParticipantIndex, G::Point>> {
    if threshold == 0 || entries.len() < threshold || bool::from(public_key.is_identity()) {
        return Err(Error::InvalidPredecessor);
    }
    canonical_encoding::<G>(public_key)?;
    let mut shares = BTreeMap::new();
    for (participant, point) in entries {
        participant.to_scalar::<G::Scalar>()?;
        canonical_encoding::<G>(&point)?;
        if shares.insert(participant, point).is_some() {
            return Err(Error::InvalidPredecessor);
        }
    }
    if !on_polynomial::<G>(threshold, public_key, &shares)? {
        return Err(Error::InvalidPredecessor);
    }
    Ok(shares)
}
fn canonical_encoding<G: DkgGroup>(point: &G::Point) -> Result<Vec<u8>> {
    let encoded = G::encode_point(point);
    if G::decode_point(&encoded)? != *point {
        return Err(Error::InvalidEncoding);
    }
    Ok(encoded)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReshareTopology<G: DkgGroup> {
    dealers: ParticipantRegistry<G>,
    max_corrupt_receivers: usize,
    predecessor: ResharePredecessor<G>,
}

/// Immutable, fully validated public protocol configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig<G: DkgGroup> {
    threshold: usize,
    session_id: SessionId,
    registry: ParticipantRegistry<G>,
    reshare: Option<ReshareTopology<G>>,
    instances: Vec<DkgInstanceKind>,
    canonical: Vec<u8>,
    root: TranscriptRoot,
}
impl<G: DkgGroup> DkgConfig<G> {
    /// Construct a nonempty ordered batch; reconstruction threshold is in `1..=n`.
    /// `Reshare` instances require [`Self::new_reshare`].
    pub fn new(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
        instances: Vec<DkgInstanceKind>,
    ) -> Result<Self> {
        check_threshold(threshold, registry.len())?;
        if instances.is_empty() {
            return Err(Error::EmptyDkgBatch);
        }
        if instances.contains(&DkgInstanceKind::Reshare) {
            return Err(Error::InvalidReshareConfiguration);
        }
        check_dimensions(threshold, registry.len(), &instances)?;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        framed(&mut canonical, G::GROUP_ID.as_bytes())?;
        count(&mut canonical, threshold)?;
        canonical.extend_from_slice(&session_id.0);
        append_entries::<G>(&mut canonical, registry.entries())?;
        append_kinds(&mut canonical, &instances)?;
        let root = crate::transcript::hash_payload(b"golden-dkg/config-root/v3", &canonical)?;
        Ok(Self {
            threshold,
            session_id,
            registry,
            reshare: None,
            instances,
            canonical,
            root,
        })
    }
    /// Construct a reshare of `predecessor`'s group key from `dealers`, keyed by predecessor
    /// indexes, to `receivers`, keyed by new indexes, with reconstruction threshold `threshold`.
    /// `instances` holds exactly one `Reshare` and otherwise `Zero`. `max_corrupt_receivers`
    /// is the declared bound on corrupt receivers across every attempt.
    pub fn new_reshare(
        threshold: usize,
        max_corrupt_receivers: usize,
        session_id: SessionId,
        dealers: ParticipantRegistry<G>,
        receivers: ParticipantRegistry<G>,
        predecessor: ResharePredecessor<G>,
        instances: Vec<DkgInstanceKind>,
    ) -> Result<Self> {
        check_threshold(threshold, receivers.len())?;
        if max_corrupt_receivers >= threshold {
            return Err(Error::InsecureReshareThreshold {
                threshold,
                max_corrupt_receivers,
            });
        }
        if instances.is_empty() {
            return Err(Error::EmptyDkgBatch);
        }
        if instances
            .iter()
            .filter(|kind| **kind == DkgInstanceKind::Reshare)
            .count()
            != 1
            || instances
                .iter()
                .any(|kind| !matches!(kind, DkgInstanceKind::Reshare | DkgInstanceKind::Zero))
        {
            return Err(Error::InvalidReshareConfiguration);
        }
        if dealers.len() < predecessor.threshold()
            || dealers
                .indexes()
                .any(|dealer| predecessor.public_key_share(dealer).is_none())
        {
            return Err(Error::InvalidReshareConfiguration);
        }
        let mut keys = BTreeSet::new();
        for (_, key) in dealers.entries().chain(receivers.entries()) {
            if !keys.insert(G::encode_point(key)) || !keys.insert(G::encode_point(&-*key)) {
                return Err(Error::ReshareKeyCollision);
            }
        }
        check_dimensions(threshold, receivers.len(), &instances)?;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        framed(&mut canonical, RESHARE_LABEL)?;
        framed(&mut canonical, G::GROUP_ID.as_bytes())?;
        count(&mut canonical, threshold)?;
        count(&mut canonical, max_corrupt_receivers)?;
        canonical.extend_from_slice(&session_id.0);
        append_entries::<G>(&mut canonical, receivers.entries())?;
        append_entries::<G>(&mut canonical, dealers.entries())?;
        count(&mut canonical, predecessor.threshold())?;
        canonical.extend_from_slice(&G::encode_point(predecessor.public_key()));
        canonical.extend_from_slice(&predecessor.config_root());
        canonical.extend_from_slice(&predecessor.completion_root());
        append_entries::<G>(&mut canonical, predecessor.public_key_shares())?;
        append_kinds(&mut canonical, &instances)?;
        let root =
            crate::transcript::hash_payload(b"golden-dkg/reshare-config-root/v3", &canonical)?;
        Ok(Self {
            threshold,
            session_id,
            registry: receivers,
            reshare: Some(ReshareTopology {
                dealers,
                max_corrupt_receivers,
                predecessor,
            }),
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
    /// Canonical share-holder registry; the receivers of a reshare configuration.
    pub fn registry(&self) -> &ParticipantRegistry<G> {
        &self.registry
    }
    /// Registered share-holder identity key, if present.
    pub fn identity_public_key(&self, participant: ParticipantIndex) -> Option<&G::Point> {
        self.registry.participants.get(&participant)
    }
    /// Canonical dealer registry; the share holders of a plain configuration.
    pub fn dealers(&self) -> &ParticipantRegistry<G> {
        self.reshare
            .as_ref()
            .map_or(&self.registry, |reshare| &reshare.dealers)
    }
    /// Registered dealer identity key, if present.
    pub fn dealer_public_key(&self, dealer: ParticipantIndex) -> Option<&G::Point> {
        self.dealers().participants.get(&dealer)
    }
    /// Canonical receivers of one registered dealer's sharings; plain configurations exclude
    /// the dealer.
    pub fn receivers(
        &self,
        dealer: ParticipantIndex,
    ) -> impl Iterator<Item = (ParticipantIndex, &G::Point)> + '_ {
        let excluded = self.reshare.is_none().then_some(dealer);
        self.registry
            .entries()
            .filter(move |(participant, _)| Some(*participant) != excluded)
    }
    /// Receiver count of every dealer's sharings.
    pub fn receiver_count(&self) -> usize {
        self.registry.len() - usize::from(self.reshare.is_none())
    }
    /// Predecessor key set of a reshare configuration.
    pub fn predecessor(&self) -> Option<&ResharePredecessor<G>> {
        self.reshare.as_ref().map(|reshare| &reshare.predecessor)
    }
    /// Declared corrupt-receiver bound of a reshare configuration.
    pub fn max_corrupt_receivers(&self) -> Option<usize> {
        self.reshare
            .as_ref()
            .map(|reshare| reshare.max_corrupt_receivers)
    }
    /// Constant of `dealer`'s `kind` sharings, if pinned.
    pub(crate) fn pinned_constant(
        &self,
        kind: DkgInstanceKind,
        dealer: ParticipantIndex,
    ) -> Result<Option<G::Point>> {
        match kind {
            DkgInstanceKind::Random => Ok(None),
            DkgInstanceKind::Zero => Ok(Some(G::Point::identity())),
            DkgInstanceKind::Reshare => self
                .predecessor()
                .and_then(|predecessor| predecessor.public_key_share(dealer))
                .map(|share| Some(*share))
                .ok_or(Error::InvalidEncoding),
        }
    }
    /// Public key every `kind` instance must aggregate to, if pinned.
    pub(crate) fn pinned_key(&self, kind: DkgInstanceKind) -> Result<Option<G::Point>> {
        match kind {
            DkgInstanceKind::Random => Ok(None),
            DkgInstanceKind::Zero => Ok(Some(G::Point::identity())),
            DkgInstanceKind::Reshare => self
                .predecessor()
                .map(|predecessor| Some(*predecessor.public_key()))
                .ok_or(Error::InvalidPersistedState),
        }
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
fn check_threshold(threshold: usize, holders: usize) -> Result<()> {
    if threshold == 0 || threshold > holders {
        return Err(Error::InvalidThreshold {
            threshold,
            participants: holders,
        });
    }
    Ok(())
}
fn check_dimensions(threshold: usize, holders: usize, instances: &[DkgInstanceKind]) -> Result<()> {
    u32::try_from(instances.len()).map_err(|_| Error::ArithmeticOverflow)?;
    instances
        .len()
        .checked_mul(holders)
        .and_then(|v| v.checked_mul(threshold))
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(())
}
pub(crate) fn append_entries<'a, G: DkgGroup>(
    out: &mut Vec<u8>,
    entries: impl ExactSizeIterator<Item = (ParticipantIndex, &'a G::Point)>,
) -> Result<()> {
    count(out, entries.len())?;
    for (participant, point) in entries {
        out.extend_from_slice(&participant.get().to_be_bytes());
        out.extend_from_slice(&G::encode_point(point));
    }
    Ok(())
}
pub(crate) fn append_kinds(out: &mut Vec<u8>, kinds: &[DkgInstanceKind]) -> Result<()> {
    count(out, kinds.len())?;
    out.extend(kinds.iter().map(|kind| kind.tag()));
    Ok(())
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
