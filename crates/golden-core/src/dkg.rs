//! Batch-native DKG orchestration over a generic Golden group.

use std::collections::{BTreeMap, BTreeSet};

use rand_core::CryptoRngCore;

use crate::main_golden::effective_message;
use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::wire::MAX_DEALER_PROOF_BYTES;
use crate::{
    Error, FeldmanCommitment, GoldenGroup, GoldenScalar, ParticipantIndex, Polynomial, Result,
    Share,
};

/// Protocol version used in transcript binding.
pub const PROTOCOL_VERSION: u32 = 4;

/// Byte length of a raw dealer nonce and an effective eVRF message.
pub const DEALER_MESSAGE_NONCE_BYTES: usize = 32;

/// Session identifier for replay protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create a random session ID.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Independently sampled raw nonce carried by one dealing body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerMessageNonce(pub [u8; DEALER_MESSAGE_NONCE_BYTES]);

impl DealerMessageNonce {
    /// Create a random dealer-message nonce.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; DEALER_MESSAGE_NONCE_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Domain-separated message passed to an eVRF backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvrfMessage(pub [u8; DEALER_MESSAGE_NONCE_BYTES]);

/// Public participant registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRegistry<G: GoldenGroup> {
    participants: BTreeMap<ParticipantIndex, G::Element>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> ParticipantRegistry<G> {
    /// Build a registry from participant identity public keys.
    pub fn new(entries: Vec<(ParticipantIndex, G::Element)>) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::EmptyParticipantRegistry);
        }

        let mut participants = BTreeMap::new();
        let mut public_keys = Vec::<(Vec<u8>, ParticipantIndex)>::new();
        for (participant, public_key) in entries {
            if participants.contains_key(&participant) {
                return Err(Error::DuplicateParticipantIndex(participant.get()));
            }
            if bool::from(G::is_identity(&public_key)) {
                return Err(Error::InvalidEncoding);
            }
            let encoded_public_key = G::encode_element(&public_key);
            if let Some((_, first)) = public_keys
                .iter()
                .find(|(known, _)| known.as_slice() == encoded_public_key.as_ref())
            {
                return Err(Error::DuplicateParticipantPublicKey {
                    first: first.get(),
                    second: participant.get(),
                });
            }
            public_keys.push((encoded_public_key.as_ref().to_vec(), participant));
            participants.insert(participant, public_key);
        }

        let root = registry_root::<G>(&participants);
        Ok(Self { participants, root })
    }

    /// Number of registered participants.
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Return the registry root.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }

    /// Return a participant public key.
    pub fn public_key(&self, participant: ParticipantIndex) -> Result<&G::Element> {
        self.participants
            .get(&participant)
            .ok_or(Error::UnknownParticipant(participant.get()))
    }

    /// Return participant indexes in canonical order.
    pub fn indexes(&self) -> impl Iterator<Item = ParticipantIndex> + '_ {
        self.participants.keys().copied()
    }

    /// Return participant entries in canonical order.
    pub fn entries(&self) -> impl Iterator<Item = (ParticipantIndex, &G::Element)> + '_ {
        self.participants
            .iter()
            .map(|(participant, public_key)| (*participant, public_key))
    }
}

/// Constant-term policy for one sharing in an ordered DKG batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgInstanceKind {
    /// Independently sampled random constant term.
    Random,
    /// Identity/zero constant term.
    Zero,
}

/// Immutable, validated DKG configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig<G: GoldenGroup> {
    threshold: usize,
    session_id: SessionId,
    registry: ParticipantRegistry<G>,
    instances: Vec<DkgInstanceKind>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> DkgConfig<G> {
    /// Construct an arbitrary ordered, nonempty set of sharing instances.
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
        let root = config_root::<G>(threshold, session_id, &registry, &instances);
        Ok(Self {
            threshold,
            session_id,
            registry,
            instances,
            root,
        })
    }

    /// Construct one random sharing.
    pub fn new_random(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
    ) -> Result<Self> {
        Self::new(
            threshold,
            session_id,
            registry,
            vec![DkgInstanceKind::Random],
        )
    }

    /// Construct one zero sharing.
    pub fn new_zero(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
    ) -> Result<Self> {
        Self::new(threshold, session_id, registry, vec![DkgInstanceKind::Zero])
    }

    /// Return the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return the session identifier.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Return the participant registry.
    pub fn registry(&self) -> &ParticipantRegistry<G> {
        &self.registry
    }

    /// Return one registered participant identity public key.
    pub fn identity_public_key(&self, participant: ParticipantIndex) -> Option<&G::Element> {
        self.registry.participants.get(&participant)
    }

    /// Return configured instance kinds in protocol order.
    pub fn instances(&self) -> &[DkgInstanceKind] {
        &self.instances
    }

    /// Return one configured instance kind by protocol position.
    pub fn instance(&self, position: usize) -> Option<DkgInstanceKind> {
        self.instances.get(position).copied()
    }

    /// Return the canonical configuration root.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }
}

/// Public inputs for one receiver relation inside one dealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvrfReceiverStatement<G: GoldenGroup> {
    /// Receiver participant index.
    pub receiver: ParticipantIndex,
    /// Receiver identity public key.
    pub receiver_public_key: G::Element,
    /// Public commitment to the receiver share.
    pub share_commitment: G::Element,
    /// Public commitment to the pad scalar.
    pub pad_commitment: G::Element,
    /// Encrypted share scalar, `pad + share`.
    pub encrypted_share: G::Scalar,
}

/// Public inputs for one dealing in a joint dealer proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvrfDealingStatement<G: GoldenGroup> {
    /// Effective, domain-separated eVRF message.
    pub message: EvrfMessage,
    /// Feldman commitment to the shared polynomial.
    pub commitment: FeldmanCommitment<G>,
    /// Receiver relations in canonical participant order.
    pub receivers: Vec<EvrfReceiverStatement<G>>,
}

/// Public statement for one dealer's complete ordered batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvrfStatement<G: GoldenGroup> {
    /// Dealer identity public key.
    pub dealer_public_key: G::Element,
    /// Public eVRF coefficient.
    pub beta: G::Scalar,
    /// Canonical proof-independent dealer-message root.
    pub dealer_message_root: TranscriptRoot,
    /// Dealings in configuration order.
    pub dealings: Vec<EvrfDealingStatement<G>>,
}

impl<G: GoldenGroup> EvrfStatement<G> {
    /// Compute a stable statement root.
    pub fn root(&self) -> TranscriptRoot {
        statement_root(self)
    }
}

/// Private receiver openings in canonical order.
#[derive(Clone, Eq, PartialEq)]
pub struct EvrfReceiverWitness<G: GoldenGroup> {
    /// Receiver share scalar.
    pub share: G::Scalar,
    /// Pad scalar.
    pub pad: G::Scalar,
}

/// Private openings for one dealing, in its statement receiver order.
#[derive(Clone, Eq, PartialEq)]
pub struct EvrfDealingWitness<G: GoldenGroup> {
    /// Opening of an explicit constant Feldman commitment.
    pub polynomial_constant: Option<G::Scalar>,
    /// Receiver openings in canonical order.
    pub receivers: Vec<EvrfReceiverWitness<G>>,
}

/// Private witness for one dealer's complete ordered batch.
#[derive(Clone, Eq, PartialEq)]
pub struct EvrfWitness<G: GoldenGroup> {
    /// Dealer identity secret opening the dealer identity public key.
    pub identity_secret: G::Scalar,
    /// Per-dealing receiver openings in statement order.
    pub dealings: Vec<EvrfDealingWitness<G>>,
}

impl<G: GoldenGroup> EvrfWitness<G> {
    /// Validate that private witness dimensions match the public statement.
    pub fn validate_shape(&self, statement: &EvrfStatement<G>) -> Result<()> {
        if self.dealings.len() != statement.dealings.len()
            || self
                .dealings
                .iter()
                .zip(&statement.dealings)
                .any(|(private, public)| {
                    private.receivers.len() != public.receivers.len()
                        || private.polynomial_constant.is_some()
                            != public.commitment.constant().is_some()
                })
        {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    }
}

impl<G: GoldenGroup> core::fmt::Debug for EvrfWitness<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvrfWitness")
            .field("identity_secret", &"<redacted>")
            .field("dealings", &"<redacted>")
            .finish()
    }
}

/// eVRF proof backend boundary.
pub trait EvrfProofBackend<G: GoldenGroup> {
    /// Stable, versioned identity of this proof protocol and byte grammar.
    const PROOF_ID: &'static [u8];

    /// Evaluate a per-recipient pad from an already domain-separated message.
    fn derive_pad(
        message: EvrfMessage,
        _beta: &G::Scalar,
        identity_secret: &G::Scalar,
        peer_public_key: &G::Element,
        receiver_public_key: &G::Element,
    ) -> Result<G::Scalar> {
        let shared_secret = G::mul(peer_public_key, identity_secret);
        derive_default_pad::<G>(message, receiver_public_key, &shared_secret)
    }

    /// Produce one proof for the complete nested dealer statement.
    fn prove_batch(
        statement: &EvrfStatement<G>,
        witness: &EvrfWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>>;

    /// Verify one proof for the complete nested dealer statement.
    fn verify_batch(statement: &EvrfStatement<G>, proof: &[u8]) -> Result<()>;

    /// Verify several independent dealer proofs.
    ///
    /// Backends may combine the proof equations into one MSM. The combining
    /// coefficients must be nonzero and unpredictable to the dealers, using
    /// fresh verifier entropy or a domain-separated transcript that binds the
    /// complete ordered statements and proofs. Fixed or input-independent
    /// coefficients do not provide sound batch verification. The default
    /// preserves correctness for backends without that optimization.
    fn verify_proof_batch(batches: &[(&EvrfStatement<G>, &[u8])]) -> Result<()> {
        for (statement, proof) in batches {
            Self::verify_batch(statement, proof)?;
        }
        Ok(())
    }
}

/// Public encrypted share data for one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedShare<G: GoldenGroup> {
    /// Public commitment to the pad scalar.
    pub pad_commitment: G::Element,
    /// Encrypted share scalar, `pad + share`.
    pub encrypted_share: G::Scalar,
}

/// One proof-independent dealing body in a dealer broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealingBody<G: GoldenGroup> {
    /// Independently sampled raw nonce.
    pub nonce: DealerMessageNonce,
    /// Feldman commitment for this instance's independently sampled polynomial.
    pub commitment: FeldmanCommitment<G>,
    /// Public encrypted shares keyed by every non-dealer receiver.
    pub encrypted_shares: BTreeMap<ParticipantIndex, EncryptedShare<G>>,
}

/// Dealer broadcast for the complete configured batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealerMessage<G: GoldenGroup> {
    /// Claimed configuration root, validated before proof verification.
    pub configuration_root: TranscriptRoot,
    /// Dealer participant index.
    pub dealer: ParticipantIndex,
    /// Dealing bodies in configuration order.
    pub dealings: Vec<DealingBody<G>>,
    /// One proof covering every dealing and non-dealer receiver.
    pub proof: Vec<u8>,
}

impl<G: GoldenGroup> DealerMessage<G> {
    /// Derive the canonical proof-independent root from the current fields.
    pub fn root(&self) -> TranscriptRoot {
        dealer_message_root(self)
    }
}

/// Immutable local output from creating a dealer message.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgDealing<G: GoldenGroup> {
    message: DealerMessage<G>,
    private_shares: Vec<G::Scalar>,
}

impl<G: GoldenGroup> DkgDealing<G> {
    /// Return the public dealer broadcast.
    pub fn message(&self) -> &DealerMessage<G> {
        &self.message
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DkgDealing<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgDealing")
            .field("message", &self.message)
            .field("private_shares", &"<redacted>")
            .finish()
    }
}

/// Completed participant state for one batch position.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgInstanceOutput<G: GoldenGroup> {
    public_key: G::Element,
    secret_share: Share<G::Scalar>,
    public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
}

impl<G: GoldenGroup> DkgInstanceOutput<G> {
    /// Return the shared public key.
    pub fn public_key(&self) -> &G::Element {
        &self.public_key
    }

    /// Return this participant's secret share.
    pub fn secret_share(&self) -> &Share<G::Scalar> {
        &self.secret_share
    }

    /// Return public key shares in canonical participant order.
    pub fn public_key_shares(&self) -> &BTreeMap<ParticipantIndex, G::Element> {
        &self.public_key_shares
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DkgInstanceOutput<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgInstanceOutput")
            .field("public_key", &self.public_key)
            .field("secret_share", &"<redacted>")
            .field("public_key_shares", &self.public_key_shares)
            .finish()
    }
}

/// Immutable atomic output for the complete ordered DKG batch.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgOutput<G: GoldenGroup> {
    configuration_root: TranscriptRoot,
    instances: Vec<DkgInstanceOutput<G>>,
    completion_root: TranscriptRoot,
}

impl<G: GoldenGroup> DkgOutput<G> {
    /// Return the proof-policy-independent configuration root accepted during
    /// completion.
    pub fn configuration_root(&self) -> TranscriptRoot {
        self.configuration_root
    }

    /// Return completed instances in configuration order.
    pub fn instances(&self) -> &[DkgInstanceOutput<G>] {
        &self.instances
    }

    /// Return the atomic completion identity, including the proof policy used.
    pub fn completion_root(&self) -> TranscriptRoot {
        self.completion_root
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DkgOutput<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgOutput")
            .field("configuration_root", &self.configuration_root)
            .field("instances", &self.instances)
            .field("completion_root", &self.completion_root)
            .finish()
    }
}

/// Create one dealer message for the complete configured batch.
///
/// `legacy_beta` is the caller-selected scalar coefficient used by this legacy
/// static proof seam. It is unrelated to the protocol-wide Main Golden
/// base-field coefficient.
pub fn create_dealing<G, B>(
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<DkgDealing<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let dealer_public_key = config.registry.public_key(dealer)?;
    if G::mul_generator(dealer_identity_secret) != *dealer_public_key {
        return Err(Error::IdentityKeyMismatch);
    }

    let mut bodies = Vec::with_capacity(config.instances.len());
    let mut private_shares = Vec::with_capacity(config.instances.len());
    let mut proof_dealings = Vec::with_capacity(config.instances.len());
    let mut witness_dealings = Vec::with_capacity(config.instances.len());

    for (position, kind) in config.instances.iter().copied().enumerate() {
        let (polynomial, commitment, polynomial_constant) = match kind {
            DkgInstanceKind::Random => {
                let constant = G::Scalar::random(rng);
                let polynomial =
                    Polynomial::random_with_secret(constant.clone(), config.threshold, rng)?;
                let commitment = FeldmanCommitment::<G>::commit(&polynomial)?;
                (polynomial, commitment, Some(constant))
            }
            DkgInstanceKind::Zero => {
                let polynomial =
                    Polynomial::random_with_secret(G::Scalar::zero(), config.threshold, rng)?;
                let commitment = FeldmanCommitment::<G>::commit_zero(&polynomial)?;
                (polynomial, commitment, None)
            }
        };
        let nonce = DealerMessageNonce::random(rng);
        let message = effective_message(config.root, dealer, position, kind, nonce);

        let mut shares = BTreeMap::new();
        for receiver in config.registry.indexes() {
            shares.insert(receiver, polynomial.evaluate(receiver)?.value);
        }

        let mut encrypted_shares = BTreeMap::new();
        let mut proof_receivers = Vec::with_capacity(config.registry.len().saturating_sub(1));
        let mut witness_receivers = Vec::with_capacity(config.registry.len().saturating_sub(1));
        for receiver in public_share_receivers(config, dealer) {
            let receiver_public_key = config.registry.public_key(receiver)?;
            let share = shares
                .get(&receiver)
                .cloned()
                .ok_or(Error::MissingShare(receiver.get()))?;
            let pad = B::derive_pad(
                message,
                legacy_beta,
                dealer_identity_secret,
                receiver_public_key,
                receiver_public_key,
            )?;
            let encrypted_share = EncryptedShare::<G> {
                pad_commitment: G::mul_generator(&pad),
                encrypted_share: share.add(&pad),
            };
            proof_receivers.push(EvrfReceiverStatement {
                receiver,
                receiver_public_key: receiver_public_key.clone(),
                share_commitment: G::mul_generator(&share),
                pad_commitment: encrypted_share.pad_commitment.clone(),
                encrypted_share: encrypted_share.encrypted_share.clone(),
            });
            witness_receivers.push(EvrfReceiverWitness { share, pad });
            encrypted_shares.insert(receiver, encrypted_share);
        }

        private_shares.push(
            shares
                .get(&dealer)
                .cloned()
                .ok_or(Error::MissingShare(dealer.get()))?,
        );
        proof_dealings.push(EvrfDealingStatement {
            message,
            commitment: commitment.clone(),
            receivers: proof_receivers,
        });
        witness_dealings.push(EvrfDealingWitness {
            polynomial_constant,
            receivers: witness_receivers,
        });
        bodies.push(DealingBody {
            nonce,
            commitment,
            encrypted_shares,
        });
    }

    let mut message = DealerMessage {
        configuration_root: config.root,
        dealer,
        dealings: bodies,
        proof: Vec::new(),
    };
    let statement = EvrfStatement {
        dealer_public_key: dealer_public_key.clone(),
        beta: (*legacy_beta).clone(),
        dealer_message_root: message.root(),
        dealings: proof_dealings,
    };
    let witness = EvrfWitness {
        identity_secret: dealer_identity_secret.clone(),
        dealings: witness_dealings,
    };
    // A dealer with no other receivers (n=1) has no public receiver relation
    // to attest to; the sole share remains local.
    let proof = if statement
        .dealings
        .iter()
        .all(|dealing| dealing.receivers.is_empty())
    {
        Vec::new()
    } else {
        B::prove_batch(&statement, &witness, rng)?
    };
    if proof.len() > MAX_DEALER_PROOF_BYTES {
        return Err(Error::InvalidEncoding);
    }
    message.proof = proof;

    Ok(DkgDealing {
        message,
        private_shares,
    })
}

fn dealing_statement<G>(
    message: &DealerMessage<G>,
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
) -> Result<EvrfStatement<G>>
where
    G: GoldenGroup,
{
    if message.proof.len() > MAX_DEALER_PROOF_BYTES {
        return Err(Error::InvalidEncoding);
    }
    if message.configuration_root != config.root {
        return Err(Error::ConfigurationMismatch);
    }
    let dealer_public_key = config.registry.public_key(message.dealer)?;
    if message.dealings.len() != config.instances.len() {
        return Err(Error::InvalidDealingCount {
            expected: config.instances.len(),
            actual: message.dealings.len(),
        });
    }

    let mut dealings = Vec::with_capacity(message.dealings.len());
    for (position, (body, kind)) in message
        .dealings
        .iter()
        .zip(config.instances.iter().copied())
        .enumerate()
    {
        if body.commitment.threshold() != config.threshold {
            return Err(Error::InvalidCommitmentDegree {
                expected: config.threshold,
                actual: body.commitment.threshold(),
            });
        }
        if body.commitment.constant().is_some() != (kind == DkgInstanceKind::Random) {
            return Err(Error::CommitmentKindMismatch(position));
        }
        ensure_public_share_keys(body, message.dealer, config)?;

        let mut receivers = Vec::with_capacity(config.registry.len().saturating_sub(1));
        for receiver in public_share_receivers(config, message.dealer) {
            let share_commitment = body.commitment.public_key_share(receiver)?;
            let encrypted_share = body
                .encrypted_shares
                .get(&receiver)
                .ok_or(Error::MissingShare(receiver.get()))?;
            let encrypted_share_commitment = G::mul_generator(&encrypted_share.encrypted_share);
            let expected = G::add(&share_commitment, &encrypted_share.pad_commitment);
            if encrypted_share_commitment != expected {
                return Err(Error::CommitmentVerificationFailed);
            }
            receivers.push(EvrfReceiverStatement {
                receiver,
                receiver_public_key: config.registry.public_key(receiver)?.clone(),
                share_commitment,
                pad_commitment: encrypted_share.pad_commitment.clone(),
                encrypted_share: encrypted_share.encrypted_share.clone(),
            });
        }
        dealings.push(EvrfDealingStatement {
            message: effective_message(config.root, message.dealer, position, kind, body.nonce),
            commitment: body.commitment.clone(),
            receivers,
        });
    }

    Ok(EvrfStatement {
        dealer_public_key: dealer_public_key.clone(),
        beta: (*legacy_beta).clone(),
        dealer_message_root: message.root(),
        dealings,
    })
}

/// Verify one complete dealer message.
///
/// `legacy_beta` must be the same caller-selected scalar used to create the
/// message. It is not the Main Golden base-field coefficient.
pub fn verify_dealing<G, B>(
    message: &DealerMessage<G>,
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let statement = dealing_statement(message, config, legacy_beta)?;
    if statement
        .dealings
        .iter()
        .all(|dealing| dealing.receivers.is_empty())
    {
        // For n=1, the sole share is local and there is no public receiver
        // relation to verify. Accept only the canonical empty-proof representation.
        return if message.proof.is_empty() {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        };
    }
    B::verify_batch(&statement, &message.proof)
}

/// Verify several independent dealer messages in one backend call.
///
/// `legacy_beta` must be the same caller-selected scalar used to create every
/// message. It is not the Main Golden base-field coefficient.
pub fn verify_dealings<G, B>(
    messages: &[&DealerMessage<G>],
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    if messages.is_empty() {
        return Err(Error::ProofVerificationFailed);
    }
    let mut dealers = BTreeSet::new();
    for message in messages {
        if !dealers.insert(message.dealer) {
            return Err(Error::DuplicateParticipantIndex(message.dealer.get()));
        }
    }

    // Complete structural preflight for every message before combining proofs.
    let statements = messages
        .iter()
        .map(|message| dealing_statement(message, config, legacy_beta))
        .collect::<Result<Vec<_>>>()?;
    if statements.iter().all(|statement| {
        statement
            .dealings
            .iter()
            .all(|dealing| dealing.receivers.is_empty())
    }) {
        for message in messages {
            if !message.proof.is_empty() {
                return Err(Error::DealerProofVerificationFailed(message.dealer.get()));
            }
        }
        return Ok(());
    }
    let proof_batches = statements
        .iter()
        .zip(messages.iter())
        .map(|(statement, message)| (statement, message.proof.as_slice()))
        .collect::<Vec<_>>();
    let batch_error = match B::verify_proof_batch(&proof_batches) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    for ((statement, proof), message) in proof_batches.iter().zip(messages) {
        if B::verify_batch(statement, proof).is_err() {
            return Err(Error::DealerProofVerificationFailed(message.dealer.get()));
        }
    }
    Err(batch_error)
}

/// Complete every configured sharing atomically for one receiver.
///
/// `legacy_beta` must be the same caller-selected scalar used by every dealer.
/// It is unrelated to the protocol-wide Main Golden base-field coefficient.
pub fn complete<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    own_dealing: &DkgDealing<G>,
    peer_dealings: &BTreeMap<ParticipantIndex, DealerMessage<G>>,
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
) -> Result<DkgOutput<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let receiver_public_key = config.registry.public_key(receiver)?;
    if G::mul_generator(receiver_identity_secret) != *receiver_public_key {
        return Err(Error::IdentityKeyMismatch);
    }
    if own_dealing.message.dealer != receiver {
        return Err(Error::DealerKeyMismatch {
            map_key: receiver.get(),
            message_dealer: own_dealing.message.dealer.get(),
        });
    }

    let mut all_dealings: BTreeMap<ParticipantIndex, &DealerMessage<G>> = BTreeMap::new();
    all_dealings.insert(own_dealing.message.dealer, &own_dealing.message);
    for (dealer, message) in peer_dealings {
        if *dealer != message.dealer {
            return Err(Error::DealerKeyMismatch {
                map_key: dealer.get(),
                message_dealer: message.dealer.get(),
            });
        }
        config.registry.public_key(*dealer)?;
        if all_dealings.insert(message.dealer, message).is_some() {
            return Err(Error::DuplicateParticipantIndex(message.dealer.get()));
        }
    }

    let messages = config
        .registry
        .indexes()
        .map(|dealer| {
            all_dealings
                .get(&dealer)
                .copied()
                .ok_or(Error::MissingDealing(dealer.get()))
        })
        .collect::<Result<Vec<_>>>()?;
    verify_dealings::<G, B>(&messages, config, legacy_beta)?;

    let mut outputs = Vec::with_capacity(config.instances.len());
    for (position, kind) in config.instances.iter().copied().enumerate() {
        let mut secret_share_value = G::Scalar::zero();
        let mut aggregate_coefficients = vec![G::identity(); config.threshold];
        for message in all_dealings.values() {
            let body = &message.dealings[position];
            let share = if message.dealer == receiver {
                Share {
                    participant: receiver,
                    value: own_dealing.private_shares[position].clone(),
                }
            } else {
                decrypt_share_for_receiver::<G, B>(
                    receiver,
                    receiver_identity_secret,
                    message,
                    body,
                    position,
                    config,
                    legacy_beta,
                )?
            };
            if !body.commitment.verify_share(&share)? {
                return Err(Error::CommitmentVerificationFailed);
            }
            secret_share_value = secret_share_value.add(&share.value);

            for (aggregate, coefficient) in aggregate_coefficients
                .iter_mut()
                .zip(body.commitment.coefficients())
            {
                *aggregate = G::add(aggregate, &coefficient);
            }
        }
        let aggregate_commitment = match kind {
            DkgInstanceKind::Random => {
                FeldmanCommitment::<G>::from_coefficients(aggregate_coefficients)?
            }
            DkgInstanceKind::Zero => FeldmanCommitment::<G>::from_zero_tail(
                aggregate_coefficients.into_iter().skip(1).collect(),
            ),
        };

        let mut public_key_shares = BTreeMap::new();
        for participant in config.registry.indexes() {
            public_key_shares.insert(
                participant,
                aggregate_commitment.public_key_share(participant)?,
            );
        }
        outputs.push(DkgInstanceOutput {
            public_key: aggregate_commitment.public_key(),
            secret_share: Share {
                participant: receiver,
                value: secret_share_value,
            },
            public_key_shares,
        });
    }

    Ok(DkgOutput {
        configuration_root: config.root,
        instances: outputs,
        completion_root: completion_root::<G, B>(config.root, &all_dealings),
    })
}

fn config_root<G: GoldenGroup>(
    threshold: usize,
    session_id: SessionId,
    registry: &ParticipantRegistry<G>,
    instances: &[DkgInstanceKind],
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"dkg-config");
    transcript.u32(b"version", PROTOCOL_VERSION);
    transcript.bytes(b"curve", G::CURVE_ID.as_bytes());
    transcript.bytes(b"session", &session_id.0);
    transcript.usize(b"threshold", threshold);
    transcript.bytes(b"registry", &registry.root());
    transcript.usize(b"instances-len", instances.len());
    for kind in instances {
        transcript.u32(
            b"instance-kind",
            match kind {
                DkgInstanceKind::Random => 0,
                DkgInstanceKind::Zero => 1,
            },
        );
    }
    transcript.root()
}

fn registry_root<G: GoldenGroup>(
    participants: &BTreeMap<ParticipantIndex, G::Element>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"registry");
    transcript.bytes(b"curve", G::CURVE_ID.as_bytes());
    transcript.usize(b"len", participants.len());
    for (participant, public_key) in participants {
        transcript.participant(b"participant", *participant);
        transcript.element::<G>(b"public-key", public_key);
    }
    transcript.root()
}

fn dealer_message_root<G: GoldenGroup>(message: &DealerMessage<G>) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"dealer-message");
    transcript.bytes(b"configuration", &message.configuration_root);
    transcript.participant(b"dealer", message.dealer);
    transcript.usize(b"dealings-len", message.dealings.len());
    for body in &message.dealings {
        transcript.bytes(b"nonce", &body.nonce.0);
        transcript.bytes(
            b"constant-present",
            &[u8::from(body.commitment.constant().is_some())],
        );
        transcript.usize(b"commitment-len", body.commitment.threshold());
        for coefficient in body.commitment.coefficients() {
            transcript.element::<G>(b"commitment", &coefficient);
        }
        transcript.usize(b"encrypted-shares-len", body.encrypted_shares.len());
        for (receiver, encrypted_share) in &body.encrypted_shares {
            transcript.participant(b"receiver", *receiver);
            transcript.element::<G>(b"pad-commitment", &encrypted_share.pad_commitment);
            transcript.scalar::<G>(b"encrypted-share", &encrypted_share.encrypted_share);
        }
    }
    transcript.root()
}

fn statement_root<G: GoldenGroup>(statement: &EvrfStatement<G>) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"evrf-statement");
    transcript.u32(b"version", PROTOCOL_VERSION);
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.element::<G>(b"dealer-pk", &statement.dealer_public_key);
    transcript.scalar::<G>(b"beta", &statement.beta);
    transcript.bytes(b"dealer-message-root", &statement.dealer_message_root);
    transcript.usize(b"dealings-len", statement.dealings.len());
    for dealing in &statement.dealings {
        transcript.bytes(b"message", &dealing.message.0);
        transcript.bytes(
            b"constant-present",
            &[u8::from(dealing.commitment.constant().is_some())],
        );
        transcript.usize(b"commitment-len", dealing.commitment.threshold());
        for coefficient in dealing.commitment.coefficients() {
            transcript.element::<G>(b"commitment", &coefficient);
        }
        transcript.usize(b"receivers-len", dealing.receivers.len());
        for receiver in &dealing.receivers {
            transcript.participant(b"receiver", receiver.receiver);
            transcript.element::<G>(b"receiver-pk", &receiver.receiver_public_key);
            transcript.element::<G>(b"share-commitment", &receiver.share_commitment);
            transcript.element::<G>(b"pad-commitment", &receiver.pad_commitment);
            transcript.scalar::<G>(b"encrypted-share", &receiver.encrypted_share);
        }
    }
    transcript.root()
}

fn completion_root<G, B>(
    configuration_root: TranscriptRoot,
    dealings: &BTreeMap<ParticipantIndex, &DealerMessage<G>>,
) -> TranscriptRoot
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let mut transcript = TranscriptBuilder::new(b"completion");
    transcript.bytes(b"configuration", &configuration_root);
    transcript.bytes(b"proof-backend", B::PROOF_ID);
    transcript.usize(b"dealers-len", dealings.len());
    for message in dealings.values() {
        transcript.bytes(b"dealer-message-root", &message.root());
    }
    transcript.root()
}

fn public_share_receivers<G: GoldenGroup>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
) -> impl Iterator<Item = ParticipantIndex> + '_ {
    config
        .registry
        .indexes()
        .filter(move |receiver| *receiver != dealer)
}

fn ensure_public_share_keys<G>(
    body: &DealingBody<G>,
    dealer: ParticipantIndex,
    config: &DkgConfig<G>,
) -> Result<()>
where
    G: GoldenGroup,
{
    for receiver in body.encrypted_shares.keys() {
        if *receiver == dealer || config.registry.public_key(*receiver).is_err() {
            return Err(Error::UnexpectedShare(receiver.get()));
        }
    }
    for receiver in public_share_receivers(config, dealer) {
        if !body.encrypted_shares.contains_key(&receiver) {
            return Err(Error::MissingShare(receiver.get()));
        }
    }
    Ok(())
}

fn decrypt_share_for_receiver<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    dealer_message: &DealerMessage<G>,
    body: &DealingBody<G>,
    position: usize,
    config: &DkgConfig<G>,
    legacy_beta: &G::Scalar,
) -> Result<Share<G::Scalar>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let encrypted_share = body
        .encrypted_shares
        .get(&receiver)
        .ok_or(Error::MissingShare(receiver.get()))?;
    let dealer_public_key = config.registry.public_key(dealer_message.dealer)?;
    let receiver_public_key = config.registry.public_key(receiver)?;
    let kind = config.instances[position];
    let message = effective_message(
        config.root,
        dealer_message.dealer,
        position,
        kind,
        body.nonce,
    );
    let pad = B::derive_pad(
        message,
        legacy_beta,
        receiver_identity_secret,
        dealer_public_key,
        receiver_public_key,
    )?;
    Ok(Share {
        participant: receiver,
        value: encrypted_share.encrypted_share.sub(&pad),
    })
}

fn derive_default_pad<G: GoldenGroup>(
    message: EvrfMessage,
    receiver_public_key: &G::Element,
    shared_secret: &G::Element,
) -> Result<G::Scalar> {
    let mut transcript = TranscriptBuilder::new(b"pad");
    transcript.bytes(b"message", &message.0);
    transcript.element::<G>(b"receiver-pk", receiver_public_key);
    transcript.element::<G>(b"shared-secret", shared_secret);
    G::Scalar::hash_to_scalar(b"golden-dkg-pad-v2", &transcript.root())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::DealerProofStatement;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    enum FakeBackend {}

    impl EvrfProofBackend<TinyGroup> for FakeBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/batch-fake/v1";

        fn prove_batch(
            statement: &EvrfStatement<TinyGroup>,
            witness: &EvrfWitness<TinyGroup>,
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            witness.validate_shape(statement)?;
            if TinyGroup::mul_generator(&witness.identity_secret) != statement.dealer_public_key {
                return Err(Error::ProofVerificationFailed);
            }
            Ok(statement.root().to_vec())
        }

        fn verify_batch(statement: &EvrfStatement<TinyGroup>, proof: &[u8]) -> Result<()> {
            if proof == statement.root() {
                Ok(())
            } else {
                Err(Error::ProofVerificationFailed)
            }
        }
    }

    enum AlternateFakeBackend {}

    impl EvrfProofBackend<TinyGroup> for AlternateFakeBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/batch-fake-alternate/v1";

        fn prove_batch(
            statement: &EvrfStatement<TinyGroup>,
            witness: &EvrfWitness<TinyGroup>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeBackend::prove_batch(statement, witness, rng)
        }

        fn verify_batch(statement: &EvrfStatement<TinyGroup>, proof: &[u8]) -> Result<()> {
            FakeBackend::verify_batch(statement, proof)
        }
    }

    enum OversizedProofBackend {}

    impl EvrfProofBackend<TinyGroup> for OversizedProofBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/oversized-proof/v1";

        fn prove_batch(
            _statement: &EvrfStatement<TinyGroup>,
            _witness: &EvrfWitness<TinyGroup>,
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            Ok(vec![0; MAX_DEALER_PROOF_BYTES + 1])
        }

        fn verify_batch(_statement: &EvrfStatement<TinyGroup>, _proof: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    static BATCH_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINGLE_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);

    static LEGACY_BETA_PAD_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LEGACY_BETA_PROVE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LEGACY_BETA_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);

    enum ExplicitLegacyBetaBackend {}

    impl EvrfProofBackend<TinyGroup> for ExplicitLegacyBetaBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/explicit-legacy-beta/v1";

        fn derive_pad(
            message: EvrfMessage,
            legacy_beta: &TinyScalar,
            identity_secret: &TinyScalar,
            peer_public_key: &<TinyGroup as GoldenGroup>::Element,
            receiver_public_key: &<TinyGroup as GoldenGroup>::Element,
        ) -> Result<TinyScalar> {
            assert_eq!(legacy_beta, &explicit_legacy_beta());
            LEGACY_BETA_PAD_CALLS.fetch_add(1, Ordering::SeqCst);
            let shared_secret = TinyGroup::mul(peer_public_key, identity_secret);
            derive_default_pad::<TinyGroup>(message, receiver_public_key, &shared_secret)
        }

        fn prove_batch(
            statement: &EvrfStatement<TinyGroup>,
            witness: &EvrfWitness<TinyGroup>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            assert_eq!(statement.beta, explicit_legacy_beta());
            LEGACY_BETA_PROVE_CALLS.fetch_add(1, Ordering::SeqCst);
            FakeBackend::prove_batch(statement, witness, rng)
        }

        fn verify_batch(statement: &EvrfStatement<TinyGroup>, proof: &[u8]) -> Result<()> {
            assert_eq!(statement.beta, explicit_legacy_beta());
            LEGACY_BETA_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            FakeBackend::verify_batch(statement, proof)
        }
    }

    enum CountingBackend {}

    impl EvrfProofBackend<TinyGroup> for CountingBackend {
        const PROOF_ID: &'static [u8] = <FakeBackend as EvrfProofBackend<TinyGroup>>::PROOF_ID;

        fn prove_batch(
            statement: &EvrfStatement<TinyGroup>,
            witness: &EvrfWitness<TinyGroup>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeBackend::prove_batch(statement, witness, rng)
        }

        fn verify_batch(statement: &EvrfStatement<TinyGroup>, proof: &[u8]) -> Result<()> {
            SINGLE_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            FakeBackend::verify_batch(statement, proof)
        }

        fn verify_proof_batch(batches: &[(&EvrfStatement<TinyGroup>, &[u8])]) -> Result<()> {
            BATCH_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            for (statement, proof) in batches {
                FakeBackend::verify_batch(statement, proof)?;
            }
            Ok(())
        }
    }

    enum UnreachableBackend {}

    impl EvrfProofBackend<TinyGroup> for UnreachableBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/unreachable/v1";

        fn prove_batch(
            _statement: &EvrfStatement<TinyGroup>,
            _witness: &EvrfWitness<TinyGroup>,
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            Err(Error::ProofVerificationFailed)
        }

        fn verify_batch(_statement: &EvrfStatement<TinyGroup>, _proof: &[u8]) -> Result<()> {
            Err(Error::ProofVerificationFailed)
        }
    }

    enum BatchRejectingBackend {}

    impl EvrfProofBackend<TinyGroup> for BatchRejectingBackend {
        const PROOF_ID: &'static [u8] = <FakeBackend as EvrfProofBackend<TinyGroup>>::PROOF_ID;

        fn prove_batch(
            statement: &EvrfStatement<TinyGroup>,
            witness: &EvrfWitness<TinyGroup>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeBackend::prove_batch(statement, witness, rng)
        }

        fn verify_batch(statement: &EvrfStatement<TinyGroup>, proof: &[u8]) -> Result<()> {
            FakeBackend::verify_batch(statement, proof)
        }

        fn verify_proof_batch(_batches: &[(&EvrfStatement<TinyGroup>, &[u8])]) -> Result<()> {
            Err(Error::InvalidEncoding)
        }
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn secret(participant: ParticipantIndex) -> TinyScalar {
        TinyScalar::from_u64(u64::from(participant.get())).unwrap()
    }

    fn explicit_legacy_beta() -> TinyScalar {
        TinyScalar::from_u64(42).unwrap()
    }

    fn legacy_beta() -> TinyScalar {
        TinyScalar::from_u64(11).unwrap()
    }

    fn registry() -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(
            [idx(1), idx(2), idx(3)]
                .into_iter()
                .map(|participant| (participant, TinyGroup::mul_generator(&secret(participant))))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn registry_and_config_expose_the_final_validated_contract() {
        assert_eq!(
            ParticipantRegistry::<TinyGroup>::new(Vec::new()).unwrap_err(),
            Error::EmptyParticipantRegistry
        );

        let registry = registry();
        let config = DkgConfig::new(
            2,
            SessionId([7; 32]),
            registry.clone(),
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap();

        assert_eq!(PROTOCOL_VERSION, 4);
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.session_id(), SessionId([7; 32]));
        assert_eq!(config.registry(), &registry);
        assert_eq!(
            config.identity_public_key(idx(2)),
            Some(registry.public_key(idx(2)).unwrap())
        );
        assert_eq!(config.identity_public_key(idx(4)), None);
        assert_eq!(config.instance(0), Some(DkgInstanceKind::Random));
        assert_eq!(config.instance(1), Some(DkgInstanceKind::Zero));
        assert_eq!(config.instance(2), None);
    }

    fn mixed_config() -> DkgConfig<TinyGroup> {
        DkgConfig::new(
            2,
            SessionId([7; 32]),
            registry(),
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap()
    }

    #[test]
    fn legacy_workflow_threads_the_explicit_scalar_beta_unchanged() {
        LEGACY_BETA_PAD_CALLS.store(0, Ordering::SeqCst);
        LEGACY_BETA_PROVE_CALLS.store(0, Ordering::SeqCst);
        LEGACY_BETA_VERIFY_CALLS.store(0, Ordering::SeqCst);

        let config = mixed_config();
        let legacy_beta = explicit_legacy_beta();
        let mut rng = ChaCha20Rng::from_seed([29; 32]);
        let dealings = config
            .registry()
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing::<TinyGroup, ExplicitLegacyBetaBackend>(
                    dealer,
                    &secret(dealer),
                    &config,
                    &legacy_beta,
                    &mut rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect::<BTreeMap<_, _>>();

        assert_eq!(LEGACY_BETA_PAD_CALLS.load(Ordering::SeqCst), 12);
        assert_eq!(LEGACY_BETA_PROVE_CALLS.load(Ordering::SeqCst), 3);

        let receiver = idx(1);
        let peers = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
            .collect();
        complete::<TinyGroup, ExplicitLegacyBetaBackend>(
            receiver,
            &secret(receiver),
            &dealings[&receiver],
            &peers,
            &config,
            &legacy_beta,
        )
        .unwrap();

        assert_eq!(LEGACY_BETA_PAD_CALLS.load(Ordering::SeqCst), 16);
        assert_eq!(LEGACY_BETA_VERIFY_CALLS.load(Ordering::SeqCst), 3);
    }

    fn flat_statement(config: &DkgConfig<TinyGroup>) -> DealerProofStatement<TinyGroup> {
        DealerProofStatement::new(
            config,
            idx(1),
            [13; 32],
            vec![EvrfMessage([21; 32]), EvrfMessage([22; 32])],
            vec![
                TinyScalar::from_u64(5).unwrap(),
                TinyScalar::from_u64(7).unwrap(),
                TinyScalar::zero(),
                TinyScalar::from_u64(9).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(19).unwrap(),
                TinyScalar::from_u64(26).unwrap(),
                TinyScalar::from_u64(18).unwrap(),
                TinyScalar::from_u64(27).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(31).unwrap(),
                TinyScalar::from_u64(32).unwrap(),
                TinyScalar::from_u64(33).unwrap(),
                TinyScalar::from_u64(34).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(50).unwrap(),
                TinyScalar::from_u64(58).unwrap(),
                TinyScalar::from_u64(51).unwrap(),
                TinyScalar::from_u64(61).unwrap(),
            ],
        )
        .unwrap()
    }

    fn revealed_openings() -> Vec<(TinyScalar, TinyScalar)> {
        [(19, 31), (26, 32), (18, 33), (27, 34)]
            .into_iter()
            .map(|(share, pad)| {
                (
                    TinyScalar::from_u64(share).unwrap(),
                    TinyScalar::from_u64(pad).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn flat_dealer_proof_views_preserve_instance_and_receiver_order() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let witness = crate::main_golden::reconstruct_revealed_witness(
            &config,
            &statement,
            secret(idx(1)),
            vec![Some(TinyScalar::from_u64(5).unwrap()), None],
            revealed_openings(),
        )
        .unwrap();

        assert_eq!(statement.dealer(), idx(1));
        assert_eq!(statement.dealer_public_key(), &secret(idx(1)));
        assert_eq!(statement.dealer_message_root(), [13; 32]);
        assert_eq!(statement.instance_count(), 2);

        let random = statement.instance(0).unwrap();
        assert_eq!(random.effective_message(), EvrfMessage([21; 32]));
        assert_eq!(
            random.commitment_coefficients(),
            &[
                TinyScalar::from_u64(5).unwrap(),
                TinyScalar::from_u64(7).unwrap(),
            ]
        );
        assert_eq!(random.receiver_count(), 2);
        let first_receiver = random.receiver(0).unwrap();
        assert_eq!(first_receiver.participant(), idx(2));
        assert_eq!(first_receiver.public_key(), &secret(idx(2)));
        assert_eq!(
            first_receiver.share_commitment(),
            &TinyScalar::from_u64(19).unwrap()
        );
        assert_eq!(
            first_receiver.pad_commitment(),
            &TinyScalar::from_u64(31).unwrap()
        );
        assert_eq!(
            first_receiver.encrypted_share(),
            &TinyScalar::from_u64(50).unwrap()
        );
        assert_eq!(random.receiver(1).unwrap().participant(), idx(3));
        assert!(random.receiver(2).is_none());
        assert!(statement.instance(2).is_none());

        assert_eq!(witness.identity_secret(), &secret(idx(1)));
        assert_eq!(witness.instance_count(), 2);
        let random_witness = witness.instance(0).unwrap();
        assert_eq!(
            random_witness.polynomial_constant(),
            Some(&TinyScalar::from_u64(5).unwrap())
        );
        assert_eq!(random_witness.receiver_count(), 2);
        let first_opening = random_witness.receiver(0).unwrap();
        assert_eq!(first_opening.share(), &TinyScalar::from_u64(19).unwrap());
        assert_eq!(first_opening.pad(), &TinyScalar::from_u64(31).unwrap());
        assert!(random_witness.receiver(2).is_none());
        assert_eq!(witness.instance(1).unwrap().polynomial_constant(), None);
        assert!(witness.instance(2).is_none());
        assert_eq!(
            format!("{witness:?}"),
            "DealerProofWitness { identity_secret: \"<redacted>\", polynomial_constants: \"<redacted>\", receiver_openings: \"<redacted>\" }"
        );
    }

    #[test]
    fn flat_statement_construction_rejects_inexact_dimensions() {
        let config = mixed_config();
        let result = DealerProofStatement::new(
            &config,
            idx(1),
            [13; 32],
            vec![EvrfMessage([21; 32]), EvrfMessage([22; 32])],
            vec![TinyScalar::zero(); 3],
            vec![TinyScalar::one(); 4],
            vec![TinyScalar::one(); 4],
            vec![TinyScalar::one(); 4],
        );

        assert_eq!(result.unwrap_err(), Error::ProofGenerationFailed);
    }

    #[test]
    fn revealed_witness_reconstruction_checks_dimensions_and_kind_grammar() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let identity_secret = secret(idx(1));
        let random = TinyScalar::from_u64(5).unwrap();

        let cases = [
            (vec![Some(random)], revealed_openings()),
            (vec![None, None], revealed_openings()),
            (
                vec![Some(random), Some(TinyScalar::zero())],
                revealed_openings(),
            ),
            (
                vec![Some(random), None],
                revealed_openings().into_iter().take(3).collect(),
            ),
        ];

        for (polynomial_constants, receiver_openings) in cases {
            assert_eq!(
                crate::main_golden::reconstruct_revealed_witness(
                    &config,
                    &statement,
                    identity_secret,
                    polynomial_constants,
                    receiver_openings,
                )
                .unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }

    fn check_flat_relation(
        config: &DkgConfig<TinyGroup>,
        statement: &DealerProofStatement<TinyGroup>,
        witness: &crate::DealerProofWitness<TinyGroup>,
        alter_pad: bool,
    ) -> Result<()> {
        crate::main_golden::check_dealer_relation_with_pad(
            config,
            statement,
            witness,
            |message, _, peer_key| {
                let pad = match (message.0, *peer_key) {
                    (value, key) if value == [21; 32] && key == secret(idx(2)) => 31,
                    (value, key) if value == [21; 32] && key == secret(idx(3)) => 32,
                    (value, key) if value == [22; 32] && key == secret(idx(2)) => 33,
                    (value, key) if value == [22; 32] && key == secret(idx(3)) => 34,
                    _ => return Err(Error::ProofVerificationFailed),
                };
                TinyScalar::from_u64(pad + u64::from(alter_pad))
            },
        )
    }

    #[test]
    fn native_relation_checks_the_complete_flat_witness() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let witness = crate::main_golden::reconstruct_revealed_witness(
            &config,
            &statement,
            secret(idx(1)),
            vec![Some(TinyScalar::from_u64(5).unwrap()), None],
            revealed_openings(),
        )
        .unwrap();

        check_flat_relation(&config, &statement, &witness, false).unwrap();
        assert_eq!(
            check_flat_relation(&config, &statement, &witness, true).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn native_relation_rejects_altered_secret_constant_and_share() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let cases = [
            (
                secret(idx(2)),
                vec![Some(TinyScalar::from_u64(5).unwrap()), None],
                revealed_openings(),
            ),
            (
                secret(idx(1)),
                vec![Some(TinyScalar::from_u64(6).unwrap()), None],
                revealed_openings(),
            ),
            (
                secret(idx(1)),
                vec![Some(TinyScalar::from_u64(5).unwrap()), None],
                {
                    let mut openings = revealed_openings();
                    openings[0].0 = TinyScalar::from_u64(20).unwrap();
                    openings
                },
            ),
        ];

        for (identity_secret, polynomial_constants, receiver_openings) in cases {
            let witness = crate::main_golden::reconstruct_revealed_witness(
                &config,
                &statement,
                identity_secret,
                polynomial_constants,
                receiver_openings,
            )
            .unwrap();
            assert_eq!(
                check_flat_relation(&config, &statement, &witness, false).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }

    fn single_participant_config() -> DkgConfig<TinyGroup> {
        let participant = idx(1);
        let registry = ParticipantRegistry::new(vec![(
            participant,
            TinyGroup::mul_generator(&secret(participant)),
        )])
        .unwrap();
        DkgConfig::new(
            1,
            SessionId([8; 32]),
            registry,
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap()
    }

    fn dealer_dealings<B: EvrfProofBackend<TinyGroup>>(
        config: &DkgConfig<TinyGroup>,
        seed: u8,
    ) -> BTreeMap<ParticipantIndex, DkgDealing<TinyGroup>> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        config
            .registry()
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing::<TinyGroup, B>(
                    dealer,
                    &secret(dealer),
                    config,
                    &legacy_beta(),
                    &mut rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect()
    }

    fn dealer_messages<B: EvrfProofBackend<TinyGroup>>(
        config: &DkgConfig<TinyGroup>,
        seed: u8,
    ) -> BTreeMap<ParticipantIndex, DealerMessage<TinyGroup>> {
        dealer_dealings::<B>(config, seed)
            .into_iter()
            .map(|(dealer, dealing)| (dealer, dealing.message().clone()))
            .collect()
    }

    fn complete_receiver(
        receiver: ParticipantIndex,
        dealings: &BTreeMap<ParticipantIndex, DkgDealing<TinyGroup>>,
        config: &DkgConfig<TinyGroup>,
    ) -> Result<DkgOutput<TinyGroup>> {
        let peers = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
            .collect();
        complete::<TinyGroup, FakeBackend>(
            receiver,
            &secret(receiver),
            &dealings[&receiver],
            &peers,
            config,
            &legacy_beta(),
        )
    }

    #[test]
    fn config_constructors_validate_shape_and_bind_order() {
        for (config, expected) in [
            (
                DkgConfig::new_random(2, SessionId([7; 32]), registry()).unwrap(),
                DkgInstanceKind::Random,
            ),
            (
                DkgConfig::new_zero(2, SessionId([7; 32]), registry()).unwrap(),
                DkgInstanceKind::Zero,
            ),
        ] {
            assert_eq!(config.instances(), [expected]);
        }

        for threshold in [0, 4] {
            assert_eq!(
                DkgConfig::new_random(threshold, SessionId([7; 32]), registry(),).unwrap_err(),
                Error::InvalidThreshold {
                    threshold,
                    participants: 3,
                }
            );
        }

        assert_eq!(
            DkgConfig::new(2, SessionId([7; 32]), registry(), Vec::new(),).unwrap_err(),
            Error::EmptyDkgBatch
        );
        let config = mixed_config();
        let reversed = DkgConfig::new(
            config.threshold(),
            config.session_id(),
            config.registry().clone(),
            vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
        )
        .unwrap();
        assert_ne!(config.root(), reversed.root());
    }

    #[test]
    fn effective_message_binds_configuration_dealer_position_kind_and_nonce() {
        let configuration = mixed_config().root();
        let dealer = idx(1);
        let position = 0;
        let kind = DkgInstanceKind::Random;
        let nonce = DealerMessageNonce([3; DEALER_MESSAGE_NONCE_BYTES]);
        let message = effective_message(configuration, dealer, position, kind, nonce);
        let variants = [
            effective_message([9; 32], dealer, position, kind, nonce),
            effective_message(configuration, idx(2), position, kind, nonce),
            effective_message(configuration, dealer, 1, kind, nonce),
            effective_message(
                configuration,
                dealer,
                position,
                DkgInstanceKind::Zero,
                nonce,
            ),
            effective_message(
                configuration,
                dealer,
                position,
                kind,
                DealerMessageNonce([4; DEALER_MESSAGE_NONCE_BYTES]),
            ),
        ];
        for changed in variants {
            assert_ne!(message, changed);
        }
    }

    #[test]
    fn config_root_binds_every_configuration_dimension() {
        let base = mixed_config();
        let changed_registry = ParticipantRegistry::new(vec![
            (
                idx(1),
                TinyGroup::mul_generator(&TinyScalar::from_u64(4).unwrap()),
            ),
            (
                idx(2),
                TinyGroup::mul_generator(&TinyScalar::from_u64(5).unwrap()),
            ),
            (
                idx(3),
                TinyGroup::mul_generator(&TinyScalar::from_u64(6).unwrap()),
            ),
        ])
        .unwrap();
        let variants = [
            DkgConfig::new(
                2,
                SessionId([8; 32]),
                base.registry().clone(),
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                3,
                base.session_id(),
                base.registry().clone(),
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                2,
                base.session_id(),
                changed_registry,
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                2,
                base.session_id(),
                base.registry().clone(),
                vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
            )
            .unwrap(),
        ];
        for changed in variants {
            assert_ne!(base.root(), changed.root());
        }
    }

    #[test]
    fn single_participant_batch_skips_the_proof_backend() {
        let config = single_participant_config();
        let dealer = idx(1);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);

        let dealing = create_dealing::<TinyGroup, UnreachableBackend>(
            dealer,
            &secret(dealer),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap();
        assert!(dealing.message().proof.is_empty());
        assert!(dealing
            .message()
            .dealings
            .iter()
            .all(|body| body.encrypted_shares.is_empty()));

        verify_dealing::<TinyGroup, UnreachableBackend>(dealing.message(), &config, &legacy_beta())
            .unwrap();
        verify_dealings::<TinyGroup, UnreachableBackend>(
            &[dealing.message()],
            &config,
            &legacy_beta(),
        )
        .unwrap();

        let output = complete::<TinyGroup, UnreachableBackend>(
            dealer,
            &secret(dealer),
            &dealing,
            &BTreeMap::new(),
            &config,
            &legacy_beta(),
        )
        .unwrap();
        assert_eq!(output.instances().len(), 2);
        for instance in output.instances() {
            assert_eq!(
                instance.public_key(),
                &TinyGroup::mul_generator(&instance.secret_share().value)
            );
        }
        assert_eq!(output.instances()[1].public_key(), &TinyGroup::identity());
    }

    #[test]
    fn single_participant_batch_rejects_a_forged_proof() {
        let config = single_participant_config();
        let dealer = idx(1);
        let mut rng = ChaCha20Rng::from_seed([10; 32]);

        let mut dealing = create_dealing::<TinyGroup, UnreachableBackend>(
            dealer,
            &secret(dealer),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap();
        dealing.message.proof.push(1);

        assert_eq!(
            verify_dealing::<TinyGroup, UnreachableBackend>(
                dealing.message(),
                &config,
                &legacy_beta(),
            )
            .unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(
            verify_dealings::<TinyGroup, UnreachableBackend>(
                &[dealing.message()],
                &config,
                &legacy_beta(),
            )
            .unwrap_err(),
            Error::DealerProofVerificationFailed(dealer.get())
        );
    }

    #[test]
    fn mixed_batch_completes_atomically_for_all_participants() {
        let config = mixed_config();
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        let dealings = config
            .registry()
            .indexes()
            .map(|dealer| {
                (
                    dealer,
                    create_dealing::<TinyGroup, FakeBackend>(
                        dealer,
                        &secret(dealer),
                        &config,
                        &legacy_beta(),
                        &mut rng,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for dealing in dealings.values() {
            assert_eq!(dealing.message().dealings.len(), 2);
            assert_ne!(
                dealing.message().dealings[0].nonce,
                dealing.message().dealings[1].nonce
            );
            assert_ne!(
                dealing.message().dealings[0].commitment.coefficients(),
                dealing.message().dealings[1].commitment.coefficients()
            );
            let debug = format!("{dealing:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("private_shares: ["));
            verify_dealing::<TinyGroup, FakeBackend>(dealing.message(), &config, &legacy_beta())
                .unwrap();
        }

        let mut outputs = Vec::new();
        for receiver in config.registry().indexes() {
            let peers = dealings
                .iter()
                .filter(|(dealer, _)| **dealer != receiver)
                .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
                .collect();
            outputs.push(
                complete::<TinyGroup, FakeBackend>(
                    receiver,
                    &secret(receiver),
                    &dealings[&receiver],
                    &peers,
                    &config,
                    &legacy_beta(),
                )
                .unwrap(),
            );
        }

        for output in &outputs {
            assert!(format!("{output:?}").contains("<redacted>"));
            assert_eq!(output.configuration_root(), config.root());
            assert_eq!(output.instances().len(), 2);
            assert_eq!(output.instances()[1].public_key(), &TinyGroup::identity());
            assert_eq!(output.completion_root(), outputs[0].completion_root());
            for position in 0..2 {
                assert_eq!(
                    output.instances()[position].public_key(),
                    outputs[0].instances()[position].public_key()
                );
                assert_eq!(
                    output.instances()[position].public_key_shares(),
                    outputs[0].instances()[position].public_key_shares()
                );
            }
        }
    }

    #[test]
    fn generic_backend_cannot_bypass_dealer_proof_limit() {
        let config = mixed_config();
        let dealer = idx(1);
        let mut rng = ChaCha20Rng::from_seed([15; 32]);

        assert_eq!(
            create_dealing::<TinyGroup, OversizedProofBackend>(
                dealer,
                &secret(dealer),
                &config,
                &legacy_beta(),
                &mut rng,
            )
            .unwrap_err(),
            Error::InvalidEncoding
        );

        let mut message = create_dealing::<TinyGroup, FakeBackend>(
            dealer,
            &secret(dealer),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap()
        .message()
        .clone();
        message.proof.resize(MAX_DEALER_PROOF_BYTES + 1, 0);
        assert_eq!(
            verify_dealing::<TinyGroup, OversizedProofBackend>(&message, &config, &legacy_beta(),)
                .unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn completion_rejects_unregistered_peer_before_aggregation() {
        let config = mixed_config();
        let receiver = idx(1);
        let mut rng = ChaCha20Rng::from_seed([15; 32]);
        let own_dealing = create_dealing::<TinyGroup, FakeBackend>(
            receiver,
            &secret(receiver),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap();
        let messages = dealer_messages::<FakeBackend>(&config, 16);
        let base_peers = messages
            .into_iter()
            .filter(|(dealer, _)| *dealer != receiver)
            .collect::<BTreeMap<_, _>>();
        let unknown = idx(4);

        let mut well_shaped = base_peers[&idx(2)].clone();
        well_shaped.dealer = unknown;
        let mut short = well_shaped.clone();
        short.dealings.clear();

        for extra in [short, well_shaped] {
            let mut peers = base_peers.clone();
            peers.insert(unknown, extra);
            assert_eq!(
                complete::<TinyGroup, FakeBackend>(
                    receiver,
                    &secret(receiver),
                    &own_dealing,
                    &peers,
                    &config,
                    &legacy_beta(),
                )
                .unwrap_err(),
                Error::UnknownParticipant(unknown.get())
            );
        }
    }

    #[test]
    fn completion_rejects_missing_or_malformed_dealers_atomically() {
        let config = mixed_config();
        let receiver = idx(1);
        let dealings = dealer_dealings::<FakeBackend>(&config, 17);
        let valid_peers = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
            .collect::<BTreeMap<_, _>>();

        let mut missing = valid_peers.clone();
        missing.remove(&idx(3));
        let mut malformed = valid_peers;
        malformed.get_mut(&idx(2)).unwrap().dealings.pop();

        for (peers, expected) in [
            (missing, Error::MissingDealing(3)),
            (
                malformed,
                Error::InvalidDealingCount {
                    expected: 2,
                    actual: 1,
                },
            ),
        ] {
            assert_eq!(
                complete::<TinyGroup, FakeBackend>(
                    receiver,
                    &secret(receiver),
                    &dealings[&receiver],
                    &peers,
                    &config,
                    &legacy_beta(),
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn completion_root_changes_with_an_independent_accepted_batch() {
        let config = mixed_config();
        let first = dealer_dealings::<FakeBackend>(&config, 18);
        let second = dealer_dealings::<FakeBackend>(&config, 19);
        let first_output = complete_receiver(idx(1), &first, &config).unwrap();
        let second_output = complete_receiver(idx(1), &second, &config).unwrap();
        let first_messages = first
            .iter()
            .map(|(dealer, dealing)| (*dealer, dealing.message()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            first_output.configuration_root(),
            second_output.configuration_root()
        );
        assert_ne!(
            first_output.completion_root(),
            second_output.completion_root()
        );
        assert_ne!(
            first_output.completion_root(),
            completion_root::<TinyGroup, FakeBackend>([9; 32], &first_messages)
        );
    }

    #[test]
    fn completion_root_binds_the_accepting_proof_backend() {
        let config = mixed_config();
        let dealings = dealer_dealings::<FakeBackend>(&config, 20);
        let receiver = idx(1);
        let peers = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message().clone()))
            .collect();

        let default_output = complete::<TinyGroup, FakeBackend>(
            receiver,
            &secret(receiver),
            &dealings[&receiver],
            &peers,
            &config,
            &legacy_beta(),
        )
        .unwrap();
        let alternate_output = complete::<TinyGroup, AlternateFakeBackend>(
            receiver,
            &secret(receiver),
            &dealings[&receiver],
            &peers,
            &config,
            &legacy_beta(),
        )
        .unwrap();

        assert_eq!(
            default_output.configuration_root(),
            alternate_output.configuration_root()
        );
        assert_eq!(default_output.instances(), alternate_output.instances());
        assert_ne!(
            default_output.completion_root(),
            alternate_output.completion_root()
        );
    }

    #[test]
    fn commitment_constant_shape_matches_the_configured_instance_kind() {
        let config = mixed_config();
        let mut rng = ChaCha20Rng::from_seed([17; 32]);
        let message = create_dealing::<TinyGroup, FakeBackend>(
            idx(1),
            &secret(idx(1)),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap()
        .message()
        .clone();

        assert!(message.dealings[0].commitment.constant().is_some());
        assert!(message.dealings[1].commitment.constant().is_none());

        let mut explicit_zero = message.clone();
        explicit_zero.dealings[1].commitment = FeldmanCommitment::from_coefficients(
            explicit_zero.dealings[1].commitment.coefficients(),
        )
        .unwrap();
        assert_eq!(
            verify_dealing::<TinyGroup, FakeBackend>(&explicit_zero, &config, &legacy_beta(),)
                .unwrap_err(),
            Error::CommitmentKindMismatch(1)
        );

        let mut missing_random = message;
        let tail = missing_random.dealings[0].commitment.coefficients()[1..].to_vec();
        missing_random.dealings[0].commitment = FeldmanCommitment::from_zero_tail(tail);
        assert_eq!(
            verify_dealing::<TinyGroup, FakeBackend>(&missing_random, &config, &legacy_beta(),)
                .unwrap_err(),
            Error::CommitmentKindMismatch(0)
        );
    }

    #[test]
    fn dealing_root_excludes_proof_but_binds_body_order() {
        let config = mixed_config();
        let mut rng = ChaCha20Rng::from_seed([19; 32]);
        let mut message = create_dealing::<TinyGroup, FakeBackend>(
            idx(1),
            &secret(idx(1)),
            &config,
            &legacy_beta(),
            &mut rng,
        )
        .unwrap()
        .message()
        .clone();
        let root = message.root();
        message.proof.push(0xff);
        assert_eq!(message.root(), root);
        message.dealings.swap(0, 1);
        assert_ne!(message.root(), root);
    }

    #[test]
    fn dealer_message_root_binds_all_proof_independent_fields() {
        let config = mixed_config();
        let original = dealer_messages::<FakeBackend>(&config, 23)[&idx(1)].clone();
        let root = original.root();

        let mut changed = original.clone();
        changed.configuration_root[0] ^= 1;
        assert_ne!(changed.root(), root);

        let mut changed = original.clone();
        changed.dealer = idx(2);
        assert_ne!(changed.root(), root);

        let mut changed = original.clone();
        changed.dealings[0].nonce.0[0] ^= 1;
        assert_ne!(changed.root(), root);

        let mut changed = original.clone();
        let mut coefficients = changed.dealings[0].commitment.coefficients();
        coefficients[0] = TinyGroup::add(&coefficients[0], &TinyGroup::generator());
        changed.dealings[0].commitment =
            FeldmanCommitment::from_coefficients(coefficients).unwrap();
        assert_ne!(changed.root(), root);

        let mut changed = original;
        let encrypted = changed.dealings[0].encrypted_shares[&idx(2)].encrypted_share;
        changed.dealings[0]
            .encrypted_shares
            .get_mut(&idx(2))
            .unwrap()
            .encrypted_share = TinyGroup::add(&encrypted, &TinyScalar::one());
        assert_ne!(changed.root(), root);
    }

    #[test]
    fn cross_dealer_verification_uses_batch_path_and_attributes_bad_proof() {
        BATCH_VERIFY_CALLS.store(0, Ordering::SeqCst);
        SINGLE_VERIFY_CALLS.store(0, Ordering::SeqCst);
        let config = mixed_config();
        let messages = dealer_messages::<CountingBackend>(&config, 29);
        let refs = messages.values().collect::<Vec<_>>();
        verify_dealings::<TinyGroup, CountingBackend>(&refs, &config, &legacy_beta()).unwrap();
        assert_eq!(BATCH_VERIFY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SINGLE_VERIFY_CALLS.load(Ordering::SeqCst), 0);

        let mut messages = dealer_messages::<FakeBackend>(&config, 31);
        messages.get_mut(&idx(2)).unwrap().proof[0] ^= 1;
        let refs = messages.values().collect::<Vec<_>>();
        assert_eq!(
            verify_dealings::<TinyGroup, FakeBackend>(&refs, &config, &legacy_beta()).unwrap_err(),
            Error::DealerProofVerificationFailed(2)
        );
    }

    #[test]
    fn cross_dealer_fallback_preserves_original_batch_error() {
        let config = mixed_config();
        let messages = dealer_messages::<BatchRejectingBackend>(&config, 37);
        let refs = messages.values().collect::<Vec<_>>();
        assert_eq!(
            verify_dealings::<TinyGroup, BatchRejectingBackend>(&refs, &config, &legacy_beta(),)
                .unwrap_err(),
            Error::InvalidEncoding
        );
    }
}
