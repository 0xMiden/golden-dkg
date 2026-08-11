//! DKG message skeleton over a generic Golden group.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;

use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::{
    Error, FeldmanCommitment, GoldenGroup, GoldenScalar, ParticipantIndex, Polynomial, Result,
    Share,
};

/// Protocol version used in transcript binding.
pub const PROTOCOL_VERSION: u32 = 2;

/// Byte length of the paper's `lambda`-bit dealer message `msg_i`.
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

/// Paper `lambda`-bit dealer message `msg_i`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerMessageNonce(pub [u8; DEALER_MESSAGE_NONCE_BYTES]);

impl DealerMessageNonce {
    /// Create a random dealer message nonce.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; DEALER_MESSAGE_NONCE_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Public participant registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRegistry<G: GoldenGroup> {
    participants: BTreeMap<ParticipantIndex, G::Element>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> ParticipantRegistry<G> {
    /// Build a registry from participant identity public keys.
    pub fn new(entries: Vec<(ParticipantIndex, G::Element)>) -> Result<Self> {
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

/// DKG configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig<G: GoldenGroup> {
    /// Threshold.
    pub threshold: usize,
    /// Session ID.
    pub session_id: SessionId,
    /// Public eVRF leftover-hash-lemma coefficient from setup.
    pub beta: G::Scalar,
    /// Participant registry.
    pub registry: ParticipantRegistry<G>,
}

impl<G: GoldenGroup> DkgConfig<G> {
    /// Create a new DKG configuration.
    pub fn new(
        threshold: usize,
        session_id: SessionId,
        beta: G::Scalar,
        registry: ParticipantRegistry<G>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > registry.len() {
            return Err(Error::InvalidThreshold {
                threshold,
                participants: registry.len(),
            });
        }
        Ok(Self {
            threshold,
            session_id,
            beta,
            registry,
        })
    }
}

/// Public statement proven for one receiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvrfStatement<G: GoldenGroup> {
    /// Protocol version.
    pub protocol_version: u32,
    /// Backend identifier.
    pub backend_id: &'static str,
    /// Session ID.
    pub session_id: SessionId,
    /// Registry root.
    pub registry_root: TranscriptRoot,
    /// DKG threshold.
    pub threshold: usize,
    /// Dealer.
    pub dealer: ParticipantIndex,
    /// Receiver.
    pub receiver: ParticipantIndex,
    /// Paper dealer message `msg_i`.
    pub msg_i: DealerMessageNonce,
    /// Public eVRF leftover-hash-lemma coefficient from setup.
    pub beta: G::Scalar,
    /// Dealer identity public key.
    pub dealer_public_key: G::Element,
    /// Receiver identity public key.
    pub receiver_public_key: G::Element,
    /// Ordered Feldman commitment coefficients for the dealer polynomial.
    pub commitment_coefficients: Vec<G::Element>,
    /// Public commitment to the receiver share.
    pub share_commitment: G::Element,
    /// Public commitment to the pad scalar.
    pub pad_commitment: G::Element,
    /// Encrypted share scalar, `pad + share`.
    pub encrypted_share: G::Scalar,
    /// Dealing transcript root.
    pub transcript_root: TranscriptRoot,
}

impl<G: GoldenGroup> EvrfStatement<G> {
    /// Compute a stable statement root.
    pub fn root(&self) -> TranscriptRoot {
        statement_root(self)
    }
}

/// Private witness used by an eVRF proof backend for one receiver.
#[derive(Clone, Eq, PartialEq)]
pub struct EvrfWitness<G: GoldenGroup> {
    /// Dealer identity secret opening the dealer identity public key.
    pub identity_secret: G::Scalar,
    /// Polynomial coefficients in ascending degree order.
    pub polynomial_coefficients: Vec<G::Scalar>,
    /// Scalar share opening the public share commitment.
    pub share: G::Scalar,
    /// Scalar pad opening the public pad commitment.
    pub pad: G::Scalar,
}

impl<G: GoldenGroup> core::fmt::Debug for EvrfWitness<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvrfWitness")
            .field("identity_secret", &"<redacted>")
            .field("polynomial_coefficients", &"<redacted>")
            .field("share", &"<redacted>")
            .field("pad", &"<redacted>")
            .finish()
    }
}

/// eVRF proof backend boundary.
///
/// One proof object covers every non-self receiver in a dealer message. The
/// dealer produces a single batched proof via [`EvrfProofBackend::prove_batch`]
/// and the public verifier checks it once via [`EvrfProofBackend::verify_batch`]
/// against the full ordered receiver statement list. Per-receiver pad
/// derivation stays a separate method because the dealer computes pads while
/// building encrypted shares, before the batched statement list exists.
pub trait EvrfProofBackend<G: GoldenGroup> {
    /// Stable, versioned identity of this proof protocol and byte grammar.
    const PROOF_ID: &'static [u8];

    /// Evaluate the per-recipient pad scalar for the paper eVRF input shape.
    ///
    /// `peer_public_key` is the DH peer the dealer computes a shared secret
    /// against. In the dealer-side `create_dealing` path the peer is the
    /// receiver (so the receiver can decrypt with `receiver_identity_secret`),
    /// so callers pass `receiver_public_key` for both arguments there. A
    /// paper-faithful backend that follows the `(msg_i, PK_j)` input shape
    /// keeps the same argument; the split exists so a future receiver-side
    /// re-derivation can swap in a different peer without changing the trait.
    ///
    /// The default preserves the prototype DH-transcript derivation. A
    /// paper-faithful backend overrides this so pad generation and proof
    /// generation use the same eVRF relation.
    fn derive_pad(
        msg_i: DealerMessageNonce,
        _beta: &G::Scalar,
        identity_secret: &G::Scalar,
        peer_public_key: &G::Element,
        receiver_public_key: &G::Element,
    ) -> Result<G::Scalar> {
        let shared_secret = G::mul(peer_public_key, identity_secret);
        derive_default_pad::<G>(msg_i, receiver_public_key, &shared_secret)
    }

    /// Produce one batched proof covering every receiver statement.
    ///
    /// `statements` and `witnesses` are in the canonical ordered receiver list
    /// (excluding the dealer). The backend must bind the full ordered list into
    /// the proof transcript.
    fn prove_batch(
        statements: &[EvrfStatement<G>],
        witnesses: &[EvrfWitness<G>],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>>;

    /// Verify one batched proof against the full ordered receiver statement
    /// list. Implementations may use verifier-side randomness for multiexp
    /// (e.g. to pool scalars across the batch); when they do, soundness still
    /// follows from the standard small-subgroup-checked Schnorr argument as
    /// long as the per-statement challenge is derived from the transcript
    /// independent of that batching randomness. Verifier randomness affects
    /// only the amortized cost, not whether a bad proof is accepted.
    fn verify_batch(statements: &[EvrfStatement<G>], proof: &[u8]) -> Result<()>;

    /// Verify several independent dealer proofs.
    ///
    /// Each entry contains the ordered receiver statements and proof bytes for
    /// one dealer. Backends may combine the proof equations into one MSM. The
    /// combining coefficients must be nonzero and unpredictable to the
    /// dealers, using fresh verifier entropy or a domain-separated transcript
    /// that binds the complete ordered batch. Fixed or input-independent
    /// coefficients do not provide sound batch verification. The default
    /// preserves correctness for backends without that optimization.
    fn verify_proof_batch(batches: &[(&[EvrfStatement<G>], &[u8])]) -> Result<()> {
        for (statements, proof) in batches {
            Self::verify_batch(statements, proof)?;
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

/// Dealer broadcast message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealerMessage<G: GoldenGroup> {
    /// Session ID.
    pub session_id: SessionId,
    /// Registry root.
    pub registry_root: TranscriptRoot,
    /// Dealer.
    pub dealer: ParticipantIndex,
    /// Paper dealer message `msg_i`.
    pub msg_i: DealerMessageNonce,
    /// Dealer Feldman commitment.
    pub commitment: FeldmanCommitment<G>,
    /// Public encrypted-share data, keyed by receiver.
    pub encrypted_shares: BTreeMap<ParticipantIndex, EncryptedShare<G>>,
    /// Batched proof covering every non-self receiver in this message.
    pub proof: Vec<u8>,
    /// Transcript root for the dealing.
    pub transcript_root: TranscriptRoot,
}

/// Local output from creating a dealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgDealing<G: GoldenGroup> {
    /// Broadcast message.
    pub message: DealerMessage<G>,
    /// Dealer private share for itself.
    pub private_share: Share<G::Scalar>,
}

/// DKG output for one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgOutput<G: GoldenGroup> {
    /// Shared public key.
    pub public_key: G::Element,
    /// This participant's secret share.
    pub secret_share: Share<G::Scalar>,
    /// Public key shares for each participant.
    pub public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
    /// Transcript root over verified dealings.
    pub transcript_root: TranscriptRoot,
}

/// Create one dealer message.
pub fn create_dealing<G, B>(
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    config: &DkgConfig<G>,
    rng: &mut impl CryptoRngCore,
) -> Result<DkgDealing<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    create_dealing_with_secret::<G, B>(
        dealer,
        dealer_identity_secret,
        G::Scalar::random(rng),
        config,
        rng,
    )
}

/// Create one dealer message with a caller chosen polynomial constant.
///
/// This is the same dealing flow as [`create_dealing`], except the caller sets
/// the dealer polynomial's constant term. Ordinary DKG callers should keep
/// using [`create_dealing`].
///
/// EHTDH1 uses this helper for its zero sharing run. First, run normal DKG for
/// `x`. Then run a second DKG where every dealer passes `G::Scalar::zero()` as
/// `polynomial_secret`. The EHTDH1 adapter derives the second session id. It
/// rejects the result unless the aggregate public key is the group identity.
pub fn create_dealing_with_secret<G, B>(
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    polynomial_secret: G::Scalar,
    config: &DkgConfig<G>,
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

    let polynomial = Polynomial::random_with_secret(polynomial_secret, config.threshold, rng)?;
    let commitment = FeldmanCommitment::<G>::commit(&polynomial)?;
    let msg_i = DealerMessageNonce::random(rng);

    let mut shares = BTreeMap::new();
    for receiver in config.registry.indexes() {
        let share = polynomial.evaluate(receiver)?;
        shares.insert(receiver, share.value);
    }

    let mut encrypted_shares = BTreeMap::new();
    let mut pads = BTreeMap::new();
    for (receiver, share) in shares.iter().filter(|(receiver, _)| **receiver != dealer) {
        let receiver_public_key = config.registry.public_key(*receiver)?;
        // Dealer-side pad: DH peer is the receiver, so they can re-derive the
        // same pad with `dealer_public_key` + their own identity secret. See
        // `EvrfProofBackend::derive_pad` for why the two PK arguments match.
        let pad = B::derive_pad(
            msg_i,
            &config.beta,
            dealer_identity_secret,
            receiver_public_key,
            receiver_public_key,
        )?;
        encrypted_shares.insert(
            *receiver,
            EncryptedShare {
                pad_commitment: G::mul_generator(&pad),
                encrypted_share: share.add(&pad),
            },
        );
        pads.insert(*receiver, pad);
    }

    let transcript_root = dealing_root::<G>(
        config.session_id,
        config.registry.root(),
        dealer,
        msg_i,
        &commitment,
        &encrypted_shares,
    );

    let mut statements = Vec::new();
    let mut witnesses = Vec::new();
    for (receiver, share_value) in shares.iter().filter(|(receiver, _)| **receiver != dealer) {
        let share_commitment = commitment.public_key_share(*receiver)?;
        let encrypted_share = encrypted_shares
            .get(receiver)
            .cloned()
            .ok_or(Error::MissingShare(receiver.get()))?;
        let statement = statement_for_receiver::<G>(
            config,
            dealer,
            *receiver,
            msg_i,
            share_commitment,
            commitment.coefficients().to_vec(),
            encrypted_share,
            transcript_root,
        )?;
        let witness = EvrfWitness {
            identity_secret: dealer_identity_secret.clone(),
            polynomial_coefficients: polynomial.coefficients().to_vec(),
            share: share_value.clone(),
            // Reuse the authoritative pad we just derived above instead of
            // back-solving it from `encrypted_share - share`. The two are
            // equal by construction, but routing the source of truth forward
            // keeps the witness honest if `EncryptedShare::encrypted_share`
            // ever picks up extra padding contributors.
            pad: pads
                .get(receiver)
                .cloned()
                .ok_or(Error::MissingShare(receiver.get()))?,
        };
        statements.push(statement);
        witnesses.push(witness);

        let share = Share {
            participant: *receiver,
            value: share_value.clone(),
        };
        if !commitment.verify_share(&share)? {
            return Err(Error::CommitmentVerificationFailed);
        }
    }

    // A dealer with no other receivers has nothing for the eVRF proof to
    // attest to; the sole share is checked directly below instead.
    let proof = if statements.is_empty() {
        Vec::new()
    } else {
        B::prove_batch(&statements, &witnesses, rng)?
    };

    let private_share = Share {
        participant: dealer,
        value: shares
            .get(&dealer)
            .cloned()
            .ok_or(Error::MissingShare(dealer.get()))?,
    };
    if !commitment.verify_share(&private_share)? {
        return Err(Error::CommitmentVerificationFailed);
    }

    Ok(DkgDealing {
        message: DealerMessage {
            session_id: config.session_id,
            registry_root: config.registry.root(),
            dealer,
            msg_i,
            commitment,
            encrypted_shares,
            proof,
            transcript_root,
        },
        private_share,
    })
}

fn dealing_statements<G>(
    message: &DealerMessage<G>,
    config: &DkgConfig<G>,
) -> Result<Vec<EvrfStatement<G>>>
where
    G: GoldenGroup,
{
    if message.session_id != config.session_id {
        return Err(Error::SessionMismatch);
    }
    if message.registry_root != config.registry.root() {
        return Err(Error::RegistryMismatch);
    }
    config.registry.public_key(message.dealer)?;
    if message.commitment.coefficients().len() != config.threshold {
        return Err(Error::InvalidCommitmentDegree {
            expected: config.threshold,
            actual: message.commitment.coefficients().len(),
        });
    }

    let expected_root = dealing_root::<G>(
        message.session_id,
        message.registry_root,
        message.dealer,
        message.msg_i,
        &message.commitment,
        &message.encrypted_shares,
    );
    if expected_root != message.transcript_root {
        return Err(Error::ProofVerificationFailed);
    }
    ensure_public_share_keys(message, config)?;

    let mut statements = Vec::new();
    for receiver in public_share_receivers(config, message.dealer) {
        let share_commitment = message.commitment.public_key_share(receiver)?;
        let encrypted_share = message
            .encrypted_shares
            .get(&receiver)
            .cloned()
            .ok_or(Error::MissingShare(receiver.get()))?;
        let encrypted_share_commitment = G::mul_generator(&encrypted_share.encrypted_share);
        let expected_encrypted_share_commitment =
            G::add(&share_commitment, &encrypted_share.pad_commitment);
        if encrypted_share_commitment != expected_encrypted_share_commitment {
            return Err(Error::CommitmentVerificationFailed);
        }

        let statement = statement_for_receiver::<G>(
            config,
            message.dealer,
            receiver,
            message.msg_i,
            share_commitment,
            message.commitment.coefficients().to_vec(),
            encrypted_share,
            message.transcript_root,
        )?;
        statements.push(statement);
    }

    Ok(statements)
}

/// Verify one dealer message.
pub fn verify_dealing<G, B>(message: &DealerMessage<G>, config: &DkgConfig<G>) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let statements = dealing_statements::<G>(message, config)?;
    if statements.is_empty() {
        // A dealer with no other receivers (n=1) has no eVRF statements to
        // prove, so an empty proof is accepted without verifying knowledge of
        // the dealer's registered key. See
        // `single_participant_dkg_completes_without_proving` for why this is
        // safe in the single-participant case.
        return if message.proof.is_empty() {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        };
    }
    B::verify_batch(&statements, &message.proof)
}

/// Verify several independent dealer messages in one backend call.
///
/// Every message is checked against `config` before any proof equations are
/// combined. Backends without a cross-proof optimization use the trait's
/// linear fallback. If combined verification fails, each proof is retried so
/// the returned error can identify an invalid dealer. The original batch error
/// is preserved if every individual proof passes.
pub fn verify_dealings<G, B>(messages: &[&DealerMessage<G>], config: &DkgConfig<G>) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    if messages.is_empty() {
        return Err(Error::ProofVerificationFailed);
    }
    let statement_batches: Vec<Vec<EvrfStatement<G>>> = messages
        .iter()
        .map(|message| dealing_statements::<G>(message, config))
        .collect::<Result<_>>()?;
    if statement_batches.iter().all(Vec::is_empty) {
        // Every message is from a dealer with no other receivers (n=1), so
        // none has an eVRF statement to prove; see `verify_dealing` and
        // `single_participant_dkg_completes_without_proving` for why an empty
        // proof is accepted here.
        for message in messages {
            if !message.proof.is_empty() {
                return Err(Error::DealerProofVerificationFailed(message.dealer.get()));
            }
        }
        return Ok(());
    }
    let proof_batches: Vec<_> = statement_batches
        .iter()
        .zip(messages.iter())
        .map(|(statements, message)| (statements.as_slice(), message.proof.as_slice()))
        .collect();
    let batch_error = match B::verify_proof_batch(&proof_batches) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    for ((statements, proof), message) in proof_batches.iter().zip(messages) {
        if B::verify_batch(statements, proof).is_err() {
            return Err(Error::DealerProofVerificationFailed(message.dealer.get()));
        }
    }
    Err(batch_error)
}

/// Verify one dealer message for a concrete receiver before accepting it.
///
/// This performs public verification and, for non-dealer receivers, checks that
/// the receiver can derive and decrypt its own share from the dealing.
pub fn verify_dealing_for_receiver<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    message: &DealerMessage<G>,
    config: &DkgConfig<G>,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let receiver_public_key = config.registry.public_key(receiver)?;
    if G::mul_generator(receiver_identity_secret) != *receiver_public_key {
        return Err(Error::IdentityKeyMismatch);
    }
    verify_dealing::<G, B>(message, config)?;
    if receiver != message.dealer {
        decrypt_share_for_receiver::<G, B>(receiver, receiver_identity_secret, message, config)?;
    }
    Ok(())
}

/// Complete the DKG for one receiver after all dealings were verified.
///
/// The receiver's contribution from its own dealing comes from the local
/// `private_share`; peer contributions are decrypted from public dealer messages.
pub fn complete<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    own_dealing: &DkgDealing<G>,
    peer_dealings: &BTreeMap<ParticipantIndex, DealerMessage<G>>,
    config: &DkgConfig<G>,
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
    if own_dealing.private_share.participant != receiver {
        return Err(Error::PrivateShareParticipantMismatch {
            expected: receiver.get(),
            actual: own_dealing.private_share.participant.get(),
        });
    }

    let mut all_dealings = BTreeMap::new();
    all_dealings.insert(own_dealing.message.dealer, own_dealing.message.clone());
    for (dealer, message) in peer_dealings {
        if *dealer != message.dealer {
            return Err(Error::DealerKeyMismatch {
                map_key: dealer.get(),
                message_dealer: message.dealer.get(),
            });
        }
        if all_dealings
            .insert(message.dealer, message.clone())
            .is_some()
        {
            return Err(Error::DuplicateParticipantIndex(message.dealer.get()));
        }
    }

    let messages: Vec<_> = config
        .registry
        .indexes()
        .map(|dealer| {
            all_dealings
                .get(&dealer)
                .ok_or(Error::MissingDealing(dealer.get()))
        })
        .collect::<Result<_>>()?;
    verify_dealings::<G, B>(&messages, config)?;

    let mut secret_share_value = G::Scalar::zero();
    for message in all_dealings.values() {
        let share = if message.dealer == receiver {
            own_dealing.private_share.clone()
        } else {
            decrypt_share_for_receiver::<G, B>(receiver, receiver_identity_secret, message, config)?
        };
        if !message.commitment.verify_share(&share)? {
            return Err(Error::CommitmentVerificationFailed);
        }
        secret_share_value = secret_share_value.add(&share.value);
    }

    let mut public_key = G::identity();
    for message in all_dealings.values() {
        public_key = G::add(&public_key, &message.commitment.public_key());
    }

    let mut public_key_shares = BTreeMap::new();
    for participant in config.registry.indexes() {
        let mut share_key = G::identity();
        for message in all_dealings.values() {
            share_key = G::add(
                &share_key,
                &message.commitment.public_key_share(participant)?,
            );
        }
        public_key_shares.insert(participant, share_key);
    }

    Ok(DkgOutput {
        public_key,
        secret_share: Share {
            participant: receiver,
            value: secret_share_value,
        },
        public_key_shares,
        transcript_root: completion_root::<G>(&all_dealings),
    })
}

fn registry_root<G: GoldenGroup>(
    participants: &BTreeMap<ParticipantIndex, G::Element>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"registry");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.usize(b"len", participants.len());
    for (participant, public_key) in participants {
        transcript.participant(b"participant", *participant);
        transcript.element::<G>(b"public-key", public_key);
    }
    transcript.root()
}

impl<G: GoldenGroup> DealerMessage<G> {
    /// Recompute the dealing transcript root from the current message fields.
    ///
    /// This is the same root `create_dealing` embedded at construction. It
    /// exists so callers can rebuild the root after constructing a message
    /// from fields that do not carry it, such as wire decode.
    ///
    /// Do not call this after mutating fields that will be verified. A message
    /// whose fields changed and whose root was just recomputed is no longer
    /// the message the dealer signed. Tests may use this helper when they need
    /// a stable root for a constructed fixture.
    pub fn recompute_transcript_root(&self) -> TranscriptRoot {
        dealing_root(
            self.session_id,
            self.registry_root,
            self.dealer,
            self.msg_i,
            &self.commitment,
            &self.encrypted_shares,
        )
    }
}

fn dealing_root<G: GoldenGroup>(
    session_id: SessionId,
    registry_root: TranscriptRoot,
    dealer: ParticipantIndex,
    msg_i: DealerMessageNonce,
    commitment: &FeldmanCommitment<G>,
    encrypted_shares: &BTreeMap<ParticipantIndex, EncryptedShare<G>>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"dealing");
    transcript.u32(b"version", PROTOCOL_VERSION);
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"session", &session_id.0);
    transcript.bytes(b"registry", &registry_root);
    transcript.participant(b"dealer", dealer);
    transcript.bytes(b"msg-i", &msg_i.0);
    transcript.usize(b"commitment-len", commitment.coefficients().len());
    for coefficient in commitment.coefficients() {
        transcript.element::<G>(b"commitment", coefficient);
    }
    transcript.usize(b"encrypted-shares-len", encrypted_shares.len());
    for (receiver, encrypted_share) in encrypted_shares {
        transcript.participant(b"encrypted-receiver", *receiver);
        transcript.element::<G>(b"pad-commitment", &encrypted_share.pad_commitment);
        transcript.scalar::<G>(b"encrypted-share", &encrypted_share.encrypted_share);
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

fn ensure_public_share_keys<G>(message: &DealerMessage<G>, config: &DkgConfig<G>) -> Result<()>
where
    G: GoldenGroup,
{
    for receiver in message.encrypted_shares.keys() {
        if *receiver == message.dealer || config.registry.public_key(*receiver).is_err() {
            return Err(Error::UnexpectedShare(receiver.get()));
        }
    }
    for receiver in public_share_receivers(config, message.dealer) {
        if !message.encrypted_shares.contains_key(&receiver) {
            return Err(Error::MissingShare(receiver.get()));
        }
    }
    Ok(())
}

fn decrypt_share_for_receiver<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    message: &DealerMessage<G>,
    config: &DkgConfig<G>,
) -> Result<Share<G::Scalar>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let encrypted_share = message
        .encrypted_shares
        .get(&receiver)
        .ok_or(Error::MissingShare(receiver.get()))?;
    let pad = derive_receiver_pad::<G, B>(
        config,
        message.dealer,
        receiver,
        receiver_identity_secret,
        message.msg_i,
    )?;
    let share = Share {
        participant: receiver,
        value: encrypted_share.encrypted_share.sub(&pad),
    };

    if !message.commitment.verify_share(&share)? {
        return Err(Error::CommitmentVerificationFailed);
    }

    Ok(share)
}

fn completion_root<G: GoldenGroup>(
    dealings: &BTreeMap<ParticipantIndex, DealerMessage<G>>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"completion");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.usize(b"dealings-len", dealings.len());
    for (dealer, message) in dealings {
        transcript.participant(b"dealer", *dealer);
        transcript.bytes(b"dealing-root", &message.transcript_root);
    }
    transcript.root()
}

#[allow(clippy::too_many_arguments)]
fn statement_for_receiver<G: GoldenGroup>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    receiver: ParticipantIndex,
    msg_i: DealerMessageNonce,
    share_commitment: G::Element,
    commitment_coefficients: Vec<G::Element>,
    encrypted_share: EncryptedShare<G>,
    transcript_root: TranscriptRoot,
) -> Result<EvrfStatement<G>> {
    Ok(EvrfStatement {
        protocol_version: PROTOCOL_VERSION,
        backend_id: G::BACKEND_ID,
        session_id: config.session_id,
        registry_root: config.registry.root(),
        threshold: config.threshold,
        dealer,
        receiver,
        msg_i,
        beta: config.beta.clone(),
        dealer_public_key: config.registry.public_key(dealer)?.clone(),
        receiver_public_key: config.registry.public_key(receiver)?.clone(),
        commitment_coefficients,
        share_commitment,
        pad_commitment: encrypted_share.pad_commitment,
        encrypted_share: encrypted_share.encrypted_share,
        transcript_root,
    })
}

fn statement_root<G: GoldenGroup>(statement: &EvrfStatement<G>) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"evrf-statement");
    transcript.u32(b"version", statement.protocol_version);
    transcript.bytes(b"backend", statement.backend_id.as_bytes());
    transcript.bytes(b"session", &statement.session_id.0);
    transcript.bytes(b"registry", &statement.registry_root);
    transcript.usize(b"threshold", statement.threshold);
    transcript.participant(b"dealer", statement.dealer);
    transcript.participant(b"receiver", statement.receiver);
    transcript.bytes(b"msg-i", &statement.msg_i.0);
    transcript.scalar::<G>(b"beta", &statement.beta);
    transcript.element::<G>(b"dealer-pk", &statement.dealer_public_key);
    transcript.element::<G>(b"receiver-pk", &statement.receiver_public_key);
    transcript.usize(b"commitment-len", statement.commitment_coefficients.len());
    for coefficient in &statement.commitment_coefficients {
        transcript.element::<G>(b"commitment", coefficient);
    }
    transcript.element::<G>(b"share-commitment", &statement.share_commitment);
    transcript.element::<G>(b"pad-commitment", &statement.pad_commitment);
    transcript.scalar::<G>(b"encrypted-share", &statement.encrypted_share);
    transcript.bytes(b"dealing-root", &statement.transcript_root);
    transcript.root()
}

fn derive_receiver_pad<G, B>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    msg_i: DealerMessageNonce,
) -> Result<G::Scalar>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let dealer_public_key = config.registry.public_key(dealer)?;
    let receiver_public_key = config.registry.public_key(receiver)?;
    B::derive_pad(
        msg_i,
        &config.beta,
        receiver_identity_secret,
        dealer_public_key,
        receiver_public_key,
    )
}

fn derive_default_pad<G: GoldenGroup>(
    msg_i: DealerMessageNonce,
    receiver_public_key: &G::Element,
    shared_secret: &G::Element,
) -> Result<G::Scalar> {
    let mut transcript = TranscriptBuilder::new(b"pad");
    transcript.bytes(b"msg-i", &msg_i.0);
    transcript.element::<G>(b"receiver-pk", receiver_public_key);
    transcript.element::<G>(b"shared-secret", shared_secret);
    G::Scalar::hash_to_scalar(b"golden-dkg-pad-v1", &transcript.root())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };

    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::GoldenScalar;

    const FAKE_PROOF_ID: &[u8] = b"golden-core/fake-evrf-proof/v1";

    #[derive(Clone, Debug)]
    enum FakeEvrfBackend {}

    impl EvrfProofBackend<TinyGroup> for FakeEvrfBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            if statements.len() != witnesses.len() {
                return Err(Error::ProofVerificationFailed);
            }
            let mut last_receiver = None;
            for (statement, witness) in statements.iter().zip(witnesses.iter()) {
                if last_receiver.is_some_and(|receiver| receiver >= statement.receiver) {
                    return Err(Error::ProofVerificationFailed);
                }
                last_receiver = Some(statement.receiver);
                ensure_fake_public_relations(statement)?;
                if TinyGroup::mul_generator(&witness.identity_secret) != statement.dealer_public_key
                {
                    return Err(Error::ProofVerificationFailed);
                }
            }
            fake_proof_bytes(statements)
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            let expected = fake_proof_bytes(statements)?;
            for statement in statements {
                ensure_fake_public_relations(statement)?;
            }
            if proof == expected {
                Ok(())
            } else {
                Err(Error::ProofVerificationFailed)
            }
        }
    }

    static OPTIMIZED_SINGLE_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static OPTIMIZED_BATCH_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug)]
    enum CountingBatchBackend {}

    impl EvrfProofBackend<TinyGroup> for CountingBatchBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeEvrfBackend::prove_batch(statements, witnesses, rng)
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            OPTIMIZED_SINGLE_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            FakeEvrfBackend::verify_batch(statements, proof)
        }

        fn verify_proof_batch(batches: &[(&[EvrfStatement<TinyGroup>], &[u8])]) -> Result<()> {
            OPTIMIZED_BATCH_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            for (statements, proof) in batches {
                FakeEvrfBackend::verify_batch(statements, proof)?;
            }
            Ok(())
        }
    }

    static FALLBACK_SINGLE_VERIFY_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug)]
    enum CountingFallbackBackend {}

    impl EvrfProofBackend<TinyGroup> for CountingFallbackBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeEvrfBackend::prove_batch(statements, witnesses, rng)
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            FALLBACK_SINGLE_VERIFY_CALLS.fetch_add(1, Ordering::SeqCst);
            FakeEvrfBackend::verify_batch(statements, proof)
        }
    }

    #[derive(Clone, Debug)]
    enum BatchRejectingBackend {}

    impl EvrfProofBackend<TinyGroup> for BatchRejectingBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeEvrfBackend::prove_batch(statements, witnesses, rng)
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            FakeEvrfBackend::verify_batch(statements, proof)
        }

        fn verify_proof_batch(_batches: &[(&[EvrfStatement<TinyGroup>], &[u8])]) -> Result<()> {
            Err(Error::ProofVerificationFailed)
        }
    }

    #[derive(Clone, Debug)]
    enum UnreachableEvrfBackend {}

    impl EvrfProofBackend<TinyGroup> for UnreachableEvrfBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn prove_batch(
            _statements: &[EvrfStatement<TinyGroup>],
            _witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            Err(Error::ProofVerificationFailed)
        }

        fn verify_batch(_statements: &[EvrfStatement<TinyGroup>], _proof: &[u8]) -> Result<()> {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn fake_proof_bytes(statements: &[EvrfStatement<TinyGroup>]) -> Result<Vec<u8>> {
        let id_len =
            u32::try_from(FAKE_PROOF_ID.len()).map_err(|_| Error::ProofVerificationFailed)?;
        let mut proof = id_len.to_be_bytes().to_vec();
        proof.extend_from_slice(FAKE_PROOF_ID);
        for statement in statements {
            proof.extend_from_slice(&statement.root());
        }
        Ok(proof)
    }

    fn ensure_fake_public_relations(statement: &EvrfStatement<TinyGroup>) -> Result<()> {
        if statement.commitment_coefficients.is_empty()
            || statement.commitment_coefficients.len() != statement.threshold
        {
            return Err(Error::ProofVerificationFailed);
        }

        let x = statement.receiver.to_scalar::<TinyScalar>()?;
        let mut x_pow = TinyScalar::one();
        let mut expected_share_commitment = TinyGroup::identity();
        for coefficient in &statement.commitment_coefficients {
            expected_share_commitment = TinyGroup::add(
                &expected_share_commitment,
                &TinyGroup::mul(coefficient, &x_pow),
            );
            x_pow = x_pow.mul(&x);
        }
        if expected_share_commitment != statement.share_commitment {
            return Err(Error::ProofVerificationFailed);
        }

        let encrypted_share_commitment = TinyGroup::mul_generator(&statement.encrypted_share);
        let expected_encrypted_share_commitment =
            TinyGroup::add(&statement.share_commitment, &statement.pad_commitment);
        if encrypted_share_commitment != expected_encrypted_share_commitment {
            return Err(Error::ProofVerificationFailed);
        }

        Ok(())
    }

    #[derive(Clone, Debug)]
    enum OffsetPadBackend {}

    impl EvrfProofBackend<TinyGroup> for OffsetPadBackend {
        const PROOF_ID: &'static [u8] = FAKE_PROOF_ID;

        fn derive_pad(
            msg_i: DealerMessageNonce,
            beta: &TinyScalar,
            identity_secret: &TinyScalar,
            peer_public_key: &<TinyGroup as GoldenGroup>::Element,
            receiver_public_key: &<TinyGroup as GoldenGroup>::Element,
        ) -> Result<TinyScalar> {
            let shared_secret = TinyGroup::mul(peer_public_key, identity_secret);
            derive_default_pad::<TinyGroup>(msg_i, receiver_public_key, &shared_secret)
                .map(|pad| pad.add(beta))
        }

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            FakeEvrfBackend::prove_batch(statements, witnesses, _rng)
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            FakeEvrfBackend::verify_batch(statements, proof)
        }
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn identity_secret(participant: ParticipantIndex) -> TinyScalar {
        TinyScalar::from_u64(u64::from(participant.get()) * 10).unwrap()
    }

    fn config() -> DkgConfig<TinyGroup> {
        config_for(3, 2, 42)
    }

    fn config_for(n: usize, threshold: usize, session_byte: u8) -> DkgConfig<TinyGroup> {
        let entries = (1..=n as u32)
            .map(|value| {
                let participant = idx(value);
                (
                    participant,
                    TinyGroup::mul_generator(&identity_secret(participant)),
                )
            })
            .collect();
        let registry = ParticipantRegistry::new(entries).unwrap();
        DkgConfig::new(
            threshold,
            SessionId([session_byte; 32]),
            TinyScalar::from_u64(99).unwrap(),
            registry,
        )
        .unwrap()
    }

    fn all_dealings(
        config: &DkgConfig<TinyGroup>,
    ) -> BTreeMap<ParticipantIndex, DkgDealing<TinyGroup>> {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        config
            .registry
            .indexes()
            .map(|dealer| {
                (
                    dealer,
                    create_dealing::<TinyGroup, FakeEvrfBackend>(
                        dealer,
                        &identity_secret(dealer),
                        config,
                        &mut rng,
                    )
                    .unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn create_dealing_with_secret_sets_dealer_constant() {
        let config = config();
        let dealer = idx(1);
        let secret = TinyScalar::from_u64(37).unwrap();
        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);

        let dealing = create_dealing_with_secret::<TinyGroup, FakeEvrfBackend>(
            dealer,
            &identity_secret(dealer),
            secret,
            &config,
            &mut rng,
        )
        .unwrap();

        assert_eq!(
            dealing.message.commitment.public_key(),
            TinyGroup::mul_generator(&secret)
        );
        assert!(dealing
            .message
            .commitment
            .verify_share(&dealing.private_share)
            .unwrap());
        verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap();
    }

    #[test]
    fn zero_secret_dealing_has_identity_public_key_commitment() {
        let config = config();
        let dealer = idx(2);
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);

        let dealing = create_dealing_with_secret::<TinyGroup, FakeEvrfBackend>(
            dealer,
            &identity_secret(dealer),
            TinyScalar::zero(),
            &config,
            &mut rng,
        )
        .unwrap();

        assert_eq!(
            dealing.message.commitment.public_key(),
            TinyGroup::identity()
        );
        verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap();
    }

    #[test]
    fn all_honest_participants_compute_same_public_key_and_consistent_shares() {
        let config = config();
        let dealings = all_dealings(&config);
        let mut outputs = BTreeMap::new();

        for receiver in config.registry.indexes() {
            let own_dealing = dealings.get(&receiver).unwrap();
            let peer_dealings = dealings
                .iter()
                .filter_map(|(dealer, dealing)| {
                    if *dealer == receiver {
                        None
                    } else {
                        Some((*dealer, dealing.message.clone()))
                    }
                })
                .collect();
            let output = complete::<TinyGroup, FakeEvrfBackend>(
                receiver,
                &identity_secret(receiver),
                own_dealing,
                &peer_dealings,
                &config,
            )
            .unwrap();
            outputs.insert(receiver, output);
        }

        let first_public_key = outputs.values().next().unwrap().public_key;
        let first_public_key_shares = outputs.values().next().unwrap().public_key_shares.clone();
        for output in outputs.values() {
            assert_eq!(output.public_key, first_public_key);
            assert_eq!(output.public_key_shares, first_public_key_shares);
            assert_eq!(
                TinyGroup::mul_generator(&output.secret_share.value),
                first_public_key_shares[&output.secret_share.participant]
            );
        }
    }

    #[test]
    fn complete_uses_one_cross_proof_backend_call() {
        OPTIMIZED_SINGLE_VERIFY_CALLS.store(0, Ordering::SeqCst);
        OPTIMIZED_BATCH_VERIFY_CALLS.store(0, Ordering::SeqCst);
        let config = config();
        let dealings = all_dealings(&config);
        let receiver = idx(1);
        let own_dealing = dealings.get(&receiver).unwrap();
        let peer_dealings = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
            .collect();

        complete::<TinyGroup, CountingBatchBackend>(
            receiver,
            &identity_secret(receiver),
            own_dealing,
            &peer_dealings,
            &config,
        )
        .unwrap();

        assert_eq!(OPTIMIZED_BATCH_VERIFY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OPTIMIZED_SINGLE_VERIFY_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cross_proof_default_calls_each_single_verifier() {
        FALLBACK_SINGLE_VERIFY_CALLS.store(0, Ordering::SeqCst);
        let config = config();
        let dealings = all_dealings(&config);
        let messages: Vec<_> = dealings.values().map(|dealing| &dealing.message).collect();

        verify_dealings::<TinyGroup, CountingFallbackBackend>(&messages, &config).unwrap();

        assert_eq!(
            FALLBACK_SINGLE_VERIFY_CALLS.load(Ordering::SeqCst),
            messages.len()
        );
    }

    #[test]
    fn verify_dealings_rejects_an_invalid_proof_in_any_position() {
        let config = config();
        let dealings = all_dealings(&config);
        let honest: Vec<_> = dealings
            .values()
            .map(|dealing| dealing.message.clone())
            .collect();

        for invalid_index in 0..honest.len() {
            let mut messages = honest.clone();
            messages[invalid_index].proof[0] ^= 1;
            let references: Vec<_> = messages.iter().collect();
            assert_eq!(
                verify_dealings::<TinyGroup, FakeEvrfBackend>(&references, &config).unwrap_err(),
                Error::DealerProofVerificationFailed(messages[invalid_index].dealer.get()),
                "invalid proof at position {invalid_index} must fail"
            );
        }
    }

    #[test]
    fn verify_dealings_preserves_batch_error_when_individual_proofs_pass() {
        let config = config();
        let dealings = all_dealings(&config);
        let messages: Vec<_> = dealings.values().map(|dealing| &dealing.message).collect();

        assert_eq!(
            verify_dealings::<TinyGroup, BatchRejectingBackend>(&messages, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn verify_dealings_rejects_an_empty_batch() {
        let config = config();
        assert_eq!(
            verify_dealings::<TinyGroup, FakeEvrfBackend>(&[], &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn single_participant_dealing_skips_the_proof_backend() {
        let config = config_for(1, 1, 77);
        let dealer = idx(1);
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

        let dealing = create_dealing::<TinyGroup, UnreachableEvrfBackend>(
            dealer,
            &identity_secret(dealer),
            &config,
            &mut rng,
        )
        .unwrap();
        assert!(dealing.message.proof.is_empty());

        verify_dealing::<TinyGroup, UnreachableEvrfBackend>(&dealing.message, &config).unwrap();
        verify_dealings::<TinyGroup, UnreachableEvrfBackend>(&[&dealing.message], &config).unwrap();

        let output = complete::<TinyGroup, UnreachableEvrfBackend>(
            dealer,
            &identity_secret(dealer),
            &dealing,
            &BTreeMap::new(),
            &config,
        )
        .unwrap();
        assert_eq!(
            TinyGroup::mul_generator(&output.secret_share.value),
            output.public_key
        );
    }

    #[test]
    fn single_participant_dealing_rejects_a_forged_proof() {
        let config = config_for(1, 1, 78);
        let dealer = idx(1);
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);

        let mut dealing = create_dealing::<TinyGroup, UnreachableEvrfBackend>(
            dealer,
            &identity_secret(dealer),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing.message.proof = vec![1];

        assert_eq!(
            verify_dealing::<TinyGroup, UnreachableEvrfBackend>(&dealing.message, &config)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(
            verify_dealings::<TinyGroup, UnreachableEvrfBackend>(&[&dealing.message], &config)
                .unwrap_err(),
            Error::DealerProofVerificationFailed(dealer.get())
        );
    }

    #[test]
    fn randomized_committee_sizes_complete_consistently() {
        let mut chooser = ChaCha20Rng::from_seed([21u8; 32]);
        let mut dealing_rng = ChaCha20Rng::from_seed([22u8; 32]);

        for case in 0..32 {
            let n = 1 + (chooser.next_u32() as usize % 8);
            let threshold = 1 + (chooser.next_u32() as usize % n);
            let config = config_for(n, threshold, case as u8);
            let dealings = config
                .registry
                .indexes()
                .map(|dealer| {
                    (
                        dealer,
                        create_dealing::<TinyGroup, FakeEvrfBackend>(
                            dealer,
                            &identity_secret(dealer),
                            &config,
                            &mut dealing_rng,
                        )
                        .unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut outputs = BTreeMap::new();

            for receiver in config.registry.indexes() {
                let own_dealing = dealings.get(&receiver).unwrap();
                let peer_dealings = dealings
                    .iter()
                    .filter_map(|(dealer, dealing)| {
                        if *dealer == receiver {
                            None
                        } else {
                            Some((*dealer, dealing.message.clone()))
                        }
                    })
                    .collect();
                let output = complete::<TinyGroup, FakeEvrfBackend>(
                    receiver,
                    &identity_secret(receiver),
                    own_dealing,
                    &peer_dealings,
                    &config,
                )
                .unwrap();
                outputs.insert(receiver, output);
            }

            assert_consistent_outputs(&outputs, case, n, threshold);
        }
    }

    fn assert_consistent_outputs(
        outputs: &BTreeMap<ParticipantIndex, DkgOutput<TinyGroup>>,
        case: usize,
        n: usize,
        threshold: usize,
    ) {
        let first = outputs.values().next().unwrap();
        for output in outputs.values() {
            assert_eq!(
                output.public_key, first.public_key,
                "case {case}: n={n}, threshold={threshold}"
            );
            assert_eq!(
                output.public_key_shares, first.public_key_shares,
                "case {case}: n={n}, threshold={threshold}"
            );
            assert_eq!(
                TinyGroup::mul_generator(&output.secret_share.value),
                first.public_key_shares[&output.secret_share.participant],
                "case {case}: n={n}, threshold={threshold}"
            );
        }
    }

    #[test]
    fn session_id_is_bound_into_dealing_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut wrong_config = config.clone();
        wrong_config.session_id = SessionId([99u8; 32]);

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &wrong_config)
                .unwrap_err(),
            Error::SessionMismatch
        );
    }

    #[test]
    fn setup_beta_is_bound_into_dealing_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut wrong_config = config.clone();
        wrong_config.beta = wrong_config.beta.add(&TinyScalar::one());

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &wrong_config)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn dealer_message_contains_paper_msg_i() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([26u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();

        assert_eq!(dealing.message.msg_i.0.len(), DEALER_MESSAGE_NONCE_BYTES);
    }

    #[test]
    fn recompute_transcript_root_matches_create_dealing() {
        // Pin the contract that `DealerMessage::recompute_transcript_root`
        // returns the same bytes `create_dealing` embedded. Tests that mutate
        // the message rely on this; a divergence would let them silently
        // forge a fresh root for a mutated message and bypass verification.
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();

        assert_eq!(
            dealing.message.recompute_transcript_root(),
            dealing.message.transcript_root,
        );
    }

    #[test]
    fn tampered_transcript_root_fails_dealing_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([32u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing.message.transcript_root[0] ^= 1;

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn proof_backend_receives_dealer_identity_secret() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([28u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();

        verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap();
    }

    #[test]
    fn proof_backend_owns_pad_derivation_for_creation_and_decryption() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
        let dealer = idx(1);
        let receiver = idx(2);
        let dealing = create_dealing::<TinyGroup, OffsetPadBackend>(
            dealer,
            &identity_secret(dealer),
            &config,
            &mut rng,
        )
        .unwrap();

        verify_dealing_for_receiver::<TinyGroup, OffsetPadBackend>(
            receiver,
            &identity_secret(receiver),
            &dealing.message,
            &config,
        )
        .unwrap();

        let encrypted_share = dealing.message.encrypted_shares.get(&receiver).unwrap();
        let default_pad = derive_receiver_pad::<TinyGroup, FakeEvrfBackend>(
            &config,
            dealing.message.dealer,
            receiver,
            &identity_secret(receiver),
            dealing.message.msg_i,
        )
        .unwrap();
        let offset_pad = derive_receiver_pad::<TinyGroup, OffsetPadBackend>(
            &config,
            dealing.message.dealer,
            receiver,
            &identity_secret(receiver),
            dealing.message.msg_i,
        )
        .unwrap();
        assert_eq!(offset_pad, default_pad.add(&config.beta));

        let decrypted_share = Share {
            participant: receiver,
            value: encrypted_share.encrypted_share.sub(&offset_pad),
        };
        dealing
            .message
            .commitment
            .verify_share(&decrypted_share)
            .unwrap();

        let wrongly_decrypted_share = Share {
            participant: receiver,
            value: encrypted_share.encrypted_share.sub(&default_pad),
        };
        assert!(!dealing
            .message
            .commitment
            .verify_share(&wrongly_decrypted_share)
            .unwrap());
    }

    #[test]
    fn msg_i_is_bound_into_dealing_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([27u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing.message.msg_i.0[0] ^= 1;
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn registry_order_is_bound_into_dealing_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let registry = ParticipantRegistry::new(vec![
            (
                idx(1),
                TinyGroup::mul_generator(&TinyScalar::from_u64(10).unwrap()),
            ),
            (
                idx(2),
                TinyGroup::mul_generator(&TinyScalar::from_u64(21).unwrap()),
            ),
            (
                idx(3),
                TinyGroup::mul_generator(&TinyScalar::from_u64(30).unwrap()),
            ),
        ])
        .unwrap();
        let wrong_config = DkgConfig::new(2, config.session_id, config.beta, registry).unwrap();

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &wrong_config)
                .unwrap_err(),
            Error::RegistryMismatch
        );
    }

    #[test]
    fn duplicate_registry_public_keys_are_rejected() {
        let public_key = TinyGroup::mul_generator(&identity_secret(idx(1)));
        assert_eq!(
            ParticipantRegistry::<TinyGroup>::new(vec![(idx(1), public_key), (idx(2), public_key)])
                .unwrap_err(),
            Error::DuplicateParticipantPublicKey {
                first: 1,
                second: 2,
            }
        );
    }

    #[test]
    fn dealer_message_excludes_self_encrypted_share() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
        let dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();

        assert!(!dealing.message.encrypted_shares.contains_key(&idx(1)));
        assert_eq!(
            dealing.message.encrypted_shares.len(),
            config.registry.len() - 1
        );
        assert_eq!(dealing.private_share.participant, idx(1));
        assert!(dealing
            .message
            .commitment
            .verify_share(&dealing.private_share)
            .unwrap());
    }

    #[test]
    fn self_encrypted_share_is_rejected() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([24u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let encrypted_share = dealing.message.encrypted_shares[&idx(2)].clone();
        dealing
            .message
            .encrypted_shares
            .insert(idx(1), encrypted_share);
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::UnexpectedShare(1)
        );
    }

    #[test]
    fn missing_dealing_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let own_dealing = dealings.get(&idx(1)).unwrap();
        let peer_dealings = BTreeMap::from([(idx(2), dealings[&idx(2)].message.clone())]);

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(1)),
                own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::MissingDealing(3)
        );
    }

    #[test]
    fn duplicate_dealer_message_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let own_dealing = dealings.get(&idx(1)).unwrap();
        let peer_dealings = BTreeMap::from([
            (idx(1), dealings[&idx(1)].message.clone()),
            (idx(2), dealings[&idx(2)].message.clone()),
            (idx(3), dealings[&idx(3)].message.clone()),
        ]);

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(1)),
                own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::DuplicateParticipantIndex(1)
        );
    }

    #[test]
    fn peer_dealing_key_mismatch_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let own_dealing = dealings.get(&idx(1)).unwrap();
        let peer_dealings = BTreeMap::from([
            (idx(2), dealings[&idx(3)].message.clone()),
            (idx(3), dealings[&idx(2)].message.clone()),
        ]);

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(1)),
                own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::DealerKeyMismatch {
                map_key: 2,
                message_dealer: 3,
            }
        );
    }

    #[test]
    fn own_dealing_dealer_mismatch_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let own_dealing = dealings.get(&idx(2)).unwrap();
        let peer_dealings = BTreeMap::from([(idx(3), dealings[&idx(3)].message.clone())]);

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(1)),
                own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::DealerKeyMismatch {
                map_key: 1,
                message_dealer: 2,
            }
        );
    }

    #[test]
    fn own_private_share_participant_mismatch_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let mut own_dealing = dealings[&idx(1)].clone();
        own_dealing.private_share.participant = idx(2);
        let peer_dealings = dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                if *dealer == idx(1) {
                    None
                } else {
                    Some((*dealer, dealing.message.clone()))
                }
            })
            .collect();

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(1)),
                &own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::PrivateShareParticipantMismatch {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn wrong_receiver_proof_binding_fails() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let header_len = 4 + FAKE_PROOF_ID.len();
        let proof_for_2 = dealing.message.proof[header_len..header_len + 32].to_vec();
        dealing.message.proof[header_len + 32..header_len + 64].copy_from_slice(&proof_for_2);

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn unknown_dealer_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing.message.dealer = idx(9);

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::UnknownParticipant(9)
        );
    }

    #[test]
    fn missing_receiver_encrypted_share_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing.message.encrypted_shares.remove(&idx(2));
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::MissingShare(2)
        );
    }

    #[test]
    fn missing_receiver_proof_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        dealing
            .message
            .proof
            .truncate(dealing.message.proof.len() - 32);

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn altered_commitment_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut coefficients = dealing.message.commitment.coefficients().to_vec();
        coefficients[0] = TinyGroup::add(&coefficients[0], &TinyGroup::generator());
        dealing.message.commitment =
            FeldmanCommitment::<TinyGroup>::from_coefficients(coefficients).unwrap();

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn wrong_commitment_degree_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let mut coefficients = dealing.message.commitment.coefficients().to_vec();
        coefficients.push(TinyGroup::identity());
        dealing.message.commitment =
            FeldmanCommitment::<TinyGroup>::from_coefficients(coefficients).unwrap();
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::InvalidCommitmentDegree {
                expected: 2,
                actual: 3,
            }
        );
    }

    #[test]
    fn receiver_local_verification_rejects_publicly_valid_wrong_pad() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([16u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let receiver = idx(2);
        let share_commitment = dealing
            .message
            .commitment
            .public_key_share(receiver)
            .unwrap();
        let real_pad = derive_receiver_pad::<TinyGroup, FakeEvrfBackend>(
            &config,
            dealing.message.dealer,
            receiver,
            &identity_secret(receiver),
            dealing.message.msg_i,
        )
        .unwrap();
        let bad_pad = (1u64..97)
            .map(|value| TinyScalar::from_u64(value).unwrap())
            .find(|pad| *pad != real_pad)
            .unwrap();
        dealing.message.encrypted_shares.insert(
            receiver,
            EncryptedShare {
                pad_commitment: TinyGroup::mul_generator(&bad_pad),
                encrypted_share: share_commitment.add(&bad_pad),
            },
        );
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );
        let statements = public_share_receivers(&config, dealing.message.dealer)
            .map(|proof_receiver| {
                let encrypted_share = dealing.message.encrypted_shares[&proof_receiver].clone();
                statement_for_receiver::<TinyGroup>(
                    &config,
                    dealing.message.dealer,
                    proof_receiver,
                    dealing.message.msg_i,
                    dealing
                        .message
                        .commitment
                        .public_key_share(proof_receiver)
                        .unwrap(),
                    dealing.message.commitment.coefficients().to_vec(),
                    encrypted_share,
                    dealing.message.transcript_root,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        dealing.message.proof = fake_proof_bytes(&statements).unwrap();

        verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config)
            .expect("public verification");
        assert_eq!(
            verify_dealing_for_receiver::<TinyGroup, FakeEvrfBackend>(
                receiver,
                &identity_secret(receiver),
                &dealing.message,
                &config
            )
            .unwrap_err(),
            Error::CommitmentVerificationFailed
        );
    }

    #[test]
    fn invalid_encrypted_share_relation_fails_public_verification() {
        let config = config();
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let mut dealing = create_dealing::<TinyGroup, FakeEvrfBackend>(
            idx(1),
            &identity_secret(idx(1)),
            &config,
            &mut rng,
        )
        .unwrap();
        let encrypted_share = dealing.message.encrypted_shares.get_mut(&idx(2)).unwrap();
        encrypted_share.encrypted_share = encrypted_share.encrypted_share.add(&TinyScalar::one());
        dealing.message.transcript_root = dealing_root::<TinyGroup>(
            dealing.message.session_id,
            dealing.message.registry_root,
            dealing.message.dealer,
            dealing.message.msg_i,
            &dealing.message.commitment,
            &dealing.message.encrypted_shares,
        );

        assert_eq!(
            verify_dealing::<TinyGroup, FakeEvrfBackend>(&dealing.message, &config).unwrap_err(),
            Error::CommitmentVerificationFailed
        );
    }

    #[test]
    fn wrong_receiver_identity_secret_fails_completion() {
        let config = config();
        let dealings = all_dealings(&config);
        let own_dealing = dealings.get(&idx(1)).unwrap();
        let peer_dealings = dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                if *dealer == idx(1) {
                    None
                } else {
                    Some((*dealer, dealing.message.clone()))
                }
            })
            .collect();

        assert_eq!(
            complete::<TinyGroup, FakeEvrfBackend>(
                idx(1),
                &identity_secret(idx(2)),
                own_dealing,
                &peer_dealings,
                &config
            )
            .unwrap_err(),
            Error::IdentityKeyMismatch
        );
    }

    #[test]
    fn registry_rejects_identity_public_key() {
        // A dealer registering the group identity as their public key would
        // collapse every other participant's secret-share multiplication to
        // the identity; the registry must reject this at construction time
        // rather than let a degenerate DKG silently complete.
        let entries = vec![(idx(1), TinyGroup::identity())];
        assert_eq!(
            ParticipantRegistry::<TinyGroup>::new(entries).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn dkg_config_rejects_zero_threshold() {
        // threshold = 0 produces an empty polynomial, which has no constant
        // term to act as the secret. The constructor catches this rather
        // than letting the prover proceed with a degenerate commitment.
        let registry = ParticipantRegistry::<TinyGroup>::new(
            (1..=3)
                .map(|value| {
                    let participant = idx(value);
                    (
                        participant,
                        TinyGroup::mul_generator(&identity_secret(participant)),
                    )
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(
            DkgConfig::new(
                0,
                SessionId([8u8; 32]),
                TinyScalar::from_u64(77).unwrap(),
                registry,
            )
            .unwrap_err(),
            Error::InvalidThreshold {
                threshold: 0,
                participants: 3,
            }
        );
    }

    #[test]
    fn dkg_config_rejects_threshold_above_participant_count() {
        // threshold > n asks for k-of-n reconstruction with k > n, which is
        // information-theoretically impossible. The constructor must reject
        // this so the dealer does not silently run a protocol that can never
        // produce a valid completion.
        let registry = ParticipantRegistry::<TinyGroup>::new(
            (1..=3)
                .map(|value| {
                    let participant = idx(value);
                    (
                        participant,
                        TinyGroup::mul_generator(&identity_secret(participant)),
                    )
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(
            DkgConfig::new(
                4,
                SessionId([8u8; 32]),
                TinyScalar::from_u64(77).unwrap(),
                registry,
            )
            .unwrap_err(),
            Error::InvalidThreshold {
                threshold: 4,
                participants: 3,
            }
        );
    }
}
