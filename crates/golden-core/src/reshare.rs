//! Group-key resharing.
//!
//! A reshare moves the group key X of a completed sharing from an old
//! committee (I_old, t_old) to a new committee (I_new, t_new) with
//! 1 ≤ t_new ≤ n_new. The committees may overlap or be disjoint, and the
//! threshold may rise or fall. A refresh is a reshare onto the same members
//! at the same threshold. Each dealer i of a declared set Q ⊆ I_old with
//! |Q| ≥ t_old samples f_i of degree t_new − 1 with f_i(0) = s_i, its old
//! share, and encrypts f_i(j) to every receiver j ∈ I_new. Receiver j outputs
//! x'_j = Σ_{i∈Q} λ^Q_i·f_i(j), where λ^Q are the Lagrange coefficients at
//! zero over the old indices of Q. X does not change, so records sealed under
//! X open with the new committee. Protocol: share-of-shares resharing (Groth,
//! ePrint 2021/339).
//!
//! The supported claim is membership and threshold change under static
//! corruption, not proactive security. A reshare never revokes an old share:
//! X stays secure only while every committee that ever held it stays below
//! its own threshold until its shares are erased, and only a fresh DKG
//! recovers from a compromised x. Engineering completion does not establish
//! these claims.
//!
//! Nodes own agreement on Q and the configuration; admission and predecessor
//! authenticity; retries, meaning a replaced dealer, a fresh session and keys
//! and an attempt cap, because completion requires every declared dealer and
//! withholding is not attributable; activation; retirement of the predecessor
//! setup, which stops answering decryption requests once the new committee
//! activates; erasure of old shares, dealer secrets and backups; and lineage
//! tracking of generations.
//!
//! # Configuration
//!
//! [`ResharePredecessor`] is the predecessor's public key set: t_old, X, a
//! public-share column Y_i of at least t_old consistent shares (the `from_*`
//! constructors supply the full column) and the completion root. It holds no
//! secrets, and applications establish its authenticity. The completion root
//! is the lineage handle: it binds the predecessor's session, its registry or
//! reshare root and every dealing coefficient, hence X and the Y column. The
//! library never checks it against X and Y; it is an agreement handle.
//!
//! [`ReshareConfig`] holds t_new, the declared bound `max_corrupt_receivers`
//! on corrupt receivers in every attempt, the session, beta, Q as a dealer
//! registry keyed by old index, the new committee as a receiver registry keyed
//! by new index, and the predecessor. Its root, under the label
//! `reshare-config`, binds every one of these: the registries through their
//! roots, which bind keys but not proofs, and the predecessor through t_old,
//! X, the Y column and the completion root. The root fills the
//! `registry_root` slot of every reshare dealer message and statement, so a
//! reshare dealing fails plain verification with
//! [`Error::RegistryMismatch`], and the reverse.
//!
//! Index spaces never mix. Old indices select dealer keys, Y_i and λ^Q; new
//! indices select receiver keys, evaluation points and outputs. One integer
//! may name different parties in the two spaces, and no old index is compared
//! with a new one. An error that names seats of both registries tags each
//! index with its role.
//!
//! # Dealing and completion
//!
//! Dealer i ∈ Q checks its dealer key and g^{s_i} == Y_i before drawing
//! randomness, deals f_i to every receiver index with no self slot, and keeps
//! C_{i,0} on the wire. Verifiers require C_{i,0} == Y_i, else
//! [`Error::ReshareConstantMismatch`], before any proof check or decryption.
//! The paper backends' constant-term proof then proves knowledge of s_i. The
//! dealer message codec, root grammars, relation, proof IDs and transcript
//! labels are those of plain DKG. Every dealing has n_new ≥ t_new receiver
//! slots, so a one-receiver reshare carries a proof. Plain DKG wire bytes,
//! roots, RNG draw order and error order are unchanged.
//!
//! Completion takes exactly every declared dealer, verifies every dealing,
//! decrypts and checks the receiver's slot in each, and sets
//! x'_j = Σ λ^Q_i·f_i(j) and A'_k = Σ λ^Q_i·C_{i,k}, asserting A'_0 == X. A
//! member of both committees completes with its receiver key, and its own
//! dealing is on the board like any other. Public aggregation runs the same
//! steps without a receiver, so leaving members can confirm the result.
//!
//! In the reshare entry points, [`Error::UnknownParticipant`],
//! [`Error::MissingDealing`], [`Error::DealerKeyMismatch`],
//! [`Error::DealerProofVerificationFailed`] and
//! [`Error::ReshareConstantMismatch`] name old dealer indices, and
//! [`Error::MissingShare`] and [`Error::UnexpectedShare`] name new receiver
//! indices. A receiver outside the new committee is
//! [`Error::IdentityKeyMismatch`].
//!
//! # EHTDH1
//!
//! The decryption run is the reshare, and its decryption key must equal X, so
//! the sealing key stays X. The context run is a fresh plain zero-secret DKG
//! by the new committee over the receiver registry at t_new, with session
//! `derive_context_session_id(SessionId(root))`, where `root` is the reshare
//! configuration root. A reshared setup's `decryption_session_id` holds that
//! root, so the z column is bound to Q, both registries, t_new, beta and the
//! predecessor. The z column is checked in aggregate, Z(0) = identity, as for
//! plain EHTDH1, and no context dealer's constant is pinned. Decryption shares
//! bind the setup context root, so shares from two generations neither
//! combine nor verify across setups.
//!
//! # Deployment requirements
//!
//! 1. **Static corruption bounds per attempt.** At most
//!    `max_corrupt_receivers` new receivers are corrupt in every attempt,
//!    aborted ones included, and at most t_old − 1 old members while any old
//!    share survives; a member of both committees counts against both.
//!    [`ReshareConfig::new`] enforces
//!    `max_corrupt_receivers` < t_new ≤ n_new − `max_corrupt_receivers`.
//!    Never lower t_new or relax the bound to push a stalled reshare through,
//!    and log an explicit operator override for any t_new < t_old, which
//!    lowers fault tolerance at once; raising t_new protects nothing until old
//!    shares are erased. Reason: t_new corrupt receivers of any attempt learn
//!    every s_i in Q once its dealings are broadcast, and after erasure only
//!    honest new members reconstruct x.
//! 2. **Authenticated seats.** Admission authenticates each
//!    (session, role, index) → key binding. The library verifies a proof of
//!    knowledge for every key in both registries, but the proofs bind no
//!    seat. Reason: a copied key and proof can otherwise take an honest
//!    party's seat or leave a seat nobody can use.
//! 3. **Distinct per-role keys.** A member of both committees registers a
//!    dealer key and a separate receiver key. [`ReshareConfig::new`] rejects
//!    a key that appears, or whose negation appears, in both registries, and
//!    the library never infers that two seats belong to one party. Reason:
//!    every dealing keeps one shape with no self slot, and seats cannot be
//!    confused across roles.
//! 4. **Q declared and agreed before dealing.** Every participant confirms the
//!    reshare configuration root, which binds Q, both registries and the
//!    predecessor, with every peer before anyone deals. Each member builds the
//!    predecessor from its own trusted output or an authenticated source,
//!    never from a broadcast, and the dealer key at old index i belongs to the
//!    holder of s_i. Reason: receivers that combine over different Q hold
//!    shares of different polynomials with the same X, and the key does not
//!    show it.
//! 5. **Fresh attempts.** A `SessionId` is used by at most one plain or
//!    reshare configuration, ever, and each attempt uses fresh keys. Reason:
//!    the library does not detect a reused session or configuration root.
//! 6. **Dealer secrets are share-equivalent.** Zeroize a dealer's identity
//!    secret, encrypt it at rest if it is persisted to resend after a crash,
//!    and erase it together with s_i; a long-lived key reused as a dealer key
//!    keeps a copy of s_i for every reshare it dealt. Likewise, a receiver
//!    identity secret plus the public board recomputes that receiver's share,
//!    so erasing old shares includes old receiver identity secrets. Reason:
//!    that secret and the public board recompute every pad, hence every
//!    f_i(j), hence s_i.
//! 7. **No erasure before attested activation.** Old members erase s_i, their
//!    dealer secrets and every backup only after a globally consistent
//!    activation of the new committee, for example an event at an agreed
//!    block height that every validator sees. It carries signed attestations
//!    over the completion root from every new member, or from at least
//!    t_new + `max_corrupt_receivers`, since the root is public and only
//!    honest members' attestations show a held share. A member that has
//!    attested never discards its output. Reason: one corrupt member can make
//!    confirmation succeed for some members and fail for others, so erasing
//!    on local success can leave fewer than t_new holders and lose X.
//! 8. **Never discard a pending output on local failure.** A new member
//!    persists its output as pending until a globally visible activation or
//!    cancel; "failed" means "not activated", never "safe to delete". Reason:
//!    the split-brain attack of requirement 7. The library has no codec for
//!    outputs or dealings, so the node persists pending outputs, and the
//!    completed board, itself.
//! 9. **t_new = 1 only with `max_corrupt_receivers` = 0.** Requirement 1's
//!    check enforces this. Reason: each dealing polynomial is then constant,
//!    so every receiver decrypts each dealer's s_i and holds x (Q9).
//! 10. **Production proofs only.** Deploy only the paper backends
//!     (Secp/Secq or BLS/Jubjub). The prototype share-opening backend does
//!     not prove the pad relation, so a bad ciphertext is caught only by its
//!     receiver, and a completion failure under it names no dealer: retry
//!     attribution then relies on the node.
//!
//! # Open cryptographic questions
//!
//! These need sign-off before production use.
//!
//! * **Q1. Reshare functionality.** Define an ideal reshare functionality
//!   that outputs a sharing f' with f'(0) = x plus an adversarial shift Δ with
//!   Δ(0) = 0, including the adversary's ability to abort attempts and choose
//!   which one completes, and prove that this protocol realises it. Golden's
//!   only resharing text is a paragraph on same-committee refresh, with no
//!   proof.
//! * **Q2. Composition.** Does security hold when the predecessor is itself
//!   the biased output of key generation or of an earlier reshare, along a
//!   chain of reshares?
//! * **Q3. Constant proof.** Moot for the paper backends: C_{i,0} = Y_i stays
//!   on the wire, and the constant-term proof proves knowledge of s_i, which
//!   the n_new ≥ t_new eVRF slots also determine. Both extractors rewind,
//!   which is the Q5 question. The prototype has no constant proof
//!   (requirement 10).
//! * **Q4. Retries.** Does per-attempt secrecy hold across adversary-driven
//!   aborts, including when the new committee changes between attempts?
//! * **Q5. Proof of knowledge.** Is a static, transferable,
//!   non-online-extractable Schnorr proof of knowledge sufficient for
//!   Golden's argument, which asks for online extraction, in a reshare where
//!   corrupt receivers may register after seeing the old committee's keys, or
//!   must the proof bind session, role and index?
//! * **Q6. EHTDH1.** EHTDH1 is proven under trusted key generation. Does its
//!   reduction tolerate known additive shifts in the x and z columns, where z
//!   is dealt by the new committee and checked only in aggregate? The gap
//!   exists for fresh setups too. What is the joint corruption and query
//!   budget while both generations answer decryption requests?
//! * **Q7. Generation binding.** The setup context has no generation field.
//!   Generations are distinguished by the reshare configuration root, which
//!   binds the predecessor's completion root and fills the `registry_root`
//!   slot of every dealing. Is that sufficient, and is reusing that slot
//!   acceptable? The pad binds only `msg_i`, beta and the two identity keys;
//!   the proof binds everything else. A pad repeats across contexts only when
//!   a dealer reuses its own `msg_i`, which leaks differences of its own
//!   polynomial values.
//! * **Q8. Mixed-shape batching.** Moot: with per-role keys every dealing in
//!   a reshare has n_new receiver slots, so proofs on one board share one
//!   shape.
//! * **Q9. t_new = 1.** Accepted for any n_new when `max_corrupt_receivers`
//!   is 0. Every receiver then opens each dealer's s_i and derives every other
//!   receiver's pad in that dealing. Should t_new = 1 be restricted to
//!   n_new = 1?

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;

use crate::dkg::{
    completion_root, deal_with_layout, decrypt_share_for_receiver, verify_dealing_with_layout,
    verify_dealings_with_layout, DealerMessage, DealingLayout, DkgConfig, DkgOutput,
    EvrfProofBackend, ParticipantRegistry, SessionId, PROTOCOL_VERSION,
};
use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::{
    batch_invert, lagrange_coefficients_at_zero, Error, FeldmanCommitment, GoldenGroup,
    GoldenScalar, ParticipantIndex, Result, Share,
};

/// Public key set of the sharing a reshare preserves.
///
/// Holds the predecessor threshold t_old, the group key X, the public shares
/// Y_i of at least t_old predecessor participants and the predecessor's
/// completion root. It holds no secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResharePredecessor<G: GoldenGroup> {
    threshold: usize,
    public_key: G::Element,
    public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
    completion_root: TranscriptRoot,
}

impl<G: GoldenGroup> ResharePredecessor<G> {
    /// Validate a predecessor key set.
    ///
    /// Requires `threshold ≥ 1`, at least `threshold` shares, a non-identity
    /// `public_key`, and every share on the degree `threshold − 1` polynomial
    /// that the first `threshold` shares, in index order, interpolate to
    /// `public_key`. A share may be the identity: a corrupt dealer cooperating
    /// with a corrupt receiver can force that receiver's share to zero, and
    /// that member then reshares s_i = 0. Any failure is
    /// [`Error::InvalidPredecessor`].
    pub fn new(
        threshold: usize,
        public_key: G::Element,
        public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
        completion_root: TranscriptRoot,
    ) -> Result<Self> {
        if threshold == 0
            || public_key_shares.len() < threshold
            || bool::from(G::is_identity(&public_key))
        {
            return Err(Error::InvalidPredecessor);
        }
        if !on_polynomial::<G>(threshold, &public_key, &public_key_shares)
            .map_err(|_| Error::InvalidPredecessor)?
        {
            return Err(Error::InvalidPredecessor);
        }
        Ok(Self {
            threshold,
            public_key,
            public_key_shares,
            completion_root,
        })
    }

    /// Key set of a completed plain DKG.
    ///
    /// `output` must carry a public share for exactly the indexes of
    /// `config.registry`. The predecessor threshold is `config.threshold`.
    pub fn from_dkg_output(config: &DkgConfig<G>, output: &DkgOutput<G>) -> Result<Self> {
        if !output
            .public_key_shares
            .keys()
            .copied()
            .eq(config.registry.indexes())
        {
            return Err(Error::InvalidPredecessor);
        }
        Self::new(
            config.threshold,
            output.public_key.clone(),
            output.public_key_shares.clone(),
            output.transcript_root,
        )
    }

    /// Key set of a completed reshare, so reshares chain.
    ///
    /// `output` must carry a public share for exactly the indexes of
    /// `config.receivers()`, and its key must be the key `config` preserves.
    /// The predecessor threshold is `config.threshold()`.
    pub fn from_reshare_output(config: &ReshareConfig<G>, output: &DkgOutput<G>) -> Result<Self> {
        if output.public_key != config.predecessor.public_key
            || !output
                .public_key_shares
                .keys()
                .copied()
                .eq(config.receivers.indexes())
        {
            return Err(Error::InvalidPredecessor);
        }
        Self::new(
            config.threshold,
            output.public_key.clone(),
            output.public_key_shares.clone(),
            output.transcript_root,
        )
    }

    /// Predecessor reconstruction threshold t_old.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Group key X that the reshare preserves.
    pub fn public_key(&self) -> &G::Element {
        &self.public_key
    }

    /// Public share Y_i of one predecessor participant.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Option<&G::Element> {
        self.public_key_shares.get(&participant)
    }

    /// Public shares of every predecessor participant.
    pub fn public_key_shares(&self) -> &BTreeMap<ParticipantIndex, G::Element> {
        &self.public_key_shares
    }

    /// Predecessor completion root.
    pub fn completion_root(&self) -> TranscriptRoot {
        self.completion_root
    }
}

/// Validated reshare configuration.
///
/// Dealers are the declared set Q, keyed by predecessor index under
/// dealer-role keys. Receivers are the new committee, keyed by new index under
/// receiver-role keys. [`ReshareConfig::root`] binds every field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReshareConfig<G: GoldenGroup> {
    threshold: usize,
    max_corrupt_receivers: usize,
    session_id: SessionId,
    beta: G::Scalar,
    dealers: ParticipantRegistry<G>,
    receivers: ParticipantRegistry<G>,
    predecessor: ResharePredecessor<G>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> ReshareConfig<G> {
    /// Validate a reshare of `predecessor`'s key from `dealers` to
    /// `receivers` at threshold `threshold`.
    ///
    /// Checks, in order:
    ///
    /// 1. `1 ≤ threshold ≤ receivers.len()`, else [`Error::InvalidThreshold`];
    /// 2. `max_corrupt_receivers < threshold`, else
    ///    [`Error::InsecureReshareThreshold`];
    /// 3. `threshold ≤ receivers.len() − max_corrupt_receivers`, else
    ///    [`Error::InsufficientHonestReceivers`];
    /// 4. every dealer index has a predecessor share and there are at least
    ///    `predecessor.threshold()` dealers, else
    ///    [`Error::InvalidReshareConfiguration`];
    /// 5. no dealer key equals or negates a receiver key, else
    ///    [`Error::ReshareKeyCollision`].
    pub fn new(
        threshold: usize,
        max_corrupt_receivers: usize,
        session_id: SessionId,
        beta: G::Scalar,
        dealers: ParticipantRegistry<G>,
        receivers: ParticipantRegistry<G>,
        predecessor: ResharePredecessor<G>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > receivers.len() {
            return Err(Error::InvalidThreshold {
                threshold,
                participants: receivers.len(),
            });
        }
        if max_corrupt_receivers >= threshold {
            return Err(Error::InsecureReshareThreshold {
                threshold,
                max_corrupt_receivers,
            });
        }
        if receivers.len() - max_corrupt_receivers < threshold {
            return Err(Error::InsufficientHonestReceivers {
                threshold,
                receivers: receivers.len(),
                max_corrupt_receivers,
            });
        }
        if dealers.len() < predecessor.threshold()
            || dealers
                .indexes()
                .any(|dealer| predecessor.public_key_share(dealer).is_none())
        {
            return Err(Error::InvalidReshareConfiguration);
        }
        ensure_distinct_role_keys(&dealers, &receivers)?;

        let root = reshare_config_root(
            threshold,
            max_corrupt_receivers,
            session_id,
            &beta,
            &dealers,
            &receivers,
            &predecessor,
        );
        Ok(Self {
            threshold,
            max_corrupt_receivers,
            session_id,
            beta,
            dealers,
            receivers,
            predecessor,
            root,
        })
    }

    /// Reshare threshold t_new.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Declared bound on corrupt receivers in every attempt.
    pub fn max_corrupt_receivers(&self) -> usize {
        self.max_corrupt_receivers
    }

    /// Session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Public eVRF leftover-hash-lemma coefficient from setup.
    pub fn beta(&self) -> &G::Scalar {
        &self.beta
    }

    /// Declared dealers Q, keyed by predecessor index.
    pub fn dealers(&self) -> &ParticipantRegistry<G> {
        &self.dealers
    }

    /// New committee, keyed by new index.
    pub fn receivers(&self) -> &ParticipantRegistry<G> {
        &self.receivers
    }

    /// Predecessor key set.
    pub fn predecessor(&self) -> &ResharePredecessor<G> {
        &self.predecessor
    }

    /// Reshare configuration root.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }
}

/// Public result of a completed reshare, without a secret share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResharePublicOutput<G: GoldenGroup> {
    /// Group key, equal to the predecessor's.
    pub public_key: G::Element,
    /// Public key shares for each receiver.
    pub public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
    /// Transcript root over the verified dealings.
    pub transcript_root: TranscriptRoot,
}

/// Reshare one dealer's predecessor share to every receiver.
///
/// Before drawing randomness, checks that `dealer` is a declared dealer
/// ([`Error::UnknownParticipant`]), that `dealer_identity_secret` opens its
/// dealer key ([`Error::IdentityKeyMismatch`]), and that `predecessor_share`
/// belongs to `dealer` and opens its predecessor public share
/// ([`Error::PredecessorShareMismatch`]).
pub fn create_reshare_dealing<G, B>(
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    predecessor_share: &Share<G::Scalar>,
    config: &ReshareConfig<G>,
    rng: &mut impl CryptoRngCore,
) -> Result<DealerMessage<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    if G::mul_generator(dealer_identity_secret) != *config.dealers.public_key(dealer)? {
        return Err(Error::IdentityKeyMismatch);
    }
    if predecessor_share.participant != dealer
        || config.predecessor.public_key_share(dealer)
            != Some(&G::mul_generator(&predecessor_share.value))
    {
        return Err(Error::PredecessorShareMismatch);
    }
    let (message, _) = deal_with_layout::<G, B>(
        &DealingLayout::reshare(config),
        dealer,
        dealer_identity_secret,
        predecessor_share.value.clone(),
        rng,
    )?;
    Ok(message)
}

/// Verify one reshare dealer message.
pub fn verify_reshare_dealing<G, B>(
    message: &DealerMessage<G>,
    config: &ReshareConfig<G>,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    verify_dealing_with_layout::<G, B>(message, &DealingLayout::reshare(config))
}

/// Verify several reshare dealer messages in one backend call.
///
/// As [`crate::verify_dealings`], a failed combined verification retries each
/// proof so the error can name an invalid dealer.
pub fn verify_reshare_dealings<G, B>(
    messages: &[&DealerMessage<G>],
    config: &ReshareConfig<G>,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    verify_dealings_with_layout::<G, B>(messages, &DealingLayout::reshare(config))
}

/// Verify one reshare dealer message for a concrete receiver.
///
/// Performs public verification, then decrypts and checks the receiver's
/// share. A receiver outside `config.receivers()` or a secret that does not
/// open its receiver key is [`Error::IdentityKeyMismatch`].
pub fn verify_reshare_dealing_for_receiver<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    message: &DealerMessage<G>,
    config: &ReshareConfig<G>,
) -> Result<()>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    ensure_receiver_key(receiver, receiver_identity_secret, config)?;
    let layout = DealingLayout::reshare(config);
    verify_dealing_with_layout::<G, B>(message, &layout)?;
    decrypt_share_for_receiver::<G, B>(receiver, receiver_identity_secret, message, &layout)?;
    Ok(())
}

/// Complete a reshare for one receiver.
///
/// `dealings` is the board, keyed by old dealer index, and must hold exactly
/// the declared dealers. Every dealing is verified, the receiver's share is
/// decrypted and checked in each, and the output share is
/// x'_j = Σ λ^Q_i·f_i(j). The group key equals the predecessor's, and
/// `transcript_root` is the completion root over (old dealer index, dealing
/// root) pairs, where each dealing root binds the reshare configuration root.
///
/// A receiver outside `config.receivers()` or a secret that does not open its
/// receiver key is [`Error::IdentityKeyMismatch`]. A map key that differs from
/// its message's dealer is [`Error::DealerKeyMismatch`], an absent declared
/// dealer is [`Error::MissingDealing`], and an undeclared one is
/// [`Error::UnknownParticipant`], each naming old indices.
pub fn complete_reshare<G, B>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    dealings: &BTreeMap<ParticipantIndex, DealerMessage<G>>,
    config: &ReshareConfig<G>,
) -> Result<DkgOutput<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    ensure_receiver_key(receiver, receiver_identity_secret, config)?;
    let board = declared_dealings(dealings, config)?;
    let layout = DealingLayout::reshare(config);
    let weights = verified_weights::<G, B>(&board, &layout)?;

    let mut secret_share_value = G::Scalar::zero();
    for (message, weight) in board.values().zip(&weights) {
        let share = decrypt_share_for_receiver::<G, B>(
            receiver,
            receiver_identity_secret,
            message,
            &layout,
        )?;
        secret_share_value = secret_share_value.add(&share.value.mul(weight));
    }
    let public = aggregate_verified(&board, &weights, config)?;

    Ok(DkgOutput {
        public_key: public.public_key,
        secret_share: Share {
            participant: receiver,
            value: secret_share_value,
        },
        public_key_shares: public.public_key_shares,
        transcript_root: public.transcript_root,
    })
}

/// Verify a reshare board and compute its public result without a receiver.
///
/// Runs the checks of [`complete_reshare`] that need no receiver key, so
/// members leaving the committee can confirm the result.
pub fn aggregate_reshare_public<G, B>(
    dealings: &BTreeMap<ParticipantIndex, DealerMessage<G>>,
    config: &ReshareConfig<G>,
) -> Result<ResharePublicOutput<G>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let board = declared_dealings(dealings, config)?;
    let weights = verified_weights::<G, B>(&board, &DealingLayout::reshare(config))?;
    aggregate_verified(&board, &weights, config)
}

fn ensure_receiver_key<G: GoldenGroup>(
    receiver: ParticipantIndex,
    receiver_identity_secret: &G::Scalar,
    config: &ReshareConfig<G>,
) -> Result<()> {
    match config.receivers.public_key(receiver) {
        Ok(public_key) if G::mul_generator(receiver_identity_secret) == *public_key => Ok(()),
        _ => Err(Error::IdentityKeyMismatch),
    }
}

/// The board keyed by old dealer index, holding exactly the declared dealers.
fn declared_dealings<'a, G: GoldenGroup>(
    dealings: &'a BTreeMap<ParticipantIndex, DealerMessage<G>>,
    config: &ReshareConfig<G>,
) -> Result<BTreeMap<ParticipantIndex, &'a DealerMessage<G>>> {
    for (dealer, message) in dealings {
        if *dealer != message.dealer {
            return Err(Error::DealerKeyMismatch {
                map_key: dealer.get(),
                message_dealer: message.dealer.get(),
            });
        }
    }
    if let Some(dealer) = config
        .dealers
        .indexes()
        .find(|dealer| !dealings.contains_key(dealer))
    {
        return Err(Error::MissingDealing(dealer.get()));
    }
    if let Some(dealer) = dealings
        .keys()
        .find(|dealer| config.dealers.public_key(**dealer).is_err())
    {
        return Err(Error::UnknownParticipant(dealer.get()));
    }
    Ok(dealings
        .iter()
        .map(|(dealer, message)| (*dealer, message))
        .collect())
}

/// Verify every dealing and return the dealers' Lagrange coefficients at zero
/// over their old indices, in board order.
fn verified_weights<G, B>(
    board: &BTreeMap<ParticipantIndex, &DealerMessage<G>>,
    layout: &DealingLayout<'_, G>,
) -> Result<Vec<G::Scalar>>
where
    G: GoldenGroup,
    B: EvrfProofBackend<G>,
{
    let messages: Vec<_> = board.values().copied().collect();
    verify_dealings_with_layout::<G, B>(&messages, layout)?;
    let xs = board
        .keys()
        .map(|dealer| dealer.to_scalar::<G::Scalar>())
        .collect::<Result<Vec<_>>>()?;
    lagrange_coefficients_at_zero(&xs)
}

/// Weight each verified dealer's commitment by its coefficient, check that the
/// aggregate preserves the predecessor key, and evaluate it at every receiver.
fn aggregate_verified<G: GoldenGroup>(
    board: &BTreeMap<ParticipantIndex, &DealerMessage<G>>,
    weights: &[G::Scalar],
    config: &ReshareConfig<G>,
) -> Result<ResharePublicOutput<G>> {
    let mut aggregate_coefficients = vec![G::identity(); config.threshold];
    for (message, weight) in board.values().zip(weights) {
        for (aggregate, coefficient) in aggregate_coefficients
            .iter_mut()
            .zip(message.commitment.coefficients())
        {
            *aggregate = G::add(aggregate, &G::mul(coefficient, weight));
        }
    }
    let aggregate_commitment = FeldmanCommitment::<G>::from_coefficients(aggregate_coefficients)?;

    let public_key = aggregate_commitment.public_key();
    if public_key != config.predecessor.public_key {
        return Err(Error::CommitmentVerificationFailed);
    }
    let public_key_shares = config
        .receivers
        .indexes()
        .map(|receiver| Ok((receiver, aggregate_commitment.public_key_share(receiver)?)))
        .collect::<Result<_>>()?;

    Ok(ResharePublicOutput {
        public_key,
        public_key_shares,
        transcript_root: completion_root::<G>(board),
    })
}

/// Whether every share lies on the polynomial of degree `threshold − 1` that
/// the first `threshold` shares interpolate, and that polynomial is
/// `public_key` at zero.
fn on_polynomial<G: GoldenGroup>(
    threshold: usize,
    public_key: &G::Element,
    shares: &BTreeMap<ParticipantIndex, G::Element>,
) -> Result<bool> {
    let basis = shares.iter().take(threshold).collect::<Vec<_>>();
    let xs = basis
        .iter()
        .map(|(participant, _)| participant.to_scalar::<G::Scalar>())
        .collect::<Result<Vec<_>>>()?;
    let points = basis.iter().map(|(_, point)| *point).collect::<Vec<_>>();
    let weights = barycentric_weights(&xs)?;
    if interpolate_at::<G>(&G::Scalar::zero(), &xs, &weights, &points) != *public_key {
        return Ok(false);
    }
    for (participant, point) in shares.iter().skip(threshold) {
        let x = participant.to_scalar::<G::Scalar>()?;
        if interpolate_at::<G>(&x, &xs, &weights, &points) != *point {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Barycentric weights w_i = 1 / ∏_{k≠i} (x_i − x_k), with one batch
/// inversion. Fails with [`Error::NonInvertibleDenominator`] when two `xs`
/// coincide.
fn barycentric_weights<S: GoldenScalar>(xs: &[S]) -> Result<Vec<S>> {
    let mut weights = xs
        .iter()
        .enumerate()
        .map(|(i, xi)| {
            xs.iter()
                .enumerate()
                .filter(|(k, _)| *k != i)
                .fold(S::one(), |product, (_, xk)| product.mul(&xi.sub(xk)))
        })
        .collect::<Vec<_>>();
    batch_invert(&mut weights).ok_or(Error::NonInvertibleDenominator)?;
    Ok(weights)
}

/// Value at `x` of the polynomial through `(xs[i], points[i])`, as
/// Σ w_i · ∏_{k≠i} (x − x_k) · points[i]. Prefix and suffix products form each
/// ∏_{k≠i} in O(|xs|) without inverting x − x_i, so an `x` equal to some x_k
/// yields `points[k]`.
fn interpolate_at<G: GoldenGroup>(
    x: &G::Scalar,
    xs: &[G::Scalar],
    weights: &[G::Scalar],
    points: &[&G::Element],
) -> G::Element {
    let mut suffixes = vec![G::Scalar::one(); xs.len()];
    for i in (1..xs.len()).rev() {
        suffixes[i - 1] = suffixes[i].mul(&x.sub(&xs[i]));
    }
    let mut prefix = G::Scalar::one();
    let mut sum = G::identity();
    for (((xi, weight), suffix), point) in xs.iter().zip(weights).zip(&suffixes).zip(points) {
        let coefficient = weight.mul(&prefix).mul(suffix);
        sum = G::add(&sum, &G::mul(point, &coefficient));
        prefix = prefix.mul(&x.sub(xi));
    }
    sum
}

fn ensure_distinct_role_keys<G: GoldenGroup>(
    dealers: &ParticipantRegistry<G>,
    receivers: &ParticipantRegistry<G>,
) -> Result<()> {
    let receiver_keys = receivers
        .entries()
        .map(|(receiver, key)| (G::encode_element(key).as_ref().to_vec(), receiver))
        .collect::<BTreeMap<_, _>>();
    for (dealer, key) in dealers.entries() {
        let negated = G::sub(&G::identity(), key);
        for candidate in [key, &negated] {
            if let Some(receiver) = receiver_keys.get(G::encode_element(candidate).as_ref()) {
                return Err(Error::ReshareKeyCollision {
                    dealer: dealer.get(),
                    receiver: receiver.get(),
                });
            }
        }
    }
    Ok(())
}

fn reshare_config_root<G: GoldenGroup>(
    threshold: usize,
    max_corrupt_receivers: usize,
    session_id: SessionId,
    beta: &G::Scalar,
    dealers: &ParticipantRegistry<G>,
    receivers: &ParticipantRegistry<G>,
    predecessor: &ResharePredecessor<G>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"reshare-config");
    transcript.u32(b"version", PROTOCOL_VERSION);
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"session", &session_id.0);
    transcript.usize(b"threshold", threshold);
    transcript.usize(b"max-corrupt-receivers", max_corrupt_receivers);
    transcript.scalar::<G>(b"beta", beta);
    transcript.bytes(b"dealer-registry", &dealers.root());
    transcript.bytes(b"receiver-registry", &receivers.root());
    transcript.usize(b"predecessor-threshold", predecessor.threshold);
    transcript.element::<G>(b"predecessor-key", &predecessor.public_key);
    transcript.usize(
        b"predecessor-shares-len",
        predecessor.public_key_shares.len(),
    );
    for (participant, share) in &predecessor.public_key_shares {
        transcript.participant(b"predecessor-participant", *participant);
        transcript.element::<G>(b"predecessor-share", share);
    }
    transcript.bytes(b"predecessor-completion-root", &predecessor.completion_root);
    transcript.root()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use rand_core::{CryptoRng, CryptoRngCore, RngCore};

    use super::*;
    use crate::dkg::{
        complete, create_dealing, create_dealing_with_secret, verify_dealing, verify_dealings,
        EvrfProofBackend, EvrfStatement, EvrfWitness,
    };
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::{lagrange_interpolate_at_zero, reconstruct_secret, IdentityKeyProof};

    /// Backend whose proofs are empty and always verify. These tests need
    /// completed outputs, not proofs.
    enum NoProofBackend {}

    impl EvrfProofBackend<TinyGroup> for NoProofBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/reshare-test-no-proof/v1";

        fn prove_batch(
            _statements: &[EvrfStatement<TinyGroup>],
            _witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn verify_batch(_statements: &[EvrfStatement<TinyGroup>], _proof: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    /// Public key of identity secret `value`. In the test group an element is
    /// its own discrete logarithm, so keys are unique mod 97 and `k` negates
    /// `97 − k`.
    fn key(value: u64) -> TinyScalar {
        TinyGroup::mul_generator(&scalar(value))
    }

    fn registry(entries: &[(u32, u64)]) -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(
            entries
                .iter()
                .map(|(index, secret)| {
                    let secret = scalar(*secret);
                    (
                        idx(*index),
                        TinyGroup::mul_generator(&secret),
                        IdentityKeyProof::prove(&secret).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    /// Group key and public shares at `indexes` of the polynomial whose
    /// coefficients are `7·k + 3`, of degree `threshold − 1`.
    fn column(
        threshold: usize,
        indexes: &[u32],
    ) -> (TinyScalar, BTreeMap<ParticipantIndex, TinyScalar>) {
        let coefficients = (0..threshold as u64)
            .map(|degree| scalar(7 * degree + 3))
            .collect::<Vec<_>>();
        let shares = indexes
            .iter()
            .map(|index| {
                let x = scalar(u64::from(*index));
                let value = coefficients
                    .iter()
                    .rev()
                    .fold(TinyScalar::zero(), |acc, c| acc.mul(&x).add(c));
                (idx(*index), TinyGroup::mul_generator(&value))
            })
            .collect();
        (TinyGroup::mul_generator(&coefficients[0]), shares)
    }

    fn predecessor(completion_root: TranscriptRoot) -> ResharePredecessor<TinyGroup> {
        let (public_key, shares) = column(2, &[1, 2, 3]);
        ResharePredecessor::new(2, public_key, shares, completion_root).unwrap()
    }

    const DEALERS: &[(u32, u64)] = &[(1, 11), (2, 12)];
    const RECEIVERS: &[(u32, u64)] = &[(1, 21), (2, 22), (3, 23), (4, 24)];
    const SESSION: SessionId = SessionId([5; 32]);

    struct Topology {
        dealers: ParticipantRegistry<TinyGroup>,
        receivers: ParticipantRegistry<TinyGroup>,
        predecessor: ResharePredecessor<TinyGroup>,
    }

    impl Topology {
        fn new() -> Self {
            Self {
                dealers: registry(DEALERS),
                receivers: registry(RECEIVERS),
                predecessor: predecessor([2; 32]),
            }
        }

        fn config(
            &self,
            threshold: usize,
            max_corrupt_receivers: usize,
        ) -> Result<ReshareConfig<TinyGroup>> {
            ReshareConfig::new(
                threshold,
                max_corrupt_receivers,
                SESSION,
                scalar(99),
                self.dealers.clone(),
                self.receivers.clone(),
                self.predecessor.clone(),
            )
        }

        fn with_dealers(dealers: &[(u32, u64)]) -> Self {
            Self {
                dealers: registry(dealers),
                ..Self::new()
            }
        }

        fn with_receivers(receivers: &[(u32, u64)]) -> Self {
            Self {
                receivers: registry(receivers),
                ..Self::new()
            }
        }
    }

    #[test]
    fn constructor_checks_run_in_order() {
        // Every check fails at first; fixing one at a time exposes the next.
        let invalid = Topology::with_dealers(&[(1, 21), (4, 14)]);
        assert_eq!(
            invalid.config(5, 3).unwrap_err(),
            Error::InvalidThreshold {
                threshold: 5,
                participants: 4
            }
        );
        assert_eq!(
            invalid.config(3, 3).unwrap_err(),
            Error::InsecureReshareThreshold {
                threshold: 3,
                max_corrupt_receivers: 3
            }
        );
        assert_eq!(
            invalid.config(3, 2).unwrap_err(),
            Error::InsufficientHonestReceivers {
                threshold: 3,
                receivers: 4,
                max_corrupt_receivers: 2
            }
        );
        assert_eq!(
            invalid.config(2, 1).unwrap_err(),
            Error::InvalidReshareConfiguration
        );
        assert_eq!(
            Topology::with_dealers(&[(1, 21), (2, 12)])
                .config(2, 1)
                .unwrap_err(),
            Error::ReshareKeyCollision {
                dealer: 1,
                receiver: 1
            }
        );
        Topology::new().config(2, 1).unwrap();
    }

    #[test]
    fn constructor_rejects_invalid_thresholds() {
        let topology = Topology::new();
        for threshold in [0, 5] {
            assert_eq!(
                topology.config(threshold, 0).unwrap_err(),
                Error::InvalidThreshold {
                    threshold,
                    participants: 4
                }
            );
        }
        for max_corrupt_receivers in [2, 3, 4] {
            assert_eq!(
                topology.config(2, max_corrupt_receivers).unwrap_err(),
                Error::InsecureReshareThreshold {
                    threshold: 2,
                    max_corrupt_receivers
                }
            );
        }
        topology.config(1, 0).unwrap();
        assert_eq!(
            topology.config(1, 1).unwrap_err(),
            Error::InsecureReshareThreshold {
                threshold: 1,
                max_corrupt_receivers: 1
            }
        );
    }

    #[test]
    fn constructor_enforces_the_liveness_bound_at_its_boundary() {
        let topology = Topology::new();
        // n_new = 4: the bound holds with equality at n_new − c = t_new.
        for (threshold, max_corrupt_receivers) in [(2, 1), (3, 1), (4, 0)] {
            topology.config(threshold, max_corrupt_receivers).unwrap();
        }
        for (threshold, max_corrupt_receivers) in [(3, 2), (4, 1)] {
            assert_eq!(
                topology
                    .config(threshold, max_corrupt_receivers)
                    .unwrap_err(),
                Error::InsufficientHonestReceivers {
                    threshold,
                    receivers: 4,
                    max_corrupt_receivers
                }
            );
        }
        let two_receivers = Topology::with_receivers(&[(1, 21), (2, 22)]);
        two_receivers.config(2, 0).unwrap();
        assert_eq!(
            two_receivers.config(2, 1).unwrap_err(),
            Error::InsufficientHonestReceivers {
                threshold: 2,
                receivers: 2,
                max_corrupt_receivers: 1
            }
        );
    }

    #[test]
    fn constructor_requires_dealers_from_the_predecessor_column() {
        for dealers in [&[(1, 11), (4, 14)][..], &[(1, 11)][..]] {
            assert_eq!(
                Topology::with_dealers(dealers).config(2, 1).unwrap_err(),
                Error::InvalidReshareConfiguration
            );
        }
        Topology::with_dealers(&[(1, 11), (3, 13)])
            .config(2, 1)
            .unwrap();
        Topology::with_dealers(&[(1, 11), (2, 12), (3, 13)])
            .config(2, 1)
            .unwrap();
    }

    #[test]
    fn constructor_rejects_cross_registry_collisions_with_roles() {
        // Dealer 1 and receiver 1 hold distinct keys in the valid topology:
        // equal integers name different seats.
        Topology::new().config(2, 1).unwrap();
        for (topology, dealer, receiver) in [
            (Topology::with_dealers(&[(1, 21), (2, 12)]), 1, 1),
            (Topology::with_dealers(&[(1, 11), (2, 23)]), 2, 3),
            (Topology::with_dealers(&[(1, 11), (2, 97 - 23)]), 2, 3),
            (
                Topology::with_receivers(&[(1, 21), (2, 22), (3, 97 - 11), (4, 24)]),
                1,
                3,
            ),
            (
                Topology::with_receivers(&[(1, 21), (2, 22), (3, 23), (4, 12)]),
                2,
                4,
            ),
        ] {
            assert_eq!(
                topology.config(2, 1).unwrap_err(),
                Error::ReshareKeyCollision { dealer, receiver }
            );
        }
    }

    #[test]
    fn root_binds_every_field() {
        let topology = Topology::new();
        let config = topology.config(2, 1).unwrap();
        assert_eq!(config.root(), topology.config(2, 1).unwrap().root());

        let with = |threshold: usize,
                    max_corrupt_receivers: usize,
                    session_id: SessionId,
                    beta: u64,
                    topology: &Topology| {
            ReshareConfig::new(
                threshold,
                max_corrupt_receivers,
                session_id,
                scalar(beta),
                topology.dealers.clone(),
                topology.receivers.clone(),
                topology.predecessor.clone(),
            )
            .unwrap()
        };
        // Dealers 1, 2 and 3 under one key set that is valid for t_old = 2 and
        // t_old = 3, so only the predecessor threshold differs.
        let three_dealers = |threshold: usize, column_threshold: usize| {
            let (public_key, shares) = column(column_threshold, &[1, 2, 3]);
            Topology {
                dealers: registry(&[(1, 11), (2, 12), (3, 13)]),
                predecessor: ResharePredecessor::new(threshold, public_key, shares, [2; 32])
                    .unwrap(),
                ..Topology::new()
            }
        };
        // (x − 4)(x − 5) + 1 takes the same value at 4 and 5, so these columns
        // differ only in the index of their last share.
        let last_share_at = |last: u32| {
            let shares = [(1, 13), (2, 7), (3, 3), (last, 1)]
                .map(|(index, value)| (idx(index), key(value)))
                .into();
            Topology {
                dealers: registry(&[(1, 11), (2, 12), (3, 13)]),
                predecessor: ResharePredecessor::new(3, key(21), shares, [2; 32]).unwrap(),
                ..Topology::new()
            }
        };
        // The same polynomial with a fourth share.
        let longer_column = {
            let (public_key, shares) = column(2, &[1, 2, 3, 4]);
            Topology {
                predecessor: ResharePredecessor::new(2, public_key, shares, [2; 32]).unwrap(),
                ..Topology::new()
            }
        };
        let roots = [
            config.root(),
            with(2, 1, SessionId([6; 32]), 99, &topology).root(),
            with(3, 1, SESSION, 99, &topology).root(),
            with(2, 0, SESSION, 99, &topology).root(),
            with(2, 1, SESSION, 98, &topology).root(),
            with(
                2,
                1,
                SESSION,
                99,
                &Topology::with_dealers(&[(1, 11), (2, 15)]),
            )
            .root(),
            with(
                2,
                1,
                SESSION,
                99,
                &Topology::with_dealers(&[(1, 11), (3, 12)]),
            )
            .root(),
            with(
                2,
                1,
                SESSION,
                99,
                &Topology::with_receivers(&[(1, 21), (2, 22), (3, 23), (4, 25)]),
            )
            .root(),
            with(
                2,
                1,
                SESSION,
                99,
                &Topology::with_receivers(&[(1, 21), (2, 22), (3, 23), (5, 24)]),
            )
            .root(),
            with(
                2,
                1,
                SESSION,
                99,
                &Topology {
                    predecessor: predecessor([3; 32]),
                    ..Topology::new()
                },
            )
            .root(),
            with(2, 1, SESSION, 99, &longer_column).root(),
            with(2, 1, SESSION, 99, &three_dealers(2, 2)).root(),
            with(2, 1, SESSION, 99, &three_dealers(3, 2)).root(),
            with(2, 1, SESSION, 99, &three_dealers(3, 3)).root(),
            with(2, 1, SESSION, 99, &last_share_at(4)).root(),
            with(2, 1, SESSION, 99, &last_share_at(5)).root(),
            topology.dealers.root(),
            topology.receivers.root(),
        ];
        assert_eq!(roots.iter().collect::<BTreeSet<_>>().len(), roots.len());
    }

    #[test]
    fn accessors_return_validated_fields() {
        let topology = Topology::new();
        let config = topology.config(2, 1).unwrap();
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.max_corrupt_receivers(), 1);
        assert_eq!(config.session_id(), SESSION);
        assert_eq!(config.beta(), &scalar(99));
        assert_eq!(config.dealers(), &topology.dealers);
        assert_eq!(config.receivers(), &topology.receivers);
        assert_eq!(config.predecessor(), &topology.predecessor);
        assert_eq!(config.dealers().public_key(idx(1)).unwrap(), &key(11));
        assert_eq!(config.receivers().public_key(idx(1)).unwrap(), &key(21));
    }

    #[test]
    fn predecessor_accepts_consistent_key_sets() {
        let (public_key, shares) = column(2, &[1, 2, 3]);
        let valid =
            ResharePredecessor::<TinyGroup>::new(2, public_key, shares.clone(), [2; 32]).unwrap();
        assert_eq!(valid.threshold(), 2);
        assert_eq!(valid.public_key(), &public_key);
        assert_eq!(valid.public_key_shares(), &shares);
        assert_eq!(valid.public_key_share(idx(2)), Some(&shares[&idx(2)]));
        assert_eq!(valid.public_key_share(idx(4)), None);
        assert_eq!(valid.completion_root(), [2; 32]);

        // A degree-1 column also lies on a polynomial of degree 2.
        ResharePredecessor::<TinyGroup>::new(3, public_key, shares, [2; 32]).unwrap();
        let (public_key, quadratic) = column(3, &[1, 2, 3, 4]);
        ResharePredecessor::<TinyGroup>::new(3, public_key, quadratic, [2; 32]).unwrap();

        // The column of 1 − x holds the identity at index 1, as a corrupt
        // dealer and receiver can force.
        let zero_share = ResharePredecessor::<TinyGroup>::new(
            2,
            key(1),
            [(1, 0), (2, 96), (3, 95)]
                .map(|(index, value)| (idx(index), key(value)))
                .into(),
            [2; 32],
        )
        .unwrap();
        assert_eq!(
            zero_share.public_key_share(idx(1)),
            Some(&TinyGroup::identity())
        );
    }

    #[test]
    fn predecessor_rejects_inconsistent_key_sets() {
        let (public_key, shares) = column(2, &[1, 2, 3]);
        let replace = |index: u32, value: TinyScalar| {
            let mut changed = shares.clone();
            changed.insert(idx(index), value);
            changed
        };
        let generator = TinyGroup::generator();
        // Shares at 1, 2 and 3 on the line x·g, whose key is the identity.
        let through_identity = [(1, 1), (2, 2), (3, 3)]
            .map(|(index, value)| (idx(index), key(value)))
            .into();
        // Index 98 is index 1 mod 97, so interpolation has no inverse.
        let aliased = [(1, 10), (98, 17)]
            .map(|(index, value)| (idx(index), key(value)))
            .into();
        for (threshold, public_key, shares) in [
            (0, public_key, shares.clone()),
            (4, public_key, shares.clone()),
            (2, TinyGroup::identity(), through_identity),
            (2, TinyGroup::identity(), shares.clone()),
            (2, public_key.add(&generator), shares.clone()),
            (2, public_key, replace(1, shares[&idx(1)].add(&generator))),
            (2, public_key, replace(3, shares[&idx(3)].add(&generator))),
            (2, public_key, replace(3, TinyGroup::identity())),
            (1, public_key, shares.clone()),
            (2, public_key, aliased),
        ] {
            assert_eq!(
                ResharePredecessor::<TinyGroup>::new(threshold, public_key, shares, [2; 32])
                    .unwrap_err(),
                Error::InvalidPredecessor
            );
        }
    }

    #[test]
    fn predecessor_validates_a_long_column() {
        // Index 98 is index 1 mod 97: as an extra share it must equal the
        // share at 1, and in the basis it leaves interpolation without an
        // inverse.
        let indexes = (1..=64).chain([98]).collect::<Vec<_>>();
        let (public_key, shares) = column(32, &indexes);
        let replace = |index: u32, value: TinyScalar| {
            let mut changed = shares.clone();
            changed.insert(idx(index), value);
            changed
        };
        let generator = TinyGroup::generator();
        for (threshold, accepted) in [(1, false), (32, true), (33, true), (64, true), (65, false)] {
            assert_eq!(
                ResharePredecessor::<TinyGroup>::new(
                    threshold,
                    public_key,
                    shares.clone(),
                    [2; 32]
                )
                .is_ok(),
                accepted,
                "threshold {threshold}"
            );
        }

        let (_, degree_32) = column(33, &indexes);
        for (public_key, shares) in [
            (public_key.add(&generator), shares.clone()),
            (public_key, replace(1, shares[&idx(1)].add(&generator))),
            (public_key, replace(33, shares[&idx(33)].add(&generator))),
            (public_key, replace(64, shares[&idx(64)].add(&generator))),
            (public_key, replace(98, shares[&idx(98)].add(&generator))),
            (public_key, replace(98, shares[&idx(2)])),
            (public_key, degree_32),
        ] {
            assert_eq!(
                ResharePredecessor::<TinyGroup>::new(32, public_key, shares, [2; 32]).unwrap_err(),
                Error::InvalidPredecessor
            );
        }
    }

    /// Complete a plain TinyGroup DKG and return its config and every output.
    fn completed_dkg() -> (
        DkgConfig<TinyGroup>,
        BTreeMap<ParticipantIndex, DkgOutput<TinyGroup>>,
    ) {
        const SECRETS: &[(u32, u64)] = &[(1, 31), (2, 32), (3, 33)];
        let config = DkgConfig::new(2, SessionId([7; 32]), scalar(99), registry(SECRETS)).unwrap();
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let dealings = SECRETS
            .iter()
            .map(|(index, secret)| {
                let dealing = create_dealing::<TinyGroup, NoProofBackend>(
                    idx(*index),
                    &scalar(*secret),
                    &config,
                    &mut rng,
                )
                .unwrap();
                (idx(*index), dealing)
            })
            .collect::<BTreeMap<_, _>>();
        let outputs = SECRETS
            .iter()
            .map(|(index, secret)| {
                let receiver = idx(*index);
                let peers = dealings
                    .iter()
                    .filter(|(dealer, _)| **dealer != receiver)
                    .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
                    .collect();
                let output = complete::<TinyGroup, NoProofBackend>(
                    receiver,
                    &scalar(*secret),
                    &dealings[&receiver],
                    &peers,
                    &config,
                )
                .unwrap();
                (receiver, output)
            })
            .collect();
        (config, outputs)
    }

    #[test]
    fn predecessor_derives_from_a_completed_dkg() {
        let (config, outputs) = completed_dkg();
        let output = &outputs[&idx(1)];
        let derived = ResharePredecessor::from_dkg_output(&config, output).unwrap();
        assert_eq!(derived.threshold(), config.threshold);
        assert_eq!(derived.public_key(), &output.public_key);
        assert_eq!(derived.public_key_shares(), &output.public_key_shares);
        assert_eq!(derived.completion_root(), output.transcript_root);
        for other in outputs.values() {
            assert_eq!(
                ResharePredecessor::from_dkg_output(&config, other).unwrap(),
                derived
            );
        }

        let reshare = ReshareConfig::new(
            2,
            1,
            SESSION,
            scalar(99),
            registry(&[(1, 11), (3, 13)]),
            registry(RECEIVERS),
            derived,
        )
        .unwrap();
        assert_eq!(reshare.predecessor().public_key(), &output.public_key);

        let mut missing = output.clone();
        missing.public_key_shares.remove(&idx(3));
        let mut extra = output.clone();
        extra.public_key_shares.insert(idx(4), key(5));
        let mut wrong_key = output.clone();
        wrong_key.public_key = wrong_key.public_key.add(&TinyGroup::generator());
        for output in [missing, extra, wrong_key] {
            assert_eq!(
                ResharePredecessor::from_dkg_output(&config, &output).unwrap_err(),
                Error::InvalidPredecessor
            );
        }
        let larger = DkgConfig::new(
            2,
            SessionId([7; 32]),
            scalar(99),
            registry(&[(1, 31), (2, 32), (3, 33), (4, 34)]),
        )
        .unwrap();
        assert_eq!(
            ResharePredecessor::from_dkg_output(&larger, output).unwrap_err(),
            Error::InvalidPredecessor
        );
    }

    #[test]
    fn predecessor_derives_from_a_reshare_output() {
        let config = Topology::new().config(3, 1).unwrap();
        // The receiver column of a degree-2 sharing of the predecessor key.
        let (public_key, shares) = column(3, &[1, 2, 3, 4]);
        assert_eq!(&public_key, config.predecessor().public_key());
        let output = DkgOutput {
            public_key,
            secret_share: crate::Share {
                participant: idx(1),
                value: TinyScalar::zero(),
            },
            public_key_shares: shares,
            transcript_root: [8; 32],
        };
        let derived = ResharePredecessor::from_reshare_output(&config, &output).unwrap();
        assert_eq!(derived.threshold(), 3);
        assert_eq!(derived.public_key(), &public_key);
        assert_eq!(derived.public_key_shares(), &output.public_key_shares);
        assert_eq!(derived.completion_root(), [8; 32]);

        let mut missing = output.clone();
        missing.public_key_shares.remove(&idx(4));
        // A consistent sharing of another key: the column shifted by g.
        let generator = TinyGroup::generator();
        let other_key = DkgOutput {
            public_key: public_key.add(&generator),
            public_key_shares: output
                .public_key_shares
                .iter()
                .map(|(index, share)| (*index, share.add(&generator)))
                .collect(),
            ..output.clone()
        };
        ResharePredecessor::<TinyGroup>::new(
            3,
            other_key.public_key,
            other_key.public_key_shares.clone(),
            [8; 32],
        )
        .unwrap();
        let mut off_polynomial = output.clone();
        off_polynomial
            .public_key_shares
            .insert(idx(4), TinyGroup::identity());
        for output in [missing, other_key, off_polynomial] {
            assert_eq!(
                ResharePredecessor::from_reshare_output(&config, &output).unwrap_err(),
                Error::InvalidPredecessor
            );
        }
    }

    /// Backend whose proof is the concatenation of the statement roots, so it
    /// binds every statement field. Proving checks that the witness opens the
    /// dealer key, the constant commitment, the share and the pad.
    enum RootsBackend {}

    impl EvrfProofBackend<TinyGroup> for RootsBackend {
        const PROOF_ID: &'static [u8] = b"golden-core/reshare-test-roots/v1";

        fn prove_batch(
            statements: &[EvrfStatement<TinyGroup>],
            witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            if statements.len() != witnesses.len() {
                return Err(Error::ProofVerificationFailed);
            }
            for (statement, witness) in statements.iter().zip(witnesses) {
                let constant = witness
                    .polynomial_coefficients
                    .first()
                    .map(TinyGroup::mul_generator);
                if TinyGroup::mul_generator(&witness.identity_secret) != statement.dealer_public_key
                    || constant.as_ref() != statement.commitment_coefficients.first()
                    || TinyGroup::mul_generator(&witness.share) != statement.share_commitment
                    || TinyGroup::mul_generator(&witness.pad) != statement.pad_commitment
                {
                    return Err(Error::ProofVerificationFailed);
                }
            }
            Ok(statement_roots(statements))
        }

        fn verify_batch(statements: &[EvrfStatement<TinyGroup>], proof: &[u8]) -> Result<()> {
            if proof == statement_roots(statements) {
                Ok(())
            } else {
                Err(Error::ProofVerificationFailed)
            }
        }
    }

    fn statement_roots(statements: &[EvrfStatement<TinyGroup>]) -> Vec<u8> {
        statements.iter().flat_map(EvrfStatement::root).collect()
    }

    /// RNG whose first `next_u32` calls return `chosen`, so a test fixes the
    /// sampled polynomial coefficients; everything else comes from ChaCha.
    struct ChosenRng {
        chosen: Vec<u32>,
        rest: ChaCha20Rng,
    }

    impl ChosenRng {
        fn new(chosen: &[TinyScalar], seed: u8) -> Self {
            Self {
                chosen: chosen
                    .iter()
                    .rev()
                    .map(|value| u32::from(value.to_repr()[0]))
                    .collect(),
                rest: ChaCha20Rng::from_seed([seed; 32]),
            }
        }
    }

    impl RngCore for ChosenRng {
        fn next_u32(&mut self) -> u32 {
            self.chosen.pop().unwrap_or_else(|| self.rest.next_u32())
        }

        fn next_u64(&mut self) -> u64 {
            self.rest.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.rest.fill_bytes(dest);
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> core::result::Result<(), rand_core::Error> {
            self.rest.try_fill_bytes(dest)
        }
    }

    impl CryptoRng for ChosenRng {}

    fn dealer_secret(dealer: ParticipantIndex) -> TinyScalar {
        scalar(10 + u64::from(dealer.get()))
    }

    fn receiver_secret(receiver: ParticipantIndex) -> TinyScalar {
        scalar(20 + u64::from(receiver.get()))
    }

    /// Registry of `indexes`, each under the key of `secret(index)`.
    fn seats(
        indexes: &[u32],
        secret: fn(ParticipantIndex) -> TinyScalar,
    ) -> ParticipantRegistry<TinyGroup> {
        registry(
            &indexes
                .iter()
                .map(|index| (*index, u64::from(secret(idx(*index)).to_repr()[0])))
                .collect::<Vec<_>>(),
        )
    }

    /// `receiver`'s share of `message`, decrypted as the receiver would.
    fn decrypt(
        message: &DealerMessage<TinyGroup>,
        config: &ReshareConfig<TinyGroup>,
        receiver: ParticipantIndex,
    ) -> TinyScalar {
        let secret = receiver_secret(receiver);
        let pad = <RootsBackend as EvrfProofBackend<TinyGroup>>::derive_pad(
            message.msg_i,
            config.beta(),
            &secret,
            config.dealers().public_key(message.dealer).unwrap(),
            config.receivers().public_key(receiver).unwrap(),
        )
        .unwrap();
        message.encrypted_shares[&receiver]
            .encrypted_share
            .sub(&pad)
    }

    fn subsets(items: &[ParticipantIndex], size: usize) -> Vec<Vec<ParticipantIndex>> {
        if size == 0 {
            return vec![Vec::new()];
        }
        let Some((first, rest)) = items.split_first() else {
            return Vec::new();
        };
        let mut with_first = subsets(rest, size - 1);
        for subset in &mut with_first {
            subset.insert(0, *first);
        }
        with_first.extend(subsets(rest, size));
        with_first
    }

    /// A completed sharing: its public key set and every holder's share.
    struct Generation {
        predecessor: ResharePredecessor<TinyGroup>,
        shares: BTreeMap<ParticipantIndex, TinyScalar>,
    }

    impl Generation {
        fn from_dkg(
            config: &DkgConfig<TinyGroup>,
            outputs: &BTreeMap<ParticipantIndex, DkgOutput<TinyGroup>>,
        ) -> Self {
            let first = outputs.values().next().unwrap();
            Self {
                predecessor: ResharePredecessor::from_dkg_output(config, first).unwrap(),
                shares: outputs
                    .iter()
                    .map(|(holder, output)| (*holder, output.secret_share.value))
                    .collect(),
            }
        }

        fn plain() -> Self {
            let (config, outputs) = completed_dkg();
            Self::from_dkg(&config, &outputs)
        }

        fn share(&self, holder: ParticipantIndex) -> Share<TinyScalar> {
            Share {
                participant: holder,
                value: self.shares[&holder],
            }
        }

        fn secret(&self) -> TinyScalar {
            let basis = self
                .shares
                .keys()
                .take(self.predecessor.threshold())
                .map(|holder| self.share(*holder))
                .collect::<Vec<_>>();
            lagrange_interpolate_at_zero(&basis).unwrap()
        }

        fn reshare_config(
            &self,
            dealers: &[u32],
            receivers: &[u32],
            threshold: usize,
            session: u8,
        ) -> ReshareConfig<TinyGroup> {
            ReshareConfig::new(
                threshold,
                0,
                SessionId([session; 32]),
                scalar(99),
                seats(dealers, dealer_secret),
                seats(receivers, receiver_secret),
                self.predecessor.clone(),
            )
            .unwrap()
        }

        fn deal(
            &self,
            config: &ReshareConfig<TinyGroup>,
            dealer: ParticipantIndex,
            rng: &mut impl CryptoRngCore,
        ) -> DealerMessage<TinyGroup> {
            create_reshare_dealing::<TinyGroup, RootsBackend>(
                dealer,
                &dealer_secret(dealer),
                &self.share(dealer),
                config,
                rng,
            )
            .unwrap()
        }

        /// One honest dealing from every declared dealer.
        fn board(
            &self,
            config: &ReshareConfig<TinyGroup>,
            seed: u8,
        ) -> BTreeMap<ParticipantIndex, DealerMessage<TinyGroup>> {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            config
                .dealers()
                .indexes()
                .map(|dealer| (dealer, self.deal(config, dealer, &mut rng)))
                .collect()
        }

        /// Complete `board` for every receiver and check the result: every
        /// output and the public aggregation agree, X is unchanged, every
        /// t_new shares reconstruct x and t_new − 1 shares do not.
        fn complete(
            &self,
            config: &ReshareConfig<TinyGroup>,
            board: &BTreeMap<ParticipantIndex, DealerMessage<TinyGroup>>,
        ) -> Self {
            let public =
                aggregate_reshare_public::<TinyGroup, RootsBackend>(board, config).unwrap();
            assert_eq!(&public.public_key, self.predecessor.public_key());
            let outputs = config
                .receivers()
                .indexes()
                .map(|receiver| {
                    let output = complete_reshare::<TinyGroup, RootsBackend>(
                        receiver,
                        &receiver_secret(receiver),
                        board,
                        config,
                    )
                    .unwrap();
                    assert_eq!(output.public_key, public.public_key);
                    assert_eq!(output.public_key_shares, public.public_key_shares);
                    assert_eq!(output.transcript_root, public.transcript_root);
                    assert_eq!(output.secret_share.participant, receiver);
                    assert_eq!(
                        TinyGroup::mul_generator(&output.secret_share.value),
                        public.public_key_shares[&receiver]
                    );
                    (receiver, output)
                })
                .collect::<BTreeMap<_, _>>();
            let next = Self {
                predecessor: ResharePredecessor::from_reshare_output(
                    config,
                    outputs.values().next().unwrap(),
                )
                .unwrap(),
                shares: outputs
                    .iter()
                    .map(|(holder, output)| (*holder, output.secret_share.value))
                    .collect(),
            };

            let secret = self.secret();
            let threshold = config.threshold();
            let holders = next.shares.keys().copied().collect::<Vec<_>>();
            let shares = |subset: &[ParticipantIndex]| {
                subset
                    .iter()
                    .map(|holder| next.share(*holder))
                    .collect::<Vec<_>>()
            };
            for subset in subsets(&holders, threshold) {
                assert_eq!(
                    reconstruct_secret(&shares(&subset), threshold).unwrap(),
                    secret
                );
            }
            if threshold > 1 {
                for subset in subsets(&holders, threshold - 1) {
                    assert_ne!(
                        lagrange_interpolate_at_zero(&shares(&subset)).unwrap(),
                        secret
                    );
                }
            }
            next
        }
    }

    #[test]
    fn reshare_preserves_the_key_and_every_threshold_set_reconstructs_it() {
        let old = Generation::plain();
        for (dealers, receivers, threshold, seed) in [
            (&[1, 3][..], &[1, 2, 3, 4][..], 3, 1),
            (&[1, 2, 3][..], &[2, 5][..], 2, 2),
            (&[2, 3][..], &[1, 2, 3][..], 1, 3),
        ] {
            let config = old.reshare_config(dealers, receivers, threshold, 5);
            let board = old.board(&config, seed);
            for message in board.values() {
                for receiver in config.receivers().indexes() {
                    verify_reshare_dealing_for_receiver::<TinyGroup, RootsBackend>(
                        receiver,
                        &receiver_secret(receiver),
                        message,
                        &config,
                    )
                    .unwrap();
                }
            }
            let next = old.complete(&config, &board);
            assert_eq!(next.predecessor.public_key(), old.predecessor.public_key());
            assert_eq!(next.predecessor.threshold(), threshold);
        }
    }

    #[test]
    fn reshare_dealings_pin_the_predecessor_share_and_reach_every_receiver() {
        let old = Generation::plain();
        // Old index 1 is also a receiver index: the dealing has a slot for it.
        let config = old.reshare_config(&[1, 3], &[1, 2, 3, 4], 3, 5);
        for (dealer, message) in old.board(&config, 1) {
            assert_eq!(message.registry_root, config.root());
            assert_eq!(message.session_id, config.session_id());
            assert_eq!(message.commitment.coefficients().len(), 3);
            assert_eq!(
                message.commitment.coefficients().first(),
                config.predecessor().public_key_share(dealer)
            );
            assert!(message
                .encrypted_shares
                .keys()
                .copied()
                .eq(config.receivers().indexes()));
            assert_eq!(message.proof.len(), 32 * config.receivers().len());
            assert_eq!(message.transcript_root, message.recompute_transcript_root());
            verify_reshare_dealing::<TinyGroup, RootsBackend>(&message, &config).unwrap();
        }
    }

    #[test]
    fn reshare_dealer_checks_precede_sampling() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 2], &[1, 2, 3], 2, 5);
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let dealer = idx(1);
        let share = old.share(dealer);
        let with_value = |value: TinyScalar| Share {
            participant: dealer,
            value,
        };
        let mut attempt = |dealer: ParticipantIndex, identity: TinyScalar, share: &Share<_>| {
            create_reshare_dealing::<TinyGroup, RootsBackend>(
                dealer, &identity, share, &config, &mut rng,
            )
            .unwrap_err()
        };

        // A dealer outside Q fails first, even with a wrong key and share.
        for outsider in [3, 4] {
            assert_eq!(
                attempt(idx(outsider), scalar(1), &with_value(scalar(1))),
                Error::UnknownParticipant(outsider)
            );
        }
        // Then the dealer key, even with a wrong share.
        for identity in [dealer_secret(idx(2)), receiver_secret(dealer), scalar(31)] {
            assert_eq!(
                attempt(dealer, identity, &with_value(scalar(1))),
                Error::IdentityKeyMismatch
            );
        }
        // Then the predecessor share.
        let wrong_shares = [
            with_value(share.value.add(&TinyScalar::one())),
            with_value(TinyScalar::zero().sub(&share.value)),
            with_value(TinyScalar::zero()),
            with_value(old.share(idx(2)).value),
            old.share(idx(2)),
            Share {
                participant: idx(2),
                value: share.value,
            },
        ];
        for wrong in &wrong_shares {
            assert_eq!(
                attempt(dealer, dealer_secret(dealer), wrong),
                Error::PredecessorShareMismatch
            );
        }
        assert_eq!(rng.get_word_pos(), 0);

        old.deal(&config, dealer, &mut rng);
        assert_ne!(rng.get_word_pos(), 0);
    }

    #[test]
    fn a_constant_other_than_the_predecessor_share_is_rejected_before_proofs() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 3], &[1, 2, 3, 4], 3, 5);
        let mut board = old.board(&config, 1);
        let dealer = idx(3);

        // A dealer that deals another constant with a valid proof.
        let (dishonest, _) = deal_with_layout::<TinyGroup, RootsBackend>(
            &DealingLayout::reshare(&config),
            dealer,
            &dealer_secret(dealer),
            old.share(dealer).value.add(&TinyScalar::one()),
            &mut ChaCha20Rng::from_seed([6; 32]),
        )
        .unwrap();
        // A broadcast whose constant changed after its dealing root was
        // computed: the constant check runs before the root recompute.
        let mut tampered = board[&dealer].clone();
        let mut coefficients = tampered.commitment.coefficients().to_vec();
        coefficients[0] = coefficients[0].add(&TinyGroup::generator());
        tampered.commitment = FeldmanCommitment::from_coefficients(coefficients).unwrap();

        for message in [dishonest, tampered] {
            let expected = Error::ReshareConstantMismatch(dealer.get());
            assert_eq!(
                verify_reshare_dealing::<TinyGroup, RootsBackend>(&message, &config).unwrap_err(),
                expected
            );
            assert_eq!(
                verify_reshare_dealing_for_receiver::<TinyGroup, RootsBackend>(
                    idx(1),
                    &receiver_secret(idx(1)),
                    &message,
                    &config,
                )
                .unwrap_err(),
                expected
            );
            board.insert(dealer, message);
            let messages = board.values().collect::<Vec<_>>();
            assert_eq!(
                verify_reshare_dealings::<TinyGroup, RootsBackend>(&messages, &config).unwrap_err(),
                expected
            );
            assert_eq!(
                complete_reshare::<TinyGroup, RootsBackend>(
                    idx(1),
                    &receiver_secret(idx(1)),
                    &board,
                    &config,
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(
                aggregate_reshare_public::<TinyGroup, RootsBackend>(&board, &config).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn aggregation_rejects_a_board_that_moves_the_group_key() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 3], &[1, 2, 3, 4], 3, 5);
        let mut board = old.board(&config, 1);
        let mut coefficients = board[&idx(1)].commitment.coefficients().to_vec();
        coefficients[0] = coefficients[0].add(&TinyGroup::generator());
        board.get_mut(&idx(1)).unwrap().commitment =
            FeldmanCommitment::from_coefficients(coefficients).unwrap();
        let references = board
            .iter()
            .map(|(dealer, message)| (*dealer, message))
            .collect();
        let weights = lagrange_coefficients_at_zero(&[scalar(1), scalar(3)]).unwrap();
        assert_eq!(
            aggregate_verified(&references, &weights, &config).unwrap_err(),
            Error::CommitmentVerificationFailed
        );
    }

    #[test]
    fn plain_and_reshare_dealings_do_not_replay_into_each_other() {
        let old = Generation::plain();
        let (plain, _) = completed_dkg();
        let plain_dealings = [1, 3]
            .into_iter()
            .map(|dealer| {
                let dealing = create_dealing::<TinyGroup, RootsBackend>(
                    idx(dealer),
                    &scalar(30 + u64::from(dealer)),
                    &plain,
                    &mut ChaCha20Rng::from_seed([dealer as u8; 32]),
                )
                .unwrap();
                (idx(dealer), dealing.message)
            })
            .collect::<BTreeMap<_, _>>();

        // Same session as the plain run: the binding roots differ.
        let same_session = old.reshare_config(&[1, 3], &[1, 2, 3], 2, 7);
        assert_eq!(same_session.session_id(), plain.session_id);
        // Another session: the session check comes first.
        let other_session = old.reshare_config(&[1, 3], &[1, 2, 3], 2, 5);
        for (config, expected) in [
            (&same_session, Error::RegistryMismatch),
            (&other_session, Error::SessionMismatch),
        ] {
            let reshare_dealings = old.board(config, 1);
            for (plain_message, reshare_message) in
                plain_dealings.values().zip(reshare_dealings.values())
            {
                assert_eq!(
                    verify_reshare_dealing::<TinyGroup, RootsBackend>(plain_message, config)
                        .unwrap_err(),
                    expected
                );
                assert_eq!(
                    verify_dealing::<TinyGroup, RootsBackend>(reshare_message, &plain).unwrap_err(),
                    expected
                );
            }
            assert_eq!(
                verify_dealings::<TinyGroup, RootsBackend>(
                    &reshare_dealings.values().collect::<Vec<_>>(),
                    &plain
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(
                complete_reshare::<TinyGroup, RootsBackend>(
                    idx(1),
                    &receiver_secret(idx(1)),
                    &plain_dealings,
                    config,
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(
                aggregate_reshare_public::<TinyGroup, RootsBackend>(&plain_dealings, config)
                    .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn reshare_dealings_bind_their_predecessor() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 3], &[1, 2, 3], 2, 5);
        let message = old.board(&config, 1).remove(&idx(1)).unwrap();
        let config_with = |predecessor: ResharePredecessor<TinyGroup>| {
            Generation {
                predecessor,
                shares: BTreeMap::new(),
            }
            .reshare_config(&[1, 3], &[1, 2, 3], 2, 5)
        };
        // The same key set under another completion root.
        let sibling = config_with(
            ResharePredecessor::new(
                2,
                *old.predecessor.public_key(),
                old.predecessor.public_key_shares().clone(),
                [9; 32],
            )
            .unwrap(),
        );
        // Another sharing altogether.
        let (public_key, shares) = column(2, &[1, 2, 3]);
        let other = config_with(ResharePredecessor::new(2, public_key, shares, [2; 32]).unwrap());
        assert_ne!(
            other.predecessor().public_key_share(idx(1)),
            config.predecessor().public_key_share(idx(1))
        );

        for (target, relabelled) in [
            (&sibling, Error::ProofVerificationFailed),
            (&other, Error::ReshareConstantMismatch(1)),
        ] {
            assert_ne!(target.root(), config.root());
            assert_eq!(
                verify_reshare_dealing::<TinyGroup, RootsBackend>(&message, target).unwrap_err(),
                Error::RegistryMismatch
            );
            // Moved into the other configuration's slot, with a consistent
            // dealing root.
            let mut moved = message.clone();
            moved.registry_root = target.root();
            moved.transcript_root = moved.recompute_transcript_root();
            assert_eq!(
                verify_reshare_dealing::<TinyGroup, RootsBackend>(&moved, target).unwrap_err(),
                relabelled
            );
        }
        assert_eq!(
            create_reshare_dealing::<TinyGroup, RootsBackend>(
                idx(1),
                &dealer_secret(idx(1)),
                &old.share(idx(1)),
                &other,
                &mut ChaCha20Rng::from_seed([3; 32]),
            )
            .unwrap_err(),
            Error::PredecessorShareMismatch
        );
    }

    #[test]
    fn completion_requires_exactly_the_declared_dealers() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 3], &[1, 2, 3], 2, 5);
        let board = old.board(&config, 1);
        // A valid dealing from old index 2 under a configuration that
        // declares it.
        let wider = old.reshare_config(&[1, 2, 3], &[1, 2, 3], 2, 5);
        let undeclared = old.deal(&wider, idx(2), &mut ChaCha20Rng::from_seed([2; 32]));

        let mut missing = board.clone();
        missing.remove(&idx(3));
        let mut extra = board.clone();
        extra.insert(idx(2), undeclared);
        let mut relabelled = board.clone();
        let moved = relabelled.remove(&idx(3)).unwrap();
        relabelled.insert(idx(2), moved);
        let mut swapped = board.clone();
        let first = swapped[&idx(1)].clone();
        swapped.insert(idx(1), swapped[&idx(3)].clone());
        swapped.insert(idx(3), first);

        for (candidate, expected) in [
            (missing, Error::MissingDealing(3)),
            (extra, Error::UnknownParticipant(2)),
            (
                relabelled,
                Error::DealerKeyMismatch {
                    map_key: 2,
                    message_dealer: 3,
                },
            ),
            (
                swapped,
                Error::DealerKeyMismatch {
                    map_key: 1,
                    message_dealer: 3,
                },
            ),
            (BTreeMap::new(), Error::MissingDealing(1)),
        ] {
            assert_eq!(
                complete_reshare::<TinyGroup, RootsBackend>(
                    idx(2),
                    &receiver_secret(idx(2)),
                    &candidate,
                    &config,
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(
                aggregate_reshare_public::<TinyGroup, RootsBackend>(&candidate, &config)
                    .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn completion_rejects_a_wrong_receiver_key() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 3], &[1, 2, 3], 2, 5);
        let board = old.board(&config, 1);
        let message = &board[&idx(1)];
        for (receiver, secret) in [
            (idx(1), receiver_secret(idx(2))),
            (idx(1), dealer_secret(idx(1))),
            (idx(1), scalar(31)),
            (idx(4), receiver_secret(idx(4))),
        ] {
            assert_eq!(
                complete_reshare::<TinyGroup, RootsBackend>(receiver, &secret, &board, &config)
                    .unwrap_err(),
                Error::IdentityKeyMismatch
            );
            assert_eq!(
                verify_reshare_dealing_for_receiver::<TinyGroup, RootsBackend>(
                    receiver, &secret, message, &config,
                )
                .unwrap_err(),
                Error::IdentityKeyMismatch
            );
        }
    }

    #[test]
    fn one_receiver_reshare_requires_a_proof() {
        let old = Generation::plain();
        let config = old.reshare_config(&[1, 2], &[1], 1, 5);
        let board = old.board(&config, 1);
        for (dealer, message) in &board {
            assert_eq!(message.proof.len(), 32);
            let mut unproven = message.clone();
            unproven.proof.clear();
            assert_eq!(
                verify_reshare_dealing::<TinyGroup, RootsBackend>(&unproven, &config).unwrap_err(),
                Error::ProofVerificationFailed
            );
            assert_eq!(
                verify_reshare_dealings::<TinyGroup, RootsBackend>(&[&unproven], &config)
                    .unwrap_err(),
                Error::DealerProofVerificationFailed(dealer.get())
            );
            let mut unproven_board = board.clone();
            unproven_board.insert(*dealer, unproven);
            assert_eq!(
                complete_reshare::<TinyGroup, RootsBackend>(
                    idx(1),
                    &receiver_secret(idx(1)),
                    &unproven_board,
                    &config,
                )
                .unwrap_err(),
                Error::DealerProofVerificationFailed(dealer.get())
            );
        }
        // The dealer asks the backend for a proof even for one receiver.
        assert_eq!(
            create_reshare_dealing::<TinyGroup, FailingProver>(
                idx(1),
                &dealer_secret(idx(1)),
                &old.share(idx(1)),
                &config,
                &mut ChaCha20Rng::from_seed([1; 32]),
            )
            .unwrap_err(),
            Error::DecryptionFailed
        );
        let next = old.complete(&config, &board);
        assert_eq!(next.shares[&idx(1)], old.secret());
    }

    /// Backend whose prover fails with a marker error.
    enum FailingProver {}

    impl EvrfProofBackend<TinyGroup> for FailingProver {
        const PROOF_ID: &'static [u8] = b"golden-core/reshare-test-failing-prover/v1";

        fn prove_batch(
            _statements: &[EvrfStatement<TinyGroup>],
            _witnesses: &[EvrfWitness<TinyGroup>],
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            Err(Error::DecryptionFailed)
        }

        fn verify_batch(_statements: &[EvrfStatement<TinyGroup>], _proof: &[u8]) -> Result<()> {
            Err(Error::ProofVerificationFailed)
        }
    }

    #[test]
    fn reshares_chain_through_a_forced_zero_share() {
        let old = Generation::plain();
        // Dealer 2 and new receiver 1 are corrupt, one member of each
        // committee.
        let config = old.reshare_config(&[1, 2], &[1, 2, 3], 2, 5);
        let honest = old.deal(&config, idx(1), &mut ChaCha20Rng::from_seed([2; 32]));
        let received = decrypt(&honest, &config, idx(1));
        // The weights of dealers 1 and 2 at zero are 2 and −1, so
        // f_2(1) = 2·f_1(1) zeroes receiver 1's share while f_2(0) stays
        // dealer 2's predecessor share.
        let slope = received.add(&received).sub(&old.share(idx(2)).value);
        let corrupt = old.deal(&config, idx(2), &mut ChosenRng::new(&[slope], 3));
        let board = [(idx(1), honest), (idx(2), corrupt)].into();
        let next = old.complete(&config, &board);
        assert_eq!(next.shares[&idx(1)], TinyScalar::zero());
        assert_eq!(
            next.predecessor.public_key_share(idx(1)),
            Some(&TinyGroup::identity())
        );

        for (dealers, seed) in [(&[1, 2][..], 4), (&[1, 3][..], 5)] {
            let config = next.reshare_config(dealers, &[1, 2, 3, 4], 3, 6);
            assert_eq!(
                config.predecessor().public_key_share(idx(1)),
                Some(&TinyGroup::identity())
            );
            let last = next.complete(&config, &next.board(&config, seed));
            assert_eq!(last.secret(), old.secret());
        }
    }

    #[test]
    fn plain_outputs_with_a_forced_identity_share_reshare() {
        const SECRETS: &[(u32, u64)] = &[(1, 31), (2, 32), (3, 33)];
        let config = DkgConfig::new(2, SessionId([6; 32]), scalar(99), registry(SECRETS)).unwrap();
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        let mut dealings = [1, 2]
            .into_iter()
            .map(|dealer| {
                let dealer = idx(dealer);
                let dealing = create_dealing::<TinyGroup, RootsBackend>(
                    dealer,
                    &scalar(30 + u64::from(dealer.get())),
                    &config,
                    &mut rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect::<BTreeMap<_, _>>();
        // Participant 3 is corrupt and rushing: it decrypts its shares of the
        // honest dealings, then deals f_3 = c + a·x with f_3(3) cancelling
        // their sum, so its share is zero.
        let me = idx(3);
        let my_secret = scalar(33);
        let received = dealings
            .values()
            .map(|dealing| {
                let message = &dealing.message;
                let pad = <RootsBackend as EvrfProofBackend<TinyGroup>>::derive_pad(
                    message.msg_i,
                    &config.beta,
                    &my_secret,
                    config.registry.public_key(message.dealer).unwrap(),
                    config.registry.public_key(me).unwrap(),
                )
                .unwrap();
                message.encrypted_shares[&me].encrypted_share.sub(&pad)
            })
            .fold(TinyScalar::zero(), |sum, share| sum.add(&share));
        let constant = scalar(5);
        let slope = TinyScalar::zero()
            .sub(&received.add(&constant))
            .mul(&scalar(3).invert().unwrap());
        dealings.insert(
            me,
            create_dealing_with_secret::<TinyGroup, RootsBackend>(
                me,
                &my_secret,
                constant,
                &config,
                &mut ChosenRng::new(&[slope], 7),
            )
            .unwrap(),
        );
        let outputs = config
            .registry
            .indexes()
            .map(|receiver| {
                let peers = dealings
                    .iter()
                    .filter(|(dealer, _)| **dealer != receiver)
                    .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
                    .collect();
                let output = complete::<TinyGroup, RootsBackend>(
                    receiver,
                    &scalar(30 + u64::from(receiver.get())),
                    &dealings[&receiver],
                    &peers,
                    &config,
                )
                .unwrap();
                (receiver, output)
            })
            .collect::<BTreeMap<_, _>>();
        let plain = Generation::from_dkg(&config, &outputs);
        assert_eq!(plain.shares[&me], TinyScalar::zero());
        assert_eq!(
            plain.predecessor.public_key_share(me),
            Some(&TinyGroup::identity())
        );
        assert!(!bool::from(TinyGroup::is_identity(
            plain.predecessor.public_key()
        )));

        let config = plain.reshare_config(&[1, 3], &[1, 2, 3], 2, 8);
        assert_eq!(
            config.predecessor().public_key_share(me),
            Some(&TinyGroup::identity())
        );
        plain.complete(&config, &plain.board(&config, 8));
    }
}
