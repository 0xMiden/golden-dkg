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
//! [`ResharePredecessor`] is the predecessor's public key set: t_old, X, the
//! full public-share column Y_i and the completion root. It holds no secrets,
//! and applications establish its authenticity. The completion root is the
//! lineage handle: it binds the predecessor's session, its registry or reshare
//! root and every dealing coefficient, hence X and the Y column. The library
//! never checks it against X and Y; it is an agreement handle.
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
//! slots, so a one-receiver reshare carries a proof.
//!
//! Completion takes exactly every declared dealer, verifies every dealing,
//! decrypts and checks the receiver's slot in each, and sets
//! x'_j = Σ λ^Q_i·f_i(j) and A'_k = Σ λ^Q_i·C_{i,k}, asserting A'_0 == X. A
//! member of both committees completes with its receiver key, and its own
//! dealing is on the board like any other. Public aggregation runs the same
//! steps without a receiver, so leaving members can confirm the result.
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

use crate::dkg::{DkgConfig, DkgOutput, ParticipantRegistry, SessionId, PROTOCOL_VERSION};
use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::{
    lagrange_coefficients_at_zero, Error, GoldenGroup, GoldenScalar, ParticipantIndex, Result,
};

/// Public key set of the sharing a reshare preserves.
///
/// Holds the predecessor threshold t_old, the group key X, the public share
/// Y_i of every predecessor participant and the predecessor's completion
/// root. It holds no secrets.
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
    /// `public_key`. A share may be the identity. Any failure is
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
    if interpolate_at_zero::<G>(&xs, &points)? != *public_key {
        return Ok(false);
    }
    for (participant, point) in shares.iter().skip(threshold) {
        // Shifting every x by -x_j moves the evaluation at x_j to zero.
        let x = participant.to_scalar::<G::Scalar>()?;
        let shifted = xs.iter().map(|xi| xi.sub(&x)).collect::<Vec<_>>();
        if interpolate_at_zero::<G>(&shifted, &points)? != *point {
            return Ok(false);
        }
    }
    Ok(true)
}

fn interpolate_at_zero<G: GoldenGroup>(
    xs: &[G::Scalar],
    points: &[&G::Element],
) -> Result<G::Element> {
    let coefficients = lagrange_coefficients_at_zero(xs)?;
    Ok(points
        .iter()
        .zip(&coefficients)
        .fold(G::identity(), |sum, (point, coefficient)| {
            G::add(&sum, &G::mul(point, coefficient))
        }))
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
    use rand_core::CryptoRngCore;

    use super::*;
    use crate::dkg::{complete, create_dealing, EvrfProofBackend, EvrfStatement, EvrfWitness};
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::IdentityKeyProof;

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
}
