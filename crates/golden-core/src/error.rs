//! Error types for Golden core operations.

/// Result type used by `golden-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by Golden core operations.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A participant index was zero.
    #[error("participant indexes must be nonzero")]
    ZeroParticipantIndex,

    /// A participant index appeared more than once.
    #[error("duplicate participant index {0}")]
    DuplicateParticipantIndex(u32),

    /// A participant identity public key appeared more than once.
    #[error("duplicate participant public key for participants {first} and {second}")]
    DuplicateParticipantPublicKey {
        /// First participant index using the public key.
        first: u32,
        /// Second participant index using the public key.
        second: u32,
    },

    /// A participant identity public key was the negation of another one.
    #[error("negated participant public key for participants {first} and {second}")]
    NegatedParticipantPublicKey {
        /// Participant index registered first.
        first: u32,
        /// Participant index whose key negates the first one.
        second: u32,
    },

    /// A participant identity key proof did not verify against its key.
    #[error("invalid identity key proof for participant {0}")]
    InvalidIdentityKeyProof(u32),

    /// The threshold was invalid for the requested operation.
    #[error("invalid threshold: threshold={threshold}, participants={participants}")]
    InvalidThreshold {
        /// Requested threshold.
        threshold: usize,
        /// Number of participants.
        participants: usize,
    },

    /// An interpolation denominator was not invertible.
    #[error("non-invertible interpolation denominator")]
    NonInvertibleDenominator,

    /// A scalar or point encoding was rejected by the backend.
    #[error("invalid encoding")]
    InvalidEncoding,

    /// A Feldman commitment had no coefficients.
    #[error("empty Feldman commitment")]
    EmptyCommitment,

    /// A Feldman commitment had the wrong number of coefficients.
    #[error("invalid commitment degree: expected {expected} coefficients, got {actual}")]
    InvalidCommitmentDegree {
        /// Expected coefficient count.
        expected: usize,
        /// Actual coefficient count.
        actual: usize,
    },

    /// A message belongs to a different session.
    #[error("session mismatch")]
    SessionMismatch,

    /// A message belongs to a different participant registry.
    #[error("participant registry mismatch")]
    RegistryMismatch,

    /// An identity secret key did not match the registered identity public key.
    #[error("identity secret key does not match registered public key")]
    IdentityKeyMismatch,

    /// A participant was not present in the registry.
    #[error("unknown participant {0}")]
    UnknownParticipant(u32),

    /// A peer dealing map key did not match the message's dealer.
    #[error("dealer key mismatch: map key {map_key}, message dealer {message_dealer}")]
    DealerKeyMismatch {
        /// Dealer index from the peer-dealing map key.
        map_key: u32,
        /// Dealer index claimed by the dealer message.
        message_dealer: u32,
    },

    /// A local private share did not belong to the expected participant.
    #[error("private share participant mismatch: expected {expected}, got {actual}")]
    PrivateShareParticipantMismatch {
        /// Expected participant index.
        expected: u32,
        /// Actual private-share participant index.
        actual: u32,
    },

    /// A required dealing was missing.
    #[error("missing dealing from participant {0}")]
    MissingDealing(u32),

    /// A required share was missing.
    #[error("missing share for participant {0}")]
    MissingShare(u32),

    /// A dealing contained a share or proof for an unexpected participant.
    #[error("unexpected share for participant {0}")]
    UnexpectedShare(u32),

    /// A proof backend rejected the statement.
    #[error("proof verification failed")]
    ProofVerificationFailed,

    /// A dealer proof failed individual verification after a batch failure.
    #[error("proof verification failed for dealer {0}")]
    DealerProofVerificationFailed(u32),

    /// A dealing share did not match its Feldman commitment.
    #[error("commitment verification failed")]
    CommitmentVerificationFailed,

    /// Authenticated decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// A reshare predecessor key set was not a consistent sharing.
    #[error("invalid reshare predecessor")]
    InvalidPredecessor,

    /// A reshare dealer set was not drawn from the predecessor's shares, or
    /// was smaller than the predecessor threshold.
    #[error("invalid reshare configuration")]
    InvalidReshareConfiguration,

    /// A reshare dealer key equals or negates a receiver key.
    #[error("reshare key collision between dealer {dealer} and receiver {receiver}")]
    ReshareKeyCollision {
        /// Dealer index, in the predecessor's index space.
        dealer: u32,
        /// Receiver index, in the new committee's index space.
        receiver: u32,
    },

    /// The declared corrupt-receiver bound reached the reshare threshold.
    #[error(
        "insecure reshare threshold: threshold={threshold}, \
         max_corrupt_receivers={max_corrupt_receivers}"
    )]
    InsecureReshareThreshold {
        /// Requested reshare threshold.
        threshold: usize,
        /// Declared bound on corrupt receivers.
        max_corrupt_receivers: usize,
    },

    /// Honest receivers could not reach the reshare threshold.
    #[error(
        "honest receivers cannot reach the reshare threshold: threshold={threshold}, \
         receivers={receivers}, max_corrupt_receivers={max_corrupt_receivers}"
    )]
    InsufficientHonestReceivers {
        /// Requested reshare threshold.
        threshold: usize,
        /// Number of receivers.
        receivers: usize,
        /// Declared bound on corrupt receivers.
        max_corrupt_receivers: usize,
    },

    /// A reshare dealer's predecessor share did not match its public share.
    #[error("predecessor share does not match the dealer's public share")]
    PredecessorShareMismatch,

    /// A reshare dealing's constant commitment differed from the dealer's
    /// predecessor public share. The index is the dealer's predecessor index.
    #[error("reshare constant commitment mismatch for dealer {0}")]
    ReshareConstantMismatch(u32),
}
