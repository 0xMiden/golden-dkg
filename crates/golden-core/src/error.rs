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

    /// The threshold was invalid for the requested operation.
    #[error("invalid threshold: threshold={threshold}, participants={participants}")]
    InvalidThreshold {
        /// Requested threshold.
        threshold: usize,
        /// Number of participants.
        participants: usize,
    },

    /// A DKG batch contained no sharing instances.
    #[error("DKG batch must contain at least one instance")]
    EmptyDkgBatch,

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

    /// A message or output belongs to a different DKG configuration.
    #[error("DKG configuration mismatch")]
    ConfigurationMismatch,

    /// A dealer message had the wrong number of dealing bodies.
    #[error("invalid dealing count: expected {expected}, got {actual}")]
    InvalidDealingCount {
        /// Configured instance count.
        expected: usize,
        /// Message dealing count.
        actual: usize,
    },

    /// A dealing's constant commitment shape disagreed with its configured kind.
    #[error("commitment kind mismatch in dealing {0}")]
    CommitmentKindMismatch(usize),

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

    /// A proof system could not produce a proof for a valid request.
    #[error("proof generation failed")]
    ProofGenerationFailed,

    /// A dealer proof failed individual verification after a batch failure.
    #[error("proof verification failed for dealer {0}")]
    DealerProofVerificationFailed(u32),

    /// A dealing share did not match its Feldman commitment.
    #[error("commitment verification failed")]
    CommitmentVerificationFailed,

    /// Authenticated decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,
}
