//! Error types for Golden core operations.

use crate::participant::ParticipantIndex;

/// Result type used by `golden-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// Coarse reason why one attributed opaque dealer message was rejected.
///
/// These reasons intentionally omit byte offsets, instance and receiver
/// positions, parsed values, and proof-system details.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DealerMessageError {
    /// The complete opaque message exceeded the protocol limit.
    #[error("dealer message is too large: actual={actual}, maximum={maximum}")]
    TooLarge {
        /// Supplied byte length (or the minimum length required by the config).
        actual: usize,
        /// Maximum accepted whole-message length.
        maximum: usize,
    },

    /// The envelope or configuration-selected body grammar was malformed.
    #[error("malformed dealer message")]
    Malformed,

    /// The message was bound to another DKG configuration.
    #[error("dealer message configuration mismatch")]
    ConfigurationMismatch,

    /// The encoded dealer disagreed with the caller's routing metadata.
    #[error("encoded dealer mismatch: {encoded:?}")]
    DealerMismatch {
        /// Canonically decoded dealer carried by the message.
        encoded: ParticipantIndex,
    },

    /// A public algebraic relation in the message was invalid.
    #[error("invalid dealer message public relations")]
    InvalidPublicRelations,
}

/// Errors returned by Golden core operations.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A participant registry contained no entries.
    #[error("participant registry must not be empty")]
    EmptyParticipantRegistry,

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

    /// A complete opaque dealer message exceeded the protocol size bound.
    #[error("dealer message exceeds the protocol size limit")]
    DealerMessageTooLarge,

    /// The native Main Golden relation could not be evaluated.
    #[error("Main Golden relation evaluation failed")]
    RelationEvaluationFailed,

    /// Local eVRF evaluation produced a zero pad and must be retried afresh.
    #[error("degenerate local eVRF output; retry the complete deal operation")]
    DegenerateEvrfOutput,

    /// Dealer-local state does not belong to this participant/configuration.
    #[error("own dealing does not match the completion request")]
    OwnDealingMismatch,

    /// No candidate was supplied for one configured peer dealer.
    #[error("missing dealer candidate {dealer:?}")]
    MissingDealer {
        /// Missing configured dealer.
        dealer: ParticipantIndex,
    },

    /// More than one candidate was supplied for a configured dealer.
    #[error("duplicate dealer candidate {dealer:?}")]
    DuplicateDealer {
        /// Duplicated dealer.
        dealer: ParticipantIndex,
    },

    /// A candidate named a participant outside the expected peer set.
    #[error("unexpected dealer candidate {dealer:?}")]
    UnexpectedDealer {
        /// Unexpected dealer.
        dealer: ParticipantIndex,
    },

    /// One attributed opaque candidate failed coarse message validation.
    #[error("invalid dealer message from {dealer:?}: {reason}")]
    InvalidDealerMessage {
        /// Expected dealer supplied as routing metadata.
        dealer: ParticipantIndex,
        /// Coarse public reason for rejection.
        reason: DealerMessageError,
    },

    /// Individual fallback identified every invalid dealer proof.
    #[error("invalid dealer proofs: {dealers:?}")]
    InvalidDealerProofs {
        /// Invalid dealers in canonical participant order.
        dealers: Vec<ParticipantIndex>,
    },

    /// Batch verification failed although every individual proof passed.
    #[error("dealer proof batch verification failed")]
    BatchVerificationFailed,

    /// Prepared proof-system state cannot serve the requested configuration.
    #[error("insufficient proof capacity: required={required}, available={available}")]
    InsufficientProofCapacity {
        /// Minimum padded generator capacity required by the configuration.
        required: usize,
        /// Declared padded generator capacity available to the proof system.
        available: usize,
    },

    /// A prepared proof-generator persistence artifact was malformed.
    #[error("malformed prepared proof generators")]
    MalformedPreparedGenerators,

    /// A verified dealer message could not be decrypted for this participant.
    #[error("share decryption failed for dealer {dealer:?}")]
    ShareDecryptionFailed {
        /// Dealer whose receiver share could not be recovered.
        dealer: ParticipantIndex,
    },

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
