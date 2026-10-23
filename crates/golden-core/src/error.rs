//! Stable, coarse errors for algebra, protocol operations and proof systems.
use crate::ParticipantIndex;

/// Result used throughout Golden core and its proof extension interface.
pub type Result<T> = core::result::Result<T, Error>;

/// Public errors never contain secrets, receiver/instance positions or backend diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Empty registry.
    #[error("participant registry must not be empty")]
    EmptyParticipantRegistry,
    /// Zero interpolation index.
    #[error("participant indexes must be nonzero")]
    ZeroParticipantIndex,
    /// Duplicate interpolation index.
    #[error("duplicate participant index {0}")]
    DuplicateParticipantIndex(u32),
    /// Duplicate canonical identity key.
    #[error("duplicate participant keys for {first} and {second}")]
    DuplicateParticipantPublicKey {
        /// First index.
        first: u32,
        /// Second index.
        second: u32,
    },
    /// Invalid reconstruction threshold.
    #[error("invalid threshold: {threshold} for {participants} participants")]
    InvalidThreshold {
        /// Requested threshold.
        threshold: usize,
        /// Registry size.
        participants: usize,
    },
    /// Empty instance list.
    #[error("DKG configuration requires at least one instance")]
    EmptyDkgBatch,
    /// Checked dimension arithmetic failed.
    #[error("protocol dimension overflow")]
    ArithmeticOverflow,
    /// A bounded allocation could not be reserved.
    #[error("protocol allocation failed")]
    AllocationFailed,
    /// Invalid interpolation denominator.
    #[error("non-invertible interpolation denominator")]
    NonInvertibleDenominator,
    /// Rejected canonical encoding.
    #[error("invalid encoding")]
    InvalidEncoding,
    /// Empty polynomial commitment.
    #[error("empty Feldman commitment")]
    EmptyCommitment,
    /// Unexpected commitment degree.
    #[error("invalid commitment degree: expected {expected}, got {actual}")]
    InvalidCommitmentDegree {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// A share did not open its commitment.
    #[error("commitment verification failed")]
    CommitmentVerificationFailed,
    /// Wrong borrowed identity credential.
    #[error("identity secret does not match registered public key")]
    IdentityKeyMismatch,
    /// Unknown interpolation index.
    #[error("unknown participant {0}")]
    UnknownParticipant(u32),
    /// The only proof-system verdict that triggers individual fallback.
    #[error("invalid proof")]
    InvalidProof,
    /// Proof production failed without exposing backend details.
    #[error("proof generation failed")]
    ProofGenerationFailed,
    /// Operational proof-system failure, without dealer blame.
    #[error("proof-system operation failed")]
    ProofOperationFailed,
    /// Complete broadcast exceeded the fixed protocol limit.
    #[error("dealer message exceeds protocol size limit")]
    DealerMessageTooLarge,
    /// Native coordinate or exponent evaluation failed; not a retry verdict.
    #[error("Main Golden relation evaluation failed")]
    RelationEvaluationFailed,
    /// Retry the entire local deal operation with fresh randomness.
    #[error("degenerate local pad; retry the complete deal operation")]
    DegenerateEvrfOutput,
    /// Own state belongs to another participant/configuration or has invalid self shares.
    #[error("own dealing does not match the completion request")]
    OwnDealingMismatch,
    /// No candidates supplied to public verification.
    #[error("candidate board must not be empty")]
    EmptyBoard,
    /// A full board omitted one dealer.
    #[error("missing dealer {dealer:?}")]
    MissingDealer {
        /// Missing dealer.
        dealer: ParticipantIndex,
    },
    /// More than one association named a dealer.
    #[error("duplicate dealer {dealer:?}")]
    DuplicateDealer {
        /// Duplicate dealer.
        dealer: ParticipantIndex,
    },
    /// An association named an unregistered dealer.
    #[error("unexpected dealer {dealer:?}")]
    UnexpectedDealer {
        /// Unexpected dealer.
        dealer: ParticipantIndex,
    },
    /// Every public-invalid dealer, in canonical order.
    #[error("invalid dealer messages: {dealers:?}")]
    InvalidDealerMessages {
        /// Invalid dealers.
        dealers: Vec<ParticipantIndex>,
    },
    /// Every individually invalid dealer proof, in canonical order.
    #[error("invalid dealer proofs: {dealers:?}")]
    InvalidDealerProofs {
        /// Invalid dealers.
        dealers: Vec<ParticipantIndex>,
    },
    /// Combined verification failed while every individual proof passed.
    #[error("batch verification failed")]
    BatchVerificationFailed,
    /// Explicitly prepared generators cannot serve the requested shape.
    #[error("insufficient proof capacity: required={required}, available={available}")]
    InsufficientProofCapacity {
        /// Required padded generator count.
        required: usize,
        /// Declared available count.
        available: usize,
    },
    /// Invalid prepared-generator artifact.
    #[error("malformed prepared generators")]
    MalformedPreparedGenerators,
    /// Invalid contextual state snapshot.
    #[error("invalid persisted state")]
    InvalidPersistedState,
    /// An accepted broadcast did not yield a valid local share.
    #[error("share decryption failed")]
    ShareDecryptionFailed,
    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,
}
