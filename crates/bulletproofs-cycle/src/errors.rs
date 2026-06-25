//! Errors for the Bulletproofs R1CS proof path.

use thiserror::Error;

/// Error raised while creating or verifying a proof, or parsing proof bytes.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ProofError {
    /// The proof did not verify.
    #[error("proof verification failed")]
    VerificationError,
    /// The proof bytes could not be parsed.
    #[error("proof data could not be parsed")]
    FormatError,
    /// The generators supplied were too few for the proof shape.
    #[error("invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// The input vectors did not share a single power-of-two length.
    #[error("invalid input length, expected a single power-of-two length")]
    InvalidInputLength,
}

/// Error raised while creating or verifying an R1CS proof.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum R1CSError {
    /// Too few generators for the number of multiplication gates.
    #[error("invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// The proof bytes could not be parsed.
    #[error("proof data could not be parsed")]
    FormatError,
    /// The R1CS proof did not verify.
    #[error("R1CS proof did not verify correctly")]
    VerificationError,
    /// A gadget needed a variable assignment that was not provided.
    #[error("variable does not have a value assignment")]
    MissingAssignment,
}

impl From<ProofError> for R1CSError {
    fn from(e: ProofError) -> R1CSError {
        match e {
            ProofError::InvalidGeneratorsLength => R1CSError::InvalidGeneratorsLength,
            ProofError::FormatError => R1CSError::FormatError,
            ProofError::VerificationError => R1CSError::VerificationError,
            ProofError::InvalidInputLength => R1CSError::VerificationError,
        }
    }
}
