//! Core traits and algebra for Golden DKG.
//!
//! This crate is intentionally curve agnostic. It must not depend on concrete
//! curve crates, pairings, BLS, FROST, or proof-system crates.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod dkg;
pub mod error;
pub mod feldman;
pub mod group;
pub mod participant;
pub mod shamir;
pub mod transcript;

#[cfg(test)]
mod test_support;

pub use dkg::{
    complete, create_dealing, create_dealing_with_secret, verify_dealing,
    verify_dealing_for_receiver, DealerMessage, DealerMessageNonce, DkgConfig, DkgDealing,
    DkgOutput, EncryptedShare, EvrfProofBackend, EvrfStatement, EvrfWitness, ParticipantRegistry,
    SessionId, DEALER_MESSAGE_NONCE_BYTES, PROTOCOL_VERSION,
};
pub use error::{Error, Result};
pub use feldman::FeldmanCommitment;
pub use group::{FieldByteOrder, GoldenEvrfCurve, GoldenGroup, GoldenHashToGroup, GoldenScalar};
pub use participant::ParticipantIndex;
pub use shamir::{lagrange_interpolate_at_zero, reconstruct_secret, Polynomial, Share};
pub use transcript::{TranscriptBuilder, TranscriptRoot};
