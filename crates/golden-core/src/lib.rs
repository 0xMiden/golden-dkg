//! Core traits and algebra for Golden DKG.
//!
//! This crate is intentionally curve agnostic. It must not depend on concrete
//! curve crates, pairings, BLS, FROST, or proof-system crates.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod deal;
mod dealer_message;
mod dealer_proof;
pub mod dkg;
pub mod error;
pub mod feldman;
pub mod group;
#[doc(hidden)]
pub mod main_golden;
pub mod participant;
pub mod shamir;
pub mod transcript;
pub mod wire;

#[cfg(test)]
mod test_support;

pub use deal::{deal, max_dealer_message_bytes, OwnDealing};
pub use dealer_proof::{
    DealerProofInstanceView, DealerProofReceiverView, DealerProofRef, DealerProofStatement,
    DealerProofSystem, DealerProofWitness, DealerProofWitnessInstanceView,
    DealerProofWitnessReceiverView,
};
pub use dkg::{
    complete, create_dealing, verify_dealing, verify_dealings, DealerMessage, DealerMessageNonce,
    DealingBody, DkgConfig, DkgDealing, DkgInstanceKind, DkgInstanceOutput, DkgOutput,
    EncryptedShare, EvrfDealingStatement, EvrfDealingWitness, EvrfMessage, EvrfProofBackend,
    EvrfReceiverStatement, EvrfReceiverWitness, EvrfStatement, EvrfWitness, ParticipantRegistry,
    SessionId, DEALER_MESSAGE_NONCE_BYTES, PROTOCOL_VERSION,
};
pub use error::{Error, Result};
pub use feldman::FeldmanCommitment;
pub use group::{FieldByteOrder, GoldenCurve, GoldenGroup, GoldenHashToGroup, GoldenScalar};
pub use participant::ParticipantIndex;
pub use shamir::{
    batch_invert, lagrange_coefficients_at_zero, lagrange_interpolate_at_zero, reconstruct_secret,
    Polynomial, Share,
};
pub use transcript::{TranscriptBuilder, TranscriptRoot};
