//! Native, curve-independent Golden DKG with opaque broadcasts and explicit proofs.
//! Protocol parsing is private. Applications agree a configuration, inject a proof
//! system and retain participant-local state; deployment owns admission, broadcast,
//! agreement, trusted persistence and activation.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod config;
mod deal;
mod dealer_message;
mod dealer_proof;
pub mod error;
pub mod feldman;
pub mod group;
#[cfg(any(test, feature = "insecure-revealed-witness"))]
pub mod insecure;
#[doc(hidden)]
pub mod main_golden;
pub mod output;
pub mod participant;
pub mod persistence;
mod secret;
pub mod shamir;
pub mod transcript;
#[doc(hidden)]
pub mod wire;

pub use config::{
    DealerMessageNonce, DkgConfig, DkgInstanceKind, EvrfMessage, ParticipantRegistry,
    ResharePredecessor, SessionId, DEALER_MESSAGE_NONCE_BYTES, PROTOCOL_VERSION,
};
pub use deal::{
    aggregate_public, complete, complete_reshare, deal, deal_reshare, max_dealer_message_bytes,
    verify_dealer_message, verify_dealer_messages, DealerMessageRef, OwnDealing,
};
pub use dealer_proof::{
    DealerProofInstanceView, DealerProofReceiverView, DealerProofRef, DealerProofStatement,
    DealerProofSystem, DealerProofWitness, DealerProofWitnessInstanceView,
    DealerProofWitnessReceiverView,
};
pub use error::{Error, Result};
pub use feldman::FeldmanCommitment;
pub use group::{DkgGroup, FieldByteOrder};
pub use output::{DkgOutput, DkgPublicInstance, DkgPublicOutput};
pub use participant::ParticipantIndex;
pub use shamir::{
    lagrange_coefficients_at_zero, lagrange_interpolate_at_zero, reconstruct_secret, Polynomial,
    Share,
};
pub use transcript::{TranscriptBuilder, TranscriptRoot};
