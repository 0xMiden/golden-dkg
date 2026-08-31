//! Main Golden proof systems for Golden DKG.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod paper;

#[cfg(feature = "insecure-revealed-witness")]
mod insecure_revealed_witness;
mod proof_stream;

#[cfg(feature = "insecure-revealed-witness")]
pub use insecure_revealed_witness::InsecureRevealedWitnessProof;
