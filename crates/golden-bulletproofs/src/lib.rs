//! Explicitly prepared Bulletproof systems for the fixed Main Golden relation.
//!
//! Prepared artifacts require approved generation and authenticated application
//! storage. Structural decoding does not establish correct generator generation.
//! The separate composition/security release approval is not supplied by this crate.

#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
mod driver;
mod outer;
#[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
mod prepared;
#[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
mod shape;

#[cfg(feature = "jubjub-bls12-381")]
#[path = "bls.rs"]
mod bls_circuit;
#[cfg(feature = "secp-secq")]
#[path = "secp.rs"]
mod secp_circuit;

#[cfg(feature = "secp-secq")]
/// Secp256k1/Secq256k1 prepared artifacts and reusable proof systems.
pub mod secp_secq {
    pub use crate::secp_circuit::{SecpSecqBulletproofs, SecpSecqPrepared};
}
#[cfg(feature = "jubjub-bls12-381")]
/// Jubjub/BLS12-381 G1 prepared artifacts and reusable proof systems.
pub mod bls_jubjub {
    pub use crate::bls_circuit::{BlsJubjubBulletproofs, BlsJubjubPrepared};
}
#[cfg(feature = "jubjub-bls12-381")]
pub use bls_jubjub::{BlsJubjubBulletproofs, BlsJubjubPrepared};
#[cfg(feature = "secp-secq")]
pub use secp_secq::{SecpSecqBulletproofs, SecpSecqPrepared};

#[cfg(all(test, any(feature = "secp-secq", feature = "jubjub-bls12-381")))]
mod tests;
