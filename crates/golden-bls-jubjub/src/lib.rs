//! [`bulletproofs_cycle::Cycle`] and [`golden_core::GoldenGroup`] adapters
//! for the BLS12-381/Jubjub curve pair used by the paper eVRF's
//! BLS12-381/Jubjub instantiation.
//!
//! `Gout` is BLS12-381 G1, the Bulletproofs commitment group ([`cycle`]).
//! `Gin` is Jubjub, the identity-key / Diffie-Hellman group
//! ([`golden_group`]). Jubjub's base field is BLS12-381's scalar field, so a
//! Jubjub witness value is already an element of the R1CS field `Gout`
//! commits over — no foreign-field conversion is needed between the two, the
//! same relationship Secp256k1/Secq256k1 has in `golden-halo2curves`.

#![deny(unsafe_code)]

mod msm_blst;
mod pippenger;

pub mod cycle;
pub mod golden_group;
pub mod jubjub_cycle;

pub use cycle::Bls12_381G1Cycle;
pub use jubjub_cycle::JubjubCycle;
