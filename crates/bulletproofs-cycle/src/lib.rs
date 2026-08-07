//! Bulletproofs R1CS port over a zkcrypto-compatible curve cycle.
//!
//! This is a fork of `zkcrypto/bulletproofs` 5.0.1 with the range proof, MPC,
//! and serialization paths removed, and the hard-coded Ristretto backend
//! replaced by the [`Cycle`] trait. The first milestone targets the
//! `halo2curves` Secp/Secq cycle via the `golden-halo2curves` adapters.
//!
//! ## Pedersen blinding base: two domain separations
//!
//! [`PedersenGens::default()`] must derive a blinding base `B_blinding` from
//! the group generator. The crate ships two mutually exclusive derivations,
//! selected at build time:
//!
//! * `cycle-pedersen` (default) — our `Cycle`-generic SHAKE256 domain
//!   separation, `SHAKE256("bulletproofs-cycle/pedersen-blinding" || B_bytes)`.
//!   Works for every `Cycle` implementation.
//! * `bulletproofs-compat` — Ristretto-only, matches upstream
//!   `zkcrypto/bulletproofs` exactly: `RistrettoPoint::hash_from_bytes::<Sha3_512>`
//!   on `RISTRETTO_BASEPOINT_COMPRESSED`. Enables byte-for-byte comparison of
//!   `default()`-dependent paths (IPP, R1CS) against upstream.
//!
//! The two features are mutually exclusive; enabling both is a compile error.
//!
//! ## Upstream byte parity (Ristretto)
//!
//! Behind the `ristretto` feature, the `ristretto_cycle::RistrettoCycle`
//! impl wires the [`Cycle`] trait to `curve25519-dalek` 4.x. The test suite at
//! `tests/ristretto_parity.rs` pins that our `BulletproofGens` G generators
//! and our `LinearProof::create` output reproduce `zkcrypto/bulletproofs`
//! 5.0.0 **bit-for-bit** from identical seeded inputs, and that the serialized
//! proof verifies through upstream's verifier (and vice versa). The parity
//! tests are gated on `bulletproofs-compat` because they compare to upstream,
//! which only makes sense when our `PedersenGens::default()` domain separation
//! matches upstream's.
//!
//! Two upstream surfaces are intentionally not at byte parity:
//!
//! * `InnerProductProof` — upstream keeps the `inner_product_proof` module
//!   private, so IPP cannot be driven through the dev-dep. Its algorithm
//!   correctness is still covered by the LinearProof round-trip in
//!   `tests/ristretto_smoke.rs` (LinearProof's L/R rounds share the same
//!   transcript pattern as IPP).
//! * Under `cycle-pedersen`, `PedersenGens::default()` diverges from upstream
//!   by design (see above). Switch to `bulletproofs-compat` to recover
//!   byte parity for `default()`-dependent paths.

#![deny(unsafe_code)]
// This is a port of zkcrypto/bulletproofs 5.0.1. The prover/verifier state
// machines and inner-product proof carry tuple and closure types that match
// the upstream structure; refactoring them would diverge from the reference.
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

#[cfg(all(feature = "cycle-pedersen", feature = "bulletproofs-compat"))]
compile_error!(
    "features `cycle-pedersen` and `bulletproofs-compat` are mutually exclusive: \
     they select competing PedersenGens::default() domain separations"
);

extern crate alloc;

pub mod cycle;
pub mod errors;
pub mod generators;
pub mod inner_product_proof;
pub mod linear_proof;
pub mod r1cs;
#[cfg(feature = "ristretto")]
pub mod ristretto_cycle;
pub mod transcript;
pub mod util;

pub use cycle::{random_scalar, Cycle};
pub use errors::{ProofError, R1CSError};
pub use generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use inner_product_proof::InnerProductProof;
pub use linear_proof::LinearProof;
pub use r1cs::{
    ConstraintSystem, LinearCombination, Metrics, Prover, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable, VerificationEquation, Verifier,
};
