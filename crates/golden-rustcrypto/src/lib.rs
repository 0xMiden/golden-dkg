//! RustCrypto curve adapters for Golden DKG.
//!
//! Each adapter is gated behind a feature flag so downstream crates only pay
//! for the curves they use:
//!
//! - `p256` (NIST P-256): `GoldenGroup`, `GoldenHashToGroup`, and `GoldenCurve`.
//! - `k256` (secp256k1): the same capabilities as `p256`. The Main Golden proof
//!   system targets the Secp/Secq cycle via `golden-halo2curves`; this adapter
//!   remains the reference for cross-adapter conformance tests.
//!
//! Every adapter wrapper exposes a single pair of `Scalar` / `Element`
//! newtypes that forward to the underlying RustCrypto implementation. The
//! wrappers exist so the same concrete type can carry `Zeroize`/`Drop`
//! hygiene and the `ConstantTimeEq` bound that `GoldenGroup` requires.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(feature = "p256")]
pub mod p256_backend;

#[cfg(feature = "k256")]
pub mod k256_backend;

#[cfg(feature = "k256")]
pub use k256_backend::{K256Backend, K256Element, K256Scalar};

#[cfg(feature = "p256")]
pub use p256_backend::{P256Backend, P256Element, P256Scalar};
