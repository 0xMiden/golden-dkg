//! Proof-free native identity groups for Golden DKG.
//!
//! Enable `secp256k1`, `jubjub`, or both. No group is enabled by default.
//! Arithmetic and borrowed secret values use the native library types.

#![forbid(unsafe_code)]

#[cfg(feature = "jubjub")]
pub mod jubjub;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

#[cfg(feature = "jubjub")]
pub use jubjub::JubjubGroup;
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Group;

/// Integer reduction of little-endian bytes, with a fixed operation count.
#[cfg(any(feature = "secp256k1", feature = "jubjub"))]
fn reduce_le_bytes<F: ff::PrimeField>(bytes: &[u8]) -> F {
    let radix = F::from(256);
    bytes.iter().rev().fold(F::ZERO, |value, byte| {
        value * radix + F::from(u64::from(*byte))
    })
}
