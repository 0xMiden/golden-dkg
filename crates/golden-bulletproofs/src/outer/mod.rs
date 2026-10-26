//! Private commitment-cycle implementations and optimized multi-scalar arithmetic.
#[cfg(feature = "jubjub-bls12-381")]
pub(crate) mod cycle;
#[cfg(feature = "jubjub-bls12-381")]
pub(crate) mod g1;
#[cfg(feature = "jubjub-bls12-381")]
mod msm_blst;
#[cfg(feature = "secp-secq")]
pub(crate) mod secp;

#[cfg(all(test, any(feature = "secp-secq", feature = "jubjub-bls12-381")))]
mod tests;
