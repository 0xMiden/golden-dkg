//! R1CS constraint-system proof path, generic over a [`crate::cycle::Cycle`].

mod constraint_system;
mod linear_combination;
mod metrics;
mod proof;
mod prover;
mod verifier;

pub use self::constraint_system::{
    ConstraintSystem, RandomizableConstraintSystem, RandomizedConstraintSystem,
};
pub use self::linear_combination::{LinearCombination, Variable};
pub use self::metrics::Metrics;
pub use self::proof::R1CSProof;
pub use self::prover::Prover;
pub use self::verifier::{VerificationEquation, Verifier};

pub use crate::errors::R1CSError;
