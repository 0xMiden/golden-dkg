//! The constraint system trait, generic over a [`Cycle`].

use merlin::Transcript;

use super::{LinearCombination, Metrics, R1CSError, Variable};
use crate::cycle::Cycle;

/// Interface shared by the prover and verifier constraint systems.
pub trait ConstraintSystem<C: Cycle> {
    /// Lease the proof transcript so the caller can bind extra data.
    fn transcript(&mut self) -> &mut Transcript;

    /// Allocate `left`, `right`, `out` with the implicit constraint
    /// `left * right = out` and the explicit constraints
    /// `left = left_constraint`, `right = right_constraint`.
    fn multiply(
        &mut self,
        left: LinearCombination<C::Scalar>,
        right: LinearCombination<C::Scalar>,
    ) -> (
        Variable<C::Scalar>,
        Variable<C::Scalar>,
        Variable<C::Scalar>,
    );

    /// Allocate a single variable, reusing half-assigned multipliers.
    fn allocate(&mut self, assignment: Option<C::Scalar>)
        -> Result<Variable<C::Scalar>, R1CSError>;

    /// Allocate `left`, `right`, `out` with the implicit constraint
    /// `left * right = out`.
    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(C::Scalar, C::Scalar)>,
    ) -> Result<
        (
            Variable<C::Scalar>,
            Variable<C::Scalar>,
            Variable<C::Scalar>,
        ),
        R1CSError,
    >;

    /// Number of multiplication gates and constraints so far.
    fn metrics(&self) -> Metrics;

    /// Enforce `lc = 0`.
    fn constrain(&mut self, lc: LinearCombination<C::Scalar>);
}

/// Extension permitting randomized constraints.
pub trait RandomizableConstraintSystem<C: Cycle>: ConstraintSystem<C> {
    /// Concrete randomized constraint system type.
    type RandomizedCS: RandomizedConstraintSystem<C>;

    /// Defer randomized constraints that sample challenge scalars after the
    /// non-randomized variables are committed.
    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + FnOnce(&mut Self::RandomizedCS) -> Result<(), R1CSError>;
}

/// Constraint system in the randomization phase.
pub trait RandomizedConstraintSystem<C: Cycle>: ConstraintSystem<C> {
    /// Sample a challenge scalar bound to the transcript so far.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar;
}
