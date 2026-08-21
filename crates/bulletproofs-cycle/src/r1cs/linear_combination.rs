//! Linear combinations over a [`Cycle`]'s scalar field.
//!
//! `Variable<S>` carries the scalar type `S` so that the operator impls
//! (`Add`, `Sub`, `Neg`, `Mul`) on variables and scalars determine `S` from
//! their self or rhs type, satisfying Rust's type-parameter constraints.

use core::marker::PhantomData;
use core::ops::{Add, Mul, Neg, Sub};

use ff::Field;
use smallvec::{smallvec, SmallVec};

/// Kind of a [`Variable`]: where its value comes from in the constraint system.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum VariableKind {
    Committed(usize),
    MultiplierLeft(usize),
    MultiplierRight(usize),
    MultiplierOutput(usize),
    One,
}

/// A variable in a constraint system, tagged with its scalar field `S`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Variable<S: Field> {
    pub(crate) kind: VariableKind,
    _s: PhantomData<fn() -> S>,
}

impl<S: Field> Variable<S> {
    /// External input specified by a commitment.
    pub fn committed(i: usize) -> Self {
        Variable {
            kind: VariableKind::Committed(i),
            _s: PhantomData,
        }
    }
    /// Left input of a multiplication gate.
    pub fn multiplier_left(i: usize) -> Self {
        Variable {
            kind: VariableKind::MultiplierLeft(i),
            _s: PhantomData,
        }
    }
    /// Right input of a multiplication gate.
    pub fn multiplier_right(i: usize) -> Self {
        Variable {
            kind: VariableKind::MultiplierRight(i),
            _s: PhantomData,
        }
    }
    /// Output of a multiplication gate.
    pub fn multiplier_output(i: usize) -> Self {
        Variable {
            kind: VariableKind::MultiplierOutput(i),
            _s: PhantomData,
        }
    }
    /// The constant 1.
    pub fn one() -> Self {
        Variable {
            kind: VariableKind::One,
            _s: PhantomData,
        }
    }
}

/// A linear combination of [`Variable`]s with scalar coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearCombination<S: Field> {
    /// `(variable, coefficient)` terms.
    pub terms: SmallVec<[(Variable<S>, S); 4]>,
}

impl<S: Field> From<Variable<S>> for LinearCombination<S> {
    fn from(v: Variable<S>) -> Self {
        LinearCombination {
            terms: smallvec![(v, S::ONE)],
        }
    }
}

impl<S: Field> From<S> for LinearCombination<S> {
    fn from(s: S) -> Self {
        LinearCombination {
            terms: smallvec![(Variable::one(), s)],
        }
    }
}

impl<S: Field> Default for LinearCombination<S> {
    fn default() -> Self {
        LinearCombination {
            terms: SmallVec::new(),
        }
    }
}

impl<S: Field> Neg for Variable<S> {
    type Output = LinearCombination<S>;

    fn neg(self) -> Self::Output {
        -LinearCombination::<S>::from(self)
    }
}

impl<S: Field, L: Into<LinearCombination<S>>> Add<L> for Variable<S> {
    type Output = LinearCombination<S>;

    fn add(self, other: L) -> Self::Output {
        LinearCombination::<S>::from(self) + other.into()
    }
}

impl<S: Field, L: Into<LinearCombination<S>>> Sub<L> for Variable<S> {
    type Output = LinearCombination<S>;

    fn sub(self, other: L) -> Self::Output {
        LinearCombination::<S>::from(self) - other.into()
    }
}

impl<S: Field> Mul<S> for Variable<S> {
    type Output = LinearCombination<S>;

    fn mul(self, other: S) -> Self::Output {
        LinearCombination {
            terms: smallvec![(self, other)],
        }
    }
}

impl<S: Field, L: Into<LinearCombination<S>>> Add<L> for LinearCombination<S> {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms);
        self
    }
}

impl<S: Field, L: Into<LinearCombination<S>>> Sub<L> for LinearCombination<S> {
    type Output = Self;

    fn sub(mut self, rhs: L) -> Self::Output {
        for (var, coeff) in rhs.into().terms {
            self.terms.push((var, -coeff));
        }
        self
    }
}

impl<S: Field> Neg for LinearCombination<S> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s;
        }
        self
    }
}

impl<S: Field> Mul<S> for LinearCombination<S> {
    type Output = Self;

    fn mul(mut self, other: S) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s *= other;
        }
        self
    }
}

/// Multiply `factor` by a constraint coefficient.
pub(crate) fn scaled_by_coefficient<S: Field>(factor: S, coefficient: &S) -> S {
    if *coefficient == S::ONE {
        factor
    } else if *coefficient == -S::ONE {
        -factor
    } else {
        factor * coefficient
    }
}
