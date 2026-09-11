//! BLS12-381 G1 group operations backed by `blst` through `blstrs`.

use bls12_381::Scalar;
use group::Group;
use std::{
    borrow::Borrow,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::Choice;

/// BLS12-381 G1 projective point with `blst` arithmetic and the workspace's
/// `bls12_381::Scalar` type.
///
/// `bulletproofs-cycle` requires the point's associated scalar to be the
/// exact R1CS field type. Jubjub fixes that type to `bls12_381::Scalar`, so
/// this wrapper converts canonical scalar bytes at multiplication boundaries
/// while keeping every point operation in `blst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct BlsG1Projective(pub(crate) blstrs::G1Projective);

impl BlsG1Projective {
    pub(crate) fn scalar_to_blstrs(scalar: &Scalar) -> blstrs::Scalar {
        Option::from(blstrs::Scalar::from_bytes_le(&scalar.to_bytes()))
            .expect("canonical BLS12-381 scalars decode in blstrs")
    }
}

impl Neg for BlsG1Projective {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Neg for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn neg(self) -> Self::Output {
        -*self
    }
}

impl Add<&BlsG1Projective> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn add(self, rhs: &BlsG1Projective) -> Self::Output {
        BlsG1Projective(self.0 + rhs.0)
    }
}

impl Add<BlsG1Projective> for BlsG1Projective {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl Add<&BlsG1Projective> for BlsG1Projective {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<BlsG1Projective> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn add(self, rhs: BlsG1Projective) -> Self::Output {
        BlsG1Projective(self.0 + rhs.0)
    }
}

impl Sub<&BlsG1Projective> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn sub(self, rhs: &BlsG1Projective) -> Self::Output {
        BlsG1Projective(self.0 - rhs.0)
    }
}

impl Sub<BlsG1Projective> for BlsG1Projective {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl Sub<&BlsG1Projective> for BlsG1Projective {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<BlsG1Projective> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn sub(self, rhs: BlsG1Projective) -> Self::Output {
        BlsG1Projective(self.0 - rhs.0)
    }
}

impl AddAssign<&BlsG1Projective> for BlsG1Projective {
    fn add_assign(&mut self, rhs: &BlsG1Projective) {
        self.0 += rhs.0;
    }
}

impl AddAssign<BlsG1Projective> for BlsG1Projective {
    fn add_assign(&mut self, rhs: BlsG1Projective) {
        *self += &rhs;
    }
}

impl SubAssign<&BlsG1Projective> for BlsG1Projective {
    fn sub_assign(&mut self, rhs: &BlsG1Projective) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<BlsG1Projective> for BlsG1Projective {
    fn sub_assign(&mut self, rhs: BlsG1Projective) {
        *self -= &rhs;
    }
}

impl Mul<&Scalar> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        BlsG1Projective(self.0 * Self::Output::scalar_to_blstrs(rhs))
    }
}

impl Mul<Scalar> for BlsG1Projective {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * Self::scalar_to_blstrs(&rhs))
    }
}

impl Mul<&Scalar> for BlsG1Projective {
    type Output = Self;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Self(self.0 * Self::scalar_to_blstrs(rhs))
    }
}

impl Mul<Scalar> for &BlsG1Projective {
    type Output = BlsG1Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        BlsG1Projective(self.0 * BlsG1Projective::scalar_to_blstrs(&rhs))
    }
}

impl MulAssign<&Scalar> for BlsG1Projective {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<Scalar> for BlsG1Projective {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self *= &rhs;
    }
}

impl<T> Sum<T> for BlsG1Projective
where
    T: Borrow<Self>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |sum, point| sum + point.borrow())
    }
}

impl Group for BlsG1Projective {
    type Scalar = Scalar;

    fn random(rng: impl rand_core::RngCore) -> Self {
        Self(blstrs::G1Projective::random(rng))
    }

    fn identity() -> Self {
        Self(blstrs::G1Projective::identity())
    }

    fn generator() -> Self {
        Self(blstrs::G1Projective::generator())
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }
}
