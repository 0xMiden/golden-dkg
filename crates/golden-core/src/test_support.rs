//! Test-only finite field and group backend.

use crate::{Error, FieldByteOrder, GoldenGroup, GoldenScalar, Result};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};

const MODULUS: u8 = 97;

/// Tiny scalar field modulo 97.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TinyScalar(u8);

impl TinyScalar {
    fn reduce(value: u64) -> Self {
        Self((value % u64::from(MODULUS)) as u8)
    }
}

impl ConstantTimeEq for TinyScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl zeroize::Zeroize for TinyScalar {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl GoldenScalar for TinyScalar {
    type Repr = [u8; 1];

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self::reduce(u64::from(rng.next_u32()))
    }

    fn from_u64(value: u64) -> Result<Self> {
        Ok(Self::reduce(value))
    }

    fn add(&self, rhs: &Self) -> Self {
        Self::reduce(u64::from(self.0) + u64::from(rhs.0))
    }

    fn sub(&self, rhs: &Self) -> Self {
        Self::reduce(u64::from(MODULUS) + u64::from(self.0) - u64::from(rhs.0))
    }

    fn mul(&self, rhs: &Self) -> Self {
        Self::reduce(u64::from(self.0) * u64::from(rhs.0))
    }

    fn invert(&self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        for candidate in 1..MODULUS {
            if self.mul(&Self(candidate)) == Self::one() {
                return Some(Self(candidate));
            }
        }
        None
    }

    fn to_repr(&self) -> Self::Repr {
        [self.0]
    }

    fn from_repr(repr: &Self::Repr) -> Result<Self> {
        if repr[0] < MODULUS {
            Ok(Self(repr[0]))
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn modulus() -> Self::Repr {
        [MODULUS]
    }

    fn repr_byte_order() -> FieldByteOrder {
        FieldByteOrder::BigEndian
    }
}

/// Tiny additive group over the scalar field.
#[derive(Clone, Debug)]
pub enum TinyGroup {}

impl GoldenGroup for TinyGroup {
    type Scalar = TinyScalar;
    type Element = TinyScalar;
    type ElementRepr = [u8; 1];

    const BACKEND_ID: &'static str = "golden-test-tiny-v1";

    fn generator() -> Self::Element {
        TinyScalar::one()
    }

    fn identity() -> Self::Element {
        TinyScalar::zero()
    }

    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element {
        a.add(b)
    }

    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        a.sub(b)
    }

    fn mul(point: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        point.mul(scalar)
    }

    fn is_identity(point: &Self::Element) -> Choice {
        point.is_zero()
    }

    fn encode_element(point: &Self::Element) -> Self::ElementRepr {
        point.to_repr()
    }

    fn decode_element(repr: &Self::ElementRepr) -> Result<Self::Element> {
        TinyScalar::from_repr(repr)
    }
}
