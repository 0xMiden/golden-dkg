//! Participant identifiers and interpolation points.

use ff::PrimeField;

use crate::{Error, Result};

/// Public participant index.
///
/// Index zero is reserved for the polynomial secret `f(0)`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ParticipantIndex(u32);

impl ParticipantIndex {
    /// Create a nonzero participant index.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            return Err(Error::ZeroParticipantIndex);
        }
        Ok(Self(value))
    }

    /// Return the raw integer value.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Convert this public index into a scalar interpolation point.
    pub fn to_scalar<S: PrimeField>(self) -> Result<S> {
        // Cryptographic fields contain every u32. For a smaller field, read
        // p - 1 through parity and integer halving rather than parsing the
        // opaque PrimeField::MODULUS string. Reject reduced index aliases.
        if S::NUM_BITS <= u32::BITS {
            let mut remaining = -S::ONE;
            let mut largest = 0u64;
            for bit in 0..S::NUM_BITS {
                let odd = bool::from(remaining.is_odd());
                largest |= u64::from(odd) << bit;
                remaining = (remaining - S::from(u64::from(odd))) * S::TWO_INV;
            }
            if u64::from(self.0) > largest {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok(S::from(u64::from(self.0)))
    }
}
