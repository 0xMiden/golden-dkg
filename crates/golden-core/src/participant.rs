//! Participant identifiers and interpolation points.

use crate::{Error, GoldenScalar, Result};

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
    pub fn to_scalar<S: GoldenScalar>(self) -> Result<S> {
        S::from_u64(u64::from(self.0))
    }
}
