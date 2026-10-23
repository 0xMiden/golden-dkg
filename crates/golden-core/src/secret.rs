//! Private zeroizing ownership for native field elements.

use core::{fmt, mem::size_of};

use ff::PrimeField;
use zeroize::{DefaultIsZeroes, Zeroizing};

use crate::{Error, Result};

/// Private storage wrapper, not an arithmetic abstraction.
///
/// `DefaultIsZeroes` lets `zeroize` overwrite the native value with a volatile
/// write of `F::ZERO`, without requiring a foreign field to implement Zeroize.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct Wipeable<F: PrimeField>(pub(crate) F);

impl<F: PrimeField> Wipeable<F> {
    pub(crate) fn expose(&self) -> &F {
        &self.0
    }
}

impl<F: PrimeField> Default for Wipeable<F> {
    fn default() -> Self {
        Self(F::ZERO)
    }
}

impl<F: PrimeField> DefaultIsZeroes for Wipeable<F> {}

impl<F: PrimeField> fmt::Debug for Wipeable<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

pub(crate) type Secret<F> = Zeroizing<Wipeable<F>>;
pub(crate) type SecretVec<F> = Zeroizing<Vec<Wipeable<F>>>;

pub(crate) fn secret<F: PrimeField>(value: F) -> Secret<F> {
    Zeroizing::new(Wipeable(value))
}

/// Guard an empty buffer before reserving its checked final capacity.
///
/// Callers fill only the reserved number of entries, avoiding reallocations
/// that could leave an old allocation containing copied secret elements.
pub(crate) fn secret_vec<F: PrimeField>(capacity: usize) -> Result<SecretVec<F>> {
    let bytes = capacity
        .checked_mul(size_of::<Wipeable<F>>())
        .ok_or(Error::ArithmeticOverflow)?;
    if bytes > isize::MAX as usize {
        return Err(Error::ArithmeticOverflow);
    }
    let mut values = Zeroizing::new(Vec::new());
    values
        .try_reserve_exact(capacity)
        .map_err(|_| Error::AllocationFailed)?;
    Ok(values)
}
