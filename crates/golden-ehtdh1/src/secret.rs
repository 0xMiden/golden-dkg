//! Private storage ownership for native field scalars.
use core::fmt;
use ff::PrimeField;
use zeroize::{DefaultIsZeroes, Zeroizing};

#[derive(Clone, Copy)]
pub(crate) struct Wipeable<F: PrimeField>(F);
impl<F: PrimeField> Default for Wipeable<F> {
    fn default() -> Self {
        Self(F::ZERO)
    }
}
impl<F: PrimeField> DefaultIsZeroes for Wipeable<F> {}
impl<F: PrimeField> fmt::Debug for Wipeable<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl<F: PrimeField> Wipeable<F> {
    pub(crate) fn expose(&self) -> &F {
        &self.0
    }
}
pub(crate) type Secret<F> = Zeroizing<Wipeable<F>>;
pub(crate) fn secret<F: PrimeField>(value: F) -> Secret<F> {
    Zeroizing::new(Wipeable(value))
}
