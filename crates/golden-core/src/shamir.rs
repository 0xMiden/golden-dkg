//! Shamir sharing over native scalar fields.

use core::fmt;
use std::collections::BTreeSet;

use ff::PrimeField;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::{secret, secret_vec, Secret, SecretVec, Wipeable};
use crate::{Error, ParticipantIndex, Result};

/// An owned Shamir share with zeroizing native-field storage.
///
/// Diagnostics redact the scalar. Reading [`Self::value`] borrows the secret;
/// applications remain responsible for any scalar copies they make.
pub struct Share<F: PrimeField> {
    participant: ParticipantIndex,
    value: Secret<F>,
}

impl<F: PrimeField> Share<F> {
    /// Take ownership of a share for a validated participant index.
    pub fn new(participant: ParticipantIndex, value: F) -> Self {
        Self {
            participant,
            value: secret(value),
        }
    }

    /// Participant that owns this share.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }

    /// Borrow the native share value.
    pub fn value(&self) -> &F {
        self.value.expose()
    }
}

impl<F: PrimeField> fmt::Debug for Share<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Share")
            .field("participant", &self.participant)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<F: PrimeField> PartialEq for Share<F> {
    fn eq(&self, other: &Self) -> bool {
        self.participant == other.participant && self.value() == other.value()
    }
}

impl<F: PrimeField> Eq for Share<F> {}

impl<F: PrimeField> Zeroize for Share<F> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl<F: PrimeField> ZeroizeOnDrop for Share<F> {}

/// An owned polynomial with coefficients in ascending degree order.
///
/// The storage is guarded before filling, and every owned coefficient is
/// zeroized on drop. This does not erase callers' copies or every temporary
/// produced by field arithmetic. This secret-bearing type is not cloneable.
pub struct Polynomial<F: PrimeField> {
    coefficients: SecretVec<F>,
}

impl<F: PrimeField> Polynomial<F> {
    /// Sample every coefficient of a degree-at-most `threshold - 1` polynomial.
    ///
    /// The constant coefficient is independently uniform and may be zero.
    pub fn random(threshold: usize, rng: &mut impl CryptoRngCore) -> Result<Self> {
        validate_threshold(threshold)?;
        let mut coefficients = secret_vec(threshold)?;
        for _ in 0..threshold {
            coefficients.push(Wipeable(F::random(&mut *rng)));
        }
        Ok(Self { coefficients })
    }

    /// Sample higher coefficients while fixing the constant term.
    pub fn random_with_secret(
        value: F,
        threshold: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        validate_threshold(threshold)?;
        let mut coefficients = secret_vec(threshold)?;
        coefficients.push(Wipeable(value));
        for _ in 1..threshold {
            coefficients.push(Wipeable(F::random(&mut *rng)));
        }
        Ok(Self { coefficients })
    }

    /// Copy explicit coefficients into guarded owned storage.
    ///
    /// The borrowed source remains the caller's responsibility.
    pub fn from_coefficients(values: &[F]) -> Result<Self> {
        validate_threshold(values.len())?;
        let mut coefficients = secret_vec(values.len())?;
        for value in values {
            coefficients.push(Wipeable(*value));
        }
        Ok(Self { coefficients })
    }

    /// Number of coefficients, including a zero constant when present.
    pub fn threshold(&self) -> usize {
        self.coefficients.len()
    }

    /// Borrow coefficients in ascending degree order.
    pub fn coefficients(&self) -> impl DoubleEndedIterator<Item = &F> + ExactSizeIterator {
        self.coefficients.iter().map(Wipeable::expose)
    }

    /// Borrow one coefficient by its zero-based degree.
    pub fn coefficient(&self, degree: usize) -> Option<&F> {
        self.coefficients.get(degree).map(Wipeable::expose)
    }

    /// Evaluate the polynomial at a native field element.
    pub fn evaluate_at_scalar(&self, x: &F) -> F {
        let mut value = secret(F::ZERO);
        for coefficient in self.coefficients().rev() {
            (*value).0 = *value.expose() * x + coefficient;
        }
        *value.expose()
    }

    /// Evaluate at the participant's nonzero integer interpolation point.
    pub fn evaluate(&self, participant: ParticipantIndex) -> Result<Share<F>> {
        let x = participant.to_scalar::<F>()?;
        Ok(Share::new(participant, self.evaluate_at_scalar(&x)))
    }

    /// Evaluate at unique participant indexes in the supplied order.
    pub fn shares(&self, participants: &[ParticipantIndex]) -> Result<Vec<Share<F>>> {
        ensure_unique_participants(participants)?;
        participants
            .len()
            .checked_mul(core::mem::size_of::<Share<F>>())
            .ok_or(Error::ArithmeticOverflow)?;
        let mut shares = Vec::new();
        shares
            .try_reserve_exact(participants.len())
            .map_err(|_| Error::AllocationFailed)?;
        for participant in participants {
            shares.push(self.evaluate(*participant)?);
        }
        Ok(shares)
    }
}

impl<F: PrimeField> fmt::Debug for Polynomial<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Polynomial")
            .field("coefficient_count", &self.coefficients.len())
            .field("coefficients", &"<redacted>")
            .finish()
    }
}

impl<F: PrimeField> Zeroize for Polynomial<F> {
    fn zeroize(&mut self) {
        for coefficient in self.coefficients.iter_mut() {
            coefficient.zeroize();
        }
    }
}

impl<F: PrimeField> ZeroizeOnDrop for Polynomial<F> {}

/// Reconstruct `f(0)` from every supplied share after checking a minimum count.
///
/// This count check does not verify that the shares lie on one polynomial.
/// Authenticate or verify shares before reconstruction; select exactly the
/// desired participants before calling if only a threshold-sized set is wanted.
pub fn reconstruct_secret<F: PrimeField>(shares: &[Share<F>], threshold: usize) -> Result<F> {
    if threshold == 0 || shares.len() < threshold {
        return Err(Error::InvalidThreshold {
            threshold,
            participants: shares.len(),
        });
    }
    lagrange_interpolate_at_zero(shares)
}

/// Interpolate `f(0)` from shares with unique, valid participant indexes.
pub fn lagrange_interpolate_at_zero<F: PrimeField>(shares: &[Share<F>]) -> Result<F> {
    if shares.is_empty() {
        return Err(Error::InvalidThreshold {
            threshold: 0,
            participants: 0,
        });
    }
    let participants: Vec<_> = shares.iter().map(Share::participant).collect();
    ensure_unique_participants(&participants)?;
    let xs = participants
        .iter()
        .map(|participant| participant.to_scalar::<F>())
        .collect::<Result<Vec<_>>>()?;
    let coefficients = lagrange_coefficients_at_zero(&xs)?;
    let mut value = secret(F::ZERO);
    for (share, coefficient) in shares.iter().zip(coefficients) {
        (*value).0 += *share.value() * coefficient;
    }
    Ok(*value.expose())
}

/// Lagrange coefficients at zero, in the same order as `xs`.
///
/// This uses `O(k)` scratch space and one field inversion. Duplicate field
/// points fail because their interpolation denominator is zero.
pub fn lagrange_coefficients_at_zero<F: PrimeField>(xs: &[F]) -> Result<Vec<F>> {
    let mut numerators = Vec::with_capacity(xs.len());
    let mut denominators = Vec::with_capacity(xs.len());
    for (i, xi) in xs.iter().enumerate() {
        let mut numerator = F::ONE;
        let mut denominator = F::ONE;
        for (j, xj) in xs.iter().enumerate() {
            if i != j {
                numerator *= -*xj;
                denominator *= *xi - xj;
            }
        }
        numerators.push(numerator);
        denominators.push(denominator);
    }
    batch_invert(&mut denominators).ok_or(Error::NonInvertibleDenominator)?;
    Ok(numerators
        .into_iter()
        .zip(denominators)
        .map(|(numerator, inverse)| numerator * inverse)
        .collect())
}

/// Montgomery batch inversion, leaving `values` unchanged on a zero input.
// This helper is shared inside core; callers needing weights use the public
// interpolation API rather than an additional general arithmetic API.
pub(crate) fn batch_invert<F: PrimeField>(values: &mut [F]) -> Option<()> {
    let mut prefix = Vec::with_capacity(values.len());
    let mut product = F::ONE;
    for value in values.iter() {
        prefix.push(product);
        product *= value;
    }
    let mut inverse = Option::<F>::from(product.invert())?;
    for (value, prefix_product) in values.iter_mut().zip(prefix).rev() {
        let next = inverse * *value;
        *value = inverse * prefix_product;
        inverse = next;
    }
    Some(())
}

fn validate_threshold(threshold: usize) -> Result<()> {
    if threshold == 0 {
        return Err(Error::InvalidThreshold {
            threshold,
            participants: 0,
        });
    }
    Ok(())
}

fn ensure_unique_participants(participants: &[ParticipantIndex]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for participant in participants {
        if !seen.insert(participant.get()) {
            return Err(Error::DuplicateParticipantIndex(participant.get()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[derive(ff::PrimeField)]
    #[PrimeFieldModulus = "127"]
    #[PrimeFieldGenerator = "3"]
    #[PrimeFieldReprEndianness = "little"]
    struct TestField([u64; 1]);

    fn participant(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    #[test]
    fn threshold_subsets_reconstruct_zero_and_nonzero_constants() {
        let participants: Vec<_> = (1..=5).map(participant).collect();
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        for threshold in [1, 2, 3] {
            for constant in [0, 1, 42] {
                let constant = TestField::from(constant);
                let polynomial =
                    Polynomial::random_with_secret(constant, threshold, &mut rng).unwrap();
                let shares = polynomial.shares(&participants).unwrap();
                for offset in 0..=shares.len() - threshold {
                    assert_eq!(
                        reconstruct_secret(&shares[offset..offset + threshold], threshold).unwrap(),
                        constant
                    );
                }
                assert_eq!(reconstruct_secret(&shares, threshold).unwrap(), constant);
            }
        }
    }

    #[test]
    fn polynomial_order_and_owned_cleanup_are_explicit() {
        let mut polynomial = Polynomial::from_coefficients(&[
            TestField::from(1),
            TestField::from(2),
            TestField::from(3),
        ])
        .unwrap();
        assert_eq!(
            polynomial.evaluate_at_scalar(&TestField::from(2)),
            TestField::from(17)
        );
        assert_eq!(polynomial.coefficient(0), Some(&TestField::ONE));
        assert!(format!("{polynomial:?}").contains("<redacted>"));
        polynomial.zeroize();
        assert!(polynomial
            .coefficients()
            .all(|coefficient| bool::from(coefficient.is_zero())));
        let mut share = Share::new(participant(1), TestField::from(42));
        share.zeroize();
        assert_eq!(*share.value(), TestField::ZERO);
    }

    #[test]
    fn participant_indexes_cannot_alias_the_secret_or_another_field_point() {
        assert_eq!(
            participant(126).to_scalar::<TestField>().unwrap(),
            TestField::from(126)
        );
        for value in [127, 128, u32::MAX] {
            assert_eq!(
                participant(value).to_scalar::<TestField>(),
                Err(Error::InvalidEncoding)
            );
        }
        let shares = [
            Share::new(participant(1), TestField::from(3)),
            Share::new(participant(1), TestField::from(5)),
        ];
        assert_eq!(
            lagrange_interpolate_at_zero(&shares),
            Err(Error::DuplicateParticipantIndex(1))
        );
    }

    #[test]
    fn batch_inversion_matches_native_inversion_without_partial_zero_updates() {
        let mut values: Vec<_> = (1..12).map(TestField::from).collect();
        let expected: Vec<_> = values
            .iter()
            .map(|value| Option::<TestField>::from(value.invert()).unwrap())
            .collect();
        assert!(batch_invert(&mut values).is_some());
        assert_eq!(values, expected);
        let mut with_zero = [TestField::from(3), TestField::ZERO, TestField::from(5)];
        let original = with_zero;
        assert!(batch_invert(&mut with_zero).is_none());
        assert_eq!(with_zero, original);
    }
}
