//! Shamir secret sharing over a generic scalar field.

use std::collections::BTreeSet;

use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::{Error, GoldenScalar, ParticipantIndex, Result};

/// A Shamir share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Share<S: GoldenScalar> {
    /// Participant that owns this share.
    pub participant: ParticipantIndex,
    /// Share value `f(i)`.
    pub value: S,
}

impl<S> Zeroize for Share<S>
where
    S: GoldenScalar + Zeroize,
{
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// Polynomial over a Golden scalar field.
///
/// The first coefficient is the shared secret. `Polynomial` implements
/// `Zeroize` so callers can wipe the coefficients before dropping the
/// value; drop itself does **not** call `zeroize` because `GoldenScalar`
/// does not require `S: Zeroize`. Callers that want a guaranteed wipe on
/// drop should wrap the polynomial in `zeroize::Zeroizing<Polynomial<S>>`
/// or call `poly.zeroize()` explicitly at the end of the scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Polynomial<S: GoldenScalar> {
    coefficients: Vec<S>,
}

impl<S> Zeroize for Polynomial<S>
where
    S: GoldenScalar + Zeroize,
{
    fn zeroize(&mut self) {
        for coeff in self.coefficients.iter_mut() {
            coeff.zeroize();
        }
    }
}

impl<S: GoldenScalar> Polynomial<S> {
    /// Create a random degree `threshold - 1` polynomial with fixed secret.
    pub fn random_with_secret(
        secret: S,
        threshold: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::InvalidThreshold {
                threshold,
                participants: 0,
            });
        }

        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(secret);
        for _ in 1..threshold {
            coefficients.push(S::random(rng));
        }
        Ok(Self { coefficients })
    }

    /// Create a polynomial from explicit coefficients in ascending degree order.
    pub fn from_coefficients(coefficients: Vec<S>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::InvalidThreshold {
                threshold: 0,
                participants: 0,
            });
        }
        Ok(Self { coefficients })
    }

    /// Return polynomial coefficients in ascending degree order.
    pub fn coefficients(&self) -> &[S] {
        &self.coefficients
    }

    /// Evaluate this polynomial at a scalar point.
    pub fn evaluate_at_scalar(&self, x: &S) -> S {
        let mut result = S::zero();
        for coeff in self.coefficients.iter().rev() {
            result = result.mul(x).add(coeff);
        }
        result
    }

    /// Evaluate this polynomial for a participant.
    pub fn evaluate(&self, participant: ParticipantIndex) -> Result<Share<S>> {
        let x = participant.to_scalar::<S>()?;
        Ok(Share {
            participant,
            value: self.evaluate_at_scalar(&x),
        })
    }

    /// Generate shares for the provided participant indexes.
    pub fn shares(&self, participants: &[ParticipantIndex]) -> Result<Vec<Share<S>>> {
        ensure_unique_participants(participants)?;
        participants
            .iter()
            .copied()
            .map(|participant| self.evaluate(participant))
            .collect()
    }
}

/// Reconstruct the secret `f(0)` from shares.
///
/// `threshold` is a minimum-count gate: this function only checks that
/// `shares.len() >= threshold` and that `threshold != 0`. The interpolation
/// itself uses every supplied share, not just the first `threshold`. Callers
/// that want exactly the threshold-many shares to participate must truncate
/// the input slice themselves; passing more shares than the threshold is
/// safe (they are all points on the same polynomial of degree
/// `threshold - 1`) but produces a different forgiveness set, not a
/// different secret.
pub fn reconstruct_secret<S: GoldenScalar>(shares: &[Share<S>], threshold: usize) -> Result<S> {
    if threshold == 0 || shares.len() < threshold {
        return Err(Error::InvalidThreshold {
            threshold,
            participants: shares.len(),
        });
    }

    lagrange_interpolate_at_zero(shares)
}

/// Interpolate the value at zero from the provided shares.
pub fn lagrange_interpolate_at_zero<S: GoldenScalar>(shares: &[Share<S>]) -> Result<S> {
    if shares.is_empty() {
        return Err(Error::InvalidThreshold {
            threshold: 0,
            participants: 0,
        });
    }

    let participants: Vec<_> = shares.iter().map(|share| share.participant).collect();
    ensure_unique_participants(&participants)?;

    let xs: Vec<S> = shares
        .iter()
        .map(|share| share.participant.to_scalar::<S>())
        .collect::<Result<_>>()?;

    let coefficients = lagrange_coefficients_at_zero(&xs)?;

    let mut result = S::zero();
    for (share, coefficient) in shares.iter().zip(coefficients.iter()) {
        result = result.add(&share.value.mul(coefficient));
    }

    Ok(result)
}

/// Lagrange coefficients `lambda_i(0)` for each `x_i` in `xs`, computed with
/// `O(k)` scratch space and one batch field inversion via [`batch_invert`].
pub fn lagrange_coefficients_at_zero<S: GoldenScalar>(xs: &[S]) -> Result<Vec<S>> {
    let mut numerators = Vec::with_capacity(xs.len());
    let mut denominators = Vec::with_capacity(xs.len());
    for (i, xi) in xs.iter().enumerate() {
        let mut numerator = S::one();
        let mut denominator = S::one();
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = numerator.mul(&xj.neg());
            denominator = denominator.mul(&xi.sub(xj));
        }
        numerators.push(numerator);
        denominators.push(denominator);
    }

    batch_invert(&mut denominators).ok_or(Error::NonInvertibleDenominator)?;

    Ok(numerators
        .into_iter()
        .zip(denominators)
        .map(|(numerator, inverse)| numerator.mul(&inverse))
        .collect())
}

/// Batch-inverts `values` in place with one field inversion (the Montgomery
/// trick) instead of `values.len()` individual inversions. Returns `None`
/// if the product is zero, leaving `values` partially overwritten.
pub fn batch_invert<S: GoldenScalar>(values: &mut [S]) -> Option<()> {
    if values.is_empty() {
        return Some(());
    }

    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = S::one();
    for value in values.iter() {
        prefix.push(acc.clone());
        acc = acc.mul(value);
    }

    let mut acc_inv = acc.invert()?;
    for (value, prefix_product) in values.iter_mut().zip(prefix.iter()).rev() {
        let inverse = acc_inv.mul(prefix_product);
        acc_inv = acc_inv.mul(value);
        *value = inverse;
    }

    Some(())
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
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };

    use super::*;
    use crate::test_support::TinyScalar;

    fn participants(values: &[u32]) -> Vec<ParticipantIndex> {
        values
            .iter()
            .map(|value| ParticipantIndex::new(*value).expect("nonzero participant"))
            .collect()
    }

    #[test]
    fn reconstructs_from_threshold_subset() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let secret = TinyScalar::from_u64(42).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        assert_eq!(reconstruct_secret(&shares[0..3], 3).unwrap(), secret);
        assert_eq!(
            reconstruct_secret(
                &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
                3
            )
            .unwrap(),
            secret
        );
    }

    #[test]
    fn fewer_than_threshold_shares_are_rejected_by_reconstruction_api() {
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let secret = TinyScalar::from_u64(42).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        assert_eq!(
            reconstruct_secret(&shares[0..2], 3).unwrap_err(),
            Error::InvalidThreshold {
                threshold: 3,
                participants: 2
            }
        );
    }

    #[test]
    fn all_threshold_subsets_reconstruct_for_small_committees() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        for n in 1..=6 {
            for threshold in 1..=n {
                let secret = TinyScalar::from_u64((10 + n + threshold) as u64).unwrap();
                let poly = Polynomial::random_with_secret(secret, threshold, &mut rng).unwrap();
                let indexes: Vec<_> = (1..=n as u32)
                    .map(|value| participants(&[value])[0])
                    .collect();
                let shares = poly.shares(&indexes).unwrap();
                for subset in threshold_subsets(&shares, threshold) {
                    assert_eq!(reconstruct_secret(&subset, threshold).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn randomized_committee_sizes_reconstruct_from_threshold_subset() {
        let mut chooser = ChaCha20Rng::from_seed([21u8; 32]);
        let mut polynomial_rng = ChaCha20Rng::from_seed([22u8; 32]);

        for case in 0..128 {
            let n = 1 + (chooser.next_u32() as usize % 16);
            let threshold = 1 + (chooser.next_u32() as usize % n);
            let secret = TinyScalar::from_u64(1 + u64::from(chooser.next_u32())).unwrap();
            let polynomial =
                Polynomial::random_with_secret(secret, threshold, &mut polynomial_rng).unwrap();
            let indexes: Vec<_> = (1..=n as u32)
                .map(|value| participants(&[value])[0])
                .collect();
            let shares = polynomial.shares(&indexes).unwrap();
            let subset = randomized_subset(&shares, threshold, &mut chooser);

            assert_eq!(
                reconstruct_secret(&subset, threshold).unwrap(),
                secret,
                "case {case}: n={n}, threshold={threshold}"
            );
        }
    }

    #[test]
    fn polynomial_from_coefficients_rejects_empty() {
        // The empty-vec branch of from_coefficients is a boundary condition
        // that no other test exercises; pin it here so a regression that
        // accepts an empty polynomial fails loudly.
        assert_eq!(
            Polynomial::<TinyScalar>::from_coefficients(Vec::new()).unwrap_err(),
            Error::InvalidThreshold {
                threshold: 0,
                participants: 0
            }
        );
    }

    #[test]
    fn polynomial_evaluates_known_value() {
        // Build p(x) = 1 + 2*x + 3*x^2 (in ascending coefficient order)
        // and check p(2) = 1 + 4 + 12 = 17 (mod 97). Pins from_coefficients
        // + evaluate_at_scalar against a hand-computed value so a reordering
        // of the coefficient vector (e.g. descending order) is caught.
        let poly = Polynomial::from_coefficients(vec![
            TinyScalar::from_u64(1).unwrap(),
            TinyScalar::from_u64(2).unwrap(),
            TinyScalar::from_u64(3).unwrap(),
        ])
        .unwrap();
        let x = TinyScalar::from_u64(2).unwrap();
        let got = poly.evaluate_at_scalar(&x);
        let want = TinyScalar::from_u64(17).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn polynomial_zeroize_wipes_coefficients() {
        // Polynomial's first coefficient is the shared secret; Zeroize must
        // wipe every coefficient, not just the first. Build a polynomial
        // with nonzero coefficients across multiple slots, zeroize, and
        // confirm every slot is zero. Drop does NOT call zeroize
        // automatically (GoldenScalar does not require S: Zeroize); callers
        // must invoke it explicitly or wrap in zeroize::Zeroizing.
        let mut poly = Polynomial::from_coefficients(vec![
            TinyScalar::from_u64(11).unwrap(),
            TinyScalar::from_u64(22).unwrap(),
            TinyScalar::from_u64(33).unwrap(),
        ])
        .unwrap();
        poly.zeroize();
        for (i, coeff) in poly.coefficients().iter().enumerate() {
            assert!(*coeff == TinyScalar::zero(), "coefficient {i} not zeroized");
        }
    }

    #[test]
    fn scalar_decoding_rejects_malformed_bytes() {
        for value in 97..=u8::MAX {
            assert_eq!(
                TinyScalar::from_repr(&[value]).unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }

    fn threshold_subsets<S: GoldenScalar>(
        shares: &[Share<S>],
        threshold: usize,
    ) -> Vec<Vec<Share<S>>> {
        fn collect<S: GoldenScalar>(
            shares: &[Share<S>],
            threshold: usize,
            offset: usize,
            current: &mut Vec<Share<S>>,
            output: &mut Vec<Vec<Share<S>>>,
        ) {
            if current.len() == threshold {
                output.push(current.clone());
                return;
            }

            for index in offset..shares.len() {
                current.push(shares[index].clone());
                collect(shares, threshold, index + 1, current, output);
                current.pop();
            }
        }

        let mut output = Vec::new();
        collect(shares, threshold, 0, &mut Vec::new(), &mut output);
        output
    }

    fn randomized_subset<S: GoldenScalar>(
        shares: &[Share<S>],
        threshold: usize,
        rng: &mut impl RngCore,
    ) -> Vec<Share<S>> {
        let mut indexes: Vec<_> = (0..shares.len()).collect();
        for index in 0..indexes.len() {
            let swap_with = index + (rng.next_u32() as usize % (indexes.len() - index));
            indexes.swap(index, swap_with);
        }

        indexes
            .into_iter()
            .take(threshold)
            .map(|index| shares[index].clone())
            .collect()
    }

    #[test]
    fn interpolation_primitive_still_accepts_exact_shares() {
        let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
        let secret = TinyScalar::from_u64(42).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let shares = poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap();

        assert_eq!(
            lagrange_interpolate_at_zero(&[
                shares[0].clone(),
                shares[2].clone(),
                shares[4].clone()
            ])
            .unwrap(),
            secret
        );
    }

    #[test]
    fn duplicate_participant_indexes_are_rejected() {
        let shares = vec![
            Share {
                participant: ParticipantIndex::new(1).unwrap(),
                value: TinyScalar::from_u64(3).unwrap(),
            },
            Share {
                participant: ParticipantIndex::new(1).unwrap(),
                value: TinyScalar::from_u64(5).unwrap(),
            },
        ];

        assert_eq!(
            lagrange_interpolate_at_zero(&shares).unwrap_err(),
            Error::DuplicateParticipantIndex(1)
        );
    }

    #[test]
    fn invalid_participant_zero_is_rejected() {
        assert_eq!(
            ParticipantIndex::new(0).unwrap_err(),
            Error::ZeroParticipantIndex
        );
    }

    #[test]
    fn field_inversion_property_holds() {
        for value in 1..96 {
            let scalar = TinyScalar::from_u64(value).unwrap();
            let inverse = scalar.invert().unwrap();
            assert_eq!(scalar.mul(&inverse), TinyScalar::one());
        }
    }

    #[test]
    fn scalar_encoding_round_trips_and_rejects_noncanonical() {
        let scalar = TinyScalar::from_u64(96).unwrap();
        let repr = scalar.to_repr();
        assert_eq!(TinyScalar::from_repr(&repr).unwrap(), scalar);
        assert!(TinyScalar::from_repr(&[97]).is_err());
    }

    #[test]
    fn batch_invert_matches_individual_inversions() {
        let mut values: Vec<TinyScalar> = (1u64..12)
            .map(|value| TinyScalar::from_u64(value).unwrap())
            .collect();
        let expected: Vec<TinyScalar> = values.iter().map(|v| v.invert().unwrap()).collect();

        batch_invert(&mut values).unwrap();

        assert_eq!(values, expected);
    }

    #[test]
    fn batch_invert_empty_slice_is_a_noop() {
        let mut values: Vec<TinyScalar> = Vec::new();
        assert!(batch_invert(&mut values).is_some());
        assert!(values.is_empty());
    }

    #[test]
    fn batch_invert_rejects_a_zero_element() {
        let mut values = vec![
            TinyScalar::from_u64(3).unwrap(),
            TinyScalar::zero(),
            TinyScalar::from_u64(5).unwrap(),
        ];
        assert!(batch_invert(&mut values).is_none());
    }
}
