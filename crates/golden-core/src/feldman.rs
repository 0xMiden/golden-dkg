//! Feldman commitments over a generic Golden group.

use subtle::ConstantTimeEq;

use crate::{Error, GoldenGroup, GoldenScalar, ParticipantIndex, Polynomial, Result, Share};

/// Feldman commitment to a Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeldmanCommitment<G: GoldenGroup> {
    constant: Option<G::Element>,
    nonconstant_coefficients: Vec<G::Element>,
}

impl<G: GoldenGroup> FeldmanCommitment<G> {
    /// Commit to each polynomial coefficient as `g^a_i`.
    pub fn commit(poly: &Polynomial<G::Scalar>) -> Result<Self> {
        let coefficients: Vec<_> = poly.coefficients().iter().map(G::mul_generator).collect();
        Self::from_coefficients(coefficients)
    }

    /// Commit to a polynomial whose constant coefficient is fixed to zero.
    pub fn commit_zero(poly: &Polynomial<G::Scalar>) -> Result<Self> {
        if !bool::from(poly.coefficients()[0].is_zero()) {
            return Err(Error::CommitmentVerificationFailed);
        }
        Ok(Self::from_zero_tail(
            poly.coefficients()[1..]
                .iter()
                .map(G::mul_generator)
                .collect(),
        ))
    }

    /// Construct a commitment with an explicit constant coefficient.
    pub fn from_coefficients(coefficients: Vec<G::Element>) -> Result<Self> {
        let mut coefficients = coefficients.into_iter();
        let constant = coefficients.next().ok_or(Error::EmptyCommitment)?;
        Ok(Self {
            constant: Some(constant),
            nonconstant_coefficients: coefficients.collect(),
        })
    }

    /// Construct a fixed-zero commitment from coefficients `A_1, ..., A_(t-1)`.
    pub(crate) fn from_zero_tail(nonconstant_coefficients: Vec<G::Element>) -> Self {
        Self {
            constant: None,
            nonconstant_coefficients,
        }
    }

    /// Return the explicit constant commitment, or `None` when fixed to identity.
    pub fn constant(&self) -> Option<&G::Element> {
        self.constant.as_ref()
    }

    /// Return all logical coefficients in ascending degree order.
    pub fn coefficients(&self) -> Vec<G::Element> {
        core::iter::once(self.public_key())
            .chain(self.nonconstant_coefficients.iter().cloned())
            .collect()
    }

    /// Return the logical coefficient count, including the fixed zero constant.
    pub fn threshold(&self) -> usize {
        self.nonconstant_coefficients.len() + 1
    }

    /// Return the aggregate public key, `g^f(0)`.
    pub fn public_key(&self) -> G::Element {
        self.constant.clone().unwrap_or_else(G::identity)
    }

    /// Compute the expected public key share for a participant.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Result<G::Element> {
        let x = participant.to_scalar::<G::Scalar>()?;
        let mut result = self.public_key();
        let mut x_pow = x.clone();

        for coefficient in &self.nonconstant_coefficients {
            result = G::add(&result, &G::mul(coefficient, &x_pow));
            x_pow = x_pow.mul(&x);
        }

        Ok(result)
    }

    /// Verify a share against this commitment.
    pub fn verify_share(&self, share: &Share<G::Scalar>) -> Result<bool> {
        let expected = self.public_key_share(share.participant)?;
        let actual = G::mul_generator(&share.value);
        Ok(expected.ct_eq(&actual).into())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::GoldenScalar;

    fn participants(values: &[u32]) -> Vec<ParticipantIndex> {
        values
            .iter()
            .map(|value| ParticipantIndex::new(*value).expect("nonzero participant"))
            .collect()
    }

    #[test]
    fn valid_shares_verify() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let secret = TinyScalar::from_u64(11).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<TinyGroup>::commit(&poly).unwrap();

        for share in poly.shares(&participants(&[1, 2, 3, 4, 5])).unwrap() {
            assert!(commitment.verify_share(&share).unwrap());
        }
    }

    #[test]
    fn fixed_zero_commitment_omits_constant_without_changing_share_relation() {
        let polynomial = Polynomial::from_coefficients(vec![
            TinyScalar::zero(),
            TinyScalar::from_u64(7).unwrap(),
            TinyScalar::from_u64(9).unwrap(),
        ])
        .unwrap();
        let full = FeldmanCommitment::<TinyGroup>::commit(&polynomial).unwrap();
        let fixed_zero = FeldmanCommitment::<TinyGroup>::commit_zero(&polynomial).unwrap();

        assert_eq!(fixed_zero.constant(), None);
        assert_eq!(fixed_zero.threshold(), 3);
        assert_eq!(fixed_zero.coefficients(), full.coefficients());
        assert_eq!(
            fixed_zero.public_key_share(participants(&[2])[0]).unwrap(),
            full.public_key_share(participants(&[2])[0]).unwrap()
        );
    }

    #[test]
    fn altered_share_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let secret = TinyScalar::from_u64(13).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<TinyGroup>::commit(&poly).unwrap();
        let mut share = poly.evaluate(ParticipantIndex::new(2).unwrap()).unwrap();
        share.value = share.value.add(&TinyScalar::one());

        assert!(!commitment.verify_share(&share).unwrap());
    }

    #[test]
    fn altered_commitment_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let secret = TinyScalar::from_u64(13).unwrap();
        let poly = Polynomial::random_with_secret(secret, 3, &mut rng).unwrap();
        let commitment = FeldmanCommitment::<TinyGroup>::commit(&poly).unwrap();
        let mut coefficients = commitment.coefficients();
        coefficients[1] = TinyGroup::add(&coefficients[1], &TinyGroup::generator());
        let altered = FeldmanCommitment::<TinyGroup>::from_coefficients(coefficients).unwrap();
        let share = poly.evaluate(ParticipantIndex::new(2).unwrap()).unwrap();

        assert!(!altered.verify_share(&share).unwrap());
    }

    #[test]
    fn public_key_is_generator_times_secret() {
        let secret = TinyScalar::from_u64(17).unwrap();
        let poly = Polynomial::from_coefficients(vec![secret]).unwrap();
        let commitment = FeldmanCommitment::<TinyGroup>::commit(&poly).unwrap();

        assert_eq!(commitment.public_key(), TinyGroup::mul_generator(&secret));
    }

    #[test]
    fn group_distributes_over_scalar_addition() {
        let a = TinyScalar::from_u64(12).unwrap();
        let b = TinyScalar::from_u64(29).unwrap();
        let lhs = TinyGroup::mul_generator(&a.add(&b));
        let rhs = TinyGroup::add(&TinyGroup::mul_generator(&a), &TinyGroup::mul_generator(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn element_encoding_round_trips_and_rejects_noncanonical() {
        let point = TinyGroup::mul_generator(&TinyScalar::from_u64(23).unwrap());
        let repr = TinyGroup::encode_element(&point);
        assert_eq!(TinyGroup::decode_element(&repr).unwrap(), point);
        assert!(TinyGroup::decode_element(&[97]).is_err());
    }

    #[test]
    fn element_decoding_rejects_malformed_bytes() {
        for value in 97..=u8::MAX {
            assert_eq!(
                TinyGroup::decode_element(&[value]).unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }
}
