//! Feldman commitments over a generic Golden group.

use subtle::ConstantTimeEq;

use crate::{Error, GoldenGroup, ParticipantIndex, Polynomial, Result, Share};

/// Feldman commitment to a Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeldmanCommitment<G: GoldenGroup> {
    coefficients: Vec<G::Element>,
}

/// Variable-time double-and-add multiplication by a small public scalar.
fn mul_by_small_scalar<G: GoldenGroup>(point: &G::Element, scalar: u32) -> G::Element {
    if scalar == 0 {
        return G::identity();
    }
    let mut acc = G::identity();
    for bit in (0..u32::BITS - scalar.leading_zeros()).rev() {
        acc = G::add(&acc, &acc);
        if (scalar >> bit) & 1 == 1 {
            acc = G::add(&acc, point);
        }
    }
    acc
}

impl<G: GoldenGroup> FeldmanCommitment<G> {
    /// Commit to each polynomial coefficient as `g^a_i`.
    pub fn commit(poly: &Polynomial<G::Scalar>) -> Result<Self> {
        let coefficients: Vec<_> = poly.coefficients().iter().map(G::mul_generator).collect();
        Self::from_coefficients(coefficients)
    }

    /// Construct from explicit committed coefficients.
    pub fn from_coefficients(coefficients: Vec<G::Element>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::EmptyCommitment);
        }
        Ok(Self { coefficients })
    }

    /// Return committed coefficients in ascending degree order.
    pub fn coefficients(&self) -> &[G::Element] {
        &self.coefficients
    }

    /// Return the aggregate public key, `g^f(0)`.
    pub fn public_key(&self) -> G::Element {
        self.coefficients[0].clone()
    }

    /// Compute the expected public key share for a participant via Horner's
    /// method.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Result<G::Element> {
        let x = participant.get();
        let mut result = G::identity();

        for coefficient in self.coefficients.iter().rev() {
            result = G::add(&mul_by_small_scalar::<G>(&result, x), coefficient);
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
        let mut coefficients = commitment.coefficients().to_vec();
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
