//! Feldman commitments over native DKG group points.

use group::Group;

use crate::{DkgGroup, Error, ParticipantIndex, Polynomial, Result, Share};

/// Public coefficient commitments to a Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeldmanCommitment<G: DkgGroup> {
    coefficients: Vec<G::Point>,
}

/// Variable-time multiplication by a small public participant index.
fn mul_by_small_scalar<G: DkgGroup>(point: &G::Point, scalar: u32) -> G::Point {
    let mut result = G::Point::identity();
    for bit in (0..u32::BITS - scalar.leading_zeros()).rev() {
        result = result.double();
        if (scalar >> bit) & 1 == 1 {
            result += point;
        }
    }
    result
}

/// Evaluate borrowed logical coefficients at a public integer index.
pub(crate) fn evaluate<G: DkgGroup>(
    coefficients: &[G::Point],
    participant: ParticipantIndex,
) -> G::Point {
    coefficients
        .iter()
        .rev()
        .fold(G::Point::identity(), |value, coefficient| {
            mul_by_small_scalar::<G>(&value, participant.get()) + coefficient
        })
}

impl<G: DkgGroup> FeldmanCommitment<G> {
    /// Commit to every logical polynomial coefficient using the adapter's fixed base.
    pub fn commit(polynomial: &Polynomial<G::Scalar>) -> Result<Self> {
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(polynomial.threshold())
            .map_err(|_| Error::AllocationFailed)?;
        for coefficient in polynomial.coefficients() {
            coefficients.push(G::mul_generator(coefficient));
        }
        Self::from_coefficients(coefficients)
    }

    /// Construct from nonempty logical coefficients in ascending degree order.
    ///
    /// A zero constant is represented by the identity here. Physical omission
    /// of a Zero instance's constant is private dealer-message grammar.
    pub fn from_coefficients(coefficients: Vec<G::Point>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::EmptyCommitment);
        }
        Ok(Self { coefficients })
    }

    /// Borrow logical coefficient commitments in ascending degree order.
    pub fn coefficients(&self) -> &[G::Point] {
        &self.coefficients
    }

    /// Return the constant commitment, which may be the identity.
    pub fn public_key(&self) -> G::Point {
        self.coefficients[0]
    }

    /// Evaluate public commitments at a validated integer participant index.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Result<G::Point> {
        participant.to_scalar::<G::Scalar>()?;
        Ok(evaluate::<G>(&self.coefficients, participant))
    }

    /// Check a secret share against this public commitment.
    pub fn verify_share(&self, share: &Share<G::Scalar>) -> Result<bool> {
        let expected = self.public_key_share(share.participant())?;
        Ok(expected == G::mul_generator(share.value()))
    }
}
