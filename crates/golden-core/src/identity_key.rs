//! Proofs of knowledge for participant identity keys.

use crate::transcript::TranscriptBuilder;
use crate::{Error, GoldenGroup, GoldenScalar, Result};

/// Schnorr proof of knowledge of the secret behind an identity public key.
///
/// [`ParticipantRegistry::new`](crate::ParticipantRegistry::new) verifies one
/// proof per registered key, so a participant cannot register a key whose
/// secret it does not know, such as the negation of another participant's key.
///
/// The proof binds the group backend and the public key. It binds no session
/// or participant index, so a long-lived identity key can present the same
/// proof to every registry it joins. The nonce is derived from the identity
/// secret, so proving needs no randomness and repeated calls return the same
/// proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityKeyProof<G: GoldenGroup> {
    /// Schnorr nonce commitment.
    pub nonce_point: G::Element,
    /// Schnorr response.
    pub response: G::Scalar,
}

impl<G: GoldenGroup> IdentityKeyProof<G> {
    /// Prove knowledge of `identity_secret` for its public key.
    pub fn prove(identity_secret: &G::Scalar) -> Result<Self> {
        let public_key = G::mul_generator(identity_secret);
        let nonce = proof_nonce::<G>(identity_secret)?;
        let nonce_point = G::mul_generator(&nonce);
        let challenge = proof_challenge::<G>(&public_key, &nonce_point)?;
        Ok(Self {
            nonce_point,
            response: nonce.add(&challenge.mul(identity_secret)),
        })
    }

    /// Verify this proof against `public_key`.
    pub fn verify(&self, public_key: &G::Element) -> Result<()> {
        if bool::from(G::is_identity(&self.nonce_point)) {
            return Err(Error::ProofVerificationFailed);
        }
        let challenge = proof_challenge::<G>(public_key, &self.nonce_point)?;
        let expected = G::add(&self.nonce_point, &G::mul(public_key, &challenge));
        if G::mul_generator(&self.response) == expected {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }
}

fn proof_nonce<G: GoldenGroup>(identity_secret: &G::Scalar) -> Result<G::Scalar> {
    let mut transcript = TranscriptBuilder::new(b"identity-key-proof-nonce");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.scalar::<G>(b"identity-secret", identity_secret);
    G::Scalar::hash_to_scalar(b"golden-identity-key-proof-nonce-v1", &transcript.root())
}

fn proof_challenge<G: GoldenGroup>(
    public_key: &G::Element,
    nonce_point: &G::Element,
) -> Result<G::Scalar> {
    let mut transcript = TranscriptBuilder::new(b"identity-key-proof");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.element::<G>(b"public-key", public_key);
    transcript.element::<G>(b"nonce-point", nonce_point);
    G::Scalar::hash_to_scalar(b"golden-identity-key-proof-v1", &transcript.root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};

    fn secret(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    #[test]
    fn proof_verifies_for_its_public_key() {
        let identity_secret = secret(10);
        let proof = IdentityKeyProof::<TinyGroup>::prove(&identity_secret).unwrap();

        proof
            .verify(&TinyGroup::mul_generator(&identity_secret))
            .unwrap();
    }

    #[test]
    fn proof_is_deterministic() {
        let identity_secret = secret(10);

        assert_eq!(
            IdentityKeyProof::<TinyGroup>::prove(&identity_secret).unwrap(),
            IdentityKeyProof::<TinyGroup>::prove(&identity_secret).unwrap()
        );
    }

    #[test]
    fn proof_rejects_other_and_negated_public_keys() {
        let identity_secret = secret(10);
        let public_key = TinyGroup::mul_generator(&identity_secret);
        let proof = IdentityKeyProof::<TinyGroup>::prove(&identity_secret).unwrap();

        for other in [
            TinyGroup::mul_generator(&secret(11)),
            TinyGroup::sub(&TinyGroup::identity(), &public_key),
        ] {
            assert_eq!(
                proof.verify(&other).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }

    #[test]
    fn proof_rejects_modified_fields() {
        let identity_secret = secret(10);
        let public_key = TinyGroup::mul_generator(&identity_secret);
        let proof = IdentityKeyProof::<TinyGroup>::prove(&identity_secret).unwrap();

        let mut wrong_response = proof.clone();
        wrong_response.response = proof.response.add(&TinyScalar::one());
        let mut wrong_nonce_point = proof.clone();
        wrong_nonce_point.nonce_point = TinyGroup::add(&proof.nonce_point, &TinyGroup::generator());
        let mut identity_nonce_point = proof.clone();
        identity_nonce_point.nonce_point = TinyGroup::identity();

        for modified in [wrong_response, wrong_nonce_point, identity_nonce_point] {
            assert_eq!(
                modified.verify(&public_key).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }
}
