//! Public-verification proof backends for Golden DKG.
//!
//! [`paper`] is the Golden eVRF backend from the 2024 paper. [`prototype`]
//! is a lighter, curve-agnostic Schnorr backend for protocol plumbing tests.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use golden_core::{
    Error, EvrfProofBackend, EvrfReceiverStatement, EvrfStatement, EvrfWitness, GoldenGroup,
    GoldenScalar, Result,
};
use rand_core::CryptoRngCore;

pub mod paper;

#[cfg(feature = "insecure-revealed-witness")]
mod insecure_revealed_witness;
mod proof_stream;

#[cfg(feature = "insecure-revealed-witness")]
pub use insecure_revealed_witness::InsecureRevealedWitnessProof;

/// Curve-agnostic Schnorr backend for DKG share and pad openings.
/// Not the Golden eVRF proof; see [`paper`] for that.
pub mod prototype {
    use super::*;
    use crate::proof_stream::{
        GoldenCurve, IdentityPolicy, Observe, ProverProofStream, VerifierProofStream,
    };

    /// Generic proof backend for DKG share and pad commitments.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ShareOpeningBackend {}

    impl<G> EvrfProofBackend<G> for ShareOpeningBackend
    where
        G: GoldenGroup,
        G::ElementRepr: TryFrom<Vec<u8>>,
    {
        const PROOF_ID: &'static [u8] = b"golden-evrf/prototype-share-opening/v4";

        fn prove_batch(
            statement: &EvrfStatement<G>,
            witness: &EvrfWitness<G>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            validate_statement(statement)?;
            witness.validate_shape(statement)?;
            if G::mul_generator(&witness.identity_secret) != statement.dealer_public_key {
                return Err(Error::ProofVerificationFailed);
            }

            let mut stream = ProverProofStream::new(<Self as EvrfProofBackend<G>>::PROOF_ID)?;
            observe_statement::<G>(&mut stream, statement)?;
            for dealing in &witness.dealings {
                for receiver in &dealing.receivers {
                    let share_nonce = random_nonzero_scalar::<G>(rng);
                    let pad_nonce = random_nonzero_scalar::<G>(rng);
                    let share_nonce_point = G::mul_generator(&share_nonce);
                    let pad_nonce_point = G::mul_generator(&pad_nonce);

                    stream.send_point::<GoldenCurve<G>>(
                        b"share-nonce-point",
                        &share_nonce_point,
                        IdentityPolicy::Reject,
                    )?;
                    stream.send_point::<GoldenCurve<G>>(
                        b"pad-nonce-point",
                        &pad_nonce_point,
                        IdentityPolicy::Reject,
                    )?;
                    let challenge = challenge::<G>(&mut stream)?;
                    let share_response = share_nonce.add(&challenge.mul(&receiver.share));
                    let pad_response = pad_nonce.add(&challenge.mul(&receiver.pad));
                    stream.send_scalar::<GoldenCurve<G>>(b"share-response", &share_response)?;
                    stream.send_scalar::<GoldenCurve<G>>(b"pad-response", &pad_response)?;
                }
            }
            stream.finish_checked()
        }

        fn verify_batch(statement: &EvrfStatement<G>, proof: &[u8]) -> Result<()> {
            validate_statement(statement)?;
            let mut stream =
                VerifierProofStream::new(<Self as EvrfProofBackend<G>>::PROOF_ID, proof)?;
            observe_statement::<G>(&mut stream, statement)?;
            for dealing in &statement.dealings {
                for receiver in &dealing.receivers {
                    let share_nonce_point = stream.receive_point::<GoldenCurve<G>>(
                        b"share-nonce-point",
                        IdentityPolicy::Reject,
                    )?;
                    let pad_nonce_point = stream.receive_point::<GoldenCurve<G>>(
                        b"pad-nonce-point",
                        IdentityPolicy::Reject,
                    )?;
                    let challenge = challenge::<G>(&mut stream)?;
                    let share_response =
                        stream.receive_scalar::<GoldenCurve<G>>(b"share-response")?;
                    let pad_response = stream.receive_scalar::<GoldenCurve<G>>(b"pad-response")?;

                    let share_left = G::mul_generator(&share_response);
                    let share_right = G::add(
                        &share_nonce_point,
                        &G::mul(&receiver.share_commitment, &challenge),
                    );
                    let pad_left = G::mul_generator(&pad_response);
                    let pad_right = G::add(
                        &pad_nonce_point,
                        &G::mul(&receiver.pad_commitment, &challenge),
                    );
                    if share_left != share_right || pad_left != pad_right {
                        return Err(Error::ProofVerificationFailed);
                    }
                }
            }
            stream.finish()
        }
    }

    fn observe_statement<G: GoldenGroup>(
        stream: &mut impl Observe,
        statement: &EvrfStatement<G>,
    ) -> Result<()> {
        stream.observe_bytes(b"group-backend", G::BACKEND_ID.as_bytes());
        stream.observe_bytes(b"statement-root", &statement.root());
        Ok(())
    }

    fn validate_statement<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        let Some(first_dealing) = statement.dealings.first() else {
            return Err(Error::ProofVerificationFailed);
        };
        let threshold = first_dealing.commitment.threshold();
        let canonical_receivers = &first_dealing.receivers;
        if threshold == 0 || canonical_receivers.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        for dealing in &statement.dealings {
            if dealing.commitment.threshold() != threshold
                || dealing.receivers.len() != canonical_receivers.len()
            {
                return Err(Error::ProofVerificationFailed);
            }
            let mut previous_receiver = None;
            for (position, receiver) in dealing.receivers.iter().enumerate() {
                if previous_receiver.is_some_and(|previous| previous >= receiver.receiver)
                    || receiver.receiver != canonical_receivers[position].receiver
                    || receiver.receiver_public_key
                        != canonical_receivers[position].receiver_public_key
                {
                    return Err(Error::ProofVerificationFailed);
                }
                previous_receiver = Some(receiver.receiver);
                if dealing.commitment.public_key_share(receiver.receiver)?
                    != receiver.share_commitment
                {
                    return Err(Error::ProofVerificationFailed);
                }
                ensure_encrypted_share_relation(receiver)?;
            }
        }
        Ok(())
    }

    fn ensure_encrypted_share_relation<G: GoldenGroup>(
        receiver: &EvrfReceiverStatement<G>,
    ) -> Result<()> {
        let encrypted_share_commitment = G::mul_generator(&receiver.encrypted_share);
        let expected = G::add(&receiver.share_commitment, &receiver.pad_commitment);
        if encrypted_share_commitment == expected {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn challenge<G: GoldenGroup>(stream: &mut impl Observe) -> Result<G::Scalar> {
        let mut challenge_bytes = [0u8; 32];
        stream.challenge(b"opening-challenge", &mut challenge_bytes);
        G::Scalar::hash_to_scalar(b"golden-share-opening-challenge-v4", &challenge_bytes)
    }

    fn random_nonzero_scalar<G: GoldenGroup>(rng: &mut impl CryptoRngCore) -> G::Scalar {
        loop {
            let scalar = G::Scalar::random(rng);
            if !bool::from(scalar.is_zero()) {
                return scalar;
            }
        }
    }
}
