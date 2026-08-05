//! Public-verification proof backends for Golden DKG.
//!
//! [`paper`] is the Golden eVRF backend from the 2024 paper, built on the
//! Secp256k1/Secq256k1 curve cycle via `bulletproofs-cycle` and
//! `golden-halo2curves`. It is feature-gated on `halo2curves-secp256k1`
//! and verifies end-to-end. When the feature is off, `prove_batch` and
//! `verify_batch` return `Error::ProofVerificationFailed` so a misconfigured
//! caller fails closed instead of silently skipping the proof.
//!
//! [`prototype`] is a lighter Schnorr/Chaum-Pedersen backend that proves the
//! scalar opening of each public share commitment and pad/DH commitment.
//! It is not the Golden eVRF proof; it exists as a self-contained,
//! curve-agnostic fallback for testing the DKG transport without pulling
//! in the curve-cycle R1CS layer.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use golden_core::{
    Error, EvrfProofBackend, EvrfStatement, EvrfWitness, GoldenGroup, GoldenScalar,
    ParticipantIndex, Result,
};
use rand_core::CryptoRngCore;

pub mod paper;

mod proof_stream;

/// Curve-agnostic Schnorr/Chaum-Pedersen backend for DKG share/pad/DH
/// openings. Not the Golden eVRF proof; see [`paper`] for that.
pub mod prototype {
    use super::*;
    use crate::proof_stream::{
        GoldenCurve, IdentityPolicy, Observe, ProverProofStream, VerifierProofStream,
    };

    /// Generic proof backend for DKG share, pad, and DH commitments.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ShareOpeningBackend {}

    impl<G> EvrfProofBackend<G> for ShareOpeningBackend
    where
        G: GoldenGroup,
        G::ElementRepr: TryFrom<Vec<u8>>,
    {
        const PROOF_ID: &'static [u8] = b"golden-evrf/prototype-share-opening/v2";

        fn prove_batch(
            statements: &[EvrfStatement<G>],
            witnesses: &[EvrfWitness<G>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            if statements.len() != witnesses.len() {
                return Err(Error::ProofVerificationFailed);
            }

            let mut stream = ProverProofStream::new(<Self as EvrfProofBackend<G>>::PROOF_ID)?;
            observe_batch::<G>(&mut stream, statements)?;
            for (statement, witness) in statements.iter().zip(witnesses) {
                let share_nonce = random_nonzero_scalar::<G>(rng);
                let pad_nonce = random_nonzero_scalar::<G>(rng);
                let share_nonce_point = G::mul_generator(&share_nonce);
                let pad_nonce_point = G::mul_generator(&pad_nonce);
                let dh_nonce_point = G::mul(&statement.receiver_public_key, &pad_nonce);

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
                stream.send_point::<GoldenCurve<G>>(
                    b"dh-nonce-point",
                    &dh_nonce_point,
                    IdentityPolicy::Reject,
                )?;

                let challenge = challenge::<G>(&mut stream)?;
                let share_response = share_nonce.add(&challenge.mul(&witness.share));
                let pad_response = pad_nonce.add(&challenge.mul(&witness.pad));
                stream.send_scalar::<GoldenCurve<G>>(b"share-response", &share_response)?;
                stream.send_scalar::<GoldenCurve<G>>(b"pad-response", &pad_response)?;
            }

            Ok(stream.finish())
        }

        fn verify_batch(statements: &[EvrfStatement<G>], proof: &[u8]) -> Result<()> {
            let mut stream =
                VerifierProofStream::new(<Self as EvrfProofBackend<G>>::PROOF_ID, proof)?;
            observe_batch::<G>(&mut stream, statements)?;
            for statement in statements {
                let share_nonce_point = stream.receive_point::<GoldenCurve<G>>(
                    b"share-nonce-point",
                    IdentityPolicy::Reject,
                )?;
                let pad_nonce_point = stream
                    .receive_point::<GoldenCurve<G>>(b"pad-nonce-point", IdentityPolicy::Reject)?;
                let dh_nonce_point = stream
                    .receive_point::<GoldenCurve<G>>(b"dh-nonce-point", IdentityPolicy::Reject)?;
                let challenge = challenge::<G>(&mut stream)?;
                let share_response = stream.receive_scalar::<GoldenCurve<G>>(b"share-response")?;
                let pad_response = stream.receive_scalar::<GoldenCurve<G>>(b"pad-response")?;

                let share_left = G::mul_generator(&share_response);
                let share_right = G::add(
                    &share_nonce_point,
                    &G::mul(&statement.share_commitment, &challenge),
                );
                let pad_left = G::mul_generator(&pad_response);
                let pad_right = G::add(
                    &pad_nonce_point,
                    &G::mul(&statement.pad_commitment, &challenge),
                );
                let dh_left = G::mul(&statement.receiver_public_key, &pad_response);
                let dh_right = G::add(
                    &dh_nonce_point,
                    &G::mul(&statement.dh_commitment, &challenge),
                );

                if share_left != share_right || pad_left != pad_right || dh_left != dh_right {
                    return Err(Error::ProofVerificationFailed);
                }
            }

            stream.finish()
        }
    }

    fn observe_batch<G: GoldenGroup>(
        stream: &mut impl Observe,
        statements: &[EvrfStatement<G>],
    ) -> Result<()> {
        let statement_count =
            u64::try_from(statements.len()).map_err(|_| Error::ProofVerificationFailed)?;
        stream.observe_bytes(b"group-backend", G::BACKEND_ID.as_bytes());
        stream.observe_bytes(b"statement-count", &statement_count.to_be_bytes());
        let mut previous_receiver = None;
        for statement in statements {
            validate_statement::<G>(statement, &mut previous_receiver)?;
            stream.observe_bytes(b"statement-root", &statement.root());
        }
        Ok(())
    }

    fn validate_statement<G: GoldenGroup>(
        statement: &EvrfStatement<G>,
        previous_receiver: &mut Option<ParticipantIndex>,
    ) -> Result<()> {
        if previous_receiver.is_some_and(|previous| previous >= statement.receiver) {
            return Err(Error::ProofVerificationFailed);
        }
        *previous_receiver = Some(statement.receiver);
        ensure_backend_matches::<G>(statement)?;
        ensure_feldman_share_relation::<G>(statement)?;
        ensure_encrypted_share_relation::<G>(statement)
    }

    fn ensure_backend_matches<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        if statement.protocol_version == golden_core::PROTOCOL_VERSION
            && statement.backend_id == G::BACKEND_ID
        {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn ensure_encrypted_share_relation<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        let encrypted_share_commitment = G::mul_generator(&statement.encrypted_share);
        let expected_encrypted_share_commitment =
            G::add(&statement.share_commitment, &statement.pad_commitment);
        if encrypted_share_commitment == expected_encrypted_share_commitment {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn ensure_feldman_share_relation<G: GoldenGroup>(statement: &EvrfStatement<G>) -> Result<()> {
        if statement.commitment_coefficients.is_empty()
            || statement.commitment_coefficients.len() != statement.threshold
        {
            return Err(Error::ProofVerificationFailed);
        }

        let x = statement.receiver.to_scalar::<G::Scalar>()?;
        let mut x_pow = G::Scalar::one();
        let mut expected = G::identity();
        for coefficient in &statement.commitment_coefficients {
            expected = G::add(&expected, &G::mul(coefficient, &x_pow));
            x_pow = x_pow.mul(&x);
        }

        if expected == statement.share_commitment {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }

    fn challenge<G: GoldenGroup>(stream: &mut impl Observe) -> Result<G::Scalar> {
        let mut challenge_bytes = [0u8; 32];
        stream.challenge(b"opening-challenge", &mut challenge_bytes);
        G::Scalar::hash_to_scalar(b"golden-share-opening-challenge-v2", &challenge_bytes)
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
