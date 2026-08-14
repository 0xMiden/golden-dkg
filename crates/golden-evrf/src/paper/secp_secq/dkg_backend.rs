//! Golden DKG adapter for the Secp/Secq paper eVRF.

use golden_core::{Error, EvrfMessage, EvrfProofBackend, EvrfStatement, EvrfWitness, Result};
use golden_halo2curves::golden_group::{
    scalar_to_r1cs_field, Secp256k1Element, Secp256k1GoldenGroup, Secp256k1Scalar,
};
use halo2curves::secp256k1::{Fp, Fq};
use rand_core::CryptoRngCore;

use super::{
    affine, evrf_batched_prove, evrf_batched_verify_many, fp_to_fq, h_gin_1, h_gin_2,
    parse_batched_proof_stream, validate_batched_public_relations, BatchedDealingStatement,
    BatchedEvrfPublicParams, BatchedEvrfStatement, BatchedEvrfWitness, BatchedReceiverStatement,
    Gin, BATCHED_PROOF_ID, MESSAGE_BYTES,
};

/// Compute the paper eVRF pad `r = beta * T_1.x + T_2.x` as an `Fp`
/// element, where `T_1 = H_{G_in,1}(msg)^k`, `T_2 = H_{G_in,2}(msg)^k`,
/// and `k = int(S.x)` for `S = PK_j^sk_1`.
fn compute_pad_fp(msg: &[u8; MESSAGE_BYTES], sk1: &Fq, pkj: &Gin, beta: &Fp) -> Result<Fp> {
    let sj = *pkj * sk1;
    let (s_x, _) = affine(&sj)?;
    let k_fq = fp_to_fq(&s_x);
    let h1 = h_gin_1(msg);
    let h2 = h_gin_2(msg);
    let t1j = h1 * k_fq;
    let t2j = h2 * k_fq;
    let (t1_x, _) = affine(&t1j)?;
    let (t2_x, _) = affine(&t2j)?;
    Ok(*beta * t1_x + t2_x)
}

/// Concrete Secp/Secq paper eVRF backend for the DKG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpSecqBackend;

fn batched_statement(
    statement: &EvrfStatement<Secp256k1GoldenGroup>,
) -> Result<BatchedEvrfStatement> {
    preflight_statement_shape(statement)?;
    let beta = scalar_to_r1cs_field(&statement.beta).ok_or(Error::ProofVerificationFailed)?;
    let dealings = statement
        .dealings
        .iter()
        .map(|dealing| BatchedDealingStatement {
            msg: dealing.message.0,
            commitment: dealing.commitment.clone(),
            receivers: dealing
                .receivers
                .iter()
                .map(|receiver| BatchedReceiverStatement {
                    receiver: receiver.receiver,
                    pkj: receiver.receiver_public_key.0,
                    share_commitment: receiver.share_commitment.0,
                    pad_commitment: receiver.pad_commitment.0,
                    encrypted_share: receiver.encrypted_share.0,
                })
                .collect(),
        })
        .collect();
    let threshold = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?
        .commitment
        .threshold();
    Ok(BatchedEvrfStatement {
        pk1: statement.dealer_public_key.0,
        beta,
        threshold,
        dealer_message_root: statement.dealer_message_root,
        dealings,
    })
}

fn preflight_statement_shape(statement: &EvrfStatement<Secp256k1GoldenGroup>) -> Result<()> {
    let first_dealing = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?;
    let threshold = first_dealing.commitment.threshold();
    let receiver_count = first_dealing.receivers.len();
    BatchedEvrfPublicParams::validated_shape(threshold, statement.dealings.len(), receiver_count)?;
    if statement.dealings.iter().any(|dealing| {
        dealing.commitment.threshold() != threshold || dealing.receivers.len() != receiver_count
    }) {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(())
}

fn same_shape(left: &BatchedEvrfStatement, right: &BatchedEvrfStatement) -> bool {
    left.threshold == right.threshold
        && left.dealings.len() == right.dealings.len()
        && left.dealings.first().map(|dealing| dealing.receivers.len())
            == right
                .dealings
                .first()
                .map(|dealing| dealing.receivers.len())
}

fn public_params(
    statement: &BatchedEvrfStatement,
) -> Result<std::sync::Arc<BatchedEvrfPublicParams>> {
    #[cfg(test)]
    PUBLIC_PARAMS_REQUESTS.with(|requests| requests.set(requests.get() + 1));

    let first_dealing = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?;
    BatchedEvrfPublicParams::shared(
        statement.threshold,
        statement.dealings.len(),
        first_dealing.receivers.len(),
    )
}

#[cfg(test)]
std::thread_local! {
    static PUBLIC_PARAMS_REQUESTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl EvrfProofBackend<Secp256k1GoldenGroup> for SecpSecqBackend {
    const PROOF_ID: &'static [u8] = BATCHED_PROOF_ID;

    fn derive_pad(
        message: EvrfMessage,
        beta: &Secp256k1Scalar,
        identity_secret: &Secp256k1Scalar,
        peer_public_key: &Secp256k1Element,
        _receiver_public_key: &Secp256k1Element,
    ) -> Result<Secp256k1Scalar> {
        let beta_fp = scalar_to_r1cs_field(beta).ok_or(Error::ProofVerificationFailed)?;
        let r = compute_pad_fp(&message.0, &identity_secret.0, &peer_public_key.0, &beta_fp)?;
        Ok(Secp256k1Scalar(fp_to_fq(&r)))
    }

    fn prove_batch(
        statement: &EvrfStatement<Secp256k1GoldenGroup>,
        witness: &EvrfWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        witness.validate_shape(statement)?;
        let statement = batched_statement(statement)?;
        validate_batched_public_relations(&statement)?;
        let witness = BatchedEvrfWitness {
            sk1: witness.identity_secret.0,
            polynomial_constants: witness
                .dealings
                .iter()
                .map(|dealing| dealing.polynomial_constant.map(|constant| constant.0))
                .collect(),
        };
        let params = public_params(&statement)?;
        evrf_batched_prove(&params, &statement, &witness, rng)
    }

    fn verify_batch(statement: &EvrfStatement<Secp256k1GoldenGroup>, proof: &[u8]) -> Result<()> {
        let statement = batched_statement(statement)?;
        validate_batched_public_relations(&statement)?;
        parse_batched_proof_stream(&statement, proof)?;
        let params = public_params(&statement)?;
        evrf_batched_verify_many(&params, &[(&statement, proof)])
    }

    fn verify_proof_batch(batches: &[(&EvrfStatement<Secp256k1GoldenGroup>, &[u8])]) -> Result<()> {
        if batches.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        let statements = batches
            .iter()
            .map(|(statement, _)| batched_statement(statement))
            .collect::<Result<Vec<_>>>()?;
        let first = statements.first().ok_or(Error::ProofVerificationFailed)?;
        for (statement, (_, proof)) in statements.iter().zip(batches) {
            if !same_shape(first, statement) {
                return Err(Error::ProofVerificationFailed);
            }
            validate_batched_public_relations(statement)?;
            parse_batched_proof_stream(statement, proof)?;
        }
        let params = public_params(first)?;
        let instances = statements
            .iter()
            .zip(batches)
            .map(|(statement, (_, proof))| (statement, *proof))
            .collect::<Vec<_>>();
        evrf_batched_verify_many(&params, &instances)
    }
}

#[cfg(test)]
mod tests {
    use golden_core::{
        EvrfDealingStatement, EvrfReceiverStatement, FeldmanCommitment, GoldenGroup, GoldenScalar,
        ParticipantIndex,
    };

    use super::*;

    fn minimal_statement() -> EvrfStatement<Secp256k1GoldenGroup> {
        let receiver = ParticipantIndex::new(2).unwrap();
        let dealer_secret = Secp256k1Scalar::from_u64(3).unwrap();
        let receiver_secret = Secp256k1Scalar::from_u64(5).unwrap();
        let share = Secp256k1Scalar::from_u64(13).unwrap();
        let pad = Secp256k1Scalar::from_u64(7).unwrap();

        EvrfStatement {
            dealer_public_key: Secp256k1GoldenGroup::mul_generator(&dealer_secret),
            beta: Secp256k1Scalar::from_u64(17).unwrap(),
            dealer_message_root: [3u8; 32],
            dealings: vec![EvrfDealingStatement {
                message: EvrfMessage([9u8; MESSAGE_BYTES]),
                commitment: FeldmanCommitment::from_coefficients(vec![
                    Secp256k1GoldenGroup::mul_generator(&share),
                ])
                .unwrap(),
                receivers: vec![EvrfReceiverStatement {
                    receiver,
                    receiver_public_key: Secp256k1GoldenGroup::mul_generator(&receiver_secret),
                    share_commitment: Secp256k1GoldenGroup::mul_generator(&share),
                    pad_commitment: Secp256k1GoldenGroup::mul_generator(&pad),
                    encrypted_share: Secp256k1Scalar::add(&share, &pad),
                }],
            }],
        }
    }

    fn public_params_requests() -> usize {
        PUBLIC_PARAMS_REQUESTS.with(core::cell::Cell::get)
    }

    #[test]
    fn malformed_proof_is_rejected_before_public_parameter_lookup() {
        let statement = minimal_statement();
        let before = public_params_requests();

        assert_eq!(
            SecpSecqBackend::verify_batch(&statement, &[]).unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(public_params_requests(), before);
    }

    #[test]
    fn oversized_repeated_receiver_shape_is_rejected_before_conversion_or_params() {
        let mut statement = minimal_statement();
        let receiver = statement.dealings[0].receivers[0].clone();
        statement.dealings[0].receivers = vec![receiver; 295];
        let before = public_params_requests();

        assert_eq!(
            SecpSecqBackend::verify_batch(&statement, &[]).unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(public_params_requests(), before);
    }
}
