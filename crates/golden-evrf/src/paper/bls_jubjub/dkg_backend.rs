//! Golden DKG adapter for the BLS12-381/Jubjub paper eVRF.

use golden_bls_jubjub::golden_group::{JubjubElement, JubjubGoldenGroup, JubjubScalar};
use golden_core::{
    DealerMessageNonce, Error, EvrfProofBackend, EvrfStatement, EvrfWitness, Result,
};
use rand_core::CryptoRngCore;

use super::{
    affine, evrf_batched_prove, evrf_batched_verify_many, fp_to_fr, fr_to_fp, h_gin_1, h_gin_2,
    validate_batched_statement_shape, BatchedEvrfPublicParams, BatchedEvrfStatement,
    BatchedEvrfWitness, BatchedReceiverStatement, Gin, R1csField, BATCHED_PROOF_ID, MESSAGE_BYTES,
};

pub(super) fn ensure_same_batch_context(
    statement: &EvrfStatement<JubjubGoldenGroup>,
    first: &EvrfStatement<JubjubGoldenGroup>,
) -> Result<()> {
    if statement.protocol_version != first.protocol_version
        || statement.backend_id != first.backend_id
        || statement.session_id != first.session_id
        || statement.registry_root != first.registry_root
        || statement.threshold != first.threshold
        || statement.dealer != first.dealer
        || statement.msg_i != first.msg_i
        || statement.beta != first.beta
        || statement.dealer_public_key != first.dealer_public_key
        || statement.commitment_coefficients != first.commitment_coefficients
        || statement.transcript_root != first.transcript_root
    {
        return Err(Error::ProofVerificationFailed);
    }

    Ok(())
}

/// Compute the paper eVRF pad `r = beta * T_1.u + T_2.u` as an `R1csField`
/// element, where `T_1 = H_{G_in,1}(msg)^k`, `T_2 = H_{G_in,2}(msg)^k`, and
/// `k = int(S.u)` for `S = PK_j^sk_1`.
fn compute_pad_fp(
    msg: &[u8; MESSAGE_BYTES],
    sk1: &super::GinScalar,
    pkj: &Gin,
    beta: &R1csField,
) -> Result<R1csField> {
    let sj = *pkj * sk1;
    let (s_u, _) = affine(&sj)?;
    let k_fr = fp_to_fr(&s_u);
    let h1 = h_gin_1(msg);
    let h2 = h_gin_2(msg);
    let t1j = h1 * k_fr;
    let t2j = h2 * k_fr;
    let (t1_u, _) = affine(&t1j)?;
    let (t2_u, _) = affine(&t2j)?;
    Ok(*beta * t1_u + t2_u)
}

/// Concrete BLS12-381/Jubjub paper eVRF backend for the DKG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsJubjubBackend;

fn batched_statement(
    statements: &[EvrfStatement<JubjubGoldenGroup>],
) -> Result<BatchedEvrfStatement> {
    let first = statements.first().ok_or(Error::ProofVerificationFailed)?;
    let beta = fr_to_fp(&first.beta.0);
    let commitment_coefficients = first
        .commitment_coefficients
        .iter()
        .map(|coefficient| coefficient.0)
        .collect();

    let mut receivers = Vec::with_capacity(statements.len());
    let mut statement_roots = Vec::with_capacity(statements.len());
    for statement in statements {
        ensure_same_batch_context(statement, first)?;
        statement_roots.push(statement.root());
        receivers.push(BatchedReceiverStatement {
            receiver: statement.receiver,
            pkj: statement.receiver_public_key.0,
            share_commitment: statement.share_commitment.0,
            pad_commitment: statement.pad_commitment.0,
            encrypted_share: statement.encrypted_share.0,
        });
    }

    Ok(BatchedEvrfStatement {
        msg: first.msg_i.0,
        pk1: first.dealer_public_key.0,
        beta,
        threshold: first.threshold,
        commitment_coefficients,
        statement_roots,
        receivers,
    })
}

impl EvrfProofBackend<JubjubGoldenGroup> for BlsJubjubBackend {
    const PROOF_ID: &'static [u8] = BATCHED_PROOF_ID;

    fn derive_pad(
        msg_i: DealerMessageNonce,
        beta: &JubjubScalar,
        identity_secret: &JubjubScalar,
        peer_public_key: &JubjubElement,
        _receiver_public_key: &JubjubElement,
    ) -> Result<JubjubScalar> {
        let beta_fp = fr_to_fp(&beta.0);
        let r = compute_pad_fp(&msg_i.0, &identity_secret.0, &peer_public_key.0, &beta_fp)?;
        Ok(JubjubScalar(fp_to_fr(&r)))
    }

    fn prove_batch(
        statements: &[EvrfStatement<JubjubGoldenGroup>],
        witnesses: &[EvrfWitness<JubjubGoldenGroup>],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        if statements.is_empty() || statements.len() != witnesses.len() {
            return Err(Error::ProofVerificationFailed);
        }
        let first = &statements[0];
        let msg = first.msg_i.0;
        let pk1 = first.dealer_public_key.0;
        let beta = fr_to_fp(&first.beta.0);
        let threshold = first.threshold;
        let commitment_coefficients: Vec<Gin> = first
            .commitment_coefficients
            .iter()
            .map(|coefficient| coefficient.0)
            .collect();
        let sk1 = witnesses[0].identity_secret.0;
        let polynomial_coefficients = &witnesses[0].polynomial_coefficients;
        if polynomial_coefficients.len() != threshold {
            return Err(Error::ProofVerificationFailed);
        }
        let polynomial_constant = polynomial_coefficients
            .first()
            .ok_or(Error::ProofVerificationFailed)?
            .0;

        let mut receivers = Vec::with_capacity(statements.len());
        let mut statement_roots = Vec::with_capacity(statements.len());
        for (statement, witness) in statements.iter().zip(witnesses.iter()) {
            ensure_same_batch_context(statement, first)?;
            if witness.identity_secret.0 != sk1
                || witness.polynomial_coefficients.as_slice() != polynomial_coefficients.as_slice()
            {
                return Err(Error::ProofVerificationFailed);
            }

            let pkj = statement.receiver_public_key.0;
            let rec = BatchedReceiverStatement {
                receiver: statement.receiver,
                pkj,
                share_commitment: statement.share_commitment.0,
                pad_commitment: statement.pad_commitment.0,
                encrypted_share: statement.encrypted_share.0,
            };
            statement_roots.push(statement.root());
            receivers.push(rec);
        }

        let batched_statement = BatchedEvrfStatement {
            msg,
            pk1,
            beta,
            threshold,
            commitment_coefficients,
            statement_roots,
            receivers,
        };
        let batched_witness = BatchedEvrfWitness {
            sk1,
            polynomial_constant,
        };
        validate_batched_statement_shape(&batched_statement)?;
        let params = BatchedEvrfPublicParams::shared(threshold, batched_statement.receivers.len())?;
        evrf_batched_prove(&params, &batched_statement, &batched_witness, rng)
    }

    fn verify_batch(statements: &[EvrfStatement<JubjubGoldenGroup>], proof: &[u8]) -> Result<()> {
        let statement = batched_statement(statements)?;
        validate_batched_statement_shape(&statement)?;
        let params =
            BatchedEvrfPublicParams::shared(statement.threshold, statement.receivers.len())?;
        evrf_batched_verify_many(&params, &[(&statement, proof)])
    }

    fn verify_proof_batch(batches: &[(&[EvrfStatement<JubjubGoldenGroup>], &[u8])]) -> Result<()> {
        if batches.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        let statements = batches
            .iter()
            .map(|(batch, _)| batched_statement(batch))
            .collect::<Result<Vec<_>>>()?;
        for statement in &statements {
            validate_batched_statement_shape(statement)?;
        }
        let first = statements.first().ok_or(Error::ProofVerificationFailed)?;
        let params = BatchedEvrfPublicParams::shared(first.threshold, first.receivers.len())?;
        let instances = statements
            .iter()
            .zip(batches.iter())
            .map(|(statement, (_, proof))| (statement, *proof))
            .collect::<Vec<_>>();
        evrf_batched_verify_many(&params, &instances)
    }
}
