//! Golden DKG adapter for the Secp/Secq paper eVRF.

use golden_core::{
    DealerMessageNonce, Error, EvrfProofBackend, EvrfStatement, EvrfWitness, Result,
};
use golden_halo2curves::golden_group::{
    scalar_to_r1cs_field, Secp256k1Element, Secp256k1GoldenGroup, Secp256k1Scalar,
};
use halo2curves::secp256k1::{Fp, Fq};
use rand_core::CryptoRngCore;

use super::{
    affine, evrf_batched_prove, evrf_batched_verify, fp_to_fq, h_gin_1, h_gin_2,
    BatchedEvrfStatement, BatchedEvrfWitness, BatchedReceiverStatement, Gin, GinScalar,
    BATCHED_PROOF_ID, MESSAGE_BYTES,
};

pub(super) fn ensure_same_batch_context(
    statement: &EvrfStatement<Secp256k1GoldenGroup>,
    first: &EvrfStatement<Secp256k1GoldenGroup>,
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

impl EvrfProofBackend<Secp256k1GoldenGroup> for SecpSecqBackend {
    const PROOF_ID: &'static [u8] = BATCHED_PROOF_ID;

    fn derive_pad(
        msg_i: DealerMessageNonce,
        beta: &Secp256k1Scalar,
        identity_secret: &Secp256k1Scalar,
        peer_public_key: &Secp256k1Element,
        _receiver_public_key: &Secp256k1Element,
    ) -> Result<Secp256k1Scalar> {
        let beta_fp = scalar_to_r1cs_field(beta).ok_or(Error::ProofVerificationFailed)?;
        let r = compute_pad_fp(&msg_i.0, &identity_secret.0, &peer_public_key.0, &beta_fp)?;
        Ok(Secp256k1Scalar(fp_to_fq(&r)))
    }

    fn prove_batch(
        statements: &[EvrfStatement<Secp256k1GoldenGroup>],
        witnesses: &[EvrfWitness<Secp256k1GoldenGroup>],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        if statements.is_empty() || statements.len() != witnesses.len() {
            return Err(Error::ProofVerificationFailed);
        }
        let first = &statements[0];
        let msg = first.msg_i.0;
        let pk1 = first.dealer_public_key.0;
        let beta = scalar_to_r1cs_field(&first.beta).ok_or(Error::ProofVerificationFailed)?;
        let threshold = first.threshold;
        let commitment_coefficients: Vec<Gin> = first
            .commitment_coefficients
            .iter()
            .map(|coefficient| coefficient.0)
            .collect();
        let sk1 = witnesses[0].identity_secret.0;

        let mut receivers = Vec::with_capacity(statements.len());
        let mut statement_roots = Vec::with_capacity(statements.len());
        let mut shares = Vec::with_capacity(witnesses.len());
        let coefficient_scalars: Vec<GinScalar> = witnesses[0]
            .polynomial_coefficients
            .iter()
            .map(|coefficient| coefficient.0)
            .collect();
        for (statement, witness) in statements.iter().zip(witnesses.iter()) {
            ensure_same_batch_context(statement, first)?;
            if witness.identity_secret.0 != sk1 {
                return Err(Error::ProofVerificationFailed);
            }
            if witness.polynomial_coefficients != witnesses[0].polynomial_coefficients {
                return Err(Error::ProofVerificationFailed);
            }
            let pkj = statement.receiver_public_key.0;
            let rec = BatchedReceiverStatement {
                receiver: statement.receiver,
                pkj,
                share_commitment: statement.share_commitment.0,
                pad_commitment: statement.pad_commitment.0,
                dh_commitment: statement.dh_commitment.0,
                encrypted_share: statement.encrypted_share.0,
            };
            statement_roots.push(statement.root());
            receivers.push(rec);
            shares.push(witness.share.0);
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
            coefficient_scalars,
            shares,
        };
        evrf_batched_prove(&batched_statement, &batched_witness, rng)
    }

    fn verify_batch(
        statements: &[EvrfStatement<Secp256k1GoldenGroup>],
        proof: &[u8],
    ) -> Result<()> {
        if statements.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        let first = &statements[0];
        let msg = first.msg_i.0;
        let pk1 = first.dealer_public_key.0;
        let beta = scalar_to_r1cs_field(&first.beta).ok_or(Error::ProofVerificationFailed)?;
        let threshold = first.threshold;
        let commitment_coefficients: Vec<Gin> = first
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
                dh_commitment: statement.dh_commitment.0,
                encrypted_share: statement.encrypted_share.0,
            });
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
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
        evrf_batched_verify(&batched_statement, proof, &mut rng)
    }
}
