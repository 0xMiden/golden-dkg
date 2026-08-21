//! Insecure dealer-proof implementation that reveals the complete witness.
//!
//! This proof system exists only to exercise Golden DKG orchestration against
//! the exact native Main Golden relation. Its proof bytes disclose the dealer
//! identity secret, every Random polynomial constant, and every receiver share
//! and pad. It must never be used where witness privacy is required.

use golden_core::main_golden::{check_dealer_relation, reconstruct_revealed_witness};
use golden_core::{
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgInstanceKind, Error,
    GoldenCurve, GoldenScalar, Result, TranscriptBuilder, TranscriptRoot,
};
use rand_core::CryptoRngCore;

const PROOF_HEADER: &[u8] = b"golden-dkg/insecure-revealed-witness/v1";
const CONTEXT_ROOT_BYTES: usize = 32;

/// A deliberately insecure dealer-proof system that serializes the witness.
///
/// This is test infrastructure. The type is available only when the explicit
/// non-default `insecure-revealed-witness` feature is enabled. Its proof bytes
/// reveal every secret needed to check the dealer relation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InsecureRevealedWitnessProof;

impl<G: GoldenCurve> DealerProofSystem<G> for InsecureRevealedWitnessProof {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        check_dealer_relation(config, statement, witness)
            .map_err(|_| Error::ProofGenerationFailed)?;

        let proof_len = proof_len::<G>(config, statement).ok_or(Error::ProofGenerationFailed)?;
        let context_root =
            statement_context_root(config, statement).map_err(|_| Error::ProofGenerationFailed)?;
        let mut proof = Vec::new();
        proof
            .try_reserve_exact(proof_len)
            .map_err(|_| Error::ProofGenerationFailed)?;
        proof.extend_from_slice(PROOF_HEADER);
        proof.extend_from_slice(&context_root);
        append_scalar(&mut proof, witness.identity_secret());

        for (position, kind) in config.instances().iter().enumerate() {
            let instance = witness
                .instance(position)
                .ok_or(Error::ProofGenerationFailed)?;
            match kind {
                DkgInstanceKind::Random => append_scalar(
                    &mut proof,
                    instance
                        .polynomial_constant()
                        .ok_or(Error::ProofGenerationFailed)?,
                ),
                DkgInstanceKind::Zero => {
                    if instance.polynomial_constant().is_some() {
                        return Err(Error::ProofGenerationFailed);
                    }
                }
            }
        }

        for position in 0..witness.instance_count() {
            let instance = witness
                .instance(position)
                .ok_or(Error::ProofGenerationFailed)?;
            for receiver_position in 0..instance.receiver_count() {
                let receiver = instance
                    .receiver(receiver_position)
                    .ok_or(Error::ProofGenerationFailed)?;
                append_scalar(&mut proof, receiver.share());
                append_scalar(&mut proof, receiver.pad());
            }
        }

        if proof.len() != proof_len {
            return Err(Error::ProofGenerationFailed);
        }
        Ok(proof)
    }

    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        verify_revealed_witness(config, statement, proof)
            .map_err(|_| Error::ProofVerificationFailed)
    }
}

fn verify_revealed_witness<G: GoldenCurve>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    proof: &[u8],
) -> Result<()> {
    let expected_len = proof_len::<G>(config, statement).ok_or(Error::ProofVerificationFailed)?;
    if proof.len() != expected_len {
        return Err(Error::ProofVerificationFailed);
    }

    let expected_context = statement_context_root(config, statement)?;
    let mut reader = ProofReader::new(proof);
    if reader.read(PROOF_HEADER.len())? != PROOF_HEADER {
        return Err(Error::ProofVerificationFailed);
    }
    if reader.read(CONTEXT_ROOT_BYTES)? != expected_context.as_slice() {
        return Err(Error::ProofVerificationFailed);
    }

    let identity_secret = reader.scalar::<G::Scalar>()?;
    let mut polynomial_constants = Vec::new();
    polynomial_constants
        .try_reserve_exact(config.instances().len())
        .map_err(|_| Error::ProofVerificationFailed)?;
    for kind in config.instances() {
        polynomial_constants.push(match kind {
            DkgInstanceKind::Random => Some(reader.scalar::<G::Scalar>()?),
            DkgInstanceKind::Zero => None,
        });
    }

    let receiver_count = receiver_count(statement).ok_or(Error::ProofVerificationFailed)?;
    let mut receiver_openings = Vec::new();
    receiver_openings
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    for position in 0..statement.instance_count() {
        let instance = statement
            .instance(position)
            .ok_or(Error::ProofVerificationFailed)?;
        for _ in 0..instance.receiver_count() {
            let share = reader.scalar::<G::Scalar>()?;
            let pad = reader.scalar::<G::Scalar>()?;
            receiver_openings.push((share, pad));
        }
    }
    reader.finish()?;

    let witness = reconstruct_revealed_witness(
        config,
        statement,
        identity_secret,
        polynomial_constants,
        receiver_openings,
    )?;
    check_dealer_relation(config, statement, &witness)
}

fn statement_context_root<G: GoldenCurve>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
) -> Result<TranscriptRoot> {
    let mut transcript = TranscriptBuilder::with_prefix(PROOF_HEADER, b"statement-context");
    transcript.bytes(b"configuration-root", &config.root());
    transcript.participant(b"dealer", statement.dealer());
    transcript.element::<G>(b"dealer-public-key", statement.dealer_public_key());
    transcript.bytes(b"dealer-message-root", &statement.dealer_message_root());
    transcript.usize(b"instance-count", statement.instance_count());

    for position in 0..statement.instance_count() {
        let instance = statement
            .instance(position)
            .ok_or(Error::ProofVerificationFailed)?;
        transcript.usize(b"instance-position", position);
        transcript.bytes(b"effective-message", &instance.effective_message().0);
        transcript.usize(
            b"commitment-coefficient-count",
            instance.commitment_coefficients().len(),
        );
        for coefficient in instance.commitment_coefficients() {
            transcript.element::<G>(b"commitment-coefficient", coefficient);
        }
        transcript.usize(b"receiver-count", instance.receiver_count());
        for receiver_position in 0..instance.receiver_count() {
            let receiver = instance
                .receiver(receiver_position)
                .ok_or(Error::ProofVerificationFailed)?;
            transcript.usize(b"receiver-position", receiver_position);
            transcript.participant(b"receiver", receiver.participant());
            transcript.element::<G>(b"receiver-public-key", receiver.public_key());
            transcript.element::<G>(b"share-commitment", receiver.share_commitment());
            transcript.element::<G>(b"pad-commitment", receiver.pad_commitment());
            transcript.scalar::<G>(b"encrypted-share", receiver.encrypted_share());
        }
    }

    Ok(transcript.root())
}

fn proof_len<G: GoldenCurve>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
) -> Option<usize> {
    let random_constants = config
        .instances()
        .iter()
        .filter(|kind| matches!(kind, DkgInstanceKind::Random))
        .count();
    let receiver_scalars = receiver_count(statement)?.checked_mul(2)?;
    let scalar_count = 1usize
        .checked_add(random_constants)?
        .checked_add(receiver_scalars)?;
    let witness_bytes = scalar_count.checked_mul(G::Scalar::REPR_BYTES)?;
    PROOF_HEADER
        .len()
        .checked_add(CONTEXT_ROOT_BYTES)?
        .checked_add(witness_bytes)
}

fn receiver_count<G: GoldenCurve>(statement: &DealerProofStatement<G>) -> Option<usize> {
    let mut count = 0usize;
    for position in 0..statement.instance_count() {
        count = count.checked_add(statement.instance(position)?.receiver_count())?;
    }
    Some(count)
}

fn append_scalar<S: GoldenScalar>(output: &mut Vec<u8>, scalar: &S) {
    output.extend_from_slice(scalar.to_repr().as_ref());
}

struct ProofReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ProofReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::ProofVerificationFailed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::ProofVerificationFailed)?;
        self.position = end;
        Ok(bytes)
    }

    fn scalar<S: GoldenScalar>(&mut self) -> Result<S> {
        let bytes = self.read(S::REPR_BYTES)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(S::REPR_BYTES)
            .map_err(|_| Error::ProofVerificationFailed)?;
        encoded.extend_from_slice(bytes);
        let repr = S::Repr::try_from(encoded).map_err(|_| Error::ProofVerificationFailed)?;
        S::from_repr(&repr).map_err(|_| Error::ProofVerificationFailed)
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }
}
