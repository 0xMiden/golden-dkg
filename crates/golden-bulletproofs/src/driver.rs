//! Shared immutable preparation, framing and proof composition.
use bulletproofs_cycle::{r1cs::RandomizableConstraintSystem, ConstraintSystem, Cycle};
use golden_core::{DkgGroup, Result};

pub(crate) struct Slot<G: DkgGroup> {
    pub peer: G::Point,
    pub h1: G::Point,
    pub h2: G::Point,
    pub pad: G::Point,
}

pub(crate) trait Backend: Cycle {
    type Dkg: DkgGroup<BaseField = Self::Scalar>;
    const PROOF_ID: &'static [u8];
    const CIRCUIT_COSTS: crate::shape::CircuitCosts;
    const CYCLE_ID: &'static str;
    fn build<CS: RandomizableConstraintSystem<Self>>(
        cs: &mut CS,
        pk: &<Self::Dkg as DkgGroup>::Point,
        slots: &[Slot<Self::Dkg>],
        secret: Option<&<Self::Dkg as DkgGroup>::Scalar>,
        beta: Self::Scalar,
    ) -> Result<()>;
    #[cfg(test)]
    fn build_ladder<CS: ConstraintSystem<Self>>(
        cs: &mut CS,
        pk: &<Self::Dkg as DkgGroup>::Point,
        slots: &[Slot<Self::Dkg>],
        secret: Option<&<Self::Dkg as DkgGroup>::Scalar>,
        beta: Self::Scalar,
    ) -> Result<()>;
}

use crate::prepared::Prepared;
#[cfg(test)]
use crate::shape;
use bulletproofs_cycle::{
    r1cs::{Prover, Verifier},
    R1CSError, R1CSProof, VerificationEquation,
};
use ff::{Field, PrimeField};
use golden_core::wire::{framed as frame, Reader};
use golden_core::{
    main_golden, DealerProofRef, DealerProofStatement, DealerProofWitness, DkgConfig,
    DkgInstanceKind, Error, PROTOCOL_VERSION,
};
use group::Group;
use merlin::Transcript;
use p3_maybe_rayon::prelude::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::CryptoRngCore;

fn slots<C: Backend>(
    config: &DkgConfig<C::Dkg>,
    statement: &DealerProofStatement<C::Dkg>,
) -> Result<Vec<Slot<C::Dkg>>> {
    if statement.config_root() != config.root()
        || config.identity_public_key(statement.dealer()) != Some(statement.dealer_public_key())
        || statement.instance_count() != config.instances().len()
    {
        return Err(Error::InvalidProof);
    }
    let count = statement
        .instance_count()
        .checked_mul(
            config
                .registry()
                .len()
                .checked_sub(1)
                .ok_or(Error::InvalidProof)?,
        )
        .ok_or(Error::ProofOperationFailed)?;
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| Error::ProofOperationFailed)?;
    for instance in statement.instances() {
        if config.instance(instance.position()) != Some(instance.kind())
            || instance.receiver_count() != config.registry().len() - 1
        {
            return Err(Error::InvalidProof);
        }
        for receiver in instance.receivers() {
            slots.push(Slot {
                peer: *receiver.public_key(),
                h1: main_golden::h1::<C::Dkg>(
                    instance.effective_message(),
                    statement.dealer_public_key(),
                    receiver.public_key(),
                )
                .map_err(|_| Error::InvalidProof)?,
                h2: main_golden::h2::<C::Dkg>(
                    instance.effective_message(),
                    statement.dealer_public_key(),
                    receiver.public_key(),
                )
                .map_err(|_| Error::InvalidProof)?,
                pad: *receiver.pad_commitment(),
            });
        }
    }
    Ok(slots)
}
fn transcript<C: Backend>(
    config: &DkgConfig<C::Dkg>,
    statement: &DealerProofStatement<C::Dkg>,
) -> Transcript {
    let mut transcript = Transcript::new(C::PROOF_ID);
    transcript.append_message(b"protocol-version", &PROTOCOL_VERSION.to_be_bytes());
    transcript.append_message(b"configuration", config.canonical_bytes());
    transcript.append_message(b"statement", statement.logical_bytes());
    transcript
}
fn challenge<F: PrimeField>(transcript: &mut Transcript, label: &'static [u8]) -> F {
    let mut bytes = [0u8; 64];
    transcript.challenge_bytes(label, &mut bytes);
    bytes.iter().rev().fold(F::ZERO, |value, &byte| {
        value * F::from(256) + F::from(u64::from(byte))
    })
}
fn append_constant_context(transcript: &mut Transcript, position: usize) -> Result<()> {
    let position = u32::try_from(position).map_err(|_| Error::ProofOperationFailed)?;
    transcript.append_message(b"constant-instance", &position.to_be_bytes());
    Ok(())
}
#[derive(Clone, Copy)]
struct Nonce<F: PrimeField>(F);
impl<F: PrimeField> Default for Nonce<F> {
    fn default() -> Self {
        Self(F::ZERO)
    }
}
impl<F: PrimeField> zeroize::DefaultIsZeroes for Nonce<F> {}

fn prove_constants<G: DkgGroup>(
    transcript: &mut Transcript,
    statement: &DealerProofStatement<G>,
    witness: &DealerProofWitness<G>,
    rng: &mut impl CryptoRngCore,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    for instance in statement.instances() {
        if instance.kind() != DkgInstanceKind::Random {
            continue;
        }
        append_constant_context(transcript, instance.position())?;
        let private = witness
            .instance(instance.position())
            .ok_or(Error::ProofGenerationFailed)?;
        let constant = private
            .polynomial_constant()
            .ok_or(Error::ProofGenerationFailed)?;
        let mut nonce = zeroize::Zeroizing::new(Nonce::<G::Scalar>::default());
        loop {
            nonce.0 = G::Scalar::random(&mut *rng);
            if !bool::from(nonce.0.is_zero()) {
                break;
            }
        }
        let commitment = G::encode_point(&G::mul_generator(&nonce.0));
        transcript.append_message(b"constant-nonce", &commitment);
        bytes.extend_from_slice(&commitment);
        let challenge = challenge::<G::Scalar>(transcript, b"constant-challenge");
        let response = G::encode_scalar(&(nonce.0 + challenge * constant));
        transcript.append_message(b"constant-response", &response);
        bytes.extend_from_slice(&response);
    }
    Ok(())
}
fn verify_constants<G: DkgGroup>(
    transcript: &mut Transcript,
    statement: &DealerProofStatement<G>,
    reader: &mut Reader<'_>,
) -> Result<()> {
    for instance in statement.instances() {
        if instance.kind() != DkgInstanceKind::Random {
            continue;
        }
        append_constant_context(transcript, instance.position())?;
        let encoded = reader
            .take(G::POINT_BYTES)
            .map_err(|_| Error::InvalidProof)?;
        let nonce = G::decode_point(encoded).map_err(|_| Error::InvalidProof)?;
        if bool::from(nonce.is_identity()) {
            return Err(Error::InvalidProof);
        }
        transcript.append_message(b"constant-nonce", encoded);
        let challenge = challenge::<G::Scalar>(transcript, b"constant-challenge");
        let encoded = reader.take(32).map_err(|_| Error::InvalidProof)?;
        let response = G::decode_scalar(encoded).map_err(|_| Error::InvalidProof)?;
        transcript.append_message(b"constant-response", encoded);
        let constant = instance
            .commitment_coefficients()
            .first()
            .ok_or(Error::InvalidProof)?;
        if G::mul_generator(&response) != nonce + *constant * challenge {
            return Err(Error::InvalidProof);
        }
    }
    if reader.remaining() != 0 {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

pub(crate) fn prove<C: Backend>(
    prepared: &Prepared<C>,
    config: &DkgConfig<C::Dkg>,
    statement: &DealerProofStatement<C::Dkg>,
    witness: &DealerProofWitness<C::Dkg>,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let layout = prepared.check_capacity(config)?;
    main_golden::check_dealer_relation(config, statement, witness)
        .map_err(|_| Error::ProofGenerationFailed)?;
    if config.registry().len() == 1 {
        return Ok(Vec::new());
    }
    let slots = slots::<C>(config, statement)?;
    let (pc, bp) = prepared
        .generators
        .as_ref()
        .ok_or(Error::ProofOperationFailed)?;
    let mut transcript = transcript::<C>(config, statement);
    let mut prover = Prover::<C, _>::new(pc, &mut transcript);
    C::build(
        &mut prover,
        statement.dealer_public_key(),
        &slots,
        Some(witness.identity_secret()),
        main_golden::beta::<C::Dkg>()?,
    )
    .map_err(|_| Error::ProofGenerationFailed)?;
    if prover.metrics().multipliers != layout.phase_one {
        return Err(Error::ProofOperationFailed);
    }
    let r1cs = prover
        .prove(bp, rng)
        .map_err(|_| Error::ProofGenerationFailed)?
        .to_bytes();
    transcript.append_message(b"r1cs-proof", &r1cs);
    let mut bytes = Vec::new();
    frame(&mut bytes, C::PROOF_ID)?;
    frame(&mut bytes, &r1cs)?;
    prove_constants::<C::Dkg>(&mut transcript, statement, witness, rng, &mut bytes)?;
    Ok(bytes)
}
fn prepare_equation<C: Backend>(
    prepared: &Prepared<C>,
    config: &DkgConfig<C::Dkg>,
    statement: &DealerProofStatement<C::Dkg>,
    proof: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<VerificationEquation<C>> {
    let layout = prepared.check_capacity(config)?;
    let mut reader = Reader::new(proof);
    if reader.framed().map_err(|_| Error::InvalidProof)? != C::PROOF_ID {
        return Err(Error::InvalidProof);
    }
    let payload = reader.framed().map_err(|_| Error::InvalidProof)?;
    if payload.first() != Some(&1) {
        return Err(Error::InvalidProof);
    }
    let parsed = R1CSProof::<C>::from_bytes(payload).map_err(|_| Error::InvalidProof)?;
    if parsed.to_bytes() != payload {
        return Err(Error::InvalidProof);
    }
    let slots = slots::<C>(config, statement)?;
    let (pc, bp) = prepared
        .generators
        .as_ref()
        .ok_or(Error::ProofOperationFailed)?;
    let mut transcript = transcript::<C>(config, statement);
    let mut verifier = Verifier::<C, _>::new(&mut transcript);
    C::build(
        &mut verifier,
        statement.dealer_public_key(),
        &slots,
        None,
        main_golden::beta::<C::Dkg>()?,
    )?;
    if verifier.metrics().multipliers != layout.phase_one {
        return Err(Error::ProofOperationFailed);
    }
    let equation = verifier
        .verification_equation(&parsed, pc, bp, rng)
        .map_err(|_| Error::InvalidProof)?;
    transcript.append_message(b"r1cs-proof", payload);
    verify_constants::<C::Dkg>(&mut transcript, statement, &mut reader)?;
    Ok(equation)
}
fn batch_seed<C: Backend>(
    config: &DkgConfig<C::Dkg>,
    proofs: &[DealerProofRef<'_, C::Dkg>],
) -> Result<[u8; 32]> {
    let mut transcript = Transcript::new(b"golden-dkg/dealer-proof-batch/v1");
    transcript.append_message(b"protocol-version", &PROTOCOL_VERSION.to_be_bytes());
    transcript.append_message(b"proof-family", C::PROOF_ID);
    transcript.append_message(b"configuration", config.canonical_bytes());
    transcript.append_message(
        b"batch-length",
        &u32::try_from(proofs.len())
            .map_err(|_| Error::ProofOperationFailed)?
            .to_be_bytes(),
    );
    for item in proofs {
        transcript.append_message(b"dealer", &item.statement.dealer().get().to_be_bytes());
        transcript.append_message(b"statement", item.statement.logical_bytes());
        transcript.append_message(
            b"proof-length",
            &u64::try_from(item.proof.len())
                .map_err(|_| Error::ProofOperationFailed)?
                .to_be_bytes(),
        );
        transcript.append_message(b"proof", item.proof);
    }
    let mut seed = [0u8; 32];
    transcript.challenge_bytes(b"batch-seed", &mut seed);
    Ok(seed)
}
fn per_proof_rng(seed: &[u8; 32], position: usize) -> Result<ChaCha20Rng> {
    let mut transcript = Transcript::new(b"golden-dkg/dealer-proof-rng/v1");
    transcript.append_message(b"batch-seed", seed);
    transcript.append_message(
        b"proof-position",
        &u32::try_from(position)
            .map_err(|_| Error::ProofOperationFailed)?
            .to_be_bytes(),
    );
    let mut seed = [0u8; 32];
    transcript.challenge_bytes(b"proof-seed", &mut seed);
    Ok(ChaCha20Rng::from_seed(seed))
}
pub(crate) fn verify<C: Backend>(
    prepared: &Prepared<C>,
    config: &DkgConfig<C::Dkg>,
    statement: &DealerProofStatement<C::Dkg>,
    proof: &[u8],
) -> Result<()> {
    prepared.check_capacity(config)?;
    if config.registry().len() == 1 {
        if statement.config_root() != config.root()
            || config.identity_public_key(statement.dealer()) != Some(statement.dealer_public_key())
        {
            return Err(Error::InvalidProof);
        }
        return if proof.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        };
    }
    let refs = [DealerProofRef { statement, proof }];
    let seed = batch_seed::<C>(config, &refs)?;
    prepare_equation::<C>(
        prepared,
        config,
        statement,
        proof,
        &mut per_proof_rng(&seed, 0)?,
    )?
    .verify()
    .map_err(|_| Error::InvalidProof)
}
pub(crate) fn verify_batch<C: Backend>(
    prepared: &Prepared<C>,
    config: &DkgConfig<C::Dkg>,
    proofs: &[DealerProofRef<'_, C::Dkg>],
) -> Result<()> {
    prepared.check_capacity(config)?;
    if proofs.is_empty() {
        return Ok(());
    }
    if config.registry().len() == 1 {
        return if proofs.iter().all(|item| {
            item.proof.is_empty()
                && item.statement.config_root() == config.root()
                && config.identity_public_key(item.statement.dealer())
                    == Some(item.statement.dealer_public_key())
        }) {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        };
    }
    let seed = batch_seed::<C>(config, proofs)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    // Prepare at most one equation per worker before folding shared generator
    // scalars. The complete ordered batch is already bound above; absolute
    // indices keep each proof's entropy independent of worker scheduling.
    let chunk_size = current_num_threads().max(1);
    let results = proofs
        .chunks(chunk_size)
        .enumerate()
        .flat_map(|(chunk_index, chunk)| {
            chunk
                .par_iter()
                .enumerate()
                .map(|(offset, item)| {
                    let index = chunk_index * chunk_size + offset;
                    per_proof_rng(&seed, index).and_then(|mut rng| {
                        prepare_equation::<C>(
                            prepared,
                            config,
                            item.statement,
                            item.proof,
                            &mut rng,
                        )
                    })
                })
                .collect::<Vec<_>>()
        });
    let mut operational = None;
    let equations = results.map(|result| match result {
        Ok(equation) => Ok(equation),
        Err(Error::InvalidProof) => Err(R1CSError::VerificationError),
        Err(error) => {
            operational = Some(error);
            Err(R1CSError::VerificationError)
        }
    });
    let verdict = VerificationEquation::<C>::verify_batch_iter(equations, &mut rng);
    if let Some(error) = operational {
        return Err(error);
    }
    verdict.map_err(|_| Error::InvalidProof)
}

#[cfg(test)]
#[path = "profile.rs"]
mod profile;
