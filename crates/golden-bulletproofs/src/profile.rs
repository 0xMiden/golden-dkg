//! Reproducible, opt-in full dealer proof comparison. Run each case in its own
//! process under the platform's peak-RSS meter; timings are single observations.
use super::*;
use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
use golden_core::{
    deal, DealerProofSystem, DkgInstanceKind, ParticipantIndex, ParticipantRegistry, SessionId,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct Sample {
    witness: Duration,
    proving: Duration,
    verification: Duration,
    proof_bytes: usize,
    phase_one: usize,
}
struct Profile<C: Backend> {
    prepared: Prepared<C>,
    ladder: bool,
    sample: Mutex<Option<Sample>>,
}
fn build<C: Backend, CS: RandomizableConstraintSystem<C>>(
    cs: &mut CS,
    statement: &DealerProofStatement<C::Dkg>,
    slots: &[Slot<C::Dkg>],
    secret: Option<&<C::Dkg as DkgGroup>::Scalar>,
    ladder: bool,
) -> Result<()> {
    if ladder {
        C::build_ladder(
            cs,
            statement.dealer_public_key(),
            slots,
            secret,
            main_golden::beta::<C::Dkg>()?,
        )
    } else {
        C::build(
            cs,
            statement.dealer_public_key(),
            slots,
            secret,
            main_golden::beta::<C::Dkg>()?,
        )
    }
}
impl<C: Backend> DealerProofSystem<C::Dkg> for Profile<C> {
    fn prove(
        &self,
        config: &DkgConfig<C::Dkg>,
        statement: &DealerProofStatement<C::Dkg>,
        witness: &DealerProofWitness<C::Dkg>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let start = Instant::now();
        let layout = self.prepared.check_capacity(config)?;
        main_golden::check_dealer_relation(config, statement, witness)?;
        let slots = slots::<C>(config, statement)?;
        let (pc, bp) = self
            .prepared
            .generators
            .as_ref()
            .ok_or(Error::ProofOperationFailed)?;
        let mut transcript = transcript::<C>(config, statement);
        let mut prover = Prover::<C, _>::new(pc, &mut transcript);
        build::<C, _>(
            &mut prover,
            statement,
            &slots,
            Some(witness.identity_secret()),
            self.ladder,
        )?;
        if prover.metrics().multipliers != layout.phase_one {
            return Err(Error::ProofOperationFailed);
        }
        let witness_time = start.elapsed();
        let phase_one = prover.metrics().multipliers;
        let start = Instant::now();
        let r1cs = prover
            .prove(bp, rng)
            .map_err(|_| Error::ProofGenerationFailed)?
            .to_bytes();
        transcript.append_message(b"r1cs-proof", &r1cs);
        let mut bytes = Vec::new();
        frame(&mut bytes, C::PROOF_ID)?;
        frame(&mut bytes, &r1cs)?;
        prove_constants::<C::Dkg>(&mut transcript, statement, witness, rng, &mut bytes)?;
        let proving = start.elapsed();
        let start = Instant::now();
        self.verify(config, statement, &bytes)?;
        let verification = start.elapsed();
        *self
            .sample
            .lock()
            .map_err(|_| Error::ProofOperationFailed)? = Some(Sample {
            witness: witness_time,
            proving,
            verification,
            proof_bytes: bytes.len(),
            phase_one,
        });
        Ok(bytes)
    }
    fn verify(
        &self,
        config: &DkgConfig<C::Dkg>,
        statement: &DealerProofStatement<C::Dkg>,
        proof: &[u8],
    ) -> Result<()> {
        let layout = self.prepared.check_capacity(config)?;
        let refs = [DealerProofRef { statement, proof }];
        let seed = batch_seed::<C>(config, &refs)?;
        let mut reader = Reader::new(proof);
        if reader.framed()? != C::PROOF_ID {
            return Err(Error::InvalidProof);
        }
        let payload = reader.framed()?;
        if payload.first() != Some(&u8::from(!self.ladder)) {
            return Err(Error::InvalidProof);
        }
        let proof = R1CSProof::<C>::from_bytes(payload).map_err(|_| Error::InvalidProof)?;
        let slots = slots::<C>(config, statement)?;
        let (pc, bp) = self
            .prepared
            .generators
            .as_ref()
            .ok_or(Error::ProofOperationFailed)?;
        let mut transcript = transcript::<C>(config, statement);
        let mut verifier = Verifier::<C, _>::new(&mut transcript);
        build::<C, _>(&mut verifier, statement, &slots, None, self.ladder)?;
        if verifier.metrics().multipliers != layout.phase_one || proof.to_bytes() != payload {
            return Err(Error::ProofOperationFailed);
        }
        let mut rng = per_proof_rng(&seed, 0)?;
        verifier
            .verify(&proof, pc, bp, &mut rng)
            .map_err(|_| Error::InvalidProof)?;
        transcript.append_message(b"r1cs-proof", payload);
        verify_constants::<C::Dkg>(&mut transcript, statement, &mut reader)
    }
}

fn profile<C: Backend>() {
    let n = std::env::var("GOLDEN_PROFILE_N")
        .unwrap_or_else(|_| "3".into())
        .parse::<u32>()
        .unwrap();
    let threshold = std::env::var("GOLDEN_PROFILE_T")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(n.min(2) as usize);
    assert!((2..=10).contains(&n));
    let ladder = std::env::var("GOLDEN_PROFILE_ENGINE").is_ok_and(|v| v == "ladder");
    let entries = (1..=n)
        .map(|i| {
            (
                ParticipantIndex::new(i).unwrap(),
                <C::Dkg as DkgGroup>::mul_generator(&<C::Dkg as DkgGroup>::Scalar::from(
                    u64::from(i) + 10,
                )),
            )
        })
        .collect();
    let config = DkgConfig::new(
        threshold,
        SessionId([72; 32]),
        ParticipantRegistry::<C::Dkg>::new(entries).unwrap(),
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
    .unwrap();
    let start = Instant::now();
    let layout = if ladder {
        let generator = <C::Dkg as DkgGroup>::Point::generator();
        let data = (0..2)
            .flat_map(|_| {
                (0..n - 1).map(|i| Slot::<C::Dkg> {
                    peer: generator * <C::Dkg as DkgGroup>::Scalar::from(u64::from(i) + 2),
                    h1: generator,
                    h2: generator,
                    pad: generator,
                })
            })
            .collect::<Vec<_>>();
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"profile-layout"));
        C::build_ladder(&mut verifier, &generator, &data, None, C::Scalar::ONE).unwrap();
        shape::Layout {
            phase_one: verifier.metrics().multipliers,
            total: verifier.metrics().multipliers,
        }
    } else {
        shape::layout::<C>((n - 1) as usize, 2).unwrap()
    };
    let total = layout.total;
    let capacity = total.next_power_of_two();
    let prepared = Prepared {
        capacity,
        layout: std::sync::OnceLock::from((shape::Shape::of(&config), layout)),
        generators: Some((PedersenGens::default(), BulletproofGens::new(capacity, 1))),
    };
    let preparation = start.elapsed();
    let proofs = Profile::<C> {
        prepared,
        ladder,
        sample: Mutex::new(None),
    };
    let mut rng = ChaCha20Rng::from_seed([73; 32]);
    let start = Instant::now();
    let dealing = deal(
        &proofs,
        &config,
        ParticipantIndex::new(1).unwrap(),
        &<C::Dkg as DkgGroup>::Scalar::from(11),
        &mut rng,
    )
    .unwrap();
    let deal_and_check = start.elapsed();
    let Sample {
        witness,
        proving,
        verification,
        proof_bytes,
        phase_one,
    } = proofs.sample.lock().unwrap().unwrap();
    println!("PROFILE,curve={},engine={},n={},t={},slots={},phase_one={},capacity={},proof_bytes={},preparation_ms={:.3},witness_build_ms={:.3},proving_ms={:.3},verification_ms={:.3},deal_and_check_ms={:.3},broadcast_bytes={}",
        C::CYCLE_ID, if ladder { "ladder" } else { "ecip" }, n, threshold, total, phase_one, capacity, proof_bytes,
        preparation.as_secs_f64()*1000., witness.as_secs_f64()*1000., proving.as_secs_f64()*1000., verification.as_secs_f64()*1000., deal_and_check.as_secs_f64()*1000., dealing.broadcast_bytes().len());
}
#[cfg(feature = "secp-secq")]
#[test]
#[ignore = "full proof performance observation; run one case per process"]
fn profile_secp() {
    profile::<crate::outer::secp::SecqCycle>();
}
#[cfg(feature = "jubjub-bls12-381")]
#[test]
#[ignore = "full proof performance observation; run one case per process"]
fn profile_jubjub() {
    profile::<crate::outer::cycle::Bls12_381G1Cycle>();
}
