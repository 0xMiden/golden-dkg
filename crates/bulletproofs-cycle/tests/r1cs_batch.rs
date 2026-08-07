//! Cross-proof R1CS batch verification over Ristretto.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "ristretto")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, VerificationEquation, Verifier,
    };
    use bulletproofs_cycle::ristretto_cycle::RistrettoCycle;
    use bulletproofs_cycle::{Cycle, R1CSError};
    use group::Group;
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type C = RistrettoCycle;
    type Scalar = <C as Cycle>::Scalar;

    struct MulProof {
        proof: R1CSProof<C>,
        commitments: [<C as Cycle>::Compressed; 3],
    }

    fn prove_mul(pc_gens: &PedersenGens<C>, bp_gens: &BulletproofGens<C>, seed: u64) -> MulProof {
        prove_mul_with_extra_gates(pc_gens, bp_gens, seed, 0)
    }

    fn prove_mul_with_extra_gates(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        seed: u64,
        extra_gates: usize,
    ) -> MulProof {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let a = random_scalar::<C>(&mut rng);
        let b = random_scalar::<C>(&mut rng);
        let c = a * b;
        let mut prover = Prover::<C, _>::new(pc_gens, Transcript::new(b"r1cs-batch-test"));
        let (V_a, var_a) = prover.commit(a, random_scalar::<C>(&mut rng));
        let (V_b, var_b) = prover.commit(b, random_scalar::<C>(&mut rng));
        let (V_c, var_c) = prover.commit(c, random_scalar::<C>(&mut rng));
        let (_, _, var_o) = prover.multiply(var_a.into(), var_b.into());
        prover.constrain(var_o - var_c);
        for _ in 0..extra_gates {
            let (_, _, one) = prover.multiply(Scalar::ONE.into(), Scalar::ONE.into());
            prover.constrain(LinearCombination::from(one) - Scalar::ONE);
        }
        let proof = prover.prove(bp_gens, &mut rng).unwrap();
        MulProof {
            proof,
            commitments: [V_a, V_b, V_c],
        }
    }

    fn verifier_for(commitments: &[<C as Cycle>::Compressed; 3]) -> Verifier<C, Transcript> {
        verifier_for_with_extra_gates(commitments, 0)
    }

    fn verifier_for_with_extra_gates(
        commitments: &[<C as Cycle>::Compressed; 3],
        extra_gates: usize,
    ) -> Verifier<C, Transcript> {
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"r1cs-batch-test"));
        let var_a = verifier.commit(commitments[0].clone());
        let var_b = verifier.commit(commitments[1].clone());
        let var_c = verifier.commit(commitments[2].clone());
        let (_, _, var_o) = verifier.multiply(var_a.into(), var_b.into());
        verifier.constrain(var_o - var_c);
        for _ in 0..extra_gates {
            let (_, _, one) = verifier.multiply(Scalar::ONE.into(), Scalar::ONE.into());
            verifier.constrain(LinearCombination::from(one) - Scalar::ONE);
        }
        verifier
    }

    fn prepare(
        commitments: &[<C as Cycle>::Compressed; 3],
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        seed: u64,
    ) -> Result<VerificationEquation<C>, R1CSError> {
        prepare_with_extra_gates(commitments, proof, pc_gens, bp_gens, seed, 0)
    }

    fn prepare_with_extra_gates(
        commitments: &[<C as Cycle>::Compressed; 3],
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        seed: u64,
        extra_gates: usize,
    ) -> Result<VerificationEquation<C>, R1CSError> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (equation, _) = verifier_for_with_extra_gates(commitments, extra_gates)
            .verification_equation_and_return_transcript(proof, pc_gens, bp_gens, &mut rng)?;
        Ok(equation)
    }

    #[test]
    fn prepared_equation_matches_single_verification() {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let item = prove_mul(&pc_gens, &bp_gens, 1);

        let mut rng = ChaCha20Rng::seed_from_u64(10);
        verifier_for(&item.commitments)
            .verify(&item.proof, &pc_gens, &bp_gens, &mut rng)
            .unwrap();
        prepare(&item.commitments, &item.proof, &pc_gens, &bp_gens, 10)
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn honest_equations_share_one_msm_in_either_order() {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let first = prove_mul(&pc_gens, &bp_gens, 1);
        let second = prove_mul(&pc_gens, &bp_gens, 2);

        for reverse in [false, true] {
            let first_equation =
                prepare(&first.commitments, &first.proof, &pc_gens, &bp_gens, 11).unwrap();
            let second_equation =
                prepare(&second.commitments, &second.proof, &pc_gens, &bp_gens, 12).unwrap();
            let equations = if reverse {
                vec![second_equation, first_equation]
            } else {
                vec![first_equation, second_equation]
            };
            let mut batch_rng = ChaCha20Rng::seed_from_u64(20 + u64::from(reverse));
            VerificationEquation::verify_batch(equations, &mut batch_rng).unwrap();
        }
    }

    #[test]
    fn mismatched_statement_and_proof_fails_the_batch() {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let first = prove_mul(&pc_gens, &bp_gens, 1);
        let second = prove_mul(&pc_gens, &bp_gens, 2);
        let honest = prepare(&first.commitments, &first.proof, &pc_gens, &bp_gens, 11).unwrap();
        let mismatched =
            prepare(&first.commitments, &second.proof, &pc_gens, &bp_gens, 12).unwrap();
        let mut batch_rng = ChaCha20Rng::seed_from_u64(21);
        assert!(
            VerificationEquation::verify_batch(vec![honest, mismatched], &mut batch_rng).is_err()
        );
    }

    #[test]
    fn different_shared_generators_fail_cleanly() {
        let pc_gens = PedersenGens::<C>::default();
        let mut other_pc_gens = pc_gens;
        other_pc_gens.B_blinding += <C as Cycle>::Point::generator();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let first = prove_mul(&pc_gens, &bp_gens, 1);
        let second = prove_mul(&other_pc_gens, &bp_gens, 2);
        let first_equation =
            prepare(&first.commitments, &first.proof, &pc_gens, &bp_gens, 11).unwrap();
        let second_equation = prepare(
            &second.commitments,
            &second.proof,
            &other_pc_gens,
            &bp_gens,
            12,
        )
        .unwrap();
        let mut batch_rng = ChaCha20Rng::seed_from_u64(22);
        assert!(VerificationEquation::verify_batch(
            vec![first_equation, second_equation],
            &mut batch_rng,
        )
        .is_err());
    }

    #[test]
    fn different_generator_prefix_lengths_share_one_msm() {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let short = prove_mul(&pc_gens, &bp_gens, 1);
        let long = prove_mul_with_extra_gates(&pc_gens, &bp_gens, 2, 1);
        let short_equation =
            prepare(&short.commitments, &short.proof, &pc_gens, &bp_gens, 11).unwrap();
        let long_equation =
            prepare_with_extra_gates(&long.commitments, &long.proof, &pc_gens, &bp_gens, 12, 1)
                .unwrap();
        let mut batch_rng = ChaCha20Rng::seed_from_u64(23);
        VerificationEquation::verify_batch(vec![short_equation, long_equation], &mut batch_rng)
            .unwrap();
    }
}
