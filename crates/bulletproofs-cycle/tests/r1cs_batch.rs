//! Cross-proof R1CS batch verification over Ristretto.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "ristretto")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        VerificationEquation, Verifier,
    };
    use bulletproofs_cycle::ristretto_cycle::RistrettoCycle;
    use bulletproofs_cycle::{Cycle, R1CSError};
    use ff::Field;
    use group::Group;
    use merlin::Transcript;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
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
        let var_a = verifier.commit(commitments[0]);
        let var_b = verifier.commit(commitments[1]);
        let var_c = verifier.commit(commitments[2]);
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

    #[test]
    fn streamed_equations_verify_and_propagate_preparation_errors() {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);
        let proofs: Vec<_> = (1..=3)
            .map(|seed| prove_mul(&pc_gens, &bp_gens, seed))
            .collect();
        let equations = || {
            proofs.iter().enumerate().map(|(i, item)| {
                prepare(
                    &item.commitments,
                    &item.proof,
                    &pc_gens,
                    &bp_gens,
                    i as u64 + 10,
                )
            })
        };
        let mut rng = ChaCha20Rng::seed_from_u64(90);
        VerificationEquation::verify_batch_iter(equations(), &mut rng).unwrap();
        let mut expected_rng = ChaCha20Rng::seed_from_u64(90);
        for _ in 0..proofs.len() {
            while bool::from(random_scalar::<C>(&mut expected_rng).is_zero()) {}
        }
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
        let mut rng = ChaCha20Rng::seed_from_u64(90);
        let pulled_after_error = std::cell::Cell::new(false);
        assert!(VerificationEquation::verify_batch_iter(
            equations()
                .take(1)
                .chain(std::iter::once(Err(R1CSError::VerificationError)))
                .chain(std::iter::once_with(|| {
                    pulled_after_error.set(true);
                    Err(R1CSError::VerificationError)
                })),
            &mut rng,
        )
        .is_err());
        assert!(!pulled_after_error.get());
        assert!(
            VerificationEquation::<C>::verify_batch_iter(std::iter::empty(), &mut rng).is_err()
        );
    }

    #[test]
    fn streamed_equations_check_distinct_generator_storage_and_invalid_points() {
        let pc_gens = PedersenGens::<C>::default();
        let short_gens = BulletproofGens::<C>::new(1, 1);
        let long_gens = BulletproofGens::<C>::new(4, 1);
        let short = prove_mul(&pc_gens, &short_gens, 41);
        let long = prove_mul_with_extra_gates(&pc_gens, &long_gens, 42, 2);
        for reverse in [false, true] {
            let mut equations = vec![
                prepare(&short.commitments, &short.proof, &pc_gens, &short_gens, 51),
                prepare_with_extra_gates(
                    &long.commitments,
                    &long.proof,
                    &pc_gens,
                    &long_gens,
                    52,
                    2,
                ),
            ];
            if reverse {
                equations.reverse();
            }
            let mut rng = ChaCha20Rng::seed_from_u64(60);
            VerificationEquation::verify_batch_iter(equations, &mut rng).unwrap();
        }
        let mut invalid_commitments = short.commitments;
        invalid_commitments[0] = C::compressed_from_bytes(&[255; 32]);
        let invalid = prepare(
            &invalid_commitments,
            &short.proof,
            &pc_gens,
            &short_gens,
            51,
        );
        let mut rng = ChaCha20Rng::seed_from_u64(60);
        assert!(VerificationEquation::verify_batch_iter([invalid], &mut rng).is_err());
    }

    #[test]
    fn mixed_phase_verification_preserves_phase_and_padding_weights() {
        fn constrain_product<CS: ConstraintSystem<C>>(cs: &mut CS, value: Scalar) {
            let (_, _, product) = cs.multiply(value.into(), value.into());
            cs.constrain(product - value * value);
        }
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(4, 1);
        let mut prover = Prover::<C, _>::new(&pc_gens, Transcript::new(b"mixed-phase-batch"));
        constrain_product(&mut prover, Scalar::from(3u64));
        prover
            .specify_randomized_constraints(|cs| {
                constrain_product(cs, Scalar::from(5u64));
                constrain_product(cs, Scalar::from(7u64));
                Ok(())
            })
            .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(70);
        let proof = prover.prove(&bp_gens, &mut rng).unwrap();
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"mixed-phase-batch"));
        constrain_product(&mut verifier, Scalar::from(3u64));
        verifier
            .specify_randomized_constraints(|cs| {
                constrain_product(cs, Scalar::from(5u64));
                constrain_product(cs, Scalar::from(7u64));
                Ok(())
            })
            .unwrap();
        let equation = verifier
            .verification_equation(&proof, &pc_gens, &bp_gens, &mut rng)
            .unwrap();
        VerificationEquation::verify_batch_iter([Ok(equation)], &mut rng).unwrap();
    }
}
