//! R1CS integration tests, ported from `bulletproofs 5.0.0/tests/r1cs.rs`.
//!
//! Mirrors upstream's shuffle, example, and range-proof gadgets over the
//! `Cycle` abstraction. Differences: every helper is parameterized by
//! `C: Cycle`; the deterministic `ChaCha20Rng` (upstream `thread_rng()`)
//! threads through `Prover::prove` / `Verifier::verify`; the `Scalar::from`
//! literals become `C::Scalar::from`. Each size runs over both halves of
//! the Secp/Secq cycle so the cycle abstraction is exercised, not trusted.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

#[cfg(feature = "halo2curves-secp256k1")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSError, RandomizableConstraintSystem,
        RandomizedConstraintSystem, Variable, Verifier,
    };
    use bulletproofs_cycle::Cycle;
    use ff::Field;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use merlin::Transcript;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    // ===== Shuffle gadget =====

    struct ShuffleProof<C: Cycle>(bulletproofs_cycle::R1CSProof<C>);

    impl<C: Cycle> ShuffleProof<C> {
        fn gadget<CS: RandomizableConstraintSystem<C>>(
            cs: &mut CS,
            x: Vec<Variable<C::Scalar>>,
            y: Vec<Variable<C::Scalar>>,
        ) -> Result<(), R1CSError> {
            assert_eq!(x.len(), y.len());
            let k = x.len();

            if k == 1 {
                cs.constrain(y[0] - x[0]);
                return Ok(());
            }

            cs.specify_randomized_constraints(move |cs| {
                let z = cs.challenge_scalar(b"shuffle challenge");

                let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);
                let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
                    let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
                    o
                });

                let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);
                let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
                    let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
                    o
                });

                cs.constrain(first_mulx_out - first_muly_out);

                Ok(())
            })
        }

        fn prove(
            pc_gens: &PedersenGens<C>,
            bp_gens: &BulletproofGens<C>,
            transcript: &mut Transcript,
            rng: &mut ChaCha20Rng,
            input: &[C::Scalar],
            output: &[C::Scalar],
        ) -> Result<(ShuffleProof<C>, Vec<C::Compressed>, Vec<C::Compressed>), R1CSError> {
            let k = input.len();
            transcript.append_message(b"dom-sep", b"ShuffleProof");
            transcript.append_u64(b"k", k as u64);

            let mut prover = Prover::<C, _>::new(pc_gens, transcript);

            let (input_commitments, input_vars): (Vec<_>, Vec<_>) = input
                .iter()
                .map(|v| prover.commit(*v, random_scalar::<C>(rng)))
                .unzip();

            let (output_commitments, output_vars): (Vec<_>, Vec<_>) = output
                .iter()
                .map(|v| prover.commit(*v, random_scalar::<C>(rng)))
                .unzip();

            ShuffleProof::<C>::gadget(&mut prover, input_vars, output_vars)?;

            let proof = prover.prove(bp_gens, rng)?;

            Ok((ShuffleProof(proof), input_commitments, output_commitments))
        }

        fn verify(
            &self,
            pc_gens: &PedersenGens<C>,
            bp_gens: &BulletproofGens<C>,
            transcript: &mut Transcript,
            rng: &mut ChaCha20Rng,
            input_commitments: &[C::Compressed],
            output_commitments: &[C::Compressed],
        ) -> Result<(), R1CSError> {
            let k = input_commitments.len();
            transcript.append_message(b"dom-sep", b"ShuffleProof");
            transcript.append_u64(b"k", k as u64);

            let mut verifier = Verifier::<C, _>::new(transcript);

            let input_vars: Vec<_> = input_commitments
                .iter()
                .map(|V| verifier.commit(V.clone()))
                .collect();

            let output_vars: Vec<_> = output_commitments
                .iter()
                .map(|V| verifier.commit(V.clone()))
                .collect();

            ShuffleProof::<C>::gadget(&mut verifier, input_vars, output_vars)?;

            verifier.verify(&self.0, pc_gens, bp_gens, rng)?;
            Ok(())
        }
    }

    fn kshuffle_helper<C: Cycle>(k: usize)
    where
        C::Compressed: Clone,
    {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new((2 * k).next_power_of_two(), 1);
        let mut rng = ChaCha20Rng::seed_from_u64(k as u64);

        let (proof, input_commitments, output_commitments) = {
            let input: Vec<C::Scalar> = (0..k).map(|_| C::Scalar::from(rng.next_u64())).collect();
            let mut output = input.clone();
            // Fisher-Yates shuffle (rand::SliceRandom would pull in the rand
            // facade; we already have rand_core).
            for i in (1..output.len()).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                output.swap(i, j);
            }

            let mut prover_transcript = Transcript::new(b"ShuffleProofTest");
            ShuffleProof::<C>::prove(
                &pc_gens,
                &bp_gens,
                &mut prover_transcript,
                &mut rng,
                &input,
                &output,
            )
            .unwrap()
        };

        let mut verifier_transcript = Transcript::new(b"ShuffleProofTest");
        assert!(proof
            .verify(
                &pc_gens,
                &bp_gens,
                &mut verifier_transcript,
                &mut rng,
                &input_commitments,
                &output_commitments
            )
            .is_ok());
    }

    // ===== Example gadget =====

    /// Constrains `(a1 + a2) * (b1 + b2) = (c1 + c2)`.
    fn example_gadget<C: Cycle, CS: ConstraintSystem<C>>(
        cs: &mut CS,
        a1: LinearCombination<C::Scalar>,
        a2: LinearCombination<C::Scalar>,
        b1: LinearCombination<C::Scalar>,
        b2: LinearCombination<C::Scalar>,
        c1: LinearCombination<C::Scalar>,
        c2: LinearCombination<C::Scalar>,
    ) {
        let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
        cs.constrain(c1 + c2 - c_var);
    }

    fn example_gadget_proof<C: Cycle>(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut ChaCha20Rng,
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(bulletproofs_cycle::R1CSProof<C>, Vec<C::Compressed>), R1CSError> {
        let mut transcript = Transcript::new(b"R1CSExampleGadget");
        let mut prover = Prover::<C, _>::new(pc_gens, &mut transcript);

        let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
            .into_iter()
            .map(|x| prover.commit(C::Scalar::from(x), random_scalar::<C>(rng)))
            .unzip();

        example_gadget::<C, _>(
            &mut prover,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            vars[4].into(),
            C::Scalar::from(c2).into(),
        );

        let proof = prover.prove(bp_gens, rng)?;
        Ok((proof, commitments))
    }

    fn example_gadget_verify<C: Cycle>(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut ChaCha20Rng,
        c2: u64,
        proof: bulletproofs_cycle::R1CSProof<C>,
        commitments: Vec<C::Compressed>,
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"R1CSExampleGadget");
        let mut verifier = Verifier::<C, _>::new(&mut transcript);

        let vars: Vec<_> = commitments
            .iter()
            .map(|V| verifier.commit(V.clone()))
            .collect();

        example_gadget::<C, _>(
            &mut verifier,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            vars[4].into(),
            C::Scalar::from(c2).into(),
        );

        verifier
            .verify(&proof, pc_gens, bp_gens, rng)
            .map_err(|_| R1CSError::VerificationError)
    }

    fn example_gadget_roundtrip_helper<C: Cycle>(
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(), R1CSError>
    where
        C::Compressed: Clone,
    {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(128, 1);
        let mut rng = ChaCha20Rng::seed_from_u64(0xa1a2_b1b2);

        let (proof, commitments) =
            example_gadget_proof::<C>(&pc_gens, &bp_gens, &mut rng, a1, a2, b1, b2, c1, c2)?;

        example_gadget_verify::<C>(&pc_gens, &bp_gens, &mut rng, c2, proof, commitments)
    }

    fn example_gadget_roundtrip_serialization_helper<C: Cycle>(
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(), R1CSError>
    where
        C::Compressed: Clone,
    {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(128, 1);
        let mut rng = ChaCha20Rng::seed_from_u64(0xa1a2_b1b2);

        let (proof, commitments) =
            example_gadget_proof::<C>(&pc_gens, &bp_gens, &mut rng, a1, a2, b1, b2, c1, c2)?;

        let bytes = proof.to_bytes();
        let proof = bulletproofs_cycle::R1CSProof::<C>::from_bytes(&bytes)?;

        example_gadget_verify::<C>(&pc_gens, &bp_gens, &mut rng, c2, proof, commitments)
    }

    // ===== Range-proof gadget =====

    /// Enforces that the value `v` lies in `[0, 2^n)`.
    pub fn range_proof<C: Cycle, CS: ConstraintSystem<C>>(
        cs: &mut CS,
        mut v: LinearCombination<C::Scalar>,
        v_assignment: Option<u64>,
        n: usize,
    ) -> Result<(), R1CSError> {
        let mut exp_2 = C::Scalar::ONE;
        for i in 0..n {
            let (a, b, o) = cs.allocate_multiplier(v_assignment.map(|q| {
                let bit: u64 = (q >> i) & 1;
                (C::Scalar::from(1 - bit), C::Scalar::from(bit))
            }))?;

            cs.constrain(o.into());
            cs.constrain(a + (b - C::Scalar::ONE));
            v = v - b * exp_2;
            exp_2 = exp_2 + exp_2;
        }

        cs.constrain(v);
        Ok(())
    }

    fn range_proof_helper<C: Cycle>(v_val: u64, n: usize) -> Result<(), R1CSError>
    where
        C::Compressed: Clone,
    {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(128, 1);

        let (proof, commitment) = {
            let mut prover_transcript = Transcript::new(b"RangeProofTest");
            let mut rng = ChaCha20Rng::seed_from_u64(v_val);

            let mut prover = Prover::<C, _>::new(&pc_gens, &mut prover_transcript);

            let (com, var) = prover.commit(C::Scalar::from(v_val), random_scalar::<C>(&mut rng));
            assert!(range_proof::<C, _>(&mut prover, var.into(), Some(v_val), n).is_ok());

            let proof = prover.prove(&bp_gens, &mut rng)?;
            (proof, com)
        };

        let mut verifier_transcript = Transcript::new(b"RangeProofTest");
        let mut verifier = Verifier::<C, _>::new(&mut verifier_transcript);
        let var = verifier.commit(commitment);

        assert!(range_proof::<C, _>(&mut verifier, var.into(), None, n).is_ok());

        let mut rng = ChaCha20Rng::seed_from_u64(0x7a);
        verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)
    }

    // ===== Test runners =====

    fn run_range_proof_gadget<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5a);
        let m = 3; // values per n

        for &n in &[2usize, 10, 32, 63] {
            let max = ((1u128 << n) - 1) as u64;
            let values: Vec<u64> = (0..m).map(|_| rng.next_u64() % (max + 1)).collect();
            for v in values {
                assert!(range_proof_helper::<C>(v, n).is_ok());
            }
            assert!(range_proof_helper::<C>(max + 1, n).is_err());
        }
    }

    macro_rules! cycle_tests {
        ($test_name:ident, $helper:ident) => {
            #[test]
            fn $test_name() {
                $helper::<Secp256k1Cycle>();
                $helper::<Secq256k1Cycle>();
            }
        };
    }

    fn shuffle_1<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(1)
    }
    fn shuffle_2<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(2)
    }
    fn shuffle_3<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(3)
    }
    fn shuffle_4<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(4)
    }
    fn shuffle_5<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(5)
    }
    fn shuffle_6<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(6)
    }
    fn shuffle_7<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(7)
    }
    fn shuffle_24<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(24)
    }
    fn shuffle_42<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        kshuffle_helper::<C>(42)
    }

    cycle_tests!(shuffle_gadget_test_1, shuffle_1);
    cycle_tests!(shuffle_gadget_test_2, shuffle_2);
    cycle_tests!(shuffle_gadget_test_3, shuffle_3);
    cycle_tests!(shuffle_gadget_test_4, shuffle_4);
    cycle_tests!(shuffle_gadget_test_5, shuffle_5);
    cycle_tests!(shuffle_gadget_test_6, shuffle_6);
    cycle_tests!(shuffle_gadget_test_7, shuffle_7);
    cycle_tests!(shuffle_gadget_test_24, shuffle_24);
    cycle_tests!(shuffle_gadget_test_42, shuffle_42);

    fn example_gadget_test_runner<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        assert!(example_gadget_roundtrip_helper::<C>(3, 4, 6, 1, 40, 9).is_ok());
        assert!(example_gadget_roundtrip_helper::<C>(3, 4, 6, 1, 40, 10).is_err());
    }

    fn example_gadget_serialization_test_runner<C: Cycle>()
    where
        C::Compressed: Clone,
    {
        assert!(example_gadget_roundtrip_serialization_helper::<C>(3, 4, 6, 1, 40, 9).is_ok());
        assert!(example_gadget_roundtrip_serialization_helper::<C>(3, 4, 6, 1, 40, 10).is_err());
    }

    cycle_tests!(example_gadget_test, example_gadget_test_runner);
    cycle_tests!(
        example_gadget_serialization_test,
        example_gadget_serialization_test_runner
    );
    cycle_tests!(range_proof_gadget, run_range_proof_gadget);
}
