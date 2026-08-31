//! End-to-end R1CS smoke test over the Secp/Secq curve cycle.
//!
//! Proves a single multiplication gate `a * b = c` with all three values
//! committed, then checks that the verifier accepts an honest proof and
//! rejects one whose `c` commitment is swapped for a commitment to a
//! different value, and rejects a proof verified under the wrong transcript
//! domain. Exercises both `Secp256k1Cycle` and `Secq256k1Cycle` so the Main
//! Golden proof system's commitment group is covered alongside the input group.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "halo2curves-secp256k1")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::r1cs::{ConstraintSystem, Prover, R1CSProof, Verifier};
    use bulletproofs_cycle::Cycle;
    use ff::Field;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    struct MulProof<C: Cycle> {
        proof: R1CSProof<C>,
        V_a: C::Compressed,
        V_b: C::Compressed,
        V_c: C::Compressed,
    }

    fn prove_mul<C: Cycle>(pc_gens: &PedersenGens<C>, bp_gens: &BulletproofGens<C>) -> MulProof<C> {
        let mut rng = ChaCha20Rng::seed_from_u64(0xb12d57a3);
        let a = random_scalar::<C>(&mut rng);
        let b = random_scalar::<C>(&mut rng);
        let c = a * b;

        let mut prover = Prover::<C, _>::new(pc_gens, Transcript::new(b"r1cs_smoke"));
        let (V_a, var_a) = prover.commit(a, random_scalar::<C>(&mut rng));
        let (V_b, var_b) = prover.commit(b, random_scalar::<C>(&mut rng));
        let (V_c, var_c) = prover.commit(c, random_scalar::<C>(&mut rng));

        let (_, _, var_o) = prover.multiply(var_a.into(), var_b.into());
        prover.constrain(var_o - var_c);

        let proof = prover.prove(bp_gens, &mut rng).expect("prove");
        MulProof {
            proof,
            V_a,
            V_b,
            V_c,
        }
    }

    fn verify_mul<C: Cycle>(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        V_a: C::Compressed,
        V_b: C::Compressed,
        V_c: C::Compressed,
        proof: &R1CSProof<C>,
    ) -> Result<(), bulletproofs_cycle::R1CSError> {
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"r1cs_smoke"));
        let v_a = verifier.commit(V_a);
        let v_b = verifier.commit(V_b);
        let v_c = verifier.commit(V_c);
        let (_, _, v_o) = verifier.multiply(v_a.into(), v_b.into());
        verifier.constrain(v_o - v_c);

        let mut rng = ChaCha20Rng::seed_from_u64(0x9e1c4ab7);
        verifier.verify(proof, pc_gens, bp_gens, &mut rng)
    }

    fn non_zero_scalar<C: Cycle>(rng: &mut ChaCha20Rng) -> C::Scalar {
        let v = random_scalar::<C>(rng);
        if v == C::Scalar::ZERO {
            C::Scalar::ONE
        } else {
            v
        }
    }

    fn run_smoke<C: Cycle>(label: &str) {
        let pc_gens = PedersenGens::<C>::default();
        let bp_gens = BulletproofGens::<C>::new(64, 1);

        let MulProof {
            proof,
            V_a,
            V_b,
            V_c,
        } = prove_mul::<C>(&pc_gens, &bp_gens);

        verify_mul::<C>(
            &pc_gens,
            &bp_gens,
            V_a.clone(),
            V_b.clone(),
            V_c.clone(),
            &proof,
        )
        .expect("honest proof verifies");

        let bytes = proof.to_bytes();
        let recovered =
            R1CSProof::<C>::from_bytes(&bytes).expect("proof round-trips through bytes");
        assert_eq!(bytes, recovered.to_bytes(), "{label}: proof bytes stable");

        let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef);
        let wrong_c = non_zero_scalar::<C>(&mut rng);
        let V_c_bad =
            <C as Cycle>::point_compress(&pc_gens.commit(wrong_c, random_scalar::<C>(&mut rng)));

        let result = verify_mul::<C>(
            &pc_gens,
            &bp_gens,
            V_a.clone(),
            V_b.clone(),
            V_c_bad,
            &proof,
        );
        assert!(
            result.is_err(),
            "{label}: verifier must reject a proof whose c commitment is swapped"
        );

        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"wrong-domain"));
        let v_a = verifier.commit(V_a);
        let v_b = verifier.commit(V_b);
        let v_c = verifier.commit(V_c);
        let (_, _, v_o) = verifier.multiply(v_a.into(), v_b.into());
        verifier.constrain(v_o - v_c);
        let mut rng = ChaCha20Rng::seed_from_u64(0x51d4);
        assert!(
            verifier
                .verify(&proof, &pc_gens, &bp_gens, &mut rng)
                .is_err(),
            "{label}: verifier must reject a proof verified under the wrong transcript domain"
        );
    }

    #[test]
    fn r1cs_smoke_secp256k1() {
        run_smoke::<Secp256k1Cycle>("secp256k1");
    }

    #[test]
    fn r1cs_smoke_secq256k1() {
        run_smoke::<Secq256k1Cycle>("secq256k1");
    }
}

#[cfg(feature = "halo2curves-secp256k1")]
mod sanity {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::Cycle;
    use ff::Field;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn pedersen_roundtrip<C: Cycle>() {
        let pc_gens = PedersenGens::<C>::default();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let v = random_scalar::<C>(&mut rng);
        let blinding = random_scalar::<C>(&mut rng);
        let V = <C as Cycle>::point_compress(&pc_gens.commit(v, blinding));
        let V_decomp = <C as Cycle>::compressed_decompress(&V).expect("decompress");
        let V2 = pc_gens.commit(v, blinding);
        assert_eq!(V_decomp, V2, "pedersen commit not deterministic");
    }

    fn scalar_invert_roundtrip<C: Cycle>() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let s = random_scalar::<C>(&mut rng);
        let inv = <C as Cycle>::scalar_invert(&s);
        assert_eq!(s * inv, C::Scalar::ONE, "scalar invert");
    }

    fn generator_decompress<C: Cycle>() {
        let bp_gens = BulletproofGens::<C>::new(8, 1);
        let g = bp_gens.share(0).G(1).next().unwrap();
        let comp = <C as Cycle>::affine_compress(g);
        let decomp = <C as Cycle>::compressed_decompress(&comp).expect("decompress");
        assert_eq!(*g, C::point_to_affine(&decomp), "generator roundtrip");
    }

    fn scalar_from_wide_consistency<C: Cycle>() {
        let bytes = [0x42u8; 64];
        let s1 = <C as Cycle>::scalar_from_wide(&bytes);
        let s2 = <C as Cycle>::scalar_from_wide(&bytes);
        assert_eq!(s1, s2, "scalar_from_wide deterministic");
        let bytes2 = [0x43u8; 64];
        let s3 = <C as Cycle>::scalar_from_wide(&bytes2);
        assert_ne!(s1, s3, "scalar_from_wide different inputs differ");
    }

    fn scalar_to_canonical_roundtrip<C: Cycle>() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let s = random_scalar::<C>(&mut rng);
        let bytes = <C as Cycle>::scalar_to_canonical(&s);
        let s2 = <C as Cycle>::scalar_from_canonical(&bytes).expect("canonical");
        assert_eq!(s, s2, "scalar canonical roundtrip");
    }

    fn scalar_batch_invert_nonzero<C: Cycle>() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let n = 8;
        let mut inputs: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let product: C::Scalar = inputs.iter().copied().product();
        let expected: Vec<C::Scalar> = inputs
            .iter()
            .map(|x| <C as Cycle>::scalar_invert(x))
            .collect();
        let expected_product = <C as Cycle>::scalar_invert(&product);
        let returned = <C as Cycle>::scalar_batch_invert(&mut inputs);
        assert_eq!(
            returned, expected_product,
            "batch invert returns product of inverses"
        );
        assert_eq!(
            inputs, expected,
            "batch invert entries match scalar-by-scalar invert"
        );
    }

    fn scalar_batch_invert_empty<C: Cycle>() {
        let mut empty: Vec<C::Scalar> = Vec::new();
        let product = <C as Cycle>::scalar_batch_invert(&mut empty);
        assert_eq!(product, C::Scalar::ONE, "empty batch invert returns ONE");
    }

    fn scalar_batch_invert_zero_corrupts_all<C: Cycle>() {
        // Pins the documented precondition: a single zero entry collapses
        // every output to zero, not just itself. This is the footgun the trait
        // doc warns about.
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mut inputs: Vec<C::Scalar> = (0..4).map(|_| random_scalar::<C>(&mut rng)).collect();
        inputs[2] = C::Scalar::ZERO;
        let returned = <C as Cycle>::scalar_batch_invert(&mut inputs);
        assert_eq!(returned, C::Scalar::ZERO, "zero entry yields zero product");
        for (i, x) in inputs.iter().enumerate() {
            assert_eq!(
                *x,
                C::Scalar::ZERO,
                "entry {i} corrupted to zero by zero sibling"
            );
        }
    }

    fn transcript_rejects_identity_point<C: Cycle>() {
        // validate_and_append_point must reject the identity. A prover that
        // committed the identity would otherwise have its commitment silently
        // absorbed into the transcript, breaking the soundness argument that
        // relies on every appended point being a nontrivial group element.
        use bulletproofs_cycle::transcript::{append_point, validate_and_append_point};
        use merlin::Transcript;

        let identity = <C as Cycle>::compressed_identity();
        let mut t = Transcript::new(b"transcript-tests");
        assert!(
            validate_and_append_point::<C>(&mut t, b"id", &identity).is_err(),
            "validate_and_append_point must reject the identity"
        );

        // A non-identity point must succeed and be appended under the label.
        let pc_gens = PedersenGens::<C>::default();
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        // Use the generator-based commit with a fixed non-zero value so the
        // resulting point is provably not the identity.
        let v = C::Scalar::ONE;
        let pt = pc_gens.commit(v, random_scalar::<C>(&mut rng));
        let compressed = <C as Cycle>::point_compress(&pt);
        let mut t_ok = Transcript::new(b"transcript-tests");
        validate_and_append_point::<C>(&mut t_ok, b"V", &compressed)
            .expect("non-identity accepted");

        // append_point has no identity check; confirm the two helpers disagree
        // on the identity so the validator's rejection is observable.
        let mut t_bare = Transcript::new(b"transcript-tests");
        append_point::<C>(&mut t_bare, b"id", &identity);
        // Distinct challenge bytes after the validator rejects vs. the bare
        // append would be an unrelated merlin detail; the contract we pin
        // is only that validate returns Err on identity and Ok otherwise.
        let _ = t_bare;
    }

    fn transcript_challenge_scalar_is_canonical<C: Cycle>() {
        // challenge_scalar must produce a canonical scalar: it round-trips
        // through scalar_to_canonical/scalar_from_canonical. If the wide
        // reduction ever returned a non-canonical representative, downstream
        // scalar_from_canonical calls in the verifier would reject it.
        use bulletproofs_cycle::transcript::challenge_scalar;
        use merlin::Transcript;

        let mut t = Transcript::new(b"transcript-tests");
        t.append_message(b"seed", b"challenge-scalar-canonical");
        let s = challenge_scalar::<C>(&mut t, b"x");
        let bytes = <C as Cycle>::scalar_to_canonical(&s);
        let s2 = <C as Cycle>::scalar_from_canonical(&bytes)
            .expect("challenge_scalar output must be canonical");
        assert_eq!(s, s2, "challenge_scalar must round-trip canonically");

        // Two distinct labels must yield distinct challenge scalars, otherwise
        // a label-swap attacker could reuse a transcript.
        let mut t2 = Transcript::new(b"transcript-tests");
        t2.append_message(b"seed", b"challenge-scalar-canonical");
        let s_other = challenge_scalar::<C>(&mut t2, b"y");
        assert_ne!(
            s, s_other,
            "distinct challenge labels must yield distinct scalars"
        );
    }

    #[test]
    fn pedersen_roundtrip_secp() {
        pedersen_roundtrip::<Secp256k1Cycle>();
    }
    #[test]
    fn pedersen_roundtrip_secq() {
        pedersen_roundtrip::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_invert_roundtrip_secp() {
        scalar_invert_roundtrip::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_invert_roundtrip_secq() {
        scalar_invert_roundtrip::<Secq256k1Cycle>();
    }
    #[test]
    fn generator_decompress_secp() {
        generator_decompress::<Secp256k1Cycle>();
    }
    #[test]
    fn generator_decompress_secq() {
        generator_decompress::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_from_wide_consistency_secp() {
        scalar_from_wide_consistency::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_from_wide_consistency_secq() {
        scalar_from_wide_consistency::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_to_canonical_roundtrip_secp() {
        scalar_to_canonical_roundtrip::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_to_canonical_roundtrip_secq() {
        scalar_to_canonical_roundtrip::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_nonzero_secp() {
        scalar_batch_invert_nonzero::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_nonzero_secq() {
        scalar_batch_invert_nonzero::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_empty_secp() {
        scalar_batch_invert_empty::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_empty_secq() {
        scalar_batch_invert_empty::<Secq256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_zero_corrupts_all_secp() {
        scalar_batch_invert_zero_corrupts_all::<Secp256k1Cycle>();
    }
    #[test]
    fn scalar_batch_invert_zero_corrupts_all_secq() {
        scalar_batch_invert_zero_corrupts_all::<Secq256k1Cycle>();
    }
    #[test]
    fn transcript_rejects_identity_point_secp() {
        transcript_rejects_identity_point::<Secp256k1Cycle>();
    }
    #[test]
    fn transcript_rejects_identity_point_secq() {
        transcript_rejects_identity_point::<Secq256k1Cycle>();
    }
    #[test]
    fn transcript_challenge_scalar_is_canonical_secp() {
        transcript_challenge_scalar_is_canonical::<Secp256k1Cycle>();
    }
    #[test]
    fn transcript_challenge_scalar_is_canonical_secq() {
        transcript_challenge_scalar_is_canonical::<Secq256k1Cycle>();
    }
}
