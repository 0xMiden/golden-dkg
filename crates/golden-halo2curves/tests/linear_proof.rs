//! Linear proof tests, ported from `bulletproofs 5.0.0/src/linear_proof.rs`.
//!
//! Exercises `LinearProof::create` / `verify` / `to_bytes` / `from_bytes`
//! over both halves of the Secp/Secq cycle. The test shape mirrors
//! upstream's `test_helper(n)`; the differences are the `C: Cycle` generic,
//! the deterministic `ChaCha20Rng` (upstream uses `thread_rng()`), and the
//! use of `Cycle::vartime_msm` instead of `RistrettoPoint::vartime_multiscalar_mul`.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "halo2curves-secp256k1")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::util::inner_product;
    use bulletproofs_cycle::Cycle;
    use bulletproofs_cycle::LinearProof;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_helper<C: Cycle>(n: usize)
    where
        C::Point: Copy,
        C::Compressed: Copy,
    {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);

        let bp_gens = BulletproofGens::<C>::new(n, 1);
        let G: Vec<C::Point> = bp_gens.share(0).G(n).copied().collect();

        let pedersen_gens = PedersenGens::<C>::default();
        let F = pedersen_gens.B;
        let B = pedersen_gens.B_blinding;

        let a: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();

        let mut prover_transcript = Transcript::new(b"linearprooftest");

        // C = <a, G> + r * B + <a, b> * F
        let r = random_scalar::<C>(&mut rng);
        let c = inner_product(&a, &b);
        let mut p_scalars: Vec<C::Scalar> = a.clone();
        p_scalars.push(r);
        p_scalars.push(c);
        let mut p_points: Vec<C::Point> = G.clone();
        p_points.push(B);
        p_points.push(F);
        let C_commit = C::point_compress(&C::vartime_msm(&p_scalars, &p_points));

        let proof = LinearProof::<C>::create(
            &mut prover_transcript,
            &mut rng,
            &C_commit,
            r,
            a,
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"linearprooftest");
        assert!(proof
            .verify(&mut verifier_transcript, &C_commit, &G, &F, &B, b.clone())
            .is_ok());

        let serialized = proof.to_bytes();
        assert_eq!(proof.serialized_size(), serialized.len());

        let deserialized = LinearProof::<C>::from_bytes(&serialized).unwrap();
        let mut serde_verifier = Transcript::new(b"linearprooftest");
        assert!(deserialized
            .verify(&mut serde_verifier, &C_commit, &G, &F, &B, b)
            .is_ok());
    }

    #[test]
    fn test_linear_proof_base_secp() {
        test_helper::<Secp256k1Cycle>(1);
    }

    #[test]
    fn test_linear_proof_16_secp() {
        test_helper::<Secp256k1Cycle>(16);
    }

    #[test]
    fn test_linear_proof_32_secp() {
        test_helper::<Secp256k1Cycle>(32);
    }

    #[test]
    fn test_linear_proof_64_secp() {
        test_helper::<Secp256k1Cycle>(64);
    }

    #[test]
    fn test_linear_proof_base_secq() {
        test_helper::<Secq256k1Cycle>(1);
    }

    #[test]
    fn test_linear_proof_16_secq() {
        test_helper::<Secq256k1Cycle>(16);
    }

    #[test]
    fn test_linear_proof_32_secq() {
        test_helper::<Secq256k1Cycle>(32);
    }

    #[test]
    fn test_linear_proof_64_secq() {
        test_helper::<Secq256k1Cycle>(64);
    }
}
