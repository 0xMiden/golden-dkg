//! Smoke test that exercises the Ristretto `Cycle` impl end-to-end through
//! the linear-proof path. One test, base case, proves the impl wires up
//! correctly to dalek's API surface. Thorough byte-fixture comparisons with
//! upstream `zkcrypto/bulletproofs` are a follow-on.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "ristretto")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
    use bulletproofs_cycle::ristretto_cycle::RistrettoCycle;
    use bulletproofs_cycle::util::inner_product;
    use bulletproofs_cycle::Cycle;
    use bulletproofs_cycle::LinearProof;
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn linear_proof_roundtrips_over_ristretto() {
        let n: usize = 16;
        let mut rng = ChaCha20Rng::from_seed([42; 32]);

        let bp_gens = BulletproofGens::<RistrettoCycle>::new(n, 1);
        let G: Vec<_> = bp_gens.share(0).G(n).copied().collect();

        let pedersen_gens = PedersenGens::<RistrettoCycle>::default();
        let F = pedersen_gens.B;
        let B = pedersen_gens.B_blinding;

        let a: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();
        let b: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();

        let mut prover_transcript = Transcript::new(b"linearprooftest");

        let r = random_scalar::<RistrettoCycle>(&mut rng);
        let c = inner_product(&a, &b);
        let mut p_scalars: Vec<_> = a.clone();
        p_scalars.push(r);
        p_scalars.push(c);
        let mut p_points: Vec<_> = G.clone();
        p_points.push(B);
        p_points.push(F);
        let C_commit =
            RistrettoCycle::point_compress(&RistrettoCycle::vartime_msm(&p_scalars, &p_points));

        let proof = LinearProof::<RistrettoCycle>::create(
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

        let deserialized = LinearProof::<RistrettoCycle>::from_bytes(&serialized).unwrap();
        let mut serde_verifier = Transcript::new(b"linearprooftest");
        assert!(deserialized
            .verify(&mut serde_verifier, &C_commit, &G, &F, &B, b)
            .is_ok());
    }
}
