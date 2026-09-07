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
    fn inner_product_proof_preserves_original_transcript_bytes() {
        use bulletproofs_cycle::InnerProductProof;
        use group::Group;
        use sha3::{Digest, Sha3_256};
        type C = RistrettoCycle;
        // Captured before buffer reuse and generator-folding changes.
        for (n, expected) in [
            (
                8,
                [
                    126, 70, 115, 182, 31, 48, 173, 2, 237, 116, 29, 101, 170, 95, 134, 151, 206,
                    130, 95, 130, 118, 247, 136, 42, 167, 81, 200, 132, 215, 108, 70, 247,
                ],
            ),
            (
                512,
                [
                    228, 45, 153, 175, 64, 42, 95, 233, 194, 223, 12, 43, 236, 96, 0, 65, 221, 56,
                    207, 102, 255, 195, 101, 116, 189, 216, 142, 222, 235, 137, 181, 108,
                ],
            ),
            (
                4096,
                [
                    114, 250, 63, 74, 3, 54, 42, 120, 111, 207, 61, 139, 38, 54, 251, 83, 43, 169,
                    141, 121, 180, 125, 229, 184, 86, 35, 142, 140, 94, 194, 56, 213,
                ],
            ),
        ] {
            let gens = BulletproofGens::<C>::new(n, 1);
            let g: Vec<_> = gens.share(0).G(n).copied().collect();
            let h: Vec<_> = gens.share(0).H(n).copied().collect();
            let mut rng = ChaCha20Rng::seed_from_u64(813);
            let a = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
            let b = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
            let g_factors: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
            let h_factors: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
            let proof = InnerProductProof::<C>::create(
                &mut Transcript::new(b"ipp-byte-parity"),
                &<C as Cycle>::Point::generator(),
                &g_factors,
                &h_factors,
                &g,
                &h,
                a,
                b,
            );
            let digest: [u8; 32] = Sha3_256::digest(proof.to_bytes()).into();
            assert_eq!(digest, expected, "original IPA bytes changed at n={n}");
        }
    }

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
