//! Inner-product proof tests, ported from `bulletproofs 5.0.0/src/inner_product_proof.rs`.
//!
//! Exercises `InnerProductProof::create` / `verify` / `to_bytes` / `from_bytes`
//! over both halves of the Secp/Secq cycle. The test shape mirrors upstream's
//! `test_helper_create(n)`; the only differences are the `C: Cycle` generic,
//! the deterministic `ChaCha20Rng` (upstream uses `thread_rng()`), and the use
//! of `Cycle::point_hash_from_uniform` to derive the `Q` base (upstream hashes
//! to a RistrettoPoint via SHA3-512).

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "halo2curves-secp256k1")]
mod tests {
    use bulletproofs_cycle::cycle::random_scalar;
    use bulletproofs_cycle::generators::BulletproofGens;
    use bulletproofs_cycle::Cycle;
    use bulletproofs_cycle::InnerProductProof;
    use ff::Field;
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use core::iter;

    fn test_helper_create<C: Cycle>(n: usize)
    where
        C::Point: Copy,
        C::Compressed: Copy,
    {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);

        let bp_gens = BulletproofGens::<C>::new(n, 1);
        let G_affine: Vec<C::Affine> = bp_gens.share(0).G(n).copied().collect();
        let H_affine: Vec<C::Affine> = bp_gens.share(0).H(n).copied().collect();
        let G: Vec<C::Point> = G_affine.iter().map(C::affine_to_point).collect();
        let H: Vec<C::Point> = H_affine.iter().map(C::affine_to_point).collect();

        // Q is a fixed base derived from a uniform 64-byte input. Upstream
        // hashes b"test point" to a RistrettoPoint; we feed the same tag
        // padded to 64 bytes through Cycle::point_hash_from_uniform.
        let mut q_seed = [0u8; 64];
        let tag = b"test point";
        q_seed[..tag.len()].copy_from_slice(tag);
        let Q = C::point_hash_from_uniform(&q_seed);

        let a: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let c = bulletproofs_cycle::util::inner_product(&a, &b);

        let G_factors: Vec<C::Scalar> = iter::repeat_n(C::Scalar::ONE, n).collect();

        // y_inv plays the role of a random transcript challenge.
        let y_inv = random_scalar::<C>(&mut rng);
        let H_factors: Vec<C::Scalar> = bulletproofs_cycle::util::exp_iter(y_inv).take(n).collect();

        // Reconstruct the commitment P = <a,G> + <b',H> + <a,b> Q where
        // b' = b ∘ y^{-n}, so that the verify equation holds against the
        // same G_factors / H_factors we hand to the prover and verifier.
        let b_prime: Vec<C::Scalar> = b
            .iter()
            .zip(bulletproofs_cycle::util::exp_iter(y_inv))
            .map(|(bi, yi)| *bi * yi)
            .collect();

        let mut p_scalars: Vec<C::Scalar> = a.clone();
        p_scalars.extend_from_slice(&b_prime);
        p_scalars.push(c);
        let mut p_points: Vec<C::Point> = G.clone();
        p_points.extend_from_slice(&H);
        p_points.push(Q);
        let P = C::vartime_msm(&p_scalars, &p_points);

        let mut verifier = Transcript::new(b"innerproducttest");
        let proof = InnerProductProof::<C>::create(
            &mut verifier,
            &Q,
            &G_factors,
            &H_factors,
            &G_affine,
            &H_affine,
            a.clone(),
            b.clone(),
        );

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H
            )
            .is_ok());

        // Round-trip through bytes and verify again.
        let proof = InnerProductProof::<C>::from_bytes(proof.to_bytes().as_slice()).unwrap();
        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H
            )
            .is_ok());
    }

    #[test]
    fn make_ipp_1_secp() {
        test_helper_create::<Secp256k1Cycle>(1);
    }

    #[test]
    fn make_ipp_2_secp() {
        test_helper_create::<Secp256k1Cycle>(2);
    }

    #[test]
    fn make_ipp_4_secp() {
        test_helper_create::<Secp256k1Cycle>(4);
    }

    #[test]
    fn make_ipp_32_secp() {
        test_helper_create::<Secp256k1Cycle>(32);
    }

    #[test]
    fn make_ipp_64_secp() {
        test_helper_create::<Secp256k1Cycle>(64);
    }

    #[test]
    fn make_ipp_1_secq() {
        test_helper_create::<Secq256k1Cycle>(1);
    }

    #[test]
    fn make_ipp_2_secq() {
        test_helper_create::<Secq256k1Cycle>(2);
    }

    #[test]
    fn make_ipp_4_secq() {
        test_helper_create::<Secq256k1Cycle>(4);
    }

    #[test]
    fn make_ipp_32_secq() {
        test_helper_create::<Secq256k1Cycle>(32);
    }

    #[test]
    fn make_ipp_64_secq() {
        test_helper_create::<Secq256k1Cycle>(64);
    }

    fn test_helper_verify_rejects_dimension_mismatch<C: Cycle>(n: usize)
    where
        C::Point: Copy,
        C::Compressed: Copy,
    {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let bp_gens = BulletproofGens::<C>::new(n, 1);
        let G_affine: Vec<C::Affine> = bp_gens.share(0).G(n).copied().collect();
        let H_affine: Vec<C::Affine> = bp_gens.share(0).H(n).copied().collect();
        let G: Vec<C::Point> = G_affine.iter().map(C::affine_to_point).collect();
        let H: Vec<C::Point> = H_affine.iter().map(C::affine_to_point).collect();

        let mut q_seed = [0u8; 64];
        let tag = b"test point";
        q_seed[..tag.len()].copy_from_slice(tag);
        let Q = C::point_hash_from_uniform(&q_seed);

        let a: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let c = bulletproofs_cycle::util::inner_product(&a, &b);

        let G_factors: Vec<C::Scalar> = iter::repeat_n(C::Scalar::ONE, n).collect();
        let y_inv = random_scalar::<C>(&mut rng);
        let H_factors: Vec<C::Scalar> = bulletproofs_cycle::util::exp_iter(y_inv).take(n).collect();

        let b_prime: Vec<C::Scalar> = b
            .iter()
            .zip(bulletproofs_cycle::util::exp_iter(y_inv))
            .map(|(bi, yi)| *bi * yi)
            .collect();

        let mut p_scalars: Vec<C::Scalar> = a.clone();
        p_scalars.extend_from_slice(&b_prime);
        p_scalars.push(c);
        let mut p_points: Vec<C::Point> = G.clone();
        p_points.extend_from_slice(&H);
        p_points.push(Q);
        let P = C::vartime_msm(&p_scalars, &p_points);

        let mut verifier = Transcript::new(b"innerproducttest");
        let proof = InnerProductProof::<C>::create(
            &mut verifier,
            &Q,
            &G_factors,
            &H_factors,
            &G_affine,
            &H_affine,
            a.clone(),
            b.clone(),
        );

        // Truncating G by one entry must surface as a VerificationError
        // rather than a panic or a silently-accepted proof.
        let mut verifier = Transcript::new(b"innerproducttest");
        let short_G: Vec<C::Point> = G.iter().copied().take(n - 1).collect();
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &short_G,
                &H,
            )
            .is_err());

        // Same for H and for the factor iterators.
        let mut verifier = Transcript::new(b"innerproducttest");
        let short_H: Vec<C::Point> = H.iter().copied().take(n - 1).collect();
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &short_H,
            )
            .is_err());

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n - 1),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H,
            )
            .is_err());

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n - 1),
                &P,
                &Q,
                &G,
                &H,
            )
            .is_err());

        // Oversized factor iterators must also be rejected. The contract is
        // exactly n entries, not "at least n".
        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n + 1),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H,
            )
            .is_err());

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat_n(C::Scalar::ONE, n),
                bulletproofs_cycle::util::exp_iter(y_inv).take(n + 1),
                &P,
                &Q,
                &G,
                &H,
            )
            .is_err());
    }

    #[test]
    fn verify_rejects_short_G_secp() {
        test_helper_verify_rejects_dimension_mismatch::<Secp256k1Cycle>(4);
    }

    #[test]
    fn verify_rejects_short_G_secq() {
        test_helper_verify_rejects_dimension_mismatch::<Secq256k1Cycle>(4);
    }
}
