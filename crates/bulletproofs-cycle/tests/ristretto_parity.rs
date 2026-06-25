//! Byte-for-byte parity with `zkcrypto/bulletproofs` 5.0.0 over Ristretto.
//!
//! These tests pin that our `Cycle`-generic port produces identical output to
//! upstream `bulletproofs 5.0.0` for the pieces upstream exposes publicly:
//!
//! * `BulletproofGens` G generators (the SHAKE256-driven `GeneratorsChain`
//!   must not drift from upstream, otherwise every downstream proof diverges
//!   before the algorithm even runs).
//! * `LinearProof::create` / `to_bytes` (and cross-verification through
//!   upstream's `verify` / `from_bytes`, and vice versa).
//!
//! What is NOT covered, and why:
//!
//! * `InnerProductProof`: upstream keeps the `inner_product_proof` module
//!   private, so IPP cannot be called directly through the dev-dep. Its
//!   algorithm correctness is still exercised by `ristretto_smoke.rs`'s
//!   LinearProof round-trip (LinearProof's rounds share the same L/R
//!   construction and transcript pattern as IPP).
//! * `RangeProof`: stripped from this fork.
//! * `PedersenGens::default()`: our default derives `B_blinding` from a
//!   SHAKE256 domain-separated hash; upstream uses
//!   `RistrettoPoint::hash_from_bytes::<Sha3_512>` on the compressed
//!   basepoint. The resulting points differ by design, so any proof that
//!   builds commitments via `default()` (the R1CS path) forks at the first
//!   commitment. The tests below sidestep this by passing `F` and `B`
//!   explicitly to `LinearProof::create`.

#![allow(non_snake_case)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "bulletproofs-compat")]
mod tests {
    use bulletproofs::BulletproofGens as UpstreamGens;
    use bulletproofs::LinearProof as UpstreamLinearProof;
    use bulletproofs_cycle::generators::BulletproofGens;
    use bulletproofs_cycle::ristretto_cycle::RistrettoCycle;
    use bulletproofs_cycle::util::inner_product;
    use bulletproofs_cycle::Cycle;
    use bulletproofs_cycle::LinearProof;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    use merlin::Transcript;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha3::Sha3_512;

    const N: usize = 16;

    /// The first `n` Bulletproofs G generators from our `Cycle`-generic chain
    /// must match upstream byte-for-byte. This pins that the SHAKE256-driven
    /// `GeneratorsChain` (prefix, label encoding, fast_forward, hash-to-group)
    /// has not drifted. If this fails, every downstream proof diverges before
    /// the algorithm even runs.
    #[test]
    fn bulletproof_gens_match_upstream() {
        let ours: Vec<RistrettoPoint> = BulletproofGens::<RistrettoCycle>::new(N, 1)
            .share(0)
            .G(N)
            .copied()
            .collect();
        let theirs: Vec<RistrettoPoint> = UpstreamGens::new(N, 1).share(0).G(N).cloned().collect();
        assert_eq!(ours.len(), theirs.len());
        for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
            let ob = RistrettoCycle::point_compress(o);
            assert_eq!(
                RistrettoCycle::compressed_as_bytes(&ob),
                t.compress().as_bytes(),
                "G[{i}] diverges from upstream"
            );
        }
    }

    #[test]
    fn linear_proof_matches_upstream() {
        let G: Vec<RistrettoPoint> = BulletproofGens::<RistrettoCycle>::new(N, 1)
            .share(0)
            .G(N)
            .copied()
            .collect();
        // Pin generator parity inline so a LinearProof byte-divergence message
        // cannot be misread as a generator drift.
        let G_upstream: Vec<RistrettoPoint> =
            UpstreamGens::new(N, 1).share(0).G(N).cloned().collect();
        for (i, (o, t)) in G.iter().zip(G_upstream.iter()).enumerate() {
            let ob = RistrettoCycle::point_compress(o);
            assert_eq!(
                RistrettoCycle::compressed_as_bytes(&ob),
                t.compress().as_bytes(),
                "G[{i}] diverges from upstream"
            );
        }

        // Derive F and B identically on both sides, bypassing
        // PedersenGens::default() (where the SHAKE256 vs SHA3-512 divergence
        // lives). The create() signature takes these explicitly.
        let F = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"F");
        let B = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"B");

        const SEED: [u8; 32] = [11; 32];
        let mut rng_ours = ChaCha20Rng::from_seed(SEED);
        let mut rng_upstream = ChaCha20Rng::from_seed(SEED);

        let a: Vec<Scalar> = (0..N).map(|_| Scalar::random(&mut rng_ours)).collect();
        let b: Vec<Scalar> = (0..N).map(|_| Scalar::random(&mut rng_ours)).collect();
        let a_upstream: Vec<Scalar> = (0..N).map(|_| Scalar::random(&mut rng_upstream)).collect();
        let b_upstream: Vec<Scalar> = (0..N).map(|_| Scalar::random(&mut rng_upstream)).collect();
        assert_eq!(a, a_upstream, "seeded RNG draws must match");
        assert_eq!(b, b_upstream, "seeded RNG draws must match");

        let r = Scalar::random(&mut rng_ours);
        let r_upstream = Scalar::random(&mut rng_upstream);
        assert_eq!(r, r_upstream);

        let c = inner_product(&a, &b);

        // C = <a,G> + r*B + c*F, identical on both sides.
        let mut c_scalars: Vec<Scalar> = a.clone();
        c_scalars.push(r);
        c_scalars.push(c);
        let mut c_points: Vec<RistrettoPoint> = G.clone();
        c_points.push(B);
        c_points.push(F);
        let C_commit: CompressedRistretto =
            RistrettoPoint::vartime_multiscalar_mul(c_scalars, c_points).compress();

        // Our proof. The create() prover-side RNG draws s_j, t_j per round,
        // then s_star, t_star at the base case. Both sides draw via dalek's
        // Scalar::random on identically-seeded RNGs, so the draws line up
        // scalar-for-scalar.
        let mut prover_ours = Transcript::new(b"linearprooftest");
        let proof_ours = LinearProof::<RistrettoCycle>::create(
            &mut prover_ours,
            &mut rng_ours,
            &C_commit,
            r,
            a.clone(),
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        let mut prover_upstream = Transcript::new(b"linearprooftest");
        let proof_upstream = UpstreamLinearProof::create(
            &mut prover_upstream,
            &mut rng_upstream,
            &C_commit,
            r_upstream,
            a_upstream,
            b_upstream.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        let our_bytes = proof_ours.to_bytes();
        let upstream_bytes = proof_upstream.to_bytes();
        assert_eq!(
            our_bytes, upstream_bytes,
            "LinearProof bytes diverge from upstream"
        );

        // Cross-verify in both directions. Pins that the serialized layout is
        // interop-compatible, not just that the two in-memory structs happen
        // to serialize to the same bytes.
        let ours_at_upstream = UpstreamLinearProof::from_bytes(&our_bytes).unwrap();
        let mut v = Transcript::new(b"linearprooftest");
        assert!(ours_at_upstream
            .verify(&mut v, &C_commit, &G, &F, &B, b.clone())
            .is_ok());

        let upstream_at_ours = LinearProof::<RistrettoCycle>::from_bytes(&upstream_bytes).unwrap();
        let mut v = Transcript::new(b"linearprooftest");
        assert!(upstream_at_ours
            .verify(&mut v, &C_commit, &G, &F, &B, b)
            .is_ok());
    }
}
