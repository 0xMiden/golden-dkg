//! Linear proof benchmarks (GHL'21 lightweight inner-product variant).
//!
//! Ported from `zkcrypto/bulletproofs 5.0.1/benches/linear_proof.rs`, cycle-
//! abstracted over [`bulletproofs_cycle::Cycle`] and run over both halves of
//! the secp/secq curve cycle. Proves `<a, b> = c` where `a` is secret and `b`
//! is public; the proof shape matches the crate's
//! `LinearProof::create`/`verify` tests.
//!
//! The ancestor used `RistrettoPoint::vartime_multiscalar_mul` for the witness
//! commitment; we route the same through `Cycle::vartime_msm`.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support.rs"]
mod support;

use bulletproofs_cycle::cycle::random_scalar;
use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
use bulletproofs_cycle::util::inner_product;
use bulletproofs_cycle::{Cycle, LinearProof};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use merlin::Transcript;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use support::{Secp256k1Cycle, Secq256k1Cycle};

/// Different linear proof vector lengths to try (matches the ancestor).
static TEST_SIZES: [usize; 5] = [64, 128, 256, 512, 1024];

/// Build the witness commitment `C = <a, G> + r*B + <a,b>*F` and return it
/// with its blinding factor `r`.
fn commit_witness<C: Cycle>(
    a: &[C::Scalar],
    b: &[C::Scalar],
    G: &[C::Point],
    B: C::Point,
    F: C::Point,
    rng: &mut ChaCha20Rng,
) -> (C::Compressed, C::Scalar) {
    let r = random_scalar::<C>(rng);
    let c = inner_product(a, b);
    let mut scalars: Vec<C::Scalar> = a.to_vec();
    scalars.push(r);
    scalars.push(c);
    let mut points: Vec<C::Point> = G.to_vec();
    points.push(B);
    points.push(F);
    let C_commit = C::point_compress(&C::vartime_msm(&scalars, &points));
    (C_commit, r)
}

/// Time `LinearProof::<C>::create`.
fn linear_create<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("LinearProof::create/{curve}"));
    group.sample_size(10);
    for &n in &TEST_SIZES {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);

        let bp_gens = BulletproofGens::<C>::new(n, 1);
        let G: Vec<C::Point> = bp_gens.share(0).G(n).map(C::affine_to_point).collect();
        let pedersen_gens = PedersenGens::<C>::default();
        let F = pedersen_gens.B;
        let B = pedersen_gens.B_blinding;

        let a: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let b: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let (C_commit, r) = commit_witness::<C>(&a, &b, &G, B, F, &mut rng);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bench, _| {
            bench.iter_batched(
                || {
                    (
                        Transcript::new(b"LinearProofBenchmark"),
                        ChaCha20Rng::from_seed([42; 32]),
                        a.clone(),
                        b.clone(),
                        G.clone(),
                    )
                },
                |(mut transcript, mut rng, a, b, G)| {
                    black_box(
                        LinearProof::<C>::create(
                            &mut transcript,
                            &mut rng,
                            &C_commit,
                            r,
                            a,
                            b,
                            G,
                            &F,
                            &B,
                        )
                        .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Time `LinearProof::<C>::verify`. The proof is built once outside the timed
/// region; only verification is measured.
fn linear_verify<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("LinearProof::verify/{curve}"));
    group.sample_size(10);
    for &n in &TEST_SIZES {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);

        let bp_gens = BulletproofGens::<C>::new(n, 1);
        let G: Vec<C::Point> = bp_gens.share(0).G(n).map(C::affine_to_point).collect();
        let pedersen_gens = PedersenGens::<C>::default();
        let F = pedersen_gens.B;
        let B = pedersen_gens.B_blinding;

        let a: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let b: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
        let (C_commit, r) = commit_witness::<C>(&a, &b, &G, B, F, &mut rng);

        // Build the proof once outside the timed region.
        let proof = LinearProof::<C>::create(
            &mut Transcript::new(b"LinearProofBenchmark"),
            &mut rng,
            &C_commit,
            r,
            a.clone(),
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();
        // Sanity: it must verify before we time it.
        proof
            .verify(
                &mut Transcript::new(b"LinearProofBenchmark"),
                &C_commit,
                &G,
                &F,
                &B,
                b.clone(),
            )
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bench, _| {
            bench.iter_batched(
                || (Transcript::new(b"LinearProofBenchmark"), b.clone()),
                |(mut transcript, b)| {
                    proof
                        .verify(&mut transcript, &C_commit, &G, &F, &B, b)
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    linear_create::<Secp256k1Cycle>(c, "secp256k1");
    linear_create::<Secq256k1Cycle>(c, "secq256k1");
    linear_verify::<Secp256k1Cycle>(c, "secp256k1");
    linear_verify::<Secq256k1Cycle>(c, "secq256k1");
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
