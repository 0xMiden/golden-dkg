//! Inner-product argument (IPA) benchmarks.
//!
//! The ancestor `zkcrypto/bulletproofs` keeps `inner_product_proof` private,
//! so it ships no IPP bench (only its `linear_proof` variant). This crate
//! exposes [`bulletproofs_cycle::InnerProductProof`], so we benchmark the
//! classic Bulletproofs inner-product argument directly — create and verify —
//! over both halves of the secp/secq curve cycle.
//!
//! The proof shape mirrors `golden-halo2curves/tests/inner_product_proof.rs`
//! (itself ported from upstream's `test_helper_create(n)`): commitment
//! `P = <a,G> + <b',H> + <a,b> Q` with `G_factors = 1`, `H_factors = y^{-i}`.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support.rs"]
mod support;

use bulletproofs_cycle::cycle::random_scalar;
use bulletproofs_cycle::generators::BulletproofGens;
use bulletproofs_cycle::util::{exp_iter, inner_product};
use bulletproofs_cycle::{Cycle, InnerProductProof};
use core::iter;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use ff::Field;
use merlin::Transcript;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use support::{Secp256k1Cycle, Secq256k1Cycle};

/// Vector lengths swept for create/verify. Powers of two, matching the
/// ancestor's `linear_proof` sweep so the two IPA benches are comparable.
const SIZES: [usize; 5] = [64, 128, 256, 512, 1024];

/// Fixed `Q` base derived from a uniform 64-byte seed (same tag as the IPP
/// tests: b"test point" left-padded to 64 bytes).
fn q_base<C: Cycle>() -> C::Point {
    let mut q_seed = [0u8; 64];
    let tag = b"test point";
    q_seed[..tag.len()].copy_from_slice(tag);
    C::point_hash_from_uniform(&q_seed)
}

/// All IPA inputs for length `n`: generators, bases, witnesses, factors, and
/// the commitment `P`.
struct IppInputs<C: Cycle> {
    G: Vec<C::Point>,
    H: Vec<C::Point>,
    Q: C::Point,
    a: Vec<C::Scalar>,
    b: Vec<C::Scalar>,
    g_factors: Vec<C::Scalar>,
    h_factors: Vec<C::Scalar>,
    P: C::Point,
}

fn ipp_setup<C: Cycle>(n: usize) -> IppInputs<C> {
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    let bp_gens = BulletproofGens::<C>::new(n, 1);
    let G: Vec<C::Point> = bp_gens.share(0).G(n).copied().collect();
    let H: Vec<C::Point> = bp_gens.share(0).H(n).copied().collect();
    let Q = q_base::<C>();

    let a: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
    let b: Vec<C::Scalar> = (0..n).map(|_| random_scalar::<C>(&mut rng)).collect();
    let c = inner_product(&a, &b);

    let g_factors: Vec<C::Scalar> = iter::repeat_n(C::Scalar::ONE, n).collect();
    let y_inv = random_scalar::<C>(&mut rng);
    let h_factors: Vec<C::Scalar> = exp_iter(y_inv).take(n).collect();

    // b' = b ∘ y^{-i}, so P verifies against these factor vectors.
    let b_prime: Vec<C::Scalar> = b
        .iter()
        .zip(exp_iter(y_inv))
        .map(|(bi, yi)| *bi * yi)
        .collect();

    let mut p_scalars: Vec<C::Scalar> = a.clone();
    p_scalars.extend_from_slice(&b_prime);
    p_scalars.push(c);
    let mut p_points: Vec<C::Point> = G.clone();
    p_points.extend_from_slice(&H);
    p_points.push(Q);
    let P = C::vartime_msm(&p_scalars, &p_points);

    IppInputs {
        G,
        H,
        Q,
        a,
        b,
        g_factors,
        h_factors,
        P,
    }
}

/// Time `InnerProductProof::<C>::create`. Inputs are cloned per iteration in
/// the (untimed) setup routine so only `create` itself is measured.
fn ipp_create<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("IPA InnerProductProof::create/{curve}"));
    group.sample_size(10);
    for &n in &SIZES {
        let inputs = ipp_setup::<C>(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || {
                    (
                        Transcript::new(b"innerproducttest"),
                        inputs.G.clone(),
                        inputs.H.clone(),
                        inputs.a.clone(),
                        inputs.b.clone(),
                        inputs.g_factors.clone(),
                        inputs.h_factors.clone(),
                        inputs.Q,
                    )
                },
                |(mut transcript, G, H, a, b, g_factors, h_factors, Q)| {
                    black_box(InnerProductProof::<C>::create(
                        &mut transcript,
                        &Q,
                        &g_factors,
                        &h_factors,
                        G,
                        H,
                        a,
                        b,
                    ))
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Time `InnerProductProof::<C>::verify`. The proof is built once outside the
/// timed region; only verification is measured.
fn ipp_verify<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("IPA InnerProductProof::verify/{curve}"));
    group.sample_size(10);
    for &n in &SIZES {
        let inputs = ipp_setup::<C>(n);

        // Build the proof once outside the timed region.
        let proof = InnerProductProof::<C>::create(
            &mut Transcript::new(b"innerproducttest"),
            &inputs.Q,
            &inputs.g_factors,
            &inputs.h_factors,
            inputs.G.clone(),
            inputs.H.clone(),
            inputs.a.clone(),
            inputs.b.clone(),
        );
        // Sanity: it must verify before we time it.
        proof
            .verify(
                n,
                &mut Transcript::new(b"innerproducttest"),
                inputs.g_factors.iter().copied(),
                inputs.h_factors.iter().copied(),
                &inputs.P,
                &inputs.Q,
                &inputs.G,
                &inputs.H,
            )
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || Transcript::new(b"innerproducttest"),
                |mut transcript| {
                    proof
                        .verify(
                            n,
                            &mut transcript,
                            inputs.g_factors.iter().copied(),
                            inputs.h_factors.iter().copied(),
                            &inputs.P,
                            &inputs.Q,
                            &inputs.G,
                            &inputs.H,
                        )
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    ipp_create::<Secp256k1Cycle>(c, "secp256k1");
    ipp_create::<Secq256k1Cycle>(c, "secq256k1");
    ipp_verify::<Secp256k1Cycle>(c, "secp256k1");
    ipp_verify::<Secq256k1Cycle>(c, "secq256k1");
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
