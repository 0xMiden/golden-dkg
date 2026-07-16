//! R1CS k-shuffle benchmarks.
//!
//! Ported from `zkcrypto/bulletproofs 5.0.1/benches/r1cs.rs`, cycle-abstracted
//! over [`bulletproofs_cycle::Cycle`] and run over both halves of the secp/secq
//! curve cycle. Proves that an output vector is a permutation of an input
//! vector via the shuffle gadget from `bulletproofs 5.0.0/tests/r1cs.rs`.
//!
//! As in the ancestor, the `ShuffleProof` gadget is copied into the bench
//! harness rather than shared with the test code (criterion requires a separate
//! `harness = false` binary). The gadget body matches the cycle-abstracted port
//! in `golden-halo2curves/tests/r1cs.rs`.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::type_complexity)]

#[path = "support.rs"]
mod support;

use bulletproofs_cycle::cycle::random_scalar;
use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
use bulletproofs_cycle::r1cs::{
    ConstraintSystem, Prover, R1CSError, RandomizableConstraintSystem, RandomizedConstraintSystem,
    Variable, Verifier,
};
use bulletproofs_cycle::{Cycle, R1CSProof};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use merlin::Transcript;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use support::{Secp256k1Cycle, Secq256k1Cycle};

/// Binary logarithm of maximum shuffle size (matches the ancestor).
const LG_MAX_SHUFFLE_SIZE: usize = 10;
/// Maximum shuffle size to benchmark.
const MAX_SHUFFLE_SIZE: usize = 1 << LG_MAX_SHUFFLE_SIZE;

/// Shuffle sizes swept: powers of two `2^1 ..= 2^LG_MAX_SHUFFLE_SIZE`, matching
/// the ancestor's `(1..=LG_MAX_SHUFFLE_SIZE).map(|i| 1 << i)`.
fn shuffle_sizes() -> Vec<usize> {
    (1..=LG_MAX_SHUFFLE_SIZE).map(|i| 1 << i).collect()
}

/// A proof-of-shuffle.
struct ShuffleProof<C: Cycle>(R1CSProof<C>);

impl<C: Cycle> ShuffleProof<C> {
    /// Shuffle gadget: constrains `y` to be a permutation of `x` via the
    /// product-of-differences trick with a random challenge `z`.
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

            // Make last x multiplier for i = k-1 and k-2
            let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

            // Make multipliers for x from i == [0, k-3]
            let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
                o
            });

            // Make last y multiplier for i = k-1 and k-2
            let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

            // Make multipliers for y from i == [0, k-3]
            let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
                o
            });

            // Constrain last x mul output and last y mul output to be equal
            cs.constrain(first_mulx_out - first_muly_out);

            Ok(())
        })
    }

    /// Construct a proof that `output` is a permutation of `input`.
    /// Returns `(proof, input_commitments, output_commitments)`.
    fn prove(
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        transcript: Transcript,
        rng: &mut ChaCha20Rng,
        input: &[C::Scalar],
        output: &[C::Scalar],
    ) -> Result<(ShuffleProof<C>, Vec<C::Compressed>, Vec<C::Compressed>), R1CSError> {
        let k = input.len();
        let mut transcript = transcript;
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

    /// Verify a `ShuffleProof`.
    fn verify(
        &self,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        transcript: Transcript,
        rng: &mut ChaCha20Rng,
        input_commitments: &[C::Compressed],
        output_commitments: &[C::Compressed],
    ) -> Result<(), R1CSError> {
        let k = input_commitments.len();
        let mut transcript = transcript;
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

/// Generate a shuffled `(input, output)` pair of length `k`, plus a fresh RNG.
fn shuffled_pair<C: Cycle>(k: usize) -> (Vec<C::Scalar>, Vec<C::Scalar>, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let input: Vec<C::Scalar> = (0..k).map(|_| C::Scalar::from(rng.next_u64())).collect();
    let mut output = input.clone();
    // Fisher-Yates shuffle (rand::SliceRandom would pull in the rand facade;
    // we already have rand_core), matching the r1cs test.
    for i in (1..output.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        output.swap(i, j);
    }
    (input, output, rng)
}

/// Time `ShuffleProof::<C>::prove`. Input/output generation and generator
/// construction happen outside the timed region; only proving is measured.
fn shuffle_prove<C: Cycle>(c: &mut Criterion, curve: &str) {
    let pc_gens = PedersenGens::<C>::default();
    let bp_gens = BulletproofGens::<C>::new(2 * MAX_SHUFFLE_SIZE, 1);

    let mut group = c.benchmark_group(format!("R1CS k-shuffle prove/{curve}"));
    // Larger shuffle sizes are long; keep the sample size small, mirroring the
    // ancestor's config.
    group.sample_size(10);
    for &k in &shuffle_sizes() {
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |bench, &k| {
            bench.iter_batched(
                || {
                    let (input, output, rng) = shuffled_pair::<C>(k);
                    (Transcript::new(b"ShuffleBenchmark"), rng, input, output)
                },
                |(transcript, mut rng, input, output)| {
                    ShuffleProof::<C>::prove(
                        &pc_gens, &bp_gens, transcript, &mut rng, &input, &output,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Time `ShuffleProof::<C>::verify`. The proof is built once outside the timed
/// region; only verification is measured.
fn shuffle_verify<C: Cycle>(c: &mut Criterion, curve: &str) {
    let pc_gens = PedersenGens::<C>::default();
    let bp_gens = BulletproofGens::<C>::new(2 * MAX_SHUFFLE_SIZE, 1);

    let mut group = c.benchmark_group(format!("R1CS k-shuffle verify/{curve}"));
    group.sample_size(10);
    for &k in &shuffle_sizes() {
        // Build the proof once outside the timed region.
        let (proof, input_commitments, output_commitments) = {
            let (input, output, mut rng) = shuffled_pair::<C>(k);
            ShuffleProof::<C>::prove(
                &pc_gens,
                &bp_gens,
                Transcript::new(b"ShuffleBenchmark"),
                &mut rng,
                &input,
                &output,
            )
            .unwrap()
        };
        // Sanity: the proof must verify before we time it.
        proof
            .verify(
                &pc_gens,
                &bp_gens,
                Transcript::new(b"ShuffleBenchmark"),
                &mut ChaCha20Rng::from_seed([7u8; 32]),
                &input_commitments,
                &output_commitments,
            )
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |bench, _| {
            bench.iter_batched(
                || {
                    (
                        Transcript::new(b"ShuffleBenchmark"),
                        ChaCha20Rng::from_seed([7u8; 32]),
                    )
                },
                |(transcript, mut rng)| {
                    proof
                        .verify(
                            &pc_gens,
                            &bp_gens,
                            transcript,
                            &mut rng,
                            &input_commitments,
                            &output_commitments,
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
    shuffle_prove::<Secp256k1Cycle>(c, "secp256k1");
    shuffle_prove::<Secq256k1Cycle>(c, "secq256k1");
    shuffle_verify::<Secp256k1Cycle>(c, "secp256k1");
    shuffle_verify::<Secq256k1Cycle>(c, "secq256k1");
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
