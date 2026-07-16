//! Pedersen + Bulletproofs generators micro-benchmarks.
//!
//! Ported from `zkcrypto/bulletproofs 5.0.1/benches/generators.rs`, cycle-
//! abstracted over [`bulletproofs_cycle::Cycle`] and run over both halves of
//! the secp/secq curve cycle via the upstream `halo2curves` backend.
//!
//! Per curve, measures three things:
//!   * `PedersenGens::default()` — deriving the blinding base `B_blinding`
//!     (one SHAKE256 hash-to-curve).
//!   * `PedersenGens::commit()` — a single Pedersen commitment (a 2-element
//!     variable-time MSM).
//!   * `BulletproofGens::new(n,1)` — constructing a large generator set of
//!     `n` G/H pairs (`2n` hash-to-curves), the dominant setup cost for any
//!     proof.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support.rs"]
mod support;

use bulletproofs_cycle::cycle::random_scalar;
use bulletproofs_cycle::generators::{BulletproofGens, PedersenGens};
use bulletproofs_cycle::Cycle;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use support::{Secp256k1Cycle, Secq256k1Cycle};

/// Generator counts swept for `BulletproofGens::new`: powers of two 1..=1024,
/// matching the ancestor's `(0..10).map(|i| 2 << i)` plus the n=1 base case.
const BP_GENS_SIZES: [usize; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// Time `PedersenGens::<C>::default()` — the `B_blinding` derivation.
fn pedersen_default<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("PedersenGens::default/{curve}"));
    group.bench_function("default", |b| {
        b.iter(|| black_box(PedersenGens::<C>::default()))
    });
    group.finish();
}

/// Time a single `PedersenGens::commit(value, blinding)`.
fn pedersen_commit<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let gens = PedersenGens::<C>::default();
    let value = random_scalar::<C>(&mut rng);
    let blinding = random_scalar::<C>(&mut rng);

    let mut group = c.benchmark_group(format!("PedersenGens::commit/{curve}"));
    group.bench_function("commit", |b| {
        b.iter(|| black_box(gens.commit(value, blinding)))
    });
    group.finish();
}

/// Time `BulletproofGens::<C>::new(n, 1)` across generator counts.
fn bp_gens_new<C: Cycle>(c: &mut Criterion, curve: &str) {
    let mut group = c.benchmark_group(format!("BulletproofGens::new/{curve}"));
    // At n=1024 this does 2048 hash-to-curves; keep the sample size small so
    // the sweep finishes quickly, mirroring the ancestor's config.
    group.sample_size(10);
    for &n in &BP_GENS_SIZES {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(BulletproofGens::<C>::new(n, 1)))
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    pedersen_default::<Secp256k1Cycle>(c, "secp256k1");
    pedersen_default::<Secq256k1Cycle>(c, "secq256k1");
    pedersen_commit::<Secp256k1Cycle>(c, "secp256k1");
    pedersen_commit::<Secq256k1Cycle>(c, "secq256k1");
    bp_gens_new::<Secp256k1Cycle>(c, "secp256k1");
    bp_gens_new::<Secq256k1Cycle>(c, "secq256k1");
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
