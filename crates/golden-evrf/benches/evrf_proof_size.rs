//! Table 4 proof-size columns.
//!
//! Reports the wire byte count of one batched eVRF proof (the "|pi|"
//! column) and the concatenated size of `n_e` independent proofs (the
//! "n_e proofs" column) via criterion's `Throughput::Bytes`, which renders
//! as bytes/sec and is trivially divisible back to bytes.
//!
//! Wire bytes come from `create_dealing` -> `DkgDealing.message.proof`
//! (a `SecpSecqProof(Vec<u8>)`). This is exactly what each dealer broadcasts
//! and what the wire codec serializes, so it matches the paper's "|pi|"
//! definition.
//!
//! Sweep is limited to `n_e in {1, 9}` because each parameter requires
//! running the Bulletproofs prover (the `evrf_prove` bench reports that
//! cost: about 8s per proof at `n_e = 1` and ~20s at `n_e = 9` on this
//! backend). The single-proof size scales logarithmically in `n_e`, so the
//! two points already show the curve; extrapolating to `n_e = 49, 99` is
//! straightforward. The paper's full-sweep sizes (Table 4) are: |pi| =
//! 1.5kb / 1.9kb / 2.1kb / 2.2kb at n_e = 1 / 9 / 49 / 99.
//!
//! Unlike the timing benches, proof-size setup runs eagerly (one group per
//! `n_e`, each building its proof before registering the bench). This is
//! fine because the sweep is small and setup is seconds, not minutes. The
//! eager setup also lets us annotate the group with the exact byte count
//! via `Throughput::Bytes`, which criterion renders as bytes/sec and is
//! trivially divisible back to bytes.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use golden_core::create_dealing;
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{build_config, identity_secret, idx, BENCH_SEED, SLOW_SAMPLE_SIZE};

/// Subset of `NE_VALUES` for which we actually build proofs. Larger `n_e`
/// takes minutes per proof and adds little size information because the
/// single-proof size grows only logarithmically in `n_e`.
const NE_SIZE_SWEEP: &[usize] = &[1, 9];

/// Build one dealer's proof bytes for an `n`-participant DKG. The proof
/// covers `n - 1` receivers.
fn one_dealer_proof_bytes(n: usize) -> usize {
    let config = build_config(n, 1);
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let dealer = idx(1);
    let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    dealing.message.proof.0.len()
}

/// Build `n_e` independent dealer proofs in an `(n_e + 1)`-participant DKG.
fn n_independent_proof_byte_sizes_total(n_e: usize) -> usize {
    let n = n_e + 1;
    let config = build_config(n, 1);
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            dealing.message.proof.0.len()
        })
        .sum()
}

fn evrf_proof_size_single(c: &mut Criterion) {
    for &n_e in NE_SIZE_SWEEP {
        let bytes = one_dealer_proof_bytes(n_e + 1);
        let mut group = c.benchmark_group(format!("eVRF proof-size-single/secp256k1/{n_e}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(bytes)));
        group.finish();
    }
}

fn evrf_proof_size_concat(c: &mut Criterion) {
    for &n_e in NE_SIZE_SWEEP {
        let total = n_independent_proof_byte_sizes_total(n_e);
        let mut group = c.benchmark_group(format!("eVRF proof-size-concat/secp256k1/{n_e}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.throughput(Throughput::Bytes(total as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(total)));
        group.finish();
    }
}

fn criterion_benches(c: &mut Criterion) {
    evrf_proof_size_single(c);
    evrf_proof_size_concat(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
