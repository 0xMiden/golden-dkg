//! Table 4 proof-size columns: wire byte count of one batched eVRF proof
//! ("|pi|") and the concatenated size of `n_e` independent proofs ("n_e
//! proofs"), reported via criterion's `Throughput::Bytes`.
//!
//! Proof bytes come from the batch-native `DealerMessage` values in the
//! checked-in fixture cache. This measures the actual proof representation,
//! including its dealing-batch shape and constant-term policy, without running
//! the prover eagerly, so the bench can report all four paper rows.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use support::{build_config, idx, table4_ne_values, SLOW_SAMPLE_SIZE, TABLE4_THRESHOLD};

/// Wire byte count of one dealer's batch-native proof covering `n_e` receivers.
fn one_dealer_proof_bytes(n_e: usize) -> usize {
    let config = build_config(n_e + 1, TABLE4_THRESHOLD);
    let messages = support::cached_dealer_messages(&config);
    messages[&idx(1)].proof.len()
}

/// Total wire byte count of `n_e` independent dealer proofs.
fn n_independent_proof_byte_sizes_total(n_e: usize) -> usize {
    let n = n_e + 1;
    let config = build_config(n, TABLE4_THRESHOLD);
    let receiver = idx(n as u32);
    let mut messages = support::cached_dealer_messages(&config);
    messages.remove(&receiver);
    assert_eq!(messages.len(), n_e);
    messages.values().map(|message| message.proof.len()).sum()
}

fn evrf_proof_size_single(c: &mut Criterion) {
    for n_e in table4_ne_values() {
        let bytes = one_dealer_proof_bytes(n_e);
        let mut group = c.benchmark_group(format!("eVRF proof-size-single/secp256k1/{n_e}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(bytes)));
        group.finish();
    }
}

fn evrf_proof_size_concat(c: &mut Criterion) {
    for n_e in table4_ne_values() {
        let total = n_independent_proof_byte_sizes_total(n_e);
        let mut group = c.benchmark_group(format!("eVRF proof-size-concat/secp256k1/{n_e}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
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
