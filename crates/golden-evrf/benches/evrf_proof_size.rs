//! Table 4 proof-size columns: wire byte count of one batched eVRF proof
//! ("|pi|") and the concatenated size of `n_e` independent proofs ("n_e
//! proofs"), reported via criterion's `Throughput::Bytes`.
//!
//! Proof lengths are captured from `DealerProofSystem::prove` while producing
//! the checked-in opaque-message fixtures. Fixture loading binds each recorded
//! length and digest to the proof suffix core observes during `complete`, so
//! this still measures the actual production proof representation without
//! exposing a parsed dealer message.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use support::{build_config, idx, table4_ne_values, SLOW_SAMPLE_SIZE, TABLE4_THRESHOLD};

/// Wire byte count of one dealer's batch-native proof covering `n_e` receivers.
fn one_dealer_proof_bytes(n_e: usize) -> usize {
    let config = build_config(n_e + 1, TABLE4_THRESHOLD);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let proof_lengths = support::cached_proof_lengths(&config, &proof_system);
    proof_lengths[&idx(1)]
}

/// Total wire byte count of `n_e` independent dealer proofs.
fn n_independent_proof_byte_sizes_total(n_e: usize) -> usize {
    let n = n_e + 1;
    let config = build_config(n, TABLE4_THRESHOLD);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let receiver = idx(n as u32);
    let mut proof_lengths = support::cached_proof_lengths(&config, &proof_system);
    proof_lengths.remove(&receiver);
    assert_eq!(proof_lengths.len(), n_e);
    proof_lengths.values().sum()
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
