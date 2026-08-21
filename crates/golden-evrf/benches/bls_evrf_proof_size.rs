//! Table 4 proof-size columns over BLS12-381/Jubjub: wire byte count of one
//! batched eVRF proof ("|pi|") and the concatenated size of `n_e`
//! independent proofs ("n_e proofs"), reported via criterion's
//! `Throughput::Bytes`.
//!
//! Every batched-eVRF proof here is single-phase too, so wire length is an
//! exact function of the padded circuit size alone —
//! `BatchedEvrfPublicParams::batched_proof_wire_len` computes it without
//! building a proof or statement.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "bls_support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use golden_evrf::paper::bls_jubjub::BatchedEvrfPublicParams;
use support::{table4_ne_values, SLOW_SAMPLE_SIZE, TABLE4_THRESHOLD};

/// Wire byte count of one dealer's proof covering `n_e` receivers.
fn one_dealer_proof_bytes(n_e: usize) -> usize {
    BatchedEvrfPublicParams::batched_proof_wire_len(TABLE4_THRESHOLD, n_e)
        .expect("valid batched circuit shape")
}

fn evrf_proof_size_single(c: &mut Criterion) {
    for n_e in table4_ne_values() {
        let bytes = one_dealer_proof_bytes(n_e);
        let mut group = c.benchmark_group(format!("eVRF proof-size-single/bls12-381-jubjub/{n_e}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(bytes)));
        group.finish();
    }
}

fn evrf_proof_size_concat(c: &mut Criterion) {
    for n_e in table4_ne_values() {
        let total = n_e * one_dealer_proof_bytes(n_e);
        let mut group = c.benchmark_group(format!("eVRF proof-size-concat/bls12-381-jubjub/{n_e}"));
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
