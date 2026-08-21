//! Table 5 communication column over BLS12-381/Jubjub: per-dealer broadcast
//! message wire size as a function of participant count `n`.
//!
//! Compare against Table 5 (BLS12-381, optimized variant, per participant):
//! n=2 -> 1.7kb, n=10 -> 22kb, n=50 -> 223kb, n=100 -> 699kb.
//! Wire size depends only on the number and byte width of group
//! elements/scalars per receiver, not on the exponentiation gadget, so this
//! column (unlike prove/verify timing) should track the paper's numbers
//! more closely at the same `n` — BLS12-381 group elements are 48 bytes
//! compressed (32 for Jubjub's own `Gin` elements) vs. Secp256k1's 33.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "bls_support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use golden_core::wire::WireEncode;
use support::{build_config, idx, table5_n_values, SLOW_SAMPLE_SIZE};

fn dkg_communication(c: &mut Criterion) {
    for n in table5_n_values() {
        let config = build_config(n, n - 1);
        let dealer = idx(1);
        let messages = support::cached_dealer_messages(&config);
        let bytes = messages[&dealer].to_nested_wire_bytes().len();
        let mut group = c.benchmark_group(format!("dkg-communication/bls12-381-jubjub/{n}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(bytes)));
        group.finish();
    }
}

criterion_group!(benches, dkg_communication);
criterion_main!(benches);
