//! Table 5 communication column: per-dealer broadcast message wire size as
//! a function of participant count `n`.
//!
//! Uses `golden_core::wire::WireEncode::to_nested_wire_bytes` on a real
//! `DealerMessage` produced by `create_dealing`. The reported throughput
//! (via `Throughput::Bytes`) is the wire byte count of one dealer's
//! broadcast. Per-participant receive cost is `n - 1` peer broadcasts plus
//! the participant's own broadcast (i.e. multiply by `n`).
//!
//! Each parameter requires building one `DealerMessage` via `create_dealing`
//! (the Round 0 cost). Sweep is limited to `n in {2, 10}`; larger `n` takes
//! minutes per setup and adds little because the per-dealer wire size grows
//! linearly in `n`. Extrapolate to larger `n` from the linear fit.
//!
//! Compare against Table 5 (BLS12-381, optimized variant, per participant):
//! n=2 -> 1.7kb, n=10 -> 22kb, n=50 -> 223kb, n=100 -> 699kb.
//! Direction: dominated by the `n - 1` per-receiver `EncryptedShare` entries
//! (each carrying two group elements and one scalar), so it grows roughly
//! linearly in `n` for one dealer. Absolute numbers will differ from the
//! paper because Secp256k1 group elements are 33 bytes compressed vs 48 for
//! BLS12-381.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use golden_core::wire::WireEncode;
use support::{build_config, idx, SLOW_SAMPLE_SIZE};

/// Subset of `N_VALUES` for which setup is cheap enough to run eagerly.
/// Building one dealer message at `n = 100` takes ~36s; the wire-size curve
/// is linear in `n`, so two points suffice.
const N_COMM_SWEEP: &[usize] = &[2, 10];

fn dkg_communication(c: &mut Criterion) {
    for &n in N_COMM_SWEEP {
        let config = build_config(n, n - 1);
        let dealer = idx(1);
        let messages = support::cached_dealer_messages(&config);
        let bytes = messages[&dealer].to_nested_wire_bytes().len();
        let mut group = c.benchmark_group(format!("dkg-communication/secp256k1/{n}"));
        group.sample_size(SLOW_SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function("size", |b| b.iter(|| criterion::black_box(bytes)));
        group.finish();
    }
}

criterion_group!(benches, dkg_communication);
criterion_main!(benches);
