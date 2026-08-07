//! Table 5 runtime columns: per-participant Round 0 and Round 1 cost for an
//! n-of-n DKG over Secp256k1/Secq256k1.
//!
//! - `dkg-round0/secp256k1`: time `create_dealing` for ONE dealer at
//!   participant count `n`. Includes the batched eVRF prove over `n - 1`
//!   receivers, which dominates.
//! - `dkg-round1/secp256k1`: pre-build all `n` dealings outside the timed
//!   region, then time `complete` for ONE receiver. This is one
//!   participant's Round 1 work: verify `n` dealings (including own) and
//!   aggregate the share.
//!
//! Per the paper's Table 5 footnote, "Runtime represents the running time
//! for each participant of performing both Round 0 and Round 1". Sum
//! `round0` and `round1` for the per-participant total; we do not sum
//! inside criterion because the two halves are independent measurements.
//!
//! Compare against Table 5 (BLS12-381, zkalc, optimized variant):
//! n=2 -> 0.4s, n=10 -> 2.4s, n=50 -> 13.5s, n=100 -> 35.8s.
//! Direction: dominated by the batched eVRF proof, so this scales roughly
//! linearly in `n`. Our absolute numbers will differ from the paper because
//! of the curve choice and because we measure a real implementation rather
//! than an asymptotic estimate.
//!
//! Setup (`round0_all_dealings` builds `n` proofs for Round 1) runs inside
//! `bench_with_input`'s routine body so criterion's regex filter can skip
//! the expensive setup for benchmarks the user did not select. At `n = 100`
//! Round 1 setup is roughly 100x the Round 0 cost, i.e. about an hour; use
//! the filter to run only small `n` unless you have time.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use golden_core::{complete, create_dealing, DealerMessage};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{
    build_config, identity_secret, idx, round0_all_dealings, BENCH_SEED, N_VALUES, SLOW_SAMPLE_SIZE,
};

/// Per-participant Round 0: one dealer builds its dealing.
fn dkg_round0(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg-round0/secp256k1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    for &n in N_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // n-of-n: threshold = n - 1, matching Table 5. Setup is cheap
            // (one config); the timed region pays the prove cost per iter.
            let config = build_config(n, n - 1);
            let dealer = idx(1);
            let secret = identity_secret(dealer);
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                        dealer, &secret, &config, &mut rng,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Per-participant Round 1: one receiver verifies all `n` dealings and
/// aggregates its share.
fn dkg_round1(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg-round1/secp256k1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    for &n in N_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Expensive setup: build all `n` dealer messages. At n=100 this
            // is ~100x the per-dealer Round 0 cost. Runs only when criterion
            // selects this bench.
            let config = build_config(n, n - 1);
            let dealings = round0_all_dealings(&config);
            let receiver = idx(n as u32);
            let secret = identity_secret(receiver);
            let own_dealing = dealings.get(&receiver).cloned().unwrap();
            let peer_dealings: BTreeMap<
                golden_core::ParticipantIndex,
                DealerMessage<Secp256k1GoldenGroup>,
            > = dealings
                .iter()
                .filter_map(|(dealer, dealing)| {
                    if *dealer == receiver {
                        None
                    } else {
                        Some((*dealer, dealing.message.clone()))
                    }
                })
                .collect();
            // Sanity: receiver must complete successfully before timing.
            complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
                receiver,
                &secret,
                &own_dealing,
                &peer_dealings,
                &config,
            )
            .unwrap();
            b.iter_batched(
                || (),
                |_| {
                    complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
                        receiver,
                        &secret,
                        &own_dealing,
                        &peer_dealings,
                        &config,
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
    dkg_round0(c);
    dkg_round1(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
