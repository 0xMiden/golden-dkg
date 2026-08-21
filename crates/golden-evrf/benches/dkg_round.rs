//! Table 5 runtime columns: per-participant Round 0 and Round 1 cost for an
//! n-of-n DKG over Secp256k1/Secq256k1.
//!
//! - `paper/table-5/Secp256k1-Secq256k1/round-0` times `create_dealing` for
//!   one dealer at participant count `n`. It includes the batched eVRF prove
//!   over `n - 1` receivers, which dominates.
//! - `paper/table-5/Secp256k1-Secq256k1/round-1` pre-builds all `n` dealings
//!   outside the timed region, then times `complete` for one receiver. This is one
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
//! CodSpeed sets `GOLDEN_TABLE5_METRIC=total` to measure Round 0 and Round 1
//! together, matching the value reported by Table 5. Local runs retain the
//! separate diagnostic measurements. `GOLDEN_TABLE5_N_VALUES` may select a
//! comma-separated row subset.
//!
//! Setup (building `n` proofs for Round 1) runs inside `bench_with_input`'s
//! routine body so criterion's regex filter can skip the expensive setup
//! for benchmarks the user did not select. It is backed by the on-disk
//! fixture cache in `support_dir/fixture_cache.rs`, so only the first run
//! for a given `(n, seed)` pays the full ~100x-Round-0 cost.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use golden_core::{complete, create_dealing};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{
    build_config, identity_secret, idx, legacy_beta, table5_n_values, BENCH_SEED, SLOW_SAMPLE_SIZE,
};

/// Per-participant Round 0: one dealer builds its dealing.
fn dkg_round0(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-5/Secp256k1-Secq256k1/round-0");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n in table5_n_values() {
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
                        dealer,
                        &secret,
                        &config,
                        &legacy_beta(),
                        &mut rng,
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
    let mut group = c.benchmark_group("paper/table-5/Secp256k1-Secq256k1/round-1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n in table5_n_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Expensive setup: build all `n` dealer messages. Backed by the
            // fixture cache (see `support_dir/fixture_cache.rs`), so this is
            // only "expensive" on the first run for a given `(n, seed)`.
            // Runs only when criterion selects this bench.
            let config = build_config(n, n - 1);
            let receiver = idx(n as u32);
            let secret = identity_secret(receiver);
            let (own_dealing, peer_dealings) = support::cached_round1_setup(&config, receiver);
            // Sanity: receiver must complete successfully before timing.
            complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
                receiver,
                &secret,
                &own_dealing,
                &peer_dealings,
                &config,
                &legacy_beta(),
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
                        &legacy_beta(),
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Table 5 per-participant runtime: perform this participant's Round 0 and
/// Round 1 work in one measured iteration. Peer dealings are prepared outside
/// the timed region because their creation is work performed by other
/// participants.
fn dkg_total(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-5/Secp256k1-Secq256k1/per-participant-runtime");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n in table5_n_values() {
        let config = build_config(n, n - 1);
        let participant = idx(n as u32);
        let secret = identity_secret(participant);
        let mut peer_dealings = support::cached_dealer_messages(&config);
        peer_dealings.remove(&participant);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    let own_dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                        participant,
                        &secret,
                        &config,
                        &legacy_beta(),
                        &mut rng,
                    )
                    .unwrap();
                    complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
                        participant,
                        &secret,
                        &own_dealing,
                        &peer_dealings,
                        &config,
                        &legacy_beta(),
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
    if std::env::var("GOLDEN_TABLE5_METRIC").as_deref() == Ok("total") {
        dkg_total(c);
    } else {
        dkg_round0(c);
        dkg_round1(c);
    }
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
