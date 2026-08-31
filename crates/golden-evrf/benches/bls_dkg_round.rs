//! Table 5 runtime columns: per-participant Round 0 and Round 1 cost for an
//! n-of-n DKG over BLS12-381/Jubjub.
//!
//! - `paper/table-5/BLS12-381-Jubjub/round-0` times `create_dealing` for one
//!   dealer at participant count `n`.
//! - `paper/table-5/BLS12-381-Jubjub/round-1` pre-builds all `n` dealings
//!   outside the timed region, then times `complete` for one receiver.
//!
//! Compare against Table 5 (BLS12-381, zkalc, optimized variant):
//! n=2 -> 0.4s, n=10 -> 2.4s, n=50 -> 13.5s, n=100 -> 35.8s.
//! Our absolute numbers will differ: these are real measurements against a
//! real circuit, not the paper's asymptotic estimate.
//!
//! `GOLDEN_BLS_TABLE5_METRIC=total` measures Round 0 and Round 1 together.
//! `GOLDEN_BLS_TABLE5_N_VALUES` may select a comma-separated row subset.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "bls_support_dir/mod.rs"]
mod support;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use golden_bls_jubjub::golden_group::JubjubGoldenGroup;
use golden_core::{complete, create_dealing};
use golden_evrf::paper::bls_jubjub::BlsJubjubBackend;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{build_config, identity_secret, idx, table5_n_values, BENCH_SEED, SLOW_SAMPLE_SIZE};

/// Per-participant Round 0: one dealer builds its dealing.
fn dkg_round0(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-5/BLS12-381-Jubjub/round-0");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n in table5_n_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let config = build_config(n, n - 1);
            let dealer = idx(1);
            let secret = identity_secret(dealer);
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
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
    let mut group = c.benchmark_group("paper/table-5/BLS12-381-Jubjub/round-1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n in table5_n_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let config = build_config(n, n - 1);
            let receiver = idx(n as u32);
            let secret = identity_secret(receiver);
            let (own_dealing, peer_dealings) = support::cached_round1_setup(&config, receiver);
            complete::<JubjubGoldenGroup, BlsJubjubBackend>(
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
                    complete::<JubjubGoldenGroup, BlsJubjubBackend>(
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

/// Table 5 per-participant runtime: perform this participant's Round 0 and
/// Round 1 work in one measured iteration.
fn dkg_total(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-5/BLS12-381-Jubjub/per-participant-runtime");
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
                    let own_dealing = create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
                        participant,
                        &secret,
                        &config,
                        &mut rng,
                    )
                    .unwrap();
                    complete::<JubjubGoldenGroup, BlsJubjubBackend>(
                        participant,
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
    if std::env::var("GOLDEN_BLS_TABLE5_METRIC").as_deref() == Ok("total") {
        dkg_total(c);
    } else {
        dkg_round0(c);
        dkg_round1(c);
    }
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
