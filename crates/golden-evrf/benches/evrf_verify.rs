//! Table 4 verifier columns.
//!
//! Two groups per `n_e`:
//!
//! 1. `eVRF verify-single/secp256k1` - `evrf_batched_verify` on ONE proof
//!    covering `n_e` statements. Compare to the paper's "Verifier" column
//!    (per-proof cost, scales with statements batched inside one proof):
//!    n_e=1 -> 0.1s, n_e=9 -> 0.5s, n_e=49 -> 2.5s, n_e=99 -> 4.8s.
//!
//! 2. `eVRF verify-loop/secp256k1` - the DKG receiver's actual Round 1 work:
//!    `verify_dealing` over `n_e` independent dealer messages. This is an
//!    UPPER BOUND on the paper's "Batch Verification" column because the
//!    in-tree `verify_dealing` calls `B::verify_batch` once per dealer with
//!    no cross-proof MSM sharing (Bulletproofs Section 4.6 batch verification
//!    is not implemented in this tree). The paper's sub-linear "Batch
//!    Verification" numbers (0.6s / 6.7s / 22.1s at n_e = 9 / 49 / 99) are
//!    therefore not reproducible without new production code; this group
//!    measures the linear-in-n_e fallback the DKG actually ships today.
//!
//! Setup (proof building) runs inside `bench_with_input`'s routine body so
//! criterion's regex filter can skip the expensive setup for benchmarks the
//! user did not select.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use golden_core::{create_dealing, verify_dealing, DealerMessage, DkgConfig};
use golden_evrf::paper::secp_secq::{evrf_batched_verify, SecpSecqBackend};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use support::{
    build_config, identity_secret, idx, prove_one_batched, BENCH_SEED, NE_VALUES, SLOW_SAMPLE_SIZE,
};

/// Time `evrf_batched_verify` on one precomputed proof covering `n_e`
/// statements. The proof is built once inside the routine body (outside the
/// timed region) so criterion's filter can skip its construction.
fn evrf_verify_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("eVRF verify-single/secp256k1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    for &n_e in NE_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            // Expensive setup runs once per benchmark invocation, only when
            // criterion actually selects this benchmark.
            let (statement, proof) = prove_one_batched(n_e);
            b.iter_batched(
                || ChaCha20Rng::from_seed(BENCH_SEED),
                |mut rng| {
                    evrf_batched_verify(&statement, &proof, &mut rng).unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Build `n_e` independent dealer messages for an `(n_e + 1)`-participant
/// DKG (threshold 1). Each dealer broadcasts one batched proof over its `n_e`
/// peer receivers. The receiver then runs `verify_dealing` on each of the
/// `n_e` peer messages. This loop is what a real DKG receiver does in Round 1.
fn build_n_independent_messages(
    n_e: usize,
) -> (
    DkgConfig<Secp256k1GoldenGroup>,
    BTreeMap<golden_core::ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>>,
) {
    let n = n_e + 1;
    let config = build_config(n, 1);
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let messages: BTreeMap<_, _> = config
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
            (dealer, dealing.message)
        })
        .collect();
    (config, messages)
}

/// Time `verify_dealing` over `n_e` independent dealer messages. This is the
/// receiver's Round 1 verification loop without cross-proof MSM sharing.
fn evrf_verify_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("eVRF verify-loop/secp256k1");
    group.sample_size(SLOW_SAMPLE_SIZE);
    for &n_e in NE_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            // Expensive setup: build `n_e + 1` dealer messages, each carrying
            // one batched proof. Runs only when criterion selects this bench.
            let (config, messages) = build_n_independent_messages(n_e);
            let receiver = idx(n_e as u32 + 1);
            let peer_messages: Vec<_> = messages
                .iter()
                .filter(|(dealer, _)| **dealer != receiver)
                .map(|(_, msg)| msg.clone())
                .collect();
            for msg in &peer_messages {
                verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(msg, &config).unwrap();
            }
            b.iter_batched(
                || peer_messages.clone(),
                |msgs| {
                    for msg in &msgs {
                        verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(msg, &config)
                            .unwrap();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    evrf_verify_single(c);
    evrf_verify_loop(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
