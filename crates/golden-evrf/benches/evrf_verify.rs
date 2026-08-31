//! Table 4 verifier columns over the Secp256k1/Secq256k1 cycle.
//!
//! Two groups per `n_e`:
//!
//! 1. `paper/table-4/Secp256k1-Secq256k1/verifier` runs the production
//!    `DealerProofSystem::verify` on one dealer proof covering `n_e`
//!    receivers.
//! 2. `paper/table-4/Secp256k1-Secq256k1/batch-verification` runs the
//!    production optimized `verify_batch` on `n_e` independent dealer
//!    proofs. A private recording adapter captures the flat proof inputs from
//!    one successful public `complete`; no parsed message or alternate
//!    statement builder is exposed.
//!
//! Setup runs inside `bench_with_input`'s routine body so criterion's regex
//! filter can skip expensive setup for benchmarks the user did not select.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "support_dir/mod.rs"]
mod support;

use codspeed_criterion_compat as criterion;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use golden_core::{DealerProofRef, DealerProofStatement, DealerProofSystem, DkgConfig};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use support::{
    build_config, dealer_proof_fixture, idx, table4_ne_values, SLOW_SAMPLE_SIZE, TABLE4_THRESHOLD,
};

fn evrf_verify_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/Secp256k1-Secq256k1/verifier");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let fixture = dealer_proof_fixture(n_e);
            b.iter(|| {
                fixture
                    .proof_system
                    .verify(&fixture.config, &fixture.statement, &fixture.proof)
                    .unwrap();
            })
        });
    }
    group.finish();
}

struct BatchVerificationFixture {
    config: DkgConfig<Secp256k1GoldenGroup>,
    proof_system: SecpSecqBulletproofs,
    proofs: Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)>,
}

/// Obtain `n_e` independent, canonically ordered dealer proofs through the
/// same opaque completion workflow a receiver uses in Round 1.
fn batch_verification_fixture(n_e: usize) -> BatchVerificationFixture {
    let n = n_e + 1;
    let config = build_config(n, TABLE4_THRESHOLD);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let receiver = idx(n as u32);
    let (own_dealing, peers) = support::cached_round1_setup(&config, &proof_system, receiver);
    let mut proofs =
        support::capture_verified_proofs(&proof_system, &config, receiver, &own_dealing, &peers);
    proofs.retain(|(statement, _)| statement.dealer() != receiver);
    assert_eq!(proofs.len(), n_e);
    BatchVerificationFixture {
        config,
        proof_system,
        proofs,
    }
}

fn evrf_verify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper/table-4/Secp256k1-Secq256k1/batch-verification");
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    for n_e in table4_ne_values() {
        group.bench_with_input(BenchmarkId::from_parameter(n_e), &n_e, |b, &n_e| {
            let fixture = batch_verification_fixture(n_e);
            b.iter(|| {
                let proofs: Vec<_> = fixture
                    .proofs
                    .iter()
                    .map(|(statement, proof)| DealerProofRef { statement, proof })
                    .collect();
                fixture
                    .proof_system
                    .verify_batch(&fixture.config, &proofs)
                    .unwrap();
            })
        });
    }
    group.finish();
}

fn criterion_benches(c: &mut Criterion) {
    evrf_verify_single(c);
    evrf_verify_batch(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
