//! Paper Table 4 batched proving and verification benchmarks.
//!
//! Public parameter setup and the verification fixture proof are prepared
//! before Criterion starts timing the proof operations.

#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use golden_evrf::paper::secp_secq::{
    self as paper, BatchedEvrfPublicParams, BatchedEvrfStatement, BatchedEvrfWitness, Gin,
    GinScalar, R1csField,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

struct Fixture {
    params: BatchedEvrfPublicParams,
    statement: BatchedEvrfStatement,
    witness: BatchedEvrfWitness,
    proof: Vec<u8>,
}

fn fixture(receiver_count: usize) -> Fixture {
    let sk1 = GinScalar::from(3u64);
    let pkjs = (1..=receiver_count)
        .map(|index| Gin::generator() * GinScalar::from((index as u64) + 10))
        .collect::<Vec<_>>();
    let msg = [0x42; 32];
    let (statement, witness) =
        paper::testing::build_batched(&msg, sk1, &pkjs, R1csField::from(7u64));
    let params = BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len())
        .expect("valid public parameter shape");
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C_0004);
    let proof =
        paper::evrf_batched_prove(&params, &statement, &witness, &mut rng).expect("fixture proof");
    Fixture {
        params,
        statement,
        witness,
        proof,
    }
}

fn bench_table4(c: &mut Criterion) {
    for receiver_count in [1usize, 4, 9] {
        let fixture = fixture(receiver_count);
        let mut prove_group = c.benchmark_group("paper Table 4 batched prove");
        prove_group.sample_size(10);
        prove_group.bench_function(format!("{receiver_count} receivers"), |b| {
            b.iter_batched(
                || ChaCha20Rng::seed_from_u64(0xBA7C_0004),
                |mut rng| {
                    paper::evrf_batched_prove(
                        &fixture.params,
                        &fixture.statement,
                        &fixture.witness,
                        &mut rng,
                    )
                    .expect("proof")
                },
                BatchSize::LargeInput,
            );
        });
        prove_group.finish();

        let mut verify_group = c.benchmark_group("paper Table 4 batched verify");
        verify_group.sample_size(10);
        verify_group.bench_function(format!("{receiver_count} receivers"), |b| {
            b.iter_batched(
                || ChaCha20Rng::seed_from_u64(0xCAFE_0004),
                |mut rng| {
                    paper::evrf_batched_verify(
                        &fixture.params,
                        &fixture.statement,
                        &fixture.proof,
                        &mut rng,
                    )
                    .expect("verification")
                },
                BatchSize::LargeInput,
            );
        });
        verify_group.finish();
    }
}

criterion_group!(benches, bench_table4);
criterion_main!(benches);
