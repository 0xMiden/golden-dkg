//! Joint [Random, Zero] deal/completion; all preparation is outside timed regions.
#![allow(missing_docs, clippy::unwrap_used)]
use codspeed_criterion_compat::{criterion_group, criterion_main, Criterion};
#[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
mod enabled {
    use codspeed_criterion_compat::{BatchSize, Criterion, SamplingMode};
    use golden_core::{
        complete, deal, DealerMessageRef, DealerProofSystem, DkgConfig, DkgGroup, DkgInstanceKind,
        ParticipantIndex, ParticipantRegistry, SessionId,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    pub fn bench<G: DkgGroup, P: DealerProofSystem<G>>(
        criterion: &mut Criterion,
        name: &str,
        prepare: impl FnOnce(&DkgConfig<G>) -> P,
    ) {
        let one = ParticipantIndex::new(1).unwrap();
        let two = ParticipantIndex::new(2).unwrap();
        let first = G::Scalar::from(11);
        let second = G::Scalar::from(22);
        let registry = ParticipantRegistry::<G>::new(vec![
            (one, G::mul_generator(&first)),
            (two, G::mul_generator(&second)),
        ])
        .unwrap();
        let config = DkgConfig::new(
            2,
            SessionId([71; 32]),
            registry,
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap();
        let proofs = prepare(&config);
        let mut rng = ChaCha20Rng::from_seed([31; 32]);
        let own = deal(&proofs, &config, one, &first, &mut rng).unwrap();
        let peer = deal(&proofs, &config, two, &second, &mut rng).unwrap();
        let peers = [DealerMessageRef {
            expected_dealer: two,
            bytes: peer.broadcast_bytes(),
        }];
        let mut group = criterion.benchmark_group(format!("main-golden/{name}/n2-t2-random-zero"));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        group.bench_function("deal", |b| {
            b.iter_batched(
                || ChaCha20Rng::from_seed([37; 32]),
                |mut rng| {
                    std::hint::black_box(deal(&proofs, &config, one, &first, &mut rng).unwrap())
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function("complete", |b| {
            b.iter(|| {
                std::hint::black_box(complete(&proofs, &config, &first, &own, &peers).unwrap())
            })
        });
        group.finish();
    }
}
fn joint(criterion: &mut Criterion) {
    #[cfg(feature = "secp-secq")]
    enabled::bench::<golden_curves::Secp256k1Group, golden_bulletproofs::SecpSecqBulletproofs>(
        criterion,
        "secp-secq",
        |config| golden_bulletproofs::SecpSecqBulletproofs::prepare_for(config).unwrap(),
    );
    #[cfg(feature = "jubjub-bls12-381")]
    enabled::bench::<golden_curves::JubjubGroup, golden_bulletproofs::BlsJubjubBulletproofs>(
        criterion,
        "jubjub-bls12-381",
        |config| golden_bulletproofs::BlsJubjubBulletproofs::prepare_for(config).unwrap(),
    );
    let _ = criterion;
}
criterion_group!(benches, joint);
criterion_main!(benches);
