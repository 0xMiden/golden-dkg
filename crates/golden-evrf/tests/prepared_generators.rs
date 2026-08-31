//! Public persistence coverage for prepared Secp/Secq proof generators.

#![allow(clippy::unwrap_used)]

use golden_core::{
    DkgConfig, DkgInstanceKind, Error, GoldenGroup, GoldenScalar, ParticipantIndex,
    ParticipantRegistry, SessionId,
};
use golden_evrf::paper::secp_secq::{SecpSecqBulletproofs, SecpSecqPreparedGenerators};
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};

fn config() -> DkgConfig<Secp256k1GoldenGroup> {
    let registry = ParticipantRegistry::new(
        [1u32, 2]
            .into_iter()
            .map(|value| {
                let participant = ParticipantIndex::new(value).unwrap();
                let secret = Secp256k1Scalar::from_u64(100 + u64::from(value)).unwrap();
                (participant, Secp256k1GoldenGroup::mul_generator(&secret))
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        1,
        SessionId([71; 32]),
        registry,
        vec![DkgInstanceKind::Random],
    )
    .unwrap()
}

#[test]
fn prepared_generators_round_trip_exactly_and_reject_incomplete_artifacts() {
    let prepared = SecpSecqPreparedGenerators::prepare_for(&config()).unwrap();
    assert!(prepared.capacity() > 0);
    let encoded = prepared.to_persistence_bytes().unwrap();

    let restored = SecpSecqPreparedGenerators::from_persistence_bytes(&encoded).unwrap();
    assert_eq!(restored.capacity(), prepared.capacity());
    assert_eq!(restored.to_persistence_bytes().unwrap(), encoded);
    let _proof_system = SecpSecqBulletproofs::from_prepared(restored);

    assert_eq!(
        SecpSecqPreparedGenerators::from_persistence_bytes(&encoded[..encoded.len() - 1])
            .unwrap_err(),
        Error::MalformedPreparedGenerators
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        SecpSecqPreparedGenerators::from_persistence_bytes(&trailing).unwrap_err(),
        Error::MalformedPreparedGenerators
    );
}
