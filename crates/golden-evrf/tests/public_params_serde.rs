//! Serialization coverage for reusable batched public parameters.

#![allow(missing_docs)]

use bulletproofs_cycle::BulletproofGens;
use golden_evrf::paper::secp_secq::{BatchedEvrfPublicParams, R1csCycle};

#[test]
fn public_parameters_roundtrip_without_regeneration() {
    let params = BatchedEvrfPublicParams::setup(1, 1, 1).expect("valid public parameter shape");
    let encoded = postcard::to_allocvec(&params).expect("serialize public parameters");
    let decoded: BatchedEvrfPublicParams =
        postcard::from_bytes(&encoded).expect("deserialize public parameters");
    let reencoded = postcard::to_allocvec(&decoded).expect("reserialize public parameters");

    assert_eq!(decoded.threshold(), params.threshold());
    assert_eq!(decoded.dealing_count(), params.dealing_count());
    assert_eq!(decoded.receiver_count(), params.receiver_count());
    assert_eq!(decoded.multiplier_count(), params.multiplier_count());
    assert_eq!(decoded.gens_capacity(), params.gens_capacity());
    assert_eq!(reencoded, encoded);
    assert!(
        postcard::from_bytes::<BatchedEvrfPublicParams>(&encoded[..encoded.len() - 1]).is_err()
    );
}

#[test]
fn public_parameters_reject_wrong_generator_capacity() {
    #[derive(serde::Serialize)]
    struct Repr {
        threshold: usize,
        dealing_count: usize,
        receiver_count: usize,
        bp_gens: BulletproofGens<R1csCycle>,
    }

    let encoded = postcard::to_allocvec(&Repr {
        threshold: 1,
        dealing_count: 1,
        receiver_count: 1,
        bp_gens: BulletproofGens::new(1, 1),
    })
    .expect("serialize malformed public parameters");

    assert!(postcard::from_bytes::<BatchedEvrfPublicParams>(&encoded).is_err());
}
