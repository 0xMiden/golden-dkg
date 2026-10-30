//! Pinned plain DKG roots and dealer message bytes on P-256.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, create_dealing, wire::to_wire_bytes, DkgConfig, GoldenGroup, GoldenScalar,
    IdentityKeyProof, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
    P256Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config() -> DkgConfig<P256Backend> {
    let registry = ParticipantRegistry::new(
        (1..=3)
            .map(|value| {
                let participant = ParticipantIndex::new(value).unwrap();
                let identity_secret = identity_secret(participant);
                (
                    participant,
                    P256Backend::mul_generator(&identity_secret),
                    IdentityKeyProof::prove(&identity_secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        2,
        SessionId([0x5a; 32]),
        P256Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

// Deterministic plain n = 3, t = 2 DKG over the prototype backend. Do not
// regenerate these to absorb a change to the dealing, verification or
// completion paths: plain DKG bytes must stay stable.
const REGISTRY_ROOT: &str = "987a281e3ba24f9f7837d5a6d17a1aed60c172a250bc825c936913186a59ad36";
const DEALING_ROOTS: [&str; 3] = [
    "467110b1d28e32029daa6c035f022e9ba1403e7e1fce9d20e71d78edf0e273c1",
    "bdfe077e925f48bcc86738e5e1ab6dc434a6cb8c37591bb5c8a416f335fa2fad",
    "1545e12ed0c649327d15fac799ab3d0329283b241d1ad0020ff7b871197672e0",
];
const DEALER_MESSAGE_SHA256: [&str; 3] = [
    "4575270c582bd864441cd1ee8fb4e4af540fe19800153dc15521494e0f190c17",
    "feb45ab78bac3538f4d3ea2533e8b25bd0a5eead471d00be9a2c72e2116f8f2f",
    "bd197578c7107dd7d163679d72eaf23cdc1a5676b86b5f1f0360894404326a96",
];
const COMPLETION_ROOT: &str = "4fb6e9530b5eab868a609b34607e12fc187a0b4dc042c9eba4f76d481367d010";
const PUBLIC_KEY: &str = "02f5cf52a104bd192fe3907d4f7cc345f2a9a58fe2beb4b2f87982887f69bbb8ea";

#[test]
fn plain_dkg_wire_vectors_are_pinned() {
    let config = config();
    assert_eq!(hex(&config.registry.root()), REGISTRY_ROOT);

    let mut rng = ChaCha20Rng::from_seed([0x3c; 32]);
    let dealings: BTreeMap<_, _> = config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect();
    let dealing_roots: Vec<_> = dealings
        .values()
        .map(|dealing| hex(&dealing.message.transcript_root))
        .collect();
    assert_eq!(dealing_roots, DEALING_ROOTS);
    let message_digests: Vec<_> = dealings
        .values()
        .map(|dealing| hex(&Sha256::digest(to_wire_bytes(&dealing.message))))
        .collect();
    assert_eq!(message_digests, DEALER_MESSAGE_SHA256);

    for receiver in config.registry.indexes() {
        let peer_dealings = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != receiver)
            .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
            .collect();
        let output = complete::<P256Backend, ShareOpeningBackend>(
            receiver,
            &identity_secret(receiver),
            &dealings[&receiver],
            &peer_dealings,
            &config,
        )
        .unwrap();
        assert_eq!(hex(&output.transcript_root), COMPLETION_ROOT);
        assert_eq!(
            hex(P256Backend::encode_element(&output.public_key).as_ref()),
            PUBLIC_KEY
        );
    }
}
