//! Pinned plain DKG and reshare roots and message bytes on P-256.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, complete_reshare, create_dealing, create_reshare_dealing, wire::to_wire_bytes,
    DkgConfig, DkgDealing, DkgOutput, GoldenGroup, GoldenScalar, IdentityKeyProof,
    ParticipantIndex, ParticipantRegistry, ReshareConfig, ResharePredecessor, SessionId,
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

fn registry(
    participants: impl IntoIterator<Item = u32>,
    secret: impl Fn(ParticipantIndex) -> P256Scalar,
) -> ParticipantRegistry<P256Backend> {
    ParticipantRegistry::new(
        participants
            .into_iter()
            .map(|value| {
                let participant = ParticipantIndex::new(value).unwrap();
                let identity_secret = secret(participant);
                (
                    participant,
                    P256Backend::mul_generator(&identity_secret),
                    IdentityKeyProof::prove(&identity_secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn config() -> DkgConfig<P256Backend> {
    let registry = registry(1..=3, identity_secret);
    DkgConfig::new(
        2,
        SessionId([0x5a; 32]),
        P256Scalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn plain_dealings(
    config: &DkgConfig<P256Backend>,
) -> BTreeMap<ParticipantIndex, DkgDealing<P256Backend>> {
    let mut rng = ChaCha20Rng::from_seed([0x3c; 32]);
    config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing::<P256Backend, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                &mut rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn plain_output(
    config: &DkgConfig<P256Backend>,
    dealings: &BTreeMap<ParticipantIndex, DkgDealing<P256Backend>>,
    receiver: ParticipantIndex,
) -> DkgOutput<P256Backend> {
    let peer_dealings = dealings
        .iter()
        .filter(|(dealer, _)| **dealer != receiver)
        .map(|(dealer, dealing)| (*dealer, dealing.message.clone()))
        .collect();
    complete::<P256Backend, ShareOpeningBackend>(
        receiver,
        &identity_secret(receiver),
        &dealings[&receiver],
        &peer_dealings,
        config,
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

    let dealings = plain_dealings(&config);
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
        let output = plain_output(&config, &dealings, receiver);
        assert_eq!(hex(&output.transcript_root), COMPLETION_ROOT);
        assert_eq!(
            hex(P256Backend::encode_element(&output.public_key).as_ref()),
            PUBLIC_KEY
        );
    }
}

fn receiver_secret(receiver: ParticipantIndex) -> P256Scalar {
    P256Scalar::from_u64(200 + u64::from(receiver.get())).unwrap()
}

// Deterministic reshare of the plain DKG above from dealers 1 and 3 to four
// receivers at t = 3, over the prototype backend. Do not regenerate these to
// absorb a change to the reshare paths.
const RESHARE_CONFIG_ROOT: &str =
    "2aed9d42d3b27392983deb9e2e23569b5be2f92cb3afa1a943345023e5be86e6";
const RESHARE_CONFIG_SHA256: &str =
    "88a3328b6d4d6e48dc975ede007a3ba64076c548d66a38e05149a93fb9015b02";
const RESHARE_DEALING_ROOTS: [&str; 2] = [
    "c07522388fc2eb045188bcafaf320e5d634de49c67df321537d203ff50740189",
    "c4a558a5393183d5e498cd18152a3f2f7edb803bc6418d541cb5fe7909da1df6",
];
const RESHARE_DEALER_MESSAGE_SHA256: [&str; 2] = [
    "2f090a5bebb0c246e25097adc663e78e18cfaabca53da91b2b17319b454418db",
    "6f8d6c6d574e0b4a97076cf895c2a620724578556303ebdf51dbda8e071e2e68",
];
const RESHARE_COMPLETION_ROOT: &str =
    "108fc1b9ee7e9a86d6459cb4e749dbbabfb21a1ff237ed7ab03d6d33037c8393";

#[test]
fn reshare_wire_vectors_are_pinned() {
    let plain = config();
    let plain_dealings = plain_dealings(&plain);
    let predecessor = ResharePredecessor::from_dkg_output(
        &plain,
        &plain_output(&plain, &plain_dealings, ParticipantIndex::new(1).unwrap()),
    )
    .unwrap();
    let config = ReshareConfig::new(
        3,
        1,
        SessionId([0x6b; 32]),
        P256Scalar::from_u64(78).unwrap(),
        registry([1, 3], identity_secret),
        registry(1..=4, receiver_secret),
        predecessor,
    )
    .unwrap();
    assert_eq!(hex(&config.root()), RESHARE_CONFIG_ROOT);
    assert_eq!(
        hex(&Sha256::digest(to_wire_bytes(&config))),
        RESHARE_CONFIG_SHA256
    );

    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    let dealings: BTreeMap<_, _> = config
        .dealers()
        .indexes()
        .map(|dealer| {
            let message = create_reshare_dealing::<P256Backend, ShareOpeningBackend>(
                dealer,
                &identity_secret(dealer),
                &plain_output(&plain, &plain_dealings, dealer).secret_share,
                &config,
                &mut rng,
            )
            .unwrap();
            (dealer, message)
        })
        .collect();
    let dealing_roots: Vec<_> = dealings
        .values()
        .map(|message| hex(&message.transcript_root))
        .collect();
    assert_eq!(dealing_roots, RESHARE_DEALING_ROOTS);
    let message_digests: Vec<_> = dealings
        .values()
        .map(|message| hex(&Sha256::digest(to_wire_bytes(message))))
        .collect();
    assert_eq!(message_digests, RESHARE_DEALER_MESSAGE_SHA256);

    for receiver in config.receivers().indexes() {
        let output = complete_reshare::<P256Backend, ShareOpeningBackend>(
            receiver,
            &receiver_secret(receiver),
            &dealings,
            &config,
        )
        .unwrap();
        assert_eq!(hex(&output.transcript_root), RESHARE_COMPLETION_ROOT);
        assert_eq!(&output.public_key, config.predecessor().public_key());
        assert_eq!(
            hex(P256Backend::encode_element(&output.public_key).as_ref()),
            PUBLIC_KEY
        );
    }
}
