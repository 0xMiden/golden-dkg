//! End-to-end DKG integration tests against the paper BLS12-381/Jubjub
//! backend.
//!
//! Drives the public `golden_core::{create_dealing, verify_dealing, complete}`
//! surface bound to `BlsJubjubBackend`, mirroring
//! `crates/golden-evrf/tests/dkg_integration.rs`'s Secp/Secq coverage. Most
//! tests are `#[ignore]` because the backend proves a full R1CS instance per
//! dealing (and this backend's unwindowed additive-ladder gadget is slower
//! per proof than `secp_secq`'s windowed chord gadget — see
//! `crates/golden-evrf/src/paper/bls_jubjub.rs`'s module doc); run via
//! `cargo nextest --run-ignored only`.
//! `single_participant_dkg_completes_without_proving` is the exception: a
//! single-participant (n=1) dealing has no eVRF statement to prove, so it
//! runs unignored.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_bls_jubjub::golden_group::{JubjubGoldenGroup, JubjubScalar};
use golden_core::{
    complete, create_dealing, verify_dealing, DkgConfig, GoldenGroup, GoldenScalar,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_evrf::paper::bls_jubjub::BlsJubjubBackend;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> JubjubScalar {
    JubjubScalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config() -> DkgConfig<JubjubGoldenGroup> {
    let participants = [idx(1), idx(2), idx(3)];
    let registry = ParticipantRegistry::new(
        participants
            .iter()
            .map(|p| (*p, JubjubGoldenGroup::mul_generator(&identity_secret(*p))))
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        2,
        SessionId([42u8; 32]),
        JubjubScalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn single_participant_config() -> DkgConfig<JubjubGoldenGroup> {
    let registry = ParticipantRegistry::new(vec![(
        idx(1),
        JubjubGoldenGroup::mul_generator(&identity_secret(idx(1))),
    )])
    .unwrap();
    DkgConfig::new(
        1,
        SessionId([42u8; 32]),
        JubjubScalar::from_u64(77).unwrap(),
        registry,
    )
    .unwrap()
}

fn assert_dkg_completes(config: DkgConfig<JubjubGoldenGroup>) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let dealings: BTreeMap<_, _> = config
        .registry
        .indexes()
        .map(|dealer| {
            (
                dealer,
                create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
                    dealer,
                    &identity_secret(dealer),
                    &config,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect();

    for dealing in dealings.values() {
        verify_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(&dealing.message, &config).unwrap();
    }

    let participant_count = config.registry.indexes().count();
    let receiver = idx(2);
    let own_dealing = dealings.get(&receiver).unwrap();
    let peer_dealings = dealings
        .iter()
        .filter_map(|(dealer, dealing)| {
            if *dealer == receiver {
                None
            } else {
                Some((*dealer, dealing.message.clone()))
            }
        })
        .collect();
    let output = complete::<JubjubGoldenGroup, BlsJubjubBackend>(
        receiver,
        &identity_secret(receiver),
        own_dealing,
        &peer_dealings,
        &config,
    )
    .unwrap();
    assert_eq!(
        output.public_key_shares[&receiver],
        JubjubGoldenGroup::mul_generator(&output.secret_share.value)
    );
    assert_eq!(output.public_key_shares.len(), participant_count);
}

#[test]
fn single_participant_dkg_completes_without_proving() {
    let config = single_participant_config();
    let dealer = idx(1);
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let dealing = create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    assert!(dealing.message.proof.is_empty());
    assert!(dealing.message.encrypted_shares.is_empty());

    verify_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(&dealing.message, &config).unwrap();

    let output = complete::<JubjubGoldenGroup, BlsJubjubBackend>(
        dealer,
        &identity_secret(dealer),
        &dealing,
        &BTreeMap::new(),
        &config,
    )
    .unwrap();
    assert_eq!(
        output.public_key,
        JubjubGoldenGroup::mul_generator(&output.secret_share.value)
    );
    assert_eq!(output.public_key_shares.len(), 1);
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_completes_with_batched_evrf_backend() {
    assert_dkg_completes(config());
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn dkg_rejects_tampered_encrypted_share() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let config = config();
    let dealer = idx(1);
    let mut dealing = create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    verify_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(&dealing.message, &config).unwrap();

    let receiver = idx(2);
    let entry = dealing.message.encrypted_shares.get_mut(&receiver).unwrap();
    entry.encrypted_share = JubjubScalar::add(&entry.encrypted_share, &JubjubScalar::one());

    let result = verify_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(&dealing.message, &config);
    assert!(
        result.is_err(),
        "tampered dealing must be rejected, got {result:?}"
    );
}

#[test]
fn report_dealer_message_wire_bytes_for_readme() {
    use golden_core::wire::WireEncode;
    let config = config();
    let dealer = idx(1);
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let dealing = create_dealing::<JubjubGoldenGroup, BlsJubjubBackend>(
        dealer,
        &identity_secret(dealer),
        &config,
        &mut rng,
    )
    .unwrap();
    println!(
        "n=3 (threshold=2) dealer message wire bytes = {}",
        dealing.message.to_nested_wire_bytes().len()
    );
}
