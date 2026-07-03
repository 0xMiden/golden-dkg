//! End-to-end tests for the batched-dealer paper eVRF relation.
//!
//! These exercise the public `evrf_batched_prove` / `evrf_batched_verify`
//! surface for an arbitrary number of receivers. Each test is marked
//! `#[ignore]` because building the Bulletproofs generators dominates
//! runtime; run via `cargo nextest --run-ignored only`.

#![allow(clippy::unwrap_used)]

use ff::Field;
use golden_evrf::paper::secp_secq::{self as paper, Gin, GinScalar, R1csField};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn make_msg(seed: u64) -> [u8; 32] {
    let mut msg = [0u8; 32];
    msg[..8].copy_from_slice(&seed.to_le_bytes());
    msg
}

fn make_pkjs(rng: &mut ChaCha20Rng, n: usize) -> Vec<Gin> {
    (0..n)
        .map(|_| Gin::generator() * GinScalar::random(&mut *rng))
        .collect()
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_honest_proof_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C1);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(0xABCD);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_batched_verify(&statement, &proof, &mut verify_rng).expect("verify");
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_receiver_pk() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C2);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(1);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.receivers[0].pkj = Gin::generator() * GinScalar::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a swapped receiver PK_j"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_reordered_receivers() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C3);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 3);
    let beta = R1csField::from(7u64);
    let msg = make_msg(2);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.receivers.reverse();
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a reordered receiver list"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_missing_receiver() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C4);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 3);
    let beta = R1csField::from(7u64);
    let msg = make_msg(3);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.receivers.pop();
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a missing receiver"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_beta() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C5);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(4);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.beta = R1csField::from(99u64);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject wrong beta"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_r() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C6);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(5);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let g_out = paper::Gout::generator();
    let mut bad = statement.clone();
    bad.receivers[1].r_point_j = g_out * R1csField::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a swapped R_j"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_msg() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C7);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(6);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.msg[0] ^= 0x01;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a mutated msg"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_proof_replay_across_dealer_keys() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C8);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(7);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

    let sk1_b = GinScalar::random(&mut rng);
    let (bad, _) = paper::testing::build_batched(&msg, sk1_b, &pkjs, beta);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a proof replayed across dealer keys"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_four_receivers_verifies() {
    // Regression for generator sizing: a 4-receiver batch needs more
    // than R1CS_GENS_CAPACITY generators, so the capacity helper must
    // round up to the next power of two above 4 * 8192 = 32768.
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C9);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 4);
    let beta = R1csField::from(7u64);
    let msg = make_msg(8);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof = paper::evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_batched_verify(&statement, &proof, &mut verify_rng).expect("verify");
}
