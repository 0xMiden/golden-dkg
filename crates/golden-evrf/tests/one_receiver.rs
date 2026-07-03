//! End-to-end tests for the single-receiver paper eVRF relation.
//!
//! Exercises the public `evrf_prove` / `evrf_verify` surface against
//! honestly built statements and a battery of tampered variants.

#![allow(clippy::unwrap_used)]

use ff::Field;
use golden_evrf::paper::secp_secq::{
    self as paper, Gin, GinScalar, R1csField, SecpSecqEvrfStatement, SecpSecqEvrfWitness,
};
use halo2curves::secq256k1::Secq256k1;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

fn make_msg(seed: u64) -> [u8; 32] {
    let mut msg = [0u8; 32];
    msg[..8].copy_from_slice(&seed.to_le_bytes());
    msg
}

#[test]
fn evrf_one_receiver_honest_proof_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xFEED);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(0xBEE_u64);
    let msg = make_msg(0xCAFEBABE);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_verify(&statement, &proof, &mut verify_rng).expect("verify");
}

#[test]
fn evrf_one_receiver_rejects_wrong_pk2() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0001);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(42u64);
    let msg = make_msg(1);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    let wrong_pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let mut bad: SecpSecqEvrfStatement = statement.clone();
    bad.pk2 = wrong_pk2;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject wrong receiver PK_2"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_beta() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_BEEF);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(7u64);
    let msg = make_msg(2);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.beta = R1csField::from(99u64);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject wrong beta"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_r() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0002);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(3u64);
    let msg = make_msg(3);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    let g_out = Secq256k1::generator();
    let mut bad = statement.clone();
    bad.r_point = g_out * R1csField::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject wrong R"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_transcript_domain() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0003);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(5u64);
    let msg = make_msg(4);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    // Swap the prover's Pedersen commitment to `k` so the verifier's
    // recomputed commitment can't match what the R1CS proof carries.
    let mut bad_proof = proof.clone();
    let wrong_k = R1csField::random(&mut rng);
    bad_proof.k_commitment = paper::testing::commit_k_for_test(wrong_k);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&statement, &bad_proof, &mut verify_rng).is_err(),
        "verifier must reject a proof whose k_commitment is swapped"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_sk1() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0004);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(11u64);
    let msg = make_msg(5);
    let (statement, _witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let wrong_sk1 = GinScalar::random(&mut rng);
    let bad_witness = SecpSecqEvrfWitness { sk1: wrong_sk1 };
    assert!(
        paper::evrf_prove(&statement, &bad_witness, &mut rng).is_err(),
        "prover must refuse to prove with a sk1 inconsistent with S"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_msg() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0005);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(13u64);
    let msg = make_msg(6);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    let mut bad = statement.clone();
    bad.msg[0] ^= 0x01;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a proof whose msg has been mutated"
    );
}

#[test]
fn evrf_one_receiver_rejects_wrong_s() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0006);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(17u64);
    let msg = make_msg(7);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");

    let wrong_s = pk2 * GinScalar::random(&mut rng);
    let mut bad = statement.clone();
    bad.s = wrong_s;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
        "verifier must reject a proof whose S has been swapped"
    );
}
