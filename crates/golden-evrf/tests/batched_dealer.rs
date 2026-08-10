//! End-to-end tests for the batched-dealer paper eVRF relation.
//!
//! These exercise the public `evrf_batched_prove` / `evrf_batched_verify`
//! surface for an arbitrary number of receivers. Tests that build full proofs
//! are marked `#[ignore]` because building the Bulletproofs generators
//! dominates runtime; run them via `cargo nextest --run-ignored only`.

#![allow(clippy::unwrap_used)]

use ff::Field;
use golden_evrf::paper::secp_secq::{self as paper, Gin, GinScalar, R1csField};
use group::Group;
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

fn public_params(
    statement: &paper::BatchedEvrfStatement,
) -> std::sync::Arc<paper::BatchedEvrfPublicParams> {
    paper::BatchedEvrfPublicParams::shared(statement.threshold, statement.receivers.len())
        .expect("public parameter setup")
}

#[test]
#[ignore = "slow: pins the complete batched dealer proof stream"]
fn evrf_batched_dealer_matches_v4_vector() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C_0002);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 1);
    let beta = R1csField::from(7u64);
    let msg = make_msg(0xABCD);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    assert_eq!(
        proof.as_slice(),
        include_bytes!("vectors/paper-batched-dealer-v4.bin")
    );
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_batched_verify(
        &public_params(&statement),
        &statement,
        &proof,
        &mut verify_rng,
    )
    .expect("verify");
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_batched_verify(
        &public_params(&statement),
        &statement,
        &proof,
        &mut verify_rng,
    )
    .expect("verify");
}

#[test]
fn evrf_batched_dealer_rejects_identity_share_commitment() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C10);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 1);
    let beta = R1csField::from(7u64);
    let msg = make_msg(0xABCE);
    let (mut statement, mut witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let pad = statement.receivers[0].encrypted_share - witness.shares[0];
    witness.shares[0] = GinScalar::ZERO;
    witness.coefficient_scalars = vec![GinScalar::ZERO];
    statement.threshold = 1;
    statement.commitment_coefficients = vec![Gin::identity()];
    statement.receivers[0].share_commitment = Gin::identity();
    statement.receivers[0].encrypted_share = pad;

    assert!(
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .is_err(),
        "batched proof should reject identity share commitments before circuit construction"
    );
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers[0].pkj = Gin::generator() * GinScalar::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers.reverse();
    bad.statement_roots.reverse();
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers.pop();
    bad.statement_roots.pop();
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.beta = R1csField::from(99u64);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject wrong beta"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_pad_commitment() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C6);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(5);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers[1].pad_commitment = Gin::generator() * GinScalar::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a swapped pad commitment"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_share_commitment() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C61);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(5);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers[1].share_commitment = Gin::generator() * GinScalar::random(&mut rng);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a swapped share commitment"
    );
}

#[test]
fn evrf_batched_dealer_rejects_wrong_polynomial_coefficient_witness() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C63);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(5);
    let (statement, mut witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    witness.coefficient_scalars[0] += GinScalar::ONE;
    assert!(
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng).is_err(),
        "prover must reject polynomial coefficients that do not open the public Feldman commitments"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_encrypted_share() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C62);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(5);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.receivers[1].encrypted_share += GinScalar::from(1u64);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a swapped encrypted share"
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.msg[0] ^= 0x01;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a mutated msg"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_rejects_wrong_statement_root() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C70);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 2);
    let beta = R1csField::from(7u64);
    let msg = make_msg(6);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let mut bad = statement.clone();
    bad.statement_roots[0][0] ^= 0x80;
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a proof replayed under a different statement root"
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

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");

    let sk1_b = GinScalar::random(&mut rng);
    let (bad, _) = paper::testing::build_batched(&msg, sk1_b, &pkjs, beta);
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_batched_verify(&public_params(&statement), &bad, &proof, &mut verify_rng)
            .is_err(),
        "verifier must reject a proof replayed across dealer keys"
    );
}

#[test]
#[ignore = "slow: requires building large BulletproofGens; run via --run-ignored only"]
fn evrf_batched_dealer_four_receivers_verifies() {
    // Regression for generator sizing: this two-coefficient, four-receiver
    // shape uses 51,031 multipliers and therefore needs 65,536 generators.
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C9);
    let sk1 = GinScalar::random(&mut rng);
    let pkjs = make_pkjs(&mut rng, 4);
    let beta = R1csField::from(7u64);
    let msg = make_msg(8);
    let (statement, witness) = paper::testing::build_batched(&msg, sk1, &pkjs, beta);

    let proof =
        paper::evrf_batched_prove(&public_params(&statement), &statement, &witness, &mut rng)
            .expect("prove");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_batched_verify(
        &public_params(&statement),
        &statement,
        &proof,
        &mut verify_rng,
    )
    .expect("verify");
}

#[test]
#[ignore = "slow: builds two full dealer proofs for cross-proof verification"]
fn evrf_cross_proof_batch_verifies_and_rejects_mismatched_pairs() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C_BA7C);
    let pkjs = make_pkjs(&mut rng, 1);
    let beta = R1csField::from(7u64);
    let (first_statement, first_witness) =
        paper::testing::build_batched(&make_msg(10), GinScalar::from(3u64), &pkjs, beta);
    let (second_statement, second_witness) =
        paper::testing::build_batched(&make_msg(11), GinScalar::from(5u64), &pkjs, beta);
    let params = public_params(&first_statement);
    let first_proof =
        paper::evrf_batched_prove(&params, &first_statement, &first_witness, &mut rng)
            .expect("first proof");
    let second_proof =
        paper::evrf_batched_prove(&params, &second_statement, &second_witness, &mut rng)
            .expect("second proof");

    paper::evrf_batched_verify_many(
        &params,
        &[
            (&first_statement, &first_proof),
            (&second_statement, &second_proof),
        ],
    )
    .expect("honest batch");
    paper::evrf_batched_verify_many(
        &params,
        &[
            (&second_statement, &second_proof),
            (&first_statement, &first_proof),
        ],
    )
    .expect("reordered honest pairs");
    assert!(paper::evrf_batched_verify_many(
        &params,
        &[
            (&first_statement, &first_proof),
            (&first_statement, &second_proof),
        ]
    )
    .is_err());
}
