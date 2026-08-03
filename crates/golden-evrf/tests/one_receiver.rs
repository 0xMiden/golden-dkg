//! End-to-end tests for the single-receiver paper eVRF relation.
//!
//! Exercises the public `evrf_prove` / `evrf_verify` surface against
//! honestly built statements and a battery of tampered variants.

#![allow(clippy::unwrap_used)]

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_evrf::paper::secp_secq::{
    self as paper, Gin, GinScalar, R1csCycle, R1csField, SecpSecqEvrfStatement, SecpSecqEvrfWitness,
};
use golden_halo2curves::Secp256k1Cycle;
use group::{Curve, Group};
use halo2curves::{secq256k1::Secq256k1, CurveAffine};
use merlin::Transcript;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const ONE_RECEIVER_PROOF_ID: &[u8] = b"golden-paper-evrf-one-receiver-v2";

fn append_point<C: Cycle>(transcript: &mut Transcript, label: &'static [u8], point: &C::Point) {
    let compressed = C::point_compress(point);
    transcript.append_message(label, C::compressed_as_bytes(&compressed));
}

fn cp_challenge_checkpoint(
    proof_id: &'static [u8],
    statement: &SecpSecqEvrfStatement,
    proof: &[u8],
    first_label: &'static [u8],
    reverse_nonce_order: bool,
) -> [u8; 64] {
    let mut transcript = Transcript::new(proof_id);
    transcript.append_message(b"statement.msg", &statement.msg);
    for (label, point) in [
        (b"statement.pk1".as_slice(), &statement.pk1),
        (b"statement.pk2".as_slice(), &statement.pk2),
        (b"statement.s".as_slice(), &statement.s),
        (b"statement.h1".as_slice(), &statement.h1),
        (b"statement.h2".as_slice(), &statement.h2),
        (b"statement.t1".as_slice(), &statement.t1),
        (b"statement.t2".as_slice(), &statement.t2),
    ] {
        append_point::<Secp256k1Cycle>(&mut transcript, label, point);
    }
    append_point::<R1csCycle>(&mut transcript, b"statement.r", &statement.r_point);
    transcript.append_message(
        b"statement.beta",
        &R1csCycle::scalar_to_canonical(&statement.beta),
    );

    let proof_id_len = u32::from_be_bytes(proof[..4].try_into().unwrap()) as usize;
    let cursor = 4 + proof_id_len;
    let point_bytes = Secp256k1Cycle::COMPRESSED_BYTES;
    let r1 = &proof[cursor..cursor + point_bytes];
    let r2 = &proof[cursor + point_bytes..cursor + 2 * point_bytes];
    if reverse_nonce_order {
        transcript.append_message(b"cp.r2", r2);
        transcript.append_message(first_label, r1);
    } else {
        transcript.append_message(first_label, r1);
        transcript.append_message(b"cp.r2", r2);
    }
    let mut checkpoint = [0u8; 64];
    transcript.challenge_bytes(b"cp.challenge", &mut checkpoint);
    checkpoint
}

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
    assert_eq!(
        proof.as_slice(),
        include_bytes!("vectors/paper-one-receiver-v2.bin")
    );
    let checkpoint =
        cp_challenge_checkpoint(ONE_RECEIVER_PROOF_ID, &statement, &proof, b"cp.r1", false);
    assert_eq!(
        checkpoint,
        [
            222, 248, 232, 123, 15, 152, 48, 49, 16, 48, 125, 227, 238, 69, 86, 18, 249, 213, 255,
            207, 58, 51, 71, 90, 116, 29, 79, 102, 31, 168, 121, 73, 138, 143, 118, 234, 226, 12,
            174, 245, 14, 217, 107, 107, 151, 117, 225, 235, 149, 63, 10, 186, 85, 21, 220, 208,
            70, 220, 42, 83, 94, 104, 79, 107,
        ]
    );

    let mut changed_statement = statement.clone();
    changed_statement.msg[0] ^= 1;
    let mut changed_message = proof.clone();
    let header_len = 4 + ONE_RECEIVER_PROOF_ID.len();
    changed_message[header_len] ^= 1;
    for variant in [
        cp_challenge_checkpoint(
            b"golden-paper-evrf-one-receiver-v2-alternate",
            &statement,
            &proof,
            b"cp.r1",
            false,
        ),
        cp_challenge_checkpoint(
            ONE_RECEIVER_PROOF_ID,
            &changed_statement,
            &proof,
            b"cp.r1",
            false,
        ),
        cp_challenge_checkpoint(
            ONE_RECEIVER_PROOF_ID,
            &statement,
            &changed_message,
            b"cp.r1",
            false,
        ),
        cp_challenge_checkpoint(
            ONE_RECEIVER_PROOF_ID,
            &statement,
            &proof,
            b"cp.renamed-r1",
            false,
        ),
        cp_challenge_checkpoint(ONE_RECEIVER_PROOF_ID, &statement, &proof, b"cp.r1", true),
    ] {
        assert_ne!(variant, checkpoint);
    }

    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_verify(&statement, &proof, &mut verify_rng).expect("verify");
}

#[test]
fn evrf_one_receiver_zero_output_proof_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let msg = make_msg(0);
    let (zero_beta_statement, _) =
        paper::testing::build_statement_witness(&msg, sk1, pk2, R1csField::ZERO);
    let t1 = zero_beta_statement.t1.to_affine();
    let t2 = zero_beta_statement.t2.to_affine();
    let t1_x = *t1.coordinates().expect("T1 coordinates").x();
    let t2_x = *t2.coordinates().expect("T2 coordinates").x();
    let beta = -t2_x * t1_x.invert().expect("nonzero T1 x-coordinate");
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);
    assert!(bool::from(statement.r_point.is_identity()));

    let proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove zero output");
    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    paper::evrf_verify(&statement, &proof, &mut verify_rng).expect("verify zero output");
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
fn evrf_one_receiver_rejects_wrong_proof_id() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0003);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(5u64);
    let msg = make_msg(4);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let mut proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");
    proof[4] ^= 0x01;

    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&statement, &proof, &mut verify_rng).is_err(),
        "verifier must reject a mismatched proof ID"
    );
}

#[test]
fn evrf_one_receiver_rejects_malformed_nested_frame() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0007);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(19u64);
    let msg = make_msg(8);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let mut proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");
    let proof_id_len = u32::from_be_bytes(proof[..4].try_into().expect("proof ID length")) as usize;
    let cp_bytes = 2 * Secp256k1Cycle::COMPRESSED_BYTES + 32;
    let nested_len_offset = 4 + proof_id_len + cp_bytes;
    proof[nested_len_offset..nested_len_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());

    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&statement, &proof, &mut verify_rng).is_err(),
        "verifier must reject an overflowing nested-frame length"
    );
}

#[test]
fn evrf_one_receiver_rejects_trailing_bytes() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0008);
    let sk1 = GinScalar::random(&mut rng);
    let pk2 = Gin::generator() * GinScalar::random(&mut rng);
    let beta = R1csField::from(23u64);
    let msg = make_msg(9);
    let (statement, witness) = paper::testing::build_statement_witness(&msg, sk1, pk2, beta);

    let mut proof = paper::evrf_prove(&statement, &witness, &mut rng).expect("prove");
    proof.push(0);

    let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    assert!(
        paper::evrf_verify(&statement, &proof, &mut verify_rng).is_err(),
        "verifier must reject bytes after the final DLOG response"
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
