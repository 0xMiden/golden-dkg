//! Group-key reshares with real Secp/Secq paper proofs.
//!
//! Every test is `#[ignore]` because each dealing proves a full R1CS instance;
//! run via `cargo nextest --run-ignored only`.

#![allow(clippy::unwrap_used)]

#[path = "support/reshare_paper.rs"]
mod support;

use golden_evrf::paper::secp_secq::{BatchedEvrfPublicParams, SecpSecqBackend};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn single_receiver_reshare_requires_proofs() {
    support::single_receiver_reshare_requires_proofs::<Secp256k1GoldenGroup, SecpSecqBackend>();
}

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn three_receiver_reshare_raises_the_threshold() {
    support::three_receiver_reshare_raises_the_threshold::<Secp256k1GoldenGroup, SecpSecqBackend>(
        BatchedEvrfPublicParams::batched_proof_wire_len,
    );
}

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn forced_zero_share_chains() {
    support::forced_zero_share_chains::<Secp256k1GoldenGroup, SecpSecqBackend>();
}
