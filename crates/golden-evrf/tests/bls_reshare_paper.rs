//! Group-key reshares with real BLS12-381/Jubjub paper proofs.
//!
//! Every test is `#[ignore]` because each dealing proves a full R1CS instance;
//! run via `cargo nextest --run-ignored only`.

#![allow(clippy::unwrap_used)]

#[path = "support/reshare_paper.rs"]
mod support;

use golden_bls_jubjub::golden_group::JubjubGoldenGroup;
use golden_evrf::paper::bls_jubjub::{BatchedEvrfPublicParams, BlsJubjubBackend};

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn single_receiver_reshare_requires_proofs() {
    support::single_receiver_reshare_requires_proofs::<JubjubGoldenGroup, BlsJubjubBackend>();
}

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn three_receiver_reshare_raises_the_threshold() {
    support::three_receiver_reshare_raises_the_threshold::<JubjubGoldenGroup, BlsJubjubBackend>(
        BatchedEvrfPublicParams::batched_proof_wire_len,
    );
}

#[test]
#[ignore = "slow: proves real reshare dealings; run via --run-ignored only"]
fn forced_zero_share_chains() {
    support::forced_zero_share_chains::<JubjubGoldenGroup, BlsJubjubBackend>();
}
