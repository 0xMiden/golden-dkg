//! Group-key reshares with real BLS12-381/Jubjub paper proofs.

#![allow(clippy::unwrap_used)]

#[path = "support/reshare_paper.rs"]
mod support;

use golden_bls_jubjub::golden_group::JubjubGoldenGroup;
use golden_evrf::paper::bls_jubjub::{BatchedEvrfPublicParams, BlsJubjubBackend};

#[test]
fn single_receiver_reshare_requires_proofs() {
    support::single_receiver_reshare_requires_proofs::<JubjubGoldenGroup, BlsJubjubBackend>();
}

#[test]
fn three_receiver_reshare_raises_the_threshold() {
    support::three_receiver_reshare_raises_the_threshold::<JubjubGoldenGroup, BlsJubjubBackend>(
        BatchedEvrfPublicParams::batched_proof_wire_len,
    );
}

#[test]
fn forced_zero_share_chains() {
    support::forced_zero_share_chains::<JubjubGoldenGroup, BlsJubjubBackend>();
}
