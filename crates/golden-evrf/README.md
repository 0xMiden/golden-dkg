# golden-evrf

Verifiable random function proof backends for Golden distributed key
generation.

This crate provides the paper backed Secp256k1 and Secq256k1 proof backend and
the fast prototype backend used by the [Golden DKG](https://github.com/0xMiden/golden-dkg)
workspace.

Backends implement the batch-native `EvrfProofBackend` interface. One nested
statement preserves the configured dealing order and the canonical receiver
order within each dealing; `prove_batch` emits one joint proof for the complete
dealer message. The paper backend supports arbitrary ordered mixtures of
random and zero sharings, including valid identity share commitments produced
by zero polynomials.
