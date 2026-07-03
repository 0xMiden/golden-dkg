# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Rust workspace for distributed key generation and verifiable randomness over a
generic group abstraction. The long-term goal is a paper-aligned Golden DKG
and eVRF; the current tree implements the core DKG, a Secp256k1/Secq256k1
curve-cycle eVRF backend, and the Bulletproofs R1CS layer it relies on.

The workspace has five crates. All are `publish = false` and expect
`rust-version = "1.86"`.

* `golden-core`: Shamir secret sharing, Feldman commitments, DKG messages,
  transcript binding, and the curve-agnostic `EvrfProofBackend` trait that
  connects the DKG to a concrete proof system.
* `golden-evrf`: the eVRF proof backends. Includes a Secp256k1/Secq256k1
  R1CS backend that proves the full Golden eVRF relation end-to-end via
  `bulletproofs-cycle`, plus a share-opening prototype backend used for
  plumbing tests.
* `golden-rustcrypto`: P-256 and secp256k1 `GoldenGroup` adapters backed by
  the RustCrypto crates, used by the prototype backend and tests.
* `bulletproofs-cycle`: a minimal fork of `zkcrypto/bulletproofs` 5.0.1
  with the Ristretto backend replaced by a `Cycle` trait over zkcrypto
  `group`/`ff`. Range-proof, MPC, and serialization paths were stripped;
  only the R1CS prover/verifier and inner-product proof remain. The
  `bulletproofs-compat` feature opts into upstream Pedersen-generators
  domain separation for byte-parity testing against `zkcrypto/bulletproofs`.
* `golden-halo2curves`: `Cycle` impls for the `halo2curves`
  Secp256k1/Secq256k1 curve cycle, plus the Secp256k1 `GoldenGroup`
  adapter used by the Secp/Secq eVRF backend.

## Useful checks

```bash
cargo fmt --all --check
cargo clippy --all --benches --tests --examples --all-features --exclude bulletproofs-cycle -- -D warnings
cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1
cargo test --workspace --doc
```

## Licensing

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
