# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Rust workspace for distributed key generation, verifiable randomness, and
context bound threshold encryption over a generic group abstraction. The
current tree implements Golden DKG, EHTDH1, a Secp256k1/Secq256k1 eVRF
backend, and the Bulletproofs R1CS layer used by that backend.

The workspace has six crates. All crates are published together and require
Rust 1.93 or later.

* `golden-core`: Shamir secret sharing, Feldman commitments, DKG messages,
  transcript binding, and the curve-agnostic `EvrfProofBackend` trait that
  connects the DKG to a concrete proof system.
* `golden-evrf`: the eVRF proof backends. Includes a Secp256k1/Secq256k1
  R1CS backend that proves the full Golden eVRF relation end-to-end via
  `bulletproofs-cycle`, plus a share-opening prototype backend used for
  plumbing tests.
* `golden-rustcrypto`: P-256 and secp256k1 `GoldenGroup` adapters backed by
  the RustCrypto crates, used by the prototype backend and tests.
* `golden-ehtdh1`: context-bound threshold encryption over Golden DKG output.
  It binds each decryption share to the setup, ciphertext, and caller context.
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
cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-ehtdh1/prototype-bridge,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1
cargo test --workspace --doc
```

## Licensing

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
