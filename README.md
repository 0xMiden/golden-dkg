# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Rust workspace for distributed key generation, verifiable randomness, and
context bound threshold encryption over a generic group abstraction. The
current tree implements Golden DKG, EHTDH1, a Secp256k1/Secq256k1 Main Golden
proof system, and its Bulletproofs R1CS layer.

The two protocol implementations follow these papers.

* **Golden DKG.** Benedikt Bünz, Kevin Choi, and Chelsea Komlo,
  “[Golden: Lightweight Non-Interactive Distributed Key Generation](https://eprint.iacr.org/2025/1924),”
  Cryptology ePrint Archive, Paper 2025/1924, 2025.
* **EHTDH1.** Dan Boneh, Benedikt Bünz, Kartik Nayak, Lior Rotem, and Victor
  Shoup, “[Context-Dependent Threshold Decryption and its Applications](https://eprint.iacr.org/2025/279),”
  Cryptology ePrint Archive, Paper 2025/279, 2025.

The DKG API is batch native. A configuration may request one random sharing,
one zero sharing, or an arbitrary nonempty ordered mixture of both. Each dealer
uses `deal` once and broadcasts only the resulting opaque bytes. `complete`
parses, validates, verifies, decrypts, and aggregates the whole candidate set
atomically, returning ordered outputs only when every dealing succeeds.

The workspace has six crates. All crates are published together and require
Rust 1.93 or later.

* `golden-core`: batch-native Shamir secret sharing, Feldman commitments, DKG
  configuration, opaque dealer messages, transcript binding, and the stateful
  `DealerProofSystem` seam used by `deal` and `complete`.
* `golden-evrf`: `SecpSecqBulletproofs`, which proves the full Main Golden
  relation end-to-end via `bulletproofs-cycle`, plus explicit reusable and
  persistable `SecpSecqPreparedGenerators`. A revealed-witness implementation
  exists only behind the non-default `insecure-revealed-witness` test feature.
* `golden-rustcrypto`: P-256 and secp256k1 `GoldenGroup` adapters backed by
  the RustCrypto crates.
* `golden-ehtdh1`: context-bound threshold encryption over Golden DKG output.
  Its setup bridge maps exactly `[Random, Zero]` to the decryption and context
  sharings, requires a nonidentity decryption aggregate key and identity
  context aggregate key, and binds the configuration and completion roots into
  the setup context used to bind each share to its ciphertext and caller
  context.
* `bulletproofs-cycle`: a minimal fork of `zkcrypto/bulletproofs` 5.0.1
  with the Ristretto group replaced by a `Cycle` trait over zkcrypto
  `group`/`ff`. Range-proof, MPC, and serialization paths were stripped;
  only the R1CS prover/verifier and inner-product proof remain. The
  `bulletproofs-compat` feature opts into upstream Pedersen-generators
  domain separation for byte-parity testing against `zkcrypto/bulletproofs`.
* `golden-halo2curves`: `Cycle` impls for the `halo2curves`
  Secp256k1/Secq256k1 curve cycle, plus the Secp256k1 `GoldenGroup`
  adapter used by the Secp/Secq proof system.

## Security model

Main Golden targets static corruptions of at most `t - 1` participants in the
ideal eVRF/ZK hybrid and random-oracle setting, with a consistent authenticated
registry/setup, authenticated broadcast semantics, and the paper's
additive-bias key-generation functionality. This implementation does not claim
adaptive security, fully unbiased key generation, or security with aborts.
The authenticated deployment process admitting a registry entry is assumed to
establish knowledge of its identity secret; core validates and binds the public
key but carries no separate proof-of-knowledge artifact. The protocol-wide
beta is sampled without bias in the full curve base field from the fixed ASCII
string `golden-dkg/main-golden-beta/v1` under explicit domain-separated
random-oracle framing. It may be zero and is neither caller- nor
session/configuration-sampled setup state.

Arbitrary ordered mixtures of Random and Zero sharings are a repository
extension. They are not attributed directly to Golden Theorem 3; a dedicated
composition review remains a release/security-claim gate and does not reopen
the fixed-beta instantiation.

EHTDH1 has its own assumptions: static corruption of fewer than the threshold
participants, the random-oracle model, the LOMDH assumption, and semantic
security of the selected symmetric cipher. It does not claim
adaptive-corruption security, and Golden setup retains the separate assumptions
above.

Prepared generators and ordinary Serde/Miden DKG values are trusted application
persistence, never dealer-message wire formats. Restoration validates their
structure and canonical encodings; the deployment must authenticate the bytes
before restoration.

## Performance

For performance-sensitive workloads, use the `optimized` profile. The
Criterion/CodSpeed suite mirrors the shapes of Tables 4 and 5 from the Golden
DKG paper over the Secp256k1/Secq256k1 cycle:

* Table 4 targets one joint dealer proof over `n_e` receivers and measures
  `DealerProofSystem::{prove, verify, verify_batch}` plus the exact proof suffix
  produced by the opaque workflow.
* Table 5 targets `(n - 1)`-of-`n` configurations and measures `deal`,
  `complete`, their per-participant total, and opaque broadcast size. Prepared
  generators and peer-dealing construction stay outside the timed regions.

The numeric results previously printed here described the removed legacy proof
framing and static APIs. They were retired with the hard compatibility cut
rather than being presented as measurements of the new stateful workflow. Run
the migrated benches (or the CodSpeed workflow) to produce current results.

## Useful checks

```bash
cargo fmt --all --check
cargo clippy --all --benches --tests --examples --all-features --exclude bulletproofs-cycle -- -D warnings
cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-ehtdh1/halo2curves-secp256k1,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1
cargo test --workspace --doc
cargo run -p golden-evrf --profile optimized --example check_bench_fixtures --features halo2curves-secp256k1,parallel,serde
```

## Licensing

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
