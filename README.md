# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Rust workspace for distributed key generation, verifiable randomness, and
context bound threshold encryption over a generic group abstraction. The
current tree implements Golden DKG, EHTDH1, a Secp256k1/Secq256k1 eVRF
backend, and the Bulletproofs R1CS layer used by that backend.

The two protocol implementations follow these papers.

* **Golden DKG.** Benedikt Bünz, Kevin Choi, and Chelsea Komlo,
  “[Golden: Lightweight Non-Interactive Distributed Key Generation](https://eprint.iacr.org/2025/1924),”
  Cryptology ePrint Archive, Paper 2025/1924, 2025.
* **EHTDH1.** Dan Boneh, Benedikt Bünz, Kartik Nayak, Lior Rotem, and Victor
  Shoup, “[Context-Dependent Threshold Decryption and its Applications](https://eprint.iacr.org/2025/279),”
  Cryptology ePrint Archive, Paper 2025/279, 2025.

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

## Performance

For performance sensitive workloads, one can use the `optimized` profile when compiling.

The following tables replicate Tables 4 and 5 from the Golden DKG paper.
All measurements are **real wall-clock timings** (criterion, flat sampling,
10 samples) over the **Secp256k1/Secq256k1 curve cycle**, not the paper's
zkalc estimates for BLS12-381.  The eVRF proof backend uses
`bulletproofs-cycle` R1CS over the halo2curves Secp256k1/Secq256k1 cycle.

Benchmarked on an **AMD Ryzen 9 9950X** (16 cores / 32 threads, up to
5.76 GHz) with the `optimized` profile (`lto = "thin"`, `codegen-units = 1`).

### Table 4 — eVRF performance (Secp256k1/Secq256k1)

`n_e` is the number of receiver statements covered by one batched proof.
“Prover” times the Bulletproofs R1CS prover only.  “Verifier” times a
single `evrf_batched_verify`.  “Batch verification” times `verify_dealings`
across `n_e` independent dealer messages (the receiver's Round 1 work).
`|π|` is the wire size of one batched proof; “n_e proofs” is the
concatenated size of `n_e` independent proofs.

| n_e | Prover     | Verifier  | Batch verification | \|π\| (single) | n_e proofs (concat) |
|-----|------------|-----------|--------------------|----------------|---------------------|
| 1   | 406 ms     | 36.2 ms   | 39.4 ms            | 1.4 kb         | 1.4 kb              |
| 9   | 1.63 s     | 149 ms    | 757 ms             | 1.5 kb         | 13.7 kb             |
| 49  | 11.5 s     | 975 ms    | 23.2 s             | 1.7 kb         | 81.0 kb             |
| 99  | 22.8 s     | 1.77 s    | —                  | 1.7 kb         | 170.2 kb            |

Every batched-eVRF proof is single-phase (the relation never defers
constraints via `specify_randomized_constraints`), so its wire length is an
exact function of the padded circuit size alone — the same
next-power-of-two step that sizes the Bulletproof generators. `|π|` and
`n_e proofs` are computed by `BatchedEvrfPublicParams::batched_proof_wire_len`
without building a proof, and checked byte-for-byte against a real proof in
`tests/batched_dealer.rs::batched_proof_wire_len_matches_v5_vector`.
Batch-verification at `n_e = 99` was omitted because its setup builds 99
independent proofs (~23 s each).

### Table 5 — DKG performance (Secp256k1/Secq256k1, n-of-n)

“Round 0” is `create_dealing` for one dealer (includes the batched eVRF
proof over `n − 1` receivers).  “Round 1” is `complete` for one receiver
(verify `n` dealings and aggregate the share).  Per-participant runtime is
Round 0 + Round 1.  Communication is the per-participant bandwidth
(`n` broadcast messages, one per dealer).

| n   | Round 0  | Round 1  | Per-participant runtime | Comm. (per participant) |
|-----|----------|----------|------------------------|------------------------|
| 2   | 246 ms   | 35.8 ms  | 282 ms                 | 3.2 kb                 |
| 10  | 1.69 s   | 1.12 s   | 2.81 s                 | 28.6 kb                |
| 50  | 12.5 s   | —        | —                      | —                      |
| 100 | 26.1 s   | —        | —                      | —                      |

Round 1 entries marked “—” were not collected because the setup builds
`n` independent proofs (one per dealer), which at `n ≥ 50` takes hours.
Communication at `n ≥ 50` was extrapolated from the linear fit at
`n = 2, 10` (the per-dealer wire size grows linearly in `n`).

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
