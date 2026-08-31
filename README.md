# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Rust workspace for distributed key generation, verifiable randomness, and
context bound threshold encryption over a generic group abstraction. The
current tree implements Golden DKG, EHTDH1, Secp256k1/Secq256k1 and
BLS12-381/Jubjub eVRF backends, and the Bulletproofs R1CS layer used by
both backends.

The two protocol implementations follow these papers.

* **Golden DKG.** Benedikt Bünz, Kevin Choi, and Chelsea Komlo,
  “[Golden: Lightweight Non-Interactive Distributed Key Generation](https://eprint.iacr.org/2025/1924),”
  Cryptology ePrint Archive, Paper 2025/1924, 2025.
* **EHTDH1.** Dan Boneh, Benedikt Bünz, Kartik Nayak, Lior Rotem, and Victor
  Shoup, “[Context-Dependent Threshold Decryption and its Applications](https://eprint.iacr.org/2025/279),”
  Cryptology ePrint Archive, Paper 2025/279, 2025.

The workspace has seven crates. All crates are published together and require
Rust 1.93 or later.

| Crate | Purpose |
|---|---|
| `golden-core` | Shamir sharing, Feldman commitments, DKG messages, transcript binding, and the curve-agnostic `EvrfProofBackend` trait. |
| `golden-evrf` | Secp256k1/Secq256k1 and BLS12-381/Jubjub R1CS backends for the full Golden eVRF relation. It also contains a share-opening prototype used by plumbing tests. |
| `golden-rustcrypto` | RustCrypto P-256 and secp256k1 `GoldenGroup` adapters used by the prototype backend and tests. |
| `golden-ehtdh1` | Context-bound threshold encryption over Golden DKG output. Each decryption share is bound to its setup, ciphertext, and caller context. |
| `bulletproofs-cycle` | A minimal fork of `zkcrypto/bulletproofs` 5.0.1 whose R1CS prover and verifier operate through a generic `Cycle` trait. The `bulletproofs-compat` feature provides byte-parity testing against the upstream crate. |
| `golden-halo2curves` | Secp256k1/Secq256k1 `Cycle` implementations and the Secp256k1 `GoldenGroup` adapter. |
| `golden-bls-jubjub` | BLS12-381 G1 and Jubjub `Cycle` implementations and the Jubjub `GoldenGroup` adapter. |

## Performance

For performance sensitive workloads, one can use the `optimized` profile when compiling.

The following tables reproduce Tables 4 and 5 from the Golden DKG paper with
real wall-clock measurements. Criterion uses flat sampling with 10 samples.
The BLS12-381/Jubjub results exercise BLS12-381 G1 as the Bulletproof
commitment group and Jubjub as the inner eVRF group. The existing
Secp256k1/Secq256k1 measurements remain below for comparison.

Benchmarked on an **AMD Ryzen 9 9950X** (16 cores / 32 threads, up to
5.76 GHz) with the `optimized` profile (`lto = "thin"`, `codegen-units = 1`).

### Table 4 (eVRF performance on BLS12-381/Jubjub)

`n_e` is the number of receiver statements in one batched proof. Prover and
verifier timings cover the Bulletproofs R1CS operations. Batch verification
measures `verify_dealings` across `n_e` independent dealer messages. Proof
sizes are exact wire lengths. The concatenated column contains `n_e`
independent proofs.

| n_e | Prover | Verifier | Batch verification | \|π\| (single) | n_e proofs (concat) |
|---:|---:|---:|---:|---:|---:|
| 1  | 151 ms | 16.4 ms | 17.0 ms | 1.9 kb | 1.9 kb |
| 9  | 1.17 s | 87.7 ms | 116 ms | 2.2 kb | 19.8 kb |
| 49 | 4.47 s | 326 ms | 1.81 s | 2.4 kb | 117.0 kb |
| 99 | 8.79 s | 618 ms | 6.56 s | 2.5 kb | 245.9 kb |

### Table 5 (DKG performance on BLS12-381/Jubjub, n-of-n)

Round 0 measures `create_dealing` for one dealer. Round 1 measures `complete`
for one receiver using all `n` dealings. Per-participant runtime is the sum of
the two measured medians. Communication counts `n` serialized dealer
broadcasts and uses decimal kilobytes.

| n | Round 0 | Round 1 | Per-participant runtime | Comm. (per participant) |
|---:|---:|---:|---:|---:|
| 2   | 152 ms | 17.9 ms | 170 ms | 4.3 kb |
| 10  | 1.19 s | 134 ms | 1.33 s | 32.4 kb |
| 50  | 4.49 s | 2.49 s | 6.98 s | 375.5 kb |
| 100 | 8.88 s | 11.8 s | 20.7 s | 1.27 MB |

The paper reports zkalc estimates on AWS EC2 m5.2xlarge. These rows measure the
real Jubjub circuit on the local Ryzen system, so the curve family now matches
the paper while the hardware and circuit implementation remain different.

### Table 4 (eVRF performance on Secp256k1/Secq256k1)

`n_e` is the number of receiver statements covered by one batched proof.
“Prover” times the Bulletproofs R1CS prover only.  “Verifier” times a
single `evrf_batched_verify`.  “Batch verification” times `verify_dealings`
across `n_e` independent dealer messages (the receiver's Round 1 work).
`|π|` is the wire size of one batched proof. “n_e proofs” is the
concatenated size of `n_e` independent proofs.

| n_e | Prover     | Verifier  | Batch verification | \|π\| (single) | n_e proofs (concat) |
|-----|------------|-----------|--------------------|----------------|---------------------|
| 1   | 119 ms     | 15.7 ms   | 16.1 ms            | 1.4 kb         | 1.4 kb              |
| 9   | 885 ms     | 103 ms    | 572 ms             | 1.6 kb         | 14.3 kb             |
| 49  | 3.12 s     | 420 ms    | 14.8 s             | 1.7 kb         | 84.2 kb             |
| 99  | 7.33 s     | 846 ms    | 59.2 s             | 1.8 kb         | 176.6 kb            |

Every batched-eVRF proof is single-phase (the relation never defers
constraints via `specify_randomized_constraints`), so its wire length is an
exact function of the padded circuit size alone, using the same
next-power-of-two step that sizes the Bulletproof generators. `|π|` and
`n_e proofs` are computed by `BatchedEvrfPublicParams::batched_proof_wire_len`
without building a proof, and checked byte-for-byte against a real proof in
`tests/batched_dealer.rs::batched_proof_wire_len_matches_v5_vector`.

### Table 5 (DKG performance on Secp256k1/Secq256k1, n-of-n)

“Round 0” is `create_dealing` for one dealer (includes the batched eVRF
proof over `n − 1` receivers).  “Round 1” is `complete` for one receiver
(verify `n` dealings and aggregate the share).  Per-participant runtime is
Round 0 + Round 1.  Communication is the per-participant bandwidth
(`n` broadcast messages, one per dealer).

| n   | Round 0  | Round 1  | Per-participant runtime | Comm. (per participant) |
|-----|----------|----------|------------------------|------------------------|
| 2   | 120 ms   | 24.6 ms  | 145 ms                 | 3.2 kb                 |
| 10  | 932 ms   | 788 ms   | 1.72 s                 | 26.3 kb                |
| 50  | 3.42 s   | 37.9 s   | 41.3 s                 | 342.0 kb               |
| 100 | 8.12 s   | 246 s    | 255 s                  | 1.2 MB                 |

## Useful checks

```bash
cargo fmt --all --check
cargo clippy --all --benches --tests --examples --all-features --exclude bulletproofs-cycle -- -D warnings
cargo nextest run --workspace --features golden-rustcrypto/p256,golden-rustcrypto/k256,golden-ehtdh1/prototype-bridge,golden-evrf/halo2curves-secp256k1,golden-halo2curves/halo2curves-secp256k1,golden-evrf/bls12-381-jubjub
cargo test --workspace --doc
```

## Licensing

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
