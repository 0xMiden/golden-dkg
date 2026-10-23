# Golden DKG

[![CI](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMiden/golden-dkg/actions/workflows/ci.yml)

Native Golden distributed key generation and context-bound threshold encryption
over Secp256k1 and Jubjub. Version 0.5 is a hard compatibility cut: configurations,
keys, broadcasts, ciphertexts, snapshots and prepared artifacts from earlier
versions require fresh setup. The full refactor contract is in
[docs/issue-71.md](docs/issue-71.md).

The protocols follow these papers:

* Benedikt Bünz, Kevin Choi, and Chelsea Komlo,
  [Golden: Lightweight Non-Interactive Distributed Key Generation](https://eprint.iacr.org/2025/1924).
* Dan Boneh, Benedikt Bünz, Kartik Nayak, Lior Rotem, and Victor Shoup,
  [Context-Dependent Threshold Decryption and its Applications](https://eprint.iacr.org/2025/279).

| Package | Responsibility |
|---|---|
| [`golden-core`](crates/golden-core) | Native algebra, immutable configuration, opaque broadcasts, verification, atomic completion and contextual persistence. |
| [`golden-curves`](crates/golden-curves) | Proof-free Secp256k1 and Jubjub adapters with strict canonical codecs. |
| [`golden-bulletproofs`](crates/golden-bulletproofs) | Joint Main Golden proofs for Secp/Secq and Jubjub/BLS12-381, explicit typed preparation and optimized MSM. |
| [`bulletproofs-cycle`](crates/bulletproofs-cycle) | Generic Bulletproofs engine with owned generator prefixes. |
| [`golden-ehtdh1`](crates/golden-ehtdh1) | Online encryption/decryption and one completed `[Random, Zero]` batch bridge. |

Rust 1.93 or later is required. Concrete adapters and proofs are opt-in features;
core does not depend on either. See each package README for the public API and
persistence responsibilities. Applications own broadcast agreement, activation,
authenticated approved-generator storage and trusted completion provenance.
Independent composition/security approval remains a release requirement.

## Checks

```sh
make check
make lint
make check-features
make test
make test-slow
```

`bulletproofs-cycle/bulletproofs-compat` and its default `cycle-pedersen` feature
are mutually exclusive, so blanket workspace `--all-features` is unsupported.
The Makefile and CI exercise compatibility mode separately. The core's explicit
`insecure-revealed-witness` feature is for tests only and reveals secret inputs.

## Measurements and fixtures

Use `--profile optimized` for real proof measurements. The `joint_dkg` benchmark
prepares generators before timing dealer creation or completion. Earlier protocol
performance tables do not describe the new circuit or formats; new measurements
must identify the curve, configuration, hardware, feature set and fixture revision.

```sh
cargo bench -p golden-bulletproofs --profile optimized \
  --features secp-secq,jubjub-bls12-381,parallel --bench joint_dkg
cargo run -p golden-bulletproofs --profile optimized \
  --features secp-secq,jubjub-bls12-381 --example check_fixtures
```

Fixture regeneration is explicit: append `-- --regenerate` to the example command,
review the changed artifacts, then run the check again without that flag.

## Licensing

Dual-licensed under MIT or Apache-2.0, at your option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
