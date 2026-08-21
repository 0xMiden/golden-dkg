# golden-ehtdh1

Context bound threshold encryption for Golden distributed key generation.

This crate implements EHTDH1 from
[ePrint 2025/279](https://eprint.iacr.org/2025/279). It converts one completed
Golden `[Random, Zero]` DKG batch into a public sealing key, public verification
shares, and one secret share for each participant. The random sharing provides
the decryption secret. The zero sharing binds each decryption share to one
decryption context. The bridge rejects an identity decryption aggregate key or
a nonidentity context aggregate key and binds both the configuration and atomic
completion roots into the EHTDH1 setup context.

The crate provides:

* Writers can encrypt data with the public sealing key.
* Participants can produce shares for one decryption context.
* Combiners can use an exact threshold set or search a larger quorum.
* Applications can store and exchange values with the canonical wire encoding.
* Optional adapters expose the same bytes through Serde or
  `miden-serde-utils`.

## Threshold record example

The `threshold_records` example shows how to protect large stored records. It
uses authenticated symmetric encryption for each record value and uses EHTDH1
only for the 32 byte content key. It also shows setup, wire encoding, quorum
recovery, and rejection of shares made for different contexts.

Run it with:

```console
cargo run -p golden-ehtdh1 --example threshold_records --features halo2curves-secp256k1
```

## Features

The crate has no default features.

* `serde` provides Serde adapters that use the canonical wire encoding.
* `miden-serde` provides `miden-serde-utils` adapters that use the same bytes.
* `halo2curves-secp256k1` enables the Secp/Secq Main Golden bridge example and
  its integration tests. The full proof lifecycle test is ignored by default
  because it is slow and remains explicitly runnable.

## Security scope

Callers must:

* Protect participant secret shares.
* Authenticate requests for decryption shares.
* Supply the intended setup, associated data, and decryption context.

The EHTDH1 security claim is for static corruption of fewer than the threshold
participants in the random-oracle model, under the LOMDH assumption and the
semantic security of the symmetric cipher. It does not claim adaptive-corruption
security. Golden DKG setup has its own separate assumptions.

This crate does not encrypt record values. It does not provide authorization,
networking, replay prevention, secret share refresh, or secret share custody.

See the [crate documentation](https://docs.rs/golden-ehtdh1) for the protocol
mapping, caller obligations, and API examples. See the
[Golden DKG repository](https://github.com/0xMiden/golden-dkg) for the full
workspace.

## License

This crate is available under the MIT License or the Apache License, Version
2.0, at your option.
