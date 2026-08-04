# golden-ehtdh1

Context bound threshold encryption for Golden distributed key generation.

This crate implements EHTDH1 from
[ePrint 2025/279](https://eprint.iacr.org/2025/279). It converts two completed
Golden DKG runs into a public sealing key, public verification shares, and one
secret share for each participant. The first DKG run shares the decryption
secret. The second shares zero so that each decryption share is bound to one
decryption context.

The crate provides two explicitly separated decryption modes:

* **Exact-ciphertext EHTDH1** follows the paper construction. A participant share
  is bound to one complete ciphertext, associated data value, decryption context,
  and Golden setup. Existing `DecryptionShare`, `combine_exact`, and
  `combine_quorum` APIs retain these semantics.
* The **disclosure-group extension** binds shares to a setup, common ephemeral
  point `R`, opaque application group ID, associated data, and decryption
  context. Participants can precompute secret-bearing `x_iR` and later issue a
  fresh proof-bearing `DisclosureGroupDecryptionShare`. A threshold reconstructs
  an opaque group key that opens any valid same-`R`/same-associated-data
  ciphertext.

Released exact and disclosure-group shares have distinct canonical wire tags and
codec IDs. Secret-bearing precomputations and reconstructed group keys have no
wire encoding. Optional adapters expose the public wire values through Serde or
`miden-serde-utils`.

## Threshold record example

The `threshold_records` example shows three writer TEEs encrypting the same
logical private payload with independent content keys and AEAD nonces. Seeded
sealing gives their distinct EHTDH1 ciphertexts one common `R`; participants
precompute `x_iR` once, issue one request-bound threshold share set, and use the
reconstructed group key to recover all three content keys.

Run it with:

```console
cargo run -p golden-ehtdh1 --example threshold_records --features prototype-bridge
```

## Features

The crate has no default features.

* `serde` provides Serde adapters that use the canonical wire encoding.
* `miden-serde` provides `miden-serde-utils` adapters that use the same bytes.
* `prototype-bridge` enables the fast Golden DKG bridge example and tests.
* `halo2curves-secp256k1` enables the ignored integration test for the
  Secp256k1 and Secq256k1 proof backend.

## Security scope

Callers must:

* Protect participant secret shares and disclosure-group `x_iR`
  precomputations. A threshold of precomputations reconstructs `xR`.
* Authenticate requests for decryption shares.
* Supply the intended setup, associated data, and decryption context.
* Keep encryption proof nonce `r'` fresh for every encryption. Reusing it across
  distinct statements can reveal seeded `r` and is a confidentiality failure.
* Use fresh disclosure-share proof nonces for every release. Reusing them across
  distinct challenges reveals that participant's long-lived `x_i` and `z_i`.
* Authenticate or retrieve a selected ciphertext from trusted storage and verify
  disclosure-group membership before releasing group shares.

The disclosure-group extension is not the exact paper scheme and deliberately
weakens binding granularity. Golden checks ciphertext proof validity, common
`R`, and associated data when opening; it cannot establish application-level
membership. Learning a reconstructed group key opens every valid payload sharing
that `R` and associated data.

Seeded sealing has an additional confidentiality boundary: anyone who learns or
guesses the seed can derive `r` and open the wrapped payload without threshold
shares. Because same-seed ciphertexts reuse one stream mask, a party that knows
one wrapped plaintext and ciphertext can recover that mask and open every sibling.
Use a common seed only when all such ciphertexts intentionally share one
disclosure scope.

This crate does not encrypt record values. It does not provide authorization,
networking, replay prevention, secret share refresh, or secret share custody.

See the [crate documentation](https://docs.rs/golden-ehtdh1) for the protocol
mapping, caller obligations, and API examples. See the
[Golden DKG repository](https://github.com/0xMiden/golden-dkg) for the full
workspace.

## License

This crate is available under the MIT License or the Apache License, Version
2.0, at your option.
