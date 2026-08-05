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
* The **disclosure-group extension** separates stable `DisclosureGroup` state
  (common ephemeral point `R`, associated data, and opaque application group ID)
  from a request-specific `DisclosureRequest` decryption context. Participants
  can precompute secret-bearing `x_iR` before a request exists, reuse it across
  authorized requests for the stable group, and issue a fresh proof-bearing
  `DisclosureGroupDecryptionShare` for each request. Shares use
  `W_i = x_iR + z_iS_group,request`; a threshold reconstructs an opaque reusable
  group key.

Released exact and disclosure-group shares have distinct canonical wire tags and
codec IDs. Secret-bearing precomputations and reconstructed group keys have no
wire encoding. Optional adapters expose the public wire values through Serde or
`miden-serde-utils`.

## Threshold record example

The `threshold_records` example shows three writer TEEs encrypting the same
logical private payload with independently uniform, fixed-length content keys and
AEAD nonces. Seeded sealing gives their distinct EHTDH1 ciphertexts one common
`R`. The transaction stage creates a stable group and precomputes `x_iR`; a later
release stage creates the request, issues one request-bound threshold share set,
and uses the reconstructed group key to recover all three content keys.

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
* Supply the intended setup, stable group ID and associated data, and
  request-specific decryption context.
* Derive each supplied 32-byte sealing seed with an application/protocol/version
  domain and inputs including the transaction or disclosure-group identity, a
  high-entropy nonce, a private-payload commitment where appropriate, and the
  application setup epoch or identity where relevant. Golden internally binds the
  backend and joint public key, but not these application values. Validators
  cannot verify caller-provided entropy, and public `R = rG` permits offline
  testing of low-entropy seed candidates.
* Keep encryption proof nonce `r'` fresh for every encryption. Reusing it across
  distinct statements can reveal seeded `r` and is a confidentiality failure.
* Use fresh disclosure-share proof nonces for every release. Reusing them across
  distinct challenges reveals that participant's long-lived `x_i` and `z_i`.
* Authenticate or retrieve a selected ciphertext from trusted storage and verify
  disclosure-group membership before releasing group shares.

The disclosure-group extension is not the exact paper scheme and deliberately
weakens binding granularity. `S_group,request` must be a random-oracle-style
hash-to-group point for which an adversary does not know a discrete-log relation
to the generator, `R`, or another selected point; it must not be implemented as a
caller-known `hash_to_scalar(...) * G` relation.

After interpolation, the recovered capability is `(R, xR)`. The group ID and
request context authorize which shares can reconstruct `xR`; they do not restrict
what `xR` can open afterward. Golden verifies the ciphertext proof, common `R`,
and expected associated data in `DisclosureGroupKey::open`, but it cannot establish
application-level membership. The associated-data equality check is a defensive
API policy, not a cryptographic restriction on extracted `xR`: raw `xR` could open
any wrapper sharing `R`, regardless of associated data. The reusable group key is
therefore opaque, has no raw-point accessor or wire encoding, and must be handled
as a sharp capability.

Seeded sealing reuses one stream mask. Given `c_1 = m_1 XOR mask` and
`c_2 = m_2 XOR mask`, an observer learns `c_1 XOR c_2 = m_1 XOR m_2`, so this is
unsafe for arbitrary structured or correlated payloads. The motivating use is
limited to independently uniform, fixed-length content keys; their XOR reveals no
useful structure to a ciphertext-only observer. This does not protect against
known plaintext: anyone who knows one wrapped plaintext can recover the mask and
open every sibling. Anyone who learns or guesses the seed can derive `r`, compute
`rX`, and do the same without threshold shares.

This crate does not encrypt record values. It does not provide authorization,
networking, replay prevention, secret share refresh, or secret share custody.

See the [crate documentation](https://docs.rs/golden-ehtdh1) for the protocol
mapping, caller obligations, and API examples. See the
[Golden DKG repository](https://github.com/0xMiden/golden-dkg) for the full
workspace.

## License

This crate is available under the MIT License or the Apache License, Version
2.0, at your option.
