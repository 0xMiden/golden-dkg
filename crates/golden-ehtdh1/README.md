# golden-ehtdh1

Context-bound threshold encryption for Golden distributed key generation,
based on [EHTDH1, ePrint 2025/279](https://eprint.iacr.org/2025/279).

Run Golden once with exactly `[DkgInstanceKind::Random,
DkgInstanceKind::Zero]`, or reshare its key with exactly
`[DkgInstanceKind::Reshare, DkgInstanceKind::Zero]`, then call
`material_from_dkg_output(&config, &output, epoch)`. The Random or Reshare
instance shares the decryption secret; the Zero instance supplies
context-binding shares. A reshare keeps the sealing key under a new setup
context, so records sealed before it open with the new committee. The
bridge checks configuration binding, instance policies, public-share
interpolation and the aggregate keys before constructing local EHTDH1 material.

## Online operations

* Writers encrypt with `SealingKey` without participant secrets or setup context.
* Participants use `UnsealingShare` to produce a share for one ciphertext and
  decryption request context.
* `Combiner` checks an exact threshold set or selects a valid threshold from a
  larger quorum.
* Canonical wire bytes support storage and exchange of setup values, keys,
  ciphertexts and decryption shares.

`SetupContext` binds the single batch session, configuration root, completion
root and application epoch. A combiner checks that its public key set matches
that completion identity. Associated data is stored in the ciphertext; use the
`*_with_associated_data` methods when acceptance requires an externally expected
value.

## Threshold record example

`threshold_records` runs a three-participant, threshold-two setup using
Secp256k1/Secq256k1 with explicitly prepared generators. It encrypts each large
record value with XChaCha20Poly1305 and uses EHTDH1 only for the fresh 32-byte
content key. The flow includes wire encoding, quorum recovery, associated-data
checks and rejection of shares from a different decryption context.

```console
cargo run -p golden-ehtdh1 --example threshold_records
```

## Features and caller responsibilities

The crate has no default features. `serde` and `miden-serde` adapt the same
canonical wire bytes to Serde and `miden-serde-utils`, respectively. EHTDH1 has
its own versioned envelope, separate from DKG broadcasts and local snapshots.
Legacy keys, ciphertexts and setup artifacts are not compatible with this cut.

Applications own authenticated setup agreement, generator provenance, secret
custody, request authorization, associated-data policy, replay handling, record
AEAD and retirement of the predecessor setup once a reshare activates. Restored
DKG outputs require authenticated storage with trusted completion provenance.
Secret diagnostics are redacted and owned storage is cleaned up on normal drop;
caller copies and application-owned serialized bytes remain the caller's
responsibility.

The retained security targets do not constitute a new audit. Mixed-instance
setup composition and both concrete proof backends require the separate
security release approval described by the
[workspace design](https://github.com/0xMiden/golden-dkg).

## License

MIT or Apache-2.0, at your option.
