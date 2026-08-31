# Make the stream curve-aware

**Blocked by:** [Keep the backend seam but remove its proof type](02-backend-bytes.md).

## Question

Should stream parsing be byte-only or own canonical curve-value validation?

## Resolution

Make the Golden stream curve-aware. Paired crate-private roles own proof bytes, Merlin transcript state, canonical parsing, and cursor state:

```text
ProverProofStream
VerifierProofStream<'proof>
```

A shared crate-private `Observe` trait owns transcript access and default `observe_bytes`, `observe_point`, and `observe_scalar` implementations. Both prover and verifier streams implement it by exposing their transcript. Public-statement observation helpers accept `&mut impl Observe`, so the canonical observation schedule is written once rather than duplicated by role. Challenge derivation is likewise implemented once as an extension over `Observe`.

Required role-specific operations:

- `send_bytes`, `send_point`, `send_scalar`;
- `receive_bytes`, `receive_point`, `receive_scalar`;
- `challenge` or `challenge_scalar` where the curve adapter defines the reduction;
- `send_nested` / `receive_nested` for the current typed R1CS child;
- `finish`.

Use a private proof-stream curve adapter so the same stream can handle:

- generic `GoldenGroup` points/scalars in the prototype path;
- Secp/Secq `Cycle` points/scalars in the paper paths.

The adapter owns fixed canonical widths, compression, strict decode, re-encode equality, canonical scalar parsing, and challenge conversion where unambiguous. Each point operation explicitly selects `AllowIdentity` or `RejectIdentity`; identity policy is relation-specific and never implicit.

All cursor arithmetic is checked. Variable frames return borrowed slices and do not allocate from attacker-controlled lengths. A failed receive advances neither cursor nor transcript.

The stream remains crate-private in `golden-evrf`. If Bulletproofs later adopts the same model, the abstraction can move or be generalized after a second real consumer exists.

## Rejected alternatives

- Byte-only parsing with curve validation scattered across envelopes.
- Coupling the public Golden core crate to Merlin or proof-engine traits.
- A public general codec hierarchy.
- Implicit point-identity policy.
