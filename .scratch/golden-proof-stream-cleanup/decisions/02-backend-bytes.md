# Keep the backend seam but remove its proof type

**Blocked by:** [Keep the cleanup at the Golden proof-composition seam](01-scope-boundary.md).

## Question

What replaces `EvrfProofBackend::Proof` without removing curve/backend configurability?

## Resolution

Keep `EvrfProofBackend<G>` and its current pad/prove/verify responsibilities, but remove its associated proof type.

Target shape:

```text
const PROOF_ID
prove_batch(statements, witnesses, rng) -> Vec<u8>
verify_batch(statements, proof: &[u8]) -> Result
```

`PROOF_ID` is a stable versioned byte string selecting the Golden proof-stream grammar and transcript domain. It is not a runtime backend registry.

Remove proof generic `P` and `B::Proof` from stored DKG values:

```text
DealerMessage<G, P> -> DealerMessage<G>
DkgDealing<G, P>    -> DkgDealing<G>
```

Creation still selects `B` at compile time, and verification still invokes `verify_dealing::<G,B>`. The backend validates that the proof stream header matches `B::PROOF_ID`.

`DealerMessage<G>` stores `proof: Vec<u8>`, not another proof wrapper. Wire decoding treats these bytes as opaque; statement-aware backend verification interprets them.

## Rejected alternatives

- Remove `EvrfProofBackend` entirely.
- Replace the associated proof type with a backend phantom generic on `DealerMessage`.
- Dynamic proof-backend negotiation.
- Add a separate independently mutable proof-ID field to `DealerMessage`.
- Introduce a public `ProofStream` value wrapper that recreates the removed proof layer.

## Impact

- source-interface change across Golden core, proof backends, integration tests, and EHTDH test type annotations;
- static proof/backend pairing becomes a stream-header check during verification.
