# 03 — Stream the batched paper dealer proof

**What to build:** Move the DKG’s batched paper proof onto the shared Golden proof stream while retaining the existing batched relation, statement schedule, typed R1CS proof, verifier behavior, and Bulletproofs implementation. The complete ordered dealer statement must be observed before one nested R1CS child, and the backend must consume the stream exactly.

**Blocked by:** 02 — Make DKG proof storage opaque through the prototype path.

**Status:** ready-for-agent

- [ ] The batched paper backend uses a versioned v2 proof-stream ID/domain.
- [ ] The complete existing ordered batched statement is observed through the shared `Observe` interface.
- [ ] The current batched R1CS prover and verifier receive the same parent Merlin transcript.
- [ ] The typed R1CS proof remains backend-private and is framed as one nested payload.
- [ ] The nested frame is not transcript-observed a second time; its semantic R1CS messages remain bound by the child protocol.
- [ ] The batched proof envelope and public Secp/Secq byte-wrapper proof type are removed.
- [ ] Canonical typed-proof reserialization or equivalent exact parsing rejects noncanonical nested encodings.
- [ ] Wrong proof ID, malformed nested length, truncation, trailing bytes, corrupted proof messages, and statement replay fail through the paper backend and DKG verification seam.
- [ ] Honest paper-backed dealer creation and public verification succeed under fixed deterministic vectors.
- [ ] No Bulletproofs engine source or internal proof grammar is changed.
