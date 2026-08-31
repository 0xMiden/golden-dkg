# Defer the Bulletproofs-internal stream migration

**Blocked by:** [Migrate every Golden proof path](05-migrate-proof-paths.md), [Let the proof stream own proof identity and framing](06-wire-versioning.md).

## Question

What proves the Golden stream seam works now, and what remains for a later Bulletproofs effort?

## Resolution

Test the stream itself and every real Golden path.

Stream tests cover:

- prover/verifier duality;
- canonical point/scalar round trips and rejection;
- explicit identity policy;
- proof-ID mismatch;
- complete public observation and challenge sensitivity;
- operation-order and label sensitivity;
- failed receive transactionality;
- every truncation point, checked length overflow, and trailing bytes;
- nested child framing without double observation.

Golden behavior tests cover:

- prototype proof creation/verification and tampering;
- standalone CP/R1CS/DLOG composition and replay rejection;
- batched dealer proof creation/verification;
- honest dealer-message v2 wire/Serde/Miden round trips;
- malformed/truncated/trailing proof streams rejected through `verify_dealing`, not only parser tests;
- complete DKG and existing EHTDH bridge tests after proof generic removal;
- deterministic proof-byte and challenge vectors under fixed RNG.

Delete tests whose only purpose is standalone proof wrapper serialization. Keep current low-level algebra/R1CS tests.

Defer:

- changing any Bulletproofs file;
- replacing `R1CSProof` or IPP proof types;
- streaming individual R1CS/IPP messages;
- changing R1CS internal bytes/phase grammar;
- transcript-derived verifier randomness/performance work;
- broader protocol/audit corrections.

The future Bulletproofs migration should reuse the paired roles, curve parsing policy, shared-transcript semantics, and test vocabulary established here rather than cherry-picking `589204d` wholesale.
