# Golden opaque proof-stream cleanup specification

**Status:** ready-for-agent  
**Target:** one PR on `cleanup/dkg-ehtdh`

## Problem Statement

Golden proof composition is represented by a collection of typed proof containers whose only durable purposes are grouping, parsing, serialization, and bridging between proof phases. The backend’s associated proof type propagates through dealer messages, dealings, DKG function signatures, wire generics, Serde/Miden adapters, integration tests, and EHTDH test annotations.

The prototype, standalone paper, and batched dealer paths each use different envelope structures and parsing logic. Chaum–Pedersen, R1CS, DLOG, batched R1CS, and prototype proof messages are composed through wrappers rather than one explicit ordered prover/verifier interaction. This makes transcript ordering, canonical parsing, exact proof consumption, and statement binding harder to review.

An experimental branch previously pushed a Proof Stream model through Bulletproofs, R1CS, and IPP. That was useful exploration but too broad for the current step. The current need is to establish the same composition model at the Golden layer while retaining the existing typed `R1CSProof` internally. The Golden design can then become the basis for a later proof-engine migration.

## Solution

Keep the existing configurable Golden group/backend architecture and mathematical relations, but replace all Golden-level proof types with opaque byte streams.

`EvrfProofBackend` remains the proof adapter seam, loses its associated proof type, identifies its versioned stream grammar with a stable proof ID, returns opaque bytes from proving, and consumes borrowed opaque bytes during verification. Stored DKG types no longer carry a proof generic.

A crate-private, curve-aware `ProverProofStream` and `VerifierProofStream` pair owns:

- proof-ID framing and transcript domain separation;
- complete public-statement observations;
- canonical point/scalar encoding and strict parsing;
- explicit point-identity policy;
- ordered sending and receiving of proof messages;
- Fiat–Shamir challenges over all prior observations/messages;
- nested child proof framing with a shared transcript;
- checked cursor arithmetic and exact trailing-byte rejection.

All Golden proof paths migrate in the same PR:

- prototype share-opening batch;
- standalone one-receiver Chaum–Pedersen/R1CS/DLOG composition;
- batched dealer R1CS proof used by DKG.

The current typed Bulletproofs `R1CSProof` remains a nested backend-private intermediate. Its child protocol receives the same mutable Merlin transcript; its raw nested frame is not observed a second time because the child already observes its semantic messages.

Proof bytes and Golden-level Fiat–Shamir challenges intentionally receive new versions. Current curve configuration, proof equations, DKG public fields, DKG lifecycle, dealer/completion roots, DKG outputs, and EHTDH production behavior remain unchanged.

## User Stories

1. As a DKG caller, I want `DealerMessage` and `DkgDealing` to depend only on the configured group, so that proof implementation types do not propagate through stored protocol values.
2. As a proof-backend implementer, I want to produce opaque bytes and verify byte slices, so that my internal proof decomposition is not part of the DKG interface.
3. As a proof-backend implementer, I want a stable proof ID to select my stream grammar and transcript domain, so that incompatible proof streams fail deterministically.
4. As a proof prover, I want one ordered stream abstraction to send every Golden proof message, so that envelopes and temporary grouping structs are unnecessary.
5. As a proof verifier, I want the matching stream abstraction to receive and validate messages in the same order, so that parsing logic cannot drift from proving order.
6. As a proof verifier, I want curve points and scalars parsed canonically inside the stream, so that envelope code does not duplicate validation rules.
7. As a proof verifier, I want every point receive to state whether identity is allowed, so that relation-specific identity policy is explicit.
8. As a proof verifier, I want malformed or noncanonical curve encodings rejected before transcript absorption, so that invalid messages cannot influence challenges.
9. As a proof verifier, I want checked cursor arithmetic and borrowed frames, so that attacker-controlled lengths cannot overflow or force arbitrary allocation.
10. As a proof verifier, I want `finish` to reject every trailing byte, so that valid proof prefixes cannot hide unparsed data.
11. As a transcript reviewer, I want the complete canonical public statement observed before proof messages, so that proofs cannot be replayed against another statement.
12. As a transcript reviewer, I want one shared transcript across all Golden proof phases, so that later phases bind earlier messages and challenges.
13. As a transcript reviewer, I want every sent/received message absorbed exactly once, so that prover and verifier challenge states remain identical.
14. As a transcript reviewer, I want labels, observations, and challenges omitted from proof bytes, so that proof bytes contain only prover-supplied data while transcript framing remains normative.
15. As a standalone paper-proof maintainer, I want Chaum–Pedersen, R1CS, and DLOG phases sequenced through one stream, so that their composition is visible without an envelope type.
16. As a batched dealer-proof maintainer, I want the existing complete batch statement observed once before the nested R1CS proof, so that dealer proof binding remains centralized.
17. As a prototype maintainer, I want receiver proofs emitted in canonical statement order, so that a serialized receiver-indexed proof map is unnecessary.
18. As a Bulletproofs maintainer, I want the existing typed R1CS proof and proof engine left unchanged for now, so that this PR establishes the higher-level seam without restoring the archived engine rewrite.
19. As a future Bulletproofs maintainer, I want the Golden stream vocabulary and tests to be reusable, so that R1CS/IPP can later adopt the same send/receive/challenge model incrementally.
20. As a transport caller, I want the outer dealer message to own opaque proof framing, so that proof wrappers do not define independent wire formats.
21. As a transport caller, I want proof grammar validation deferred until statement-aware verification, so that generic wire decoding does not need to know the selected backend.
22. As a Serde or Miden caller, I want complete dealer-message bytes to be the only proof persistence path, so that standalone proof serialization cannot diverge.
23. As a DKG participant, I want existing dealer fields, creation, verification, completion, and transcript-root semantics preserved, so that this cleanup does not become a DKG redesign.
24. As an EHTDH integrator, I want production bridge behavior unchanged, so that only proof-type annotations disappear from integration tests.
25. As a curve integrator, I want current curve configurability preserved, so that the proof-stream cleanup does not hard-code the Secp/Secq cycle into DKG types.
26. As a maintainer, I want prototype, CP, DLOG, batch, and byte-wrapper proof structs removed consistently, so that no parallel proof-representation model remains.
27. As a reviewer, I want deterministic stream and challenge vectors, so that proof-domain, label, ordering, and dependency changes are explicit.
28. As a reviewer, I want malformed streams tested through the real DKG verification seam, so that parser unit tests are not the only evidence of safe integration.
29. As a downstream caller, I want the breaking dealer-message/proof version called out clearly, so that all participants upgrade together without a hidden compatibility path.
30. As a security auditor, I want this PR explicitly not to claim that the unchanged mathematical relations satisfy every source-paper requirement, so that proof-representation cleanup is not confused with a protocol audit fix.

## Implementation Decisions

1. **Narrow scope.** This PR changes Golden proof representation, parsing, framing, and transcript composition only. It does not redesign Golden curves, fields, statements, witnesses, proof equations, DKG lifecycle, DKG outputs, or EHTDH production behavior.

2. **Backend seam retained.** `EvrfProofBackend` remains generic over the current configurable group and continues to own pad derivation, proving, and verification.

3. **Associated proof type removed.** The backend has no associated proof type. Proving returns opaque bytes; verification accepts a borrowed byte slice.

4. **Proof ID.** Every backend/path defines a stable versioned proof ID. It identifies stream grammar and transcript domain, not a dynamic backend registry.

5. **Stored values.** Dealer messages and dealings are generic only over their group. Dealer messages store opaque proof bytes directly and do not store a proof wrapper, backend marker, or separate proof-ID field.

6. **Stream visibility.** Prover/verifier stream roles and curve adapters are crate-private to the Golden proof crate. The proof-system-agnostic core crate does not depend on Merlin or proof-engine traits.

7. **Shared observation interface.** A crate-private `Observe` trait owns transcript access and the default byte/point/scalar observation behavior. Both stream roles implement it, all canonical statement-observation functions are generic over it, and shared challenge derivation is layered over the same interface. Observation schedules are never implemented separately for prover and verifier.

8. **Curve-aware parsing.** The stream owns canonical point/scalar encoding and decoding through a private adapter over existing Golden-group and cycle abstractions. It validates exact width, canonical decode/re-encode equality, canonical scalars, and explicit identity policy.

9. **Transactional receives.** A failed receive does not advance the proof cursor or absorb bytes into the transcript. All cursor/length arithmetic is checked.

10. **One transcript.** Each proof stream owns one Merlin transcript initialized by its proof ID. The complete canonical public statement is observed before any prover message.

11. **Message semantics.** A sent/received message appears in proof bytes and is transcript-observed exactly once. Public observations, labels, and challenges are transcript metadata and do not appear in proof bytes.

12. **Challenges.** Challenges derive from proof ID, complete public statement, and every prior accepted message. Challenge bytes may be converted using each existing relation’s current scalar-reduction rule.

13. **Nested child protocol.** A nested proof receives the same mutable transcript and a checked length-delimited payload. Its raw frame is not observed by the parent because the child observes its own semantic messages.

14. **Current R1CS retained.** Typed R1CS and IPP proof types, phase markers, proof parser, and engine implementation remain unchanged. The R1CS proof is serialized into a nested Golden stream frame and parsed privately by the paper backend.

15. **Prototype migration.** Prototype nonce points and response scalars are streamed directly in canonical statement order. Receiver-indexed proof structs/maps and their codecs are removed. Its mathematical equations remain unchanged.

16. **One-receiver migration.** Chaum–Pedersen messages, nested R1CS prefixes/proof, and DLOG messages run sequentially in one stream and transcript. Their envelope/container structs are removed.

17. **Batched migration.** The current complete ordered dealer statement is observed, followed by one nested current R1CS proof. Batched envelope and byte-wrapper types are removed.

18. **Proof versions.** Prototype, standalone paper, and batched paper proof IDs/domains all receive v2 identifiers. Existing proof bytes and Golden-level challenge vectors are intentionally incompatible.

19. **Dealer-message wire.** Dealer-message encoding owns one length-delimited opaque proof field and no longer delegates to a proof `WireMessage`. Its codec becomes v2. The global Golden wire magic and unrelated codecs need not change.

20. **No legacy decode.** The crates are unpublished; old proof and dealer-message values are rejected. No compatibility aliases, default proof generic, or dual decoder are added.

21. **Serialization ownership.** Standalone proof wire, Serde, and Miden adapters are removed. Complete dealer-message serialization is the sole persistence path for proof bytes.

22. **Roots and outputs.** Existing statement, dealing, and completion root algorithms are preserved. Proof bytes remain outside dealing/completion roots, so DKG output and EHTDH setup values require no migration.

23. **Production EHTDH unchanged.** Only integration-test imports, aliases, and generic annotations change. Production setup/material conversion remains as implemented.

24. **Deletion.** Remove Golden-level prototype, CP, DLOG, one-receiver envelope, batched envelope, public byte wrapper, test fake proof containers, associated proof generics, and standalone proof serialization tests.

25. **Future proof-engine migration.** A later effort may move stream roles into Bulletproofs and replace typed R1CS/IPP messages. This PR does not predesign or implement that migration beyond creating a reusable vocabulary and behavior contract.

### Breaking-change classification

| Change | Impact |
|---|---|
| Remove backend associated proof and stored proof generics | source-interface change |
| Dealer-message v2 opaque proof field | dealer wire-format and persisted dealer-message change |
| Versioned proof-stream header/framing | proof-byte change |
| One shared Golden transcript | Fiat–Shamir challenge and proof-byte change |
| Remove standalone proof codecs | source/persistence interface change |
| EHTDH test generic cleanup | source-only test change |

There is no intended mathematical-relation, DKG-output, DKG-root, EHTDH-root, or EHTDH-material change. Old proof/dealer-message artifacts are not accepted; all workspace callers migrate atomically and deterministic v2 fixtures replace v1 fixtures.

## Testing Decisions

1. **Highest seam.** The primary integration seam is real dealer creation, dealer-message v2 serialization/deserialization, and `verify_dealing`. Proof-stream parser tests supplement but do not replace this seam.
2. **Role duality.** Prover and verifier must derive identical transcripts/challenges for identical mixed-curve operations.
3. **Canonical curve parsing.** Test valid points/scalars, malformed encodings, noncanonical encodings, and both explicit identity policies.
4. **Parser safety.** Test checked overflow, every truncation boundary, invalid proof-ID headers, invalid nested lengths, failed-receive transactionality, and trailing bytes.
5. **Transcript sensitivity.** Pin challenge changes for proof domain, public observation, label, prior message, and operation ordering.
6. **No double observation.** Use a nested test child to demonstrate that semantic child messages are observed once while raw child framing is not observed again.
7. **Prototype behavior.** Test honest proof, every nonce/response tamper, missing/extra/reordered records, deterministic stream vector, and full fast DKG completion.
8. **One-receiver composition.** Test honest CP/R1CS/DLOG stream, per-phase tampering, replay across statements, and that early-phase changes alter later challenges.
9. **Batched dealer behavior.** Test honest real paper proof, complete statement binding, malformed nested typed R1CS bytes, exact stream completion, and deterministic proof/challenge vectors.
10. **Dealer-message wire.** Test canonical v2 round trip, Serde/Miden parity, malformed outer proof lengths, and that structurally opaque malformed inner proof bytes fail only during statement-aware verification.
11. **DKG regression.** Preserve existing non-proof dealer tamper tests and complete DKG consistency tests after generic proof-type removal.
12. **EHTDH regression.** Run existing prototype-backed bridge tests and explicitly run the ignored paper-backed DKG-to-EHTDH path; no production EHTDH behavior should change.
13. **Deletion replacement.** Delete standalone proof-wrapper serialization tests after equivalent dealer-message and stream tests exist. Keep current low-level relation, circuit, and Bulletproofs tests.
14. **Workspace validation.** Run formatting, clippy, workspace/all-feature tests, and explicit ignored real-paper tests. Assert no source diff under the Bulletproofs crate.

## Out of Scope

- Any Bulletproofs engine source change.
- Removing or redesigning typed R1CS or IPP proof values.
- Changing R1CS/IPP byte grammar, phase markers, generators, verifier randomness, or performance.
- Changing curve/group configurability or exposing only one concrete cycle.
- Correcting or redesigning current eVRF, prototype, Feldman, or batched equations.
- Changing beta, hash-to-curve, statement/witness types, dealer public fields, or receiver records.
- Changing DKG verification/recovery/completion state transitions or output types.
- Changing statement, dealing, completion, or EHTDH setup roots.
- Production EHTDH setup, encryption, decryption, bridge, or serialization redesign.
- Runtime proof-backend negotiation or a general cross-project proof framework.
- Legacy proof/dealer-message compatibility.
- Broader audit findings unrelated to proof representation and transcript composition.

## Further Notes

- The archived `589204d` branch remains useful for paired-role, canonical parsing, cursor, challenge, nested-protocol, and exact-finish ideas. Its R1CS/IPP rewrite is not restored or cherry-picked.
- Golden’s dealer output includes correctness proof material, and the optimized construction uses one batched proof per dealer (`2025-bunz-choi-komlo-golden-dkg`, PDF pp. 27–29). This spec changes representation/composition, not that protocol role.
- Detailed current/target flows, type inventory, stream interfaces, phase sequences, wire impact, breaking ledger, tests, and deletion budget are in `research-synthesis.md` beside this spec.
- Estimated gross deletion is roughly 700–1,250 lines, offset by 400–750 lines of stream implementation and focused tests, for an expected net deletion of roughly 250–600 lines.
