# Batch-native Golden DKG

Status: ready-for-agent

## Problem Statement

Golden DKG currently models one secret-sharing instance per protocol run. EHTDH1 needs both a random sharing and a zero sharing, so it must coordinate two independent DKG runs, derive a second session, retain two completion transcripts, and defensively check that the resulting artifacts belong together.

An existing batch-DKG implementation demonstrates useful protocol ideas, but it changes a broad surface at once, duplicates state across configuration, proof, message, and output structures, and mixes protocol work with benchmark and documentation redesign. That makes the change difficult to reason about and review.

The replacement should make an ordered batch the default DKG model, support both random and zero instances, and prove and complete the entire batch atomically. It should preserve the node-facing online EHTDH1 Rust interface as far as practical while allowing unrestricted DKG and wire-protocol breaks. The implementation should remain close to the existing architecture and introduce abstraction or refactoring only where it clearly removes code, duplicated state, or repeated validation.

## Solution

Replace the single-instance DKG model with one general, ordered, nonempty batch model. A configuration declares one or more instance kinds. Each dealer creates one message containing one dealing body per configured instance and one joint proof over every dealing and every non-dealer receiver. Public verification and participant completion succeed or fail for the whole ordered batch.

Provide convenience constructors for one random instance, one zero instance, and an arbitrary ordered batch. Preserve the established outer DKG names while generalizing their contents. Derive protocol roots from canonical state rather than storing duplicate claimed roots. Keep network messages inspectable and fully validate them after deserialization, while making locally constructed configuration, private dealing state, and completed output immutable where that removes defensive checks.

EHTDH1 setup consumes exactly one `[Random, Zero]` batch output. Its online sealing, share issuance, verification, and combination interfaces remain stable. Data and wire compatibility with previous releases are not required.

## User Stories

1. As a DKG caller, I want an ordered batch to be the default protocol model, so that related sharings are created and completed together.
2. As a DKG caller, I want to configure one random sharing conveniently, so that ordinary DKG remains simple.
3. As a DKG caller, I want to configure one zero sharing conveniently, so that zero-sharing use cases do not require a custom-secret interface.
4. As a DKG caller, I want to configure an arbitrary nonempty ordered sequence of random and zero instances, so that the core model is not coupled to EHTDH1’s current two-instance shape.
5. As a DKG caller, I want invalid thresholds and empty batches rejected at configuration construction, so that protocol operations can rely on configuration invariants.
6. As a dealer, I want one broadcast message for the entire configured batch, so that related dealings cannot be mixed across protocol runs.
7. As a dealer, I want each dealing to use an independently sampled nonce and polynomial, so that batching does not accidentally reuse per-instance randomness.
8. As a dealer, I want one joint proof over every dealing and receiver, so that shared proof relations can be amortized without weakening atomicity.
9. As a verifier, I want the effective eVRF message to bind the configuration, dealer, dealing position, and raw nonce, so that messages cannot be replayed or moved between positions.
10. As a verifier, I want effective-message derivation outside the circuit, so that domain separation does not add unnecessary proof constraints.
11. As a verifier, I want zero-sharing constant commitments checked outside the circuit during structural preflight, so that malformed zero dealings fail before expensive proof verification.
12. As a verifier, I want every dealer message structurally validated before any cross-dealer proof equations are combined, so that malformed public inputs never reach the batch verifier.
13. As a verifier, I want an invalid cross-dealer proof batch diagnosed to a dealer when possible, so that operators can identify the rejected contribution.
14. As a verifier, I want one dealer-message root derived from canonical proof-independent fields, so that there is no mutable claimed hash to keep synchronized.
15. As a participant, I want completion to verify and aggregate every configured instance atomically, so that I never receive a partially accepted batch.
16. As a participant, I want completed instances returned in configuration order, so that callers can interpret them deterministically.
17. As a participant, I want zero-sharing outputs to have identity public keys, so that zero-sharing semantics are observable at the public DKG interface.
18. As a participant, I want all honest participants to agree on public keys, public shares, configuration identity, and completion identity for every batch position.
19. As a proof-backend implementer, I want the public proof input to represent dealings containing receivers, so that the input matches the relation being proved.
20. As a proof-backend implementer, I want witness data to follow canonical order without repeated position or receiver identifiers, so that alignment metadata cannot disagree.
21. As a proof-backend implementer, I want the statement to contain only values consumed by the proof relation plus the canonical dealer-message root, so that protocol metadata is not duplicated.
22. As a prototype-backend user, I want the lightweight proof backend to support the same general batch interface, so that protocol plumbing remains fast to test.
23. As a paper-backend user, I want the Secp/Secq relation to support multiple dealings and receivers in one proof, so that the production proof adapter implements the batch-native protocol.
24. As an EHTDH1 setup caller, I want one `[Random, Zero]` DKG batch converted into sealing, verification, and secret-share material, so that setup no longer coordinates two DKG runs.
25. As an EHTDH1 online caller, I want sealing, ciphertext verification, share issuance, and share combination interfaces to remain stable, so that adopting batch DKG causes minimal node source changes.
26. As an EHTDH1 caller, I want the setup context to bind the batch session, configuration, and atomic completion identity, so that online transcripts refer to one coherent setup.
27. As a node operator, I want existing online Golden wrapper code to require only focused setup-context migration, so that the runtime integration remains recognizable.
28. As a wire-format consumer, I want changed values encoded canonically with explicit new versions, so that malformed or ambiguously ordered batches are rejected.
29. As a wire-format consumer, I do not need legacy bytes to decode, so that the implementation does not carry migration or compatibility machinery.
30. As a maintainer, I want existing outer DKG names retained where their roles are unchanged, so that review is focused on semantic changes rather than renaming churn.
31. As a maintainer, I want locally constructed private shares and completed outputs protected from mutation, so that downstream modules do not repeat impossible-state checks.
32. As a maintainer, I want secret-bearing debug output redacted, so that private dealer shares are not accidentally logged.
33. As a reviewer, I want the implementation to avoid unrelated module restructuring, benchmark redesign, and opportunistic cleanup, so that the protocol change remains reviewable.
34. As an implementation agent, I want a clean context that is not shaped by the previous implementation, so that the agreed design is implemented independently against the selected base.

## Implementation Decisions

- The implementation is based on the proof-simplified branch that removes the redundant DH commitment, R1CS share opening, and coefficient knowledge proof.
- The previous batch implementation is reference material only. The primary implementation session must not inspect it directly.
- When a fact about the previous implementation is genuinely needed, a fresh subagent receives one narrowly scoped question and returns concise behavioral findings with little or no code. Broad reference-branch analysis is prohibited.
- DKG configuration contains an ordered, nonempty sequence of `Random` and `Zero` instance kinds.
- Core exposes convenience constructors for one random instance, one zero instance, and a general ordered batch. All constructors produce the same representation and use the same protocol path.
- Configuration fields are immutable after validated construction and exposed through read-only accessors.
- Existing outer names remain: dealer broadcast is a `DealerMessage`, local dealer output is a `DkgDealing`, and participant completion returns a `DkgOutput`.
- A dealer message contains a configuration root, dealer identity, ordered dealing bodies, and one proof.
- Each dealing body contains an independently sampled raw nonce, one Feldman commitment, and encrypted shares for every non-dealer receiver.
- Dealer messages and dealing bodies remain publicly inspectable because they are untrusted deserialized network inputs. Verification performs complete structural preflight.
- A dealer-message transcript root is deterministically derived and is not serialized or stored as a mutable claimed field.
- The completion root binds the configuration root and canonically ordered derived dealer-message roots.
- Effective eVRF messages are derived outside the circuit from the configuration root, dealer, dealing position, and independently sampled raw nonce.
- Zero-sharing constant commitments are checked once outside the circuit during untrusted message preflight. Local construction and aggregate completion do not repeat mathematically implied checks.
- The proof statement is nested as one batch containing dealings containing receivers.
- Proof dealings do not repeat their position or kind. Position follows vector order; kind follows configuration order and is bound by the configuration root.
- The proof statement carries the public relation inputs used by the backend and the derived dealer-message root. Protocol version, backend identity, dealer index, and configuration metadata are bound or derived rather than repeated as mutable fields.
- The proof witness follows the same nested order but does not repeat dealing positions or receiver identities.
- Both prototype and paper adapters implement the same batch-native proof-backend interface.
- Cross-dealer proof batching and the existing dealer-attribution fallback remain supported.
- Receiver-specific verification that decrypts and discards shares is removed. Completion performs receiver-secret validation, decryption, commitment checking, and aggregation once.
- Explicit caller-provided polynomial secrets are removed. Random and zero instance kinds define supported constant-term behavior.
- Dealer-owned private shares are private local state. The dealer broadcast remains directly accessible. Debug formatting redacts private shares.
- Comprehensive zeroization policy changes are deferred; this work does not add isolated partial zeroization behavior.
- Completed output stores a configuration root, ordered instance outputs, and one completion root. Instance outputs do not repeat their kind.
- Completed output is constructed only by completion and exposed read-only. Pairing an output with a configuration is checked by configuration root.
- DKG wire and protocol compatibility may break freely. No legacy decoder or migration path is included.
- Only changed aggregate values require new canonical encodings. Nested dealing bodies remain nested and do not receive standalone wire interfaces without a demonstrated caller.
- EHTDH1 setup requires exactly the configuration order `[Random, Zero]` and interprets the corresponding output positions as decryption and context sharings.
- The EHTDH1 bridge changes from two configurations and two outputs to one configuration and one output.
- EHTDH1 setup context replaces two session/transcript pairs with one batch session, configuration root, and completion root.
- Existing EHTDH1 material, sealing, ciphertext, unsealing-share, decryption-share, and combiner interfaces remain stable where possible.
- Existing public EHTDH1 fields used by the node remain available except fields whose two-run meaning no longer exists.
- Existing module and file organization is retained. Helpers are extracted only when they cause a clear net deletion or centralize duplicated security validation.
- Existing benchmarks are migrated only enough to compile and preserve their prior measurement meaning. New comparative two-dealing benchmarks are separate work.
- Broad README timing-table replacement and unrelated documentation redesign are excluded from the implementation.

## Testing Decisions

- Tests assert observable protocol behavior and security invariants through existing public interfaces rather than internal helper organization.
- The primary seam is the public DKG lifecycle: configuration construction, dealer creation, public verification, cross-dealer verification, and participant completion.
- Fast structural and atomicity tests use the existing fake or prototype proof-backend pattern.
- Configuration tests cover random, zero, arbitrary ordered batches, empty-batch rejection, invalid thresholds, and root sensitivity to every ordered configuration input.
- Dealer tests cover one proof for the entire batch, independent nonces and polynomials, complete receiver sets, effective-message domain separation, and derived root sensitivity.
- Preflight tests tamper with any dealing, receiver relation, commitment degree, zero constant, configuration root, or ordering and assert failure before backend proof work when structurally detectable.
- Completion tests cover mixed batches, all-honest participant agreement at every position, atomic failure, zero public-key identity, and one shared completion root.
- Cross-dealer verification tests preserve optimized batch invocation, default fallback behavior, invalid-dealer attribution, and original batch-error preservation when individual proofs pass.
- The proof-adapter seam tests both prototype and Secp/Secq adapters against multi-dealing statements and witnesses.
- Paper-relation tests cover one dealing, multiple dealings, multiple receivers, independent effective messages and polynomial witnesses, and tampering in every dimension. Low-level tests are limited to invariants not observable through the public DKG lifecycle.
- Canonical wire tests cover round trips for changed values, ordered dealing encoding, malformed lengths and dimensions, invalid configuration construction, wrong versions/tags, trailing bytes, and proof byte preservation.
- No legacy wire vectors or compatibility behavior are tested.
- The EHTDH1 integration seam builds material from one `[Random, Zero]` output and exercises the existing online seal, verify, issue-share, and combine behavior.
- EHTDH1 tests cover wrong configuration kind order, output/configuration root mismatch, setup-context root sensitivity, and preservation of public and secret share meaning.
- Tests that mutate impossible local output states are removed when immutability makes those states unrepresentable.
- Existing tests are adapted rather than broadly rewritten. Old tests are removed only after equivalent batch-native behavior is visibly covered.
- No compilation or test execution was performed while producing this spec.

## Out of Scope

- Legacy single-instance execution paths or compatibility wrappers.
- Legacy DKG, EHTDH1 setup-context, ciphertext, share, or other wire decoding.
- Data migration for existing node setup artifacts, private records, or exported decryption shares.
- A caller-provided arbitrary polynomial secret mode.
- New DKG instance kinds beyond random and zero.
- A complaint, exclusion, or partial-completion protocol.
- Receiver pre-verification that discards decrypted shares.
- A broad module split, proof-seam lifetime redesign, or repository architecture refactor.
- Comprehensive secret zeroization or drop-policy redesign.
- New comparative two-dealing benchmark binaries or benchmark infrastructure.
- Replacement performance measurements or README timing tables.
- Unrelated cleanup, naming changes, optimization, dependency updates, or documentation work.
- Changes to the node repository beyond documenting its compatibility requirements.

## Further Notes

- The node integration audit found no live DKG API usage. The node consumes EHTDH1 artifacts and online interfaces.
- The node’s meaningful Rust compatibility surface is the online EHTDH1 material, sealing, ciphertext, share, combiner, wire helper, error, group, and participant interfaces.
- The expected node source migration is focused on replacing the old two-session setup-context validation and updating setup fixtures.
- Data compatibility is explicitly not required.
- The previous implementation is preserved on `backup/batch-dkg`. Its uncommitted benchmark work is preserved separately in a named Git stash.
- The clean implementation branch starts at the proof-simplified base commit and intentionally has no upstream configured yet.
