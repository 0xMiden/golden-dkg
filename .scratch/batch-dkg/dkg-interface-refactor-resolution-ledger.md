# Golden DKG interface refactor — resolution ledger

Status: `/to-spec` complete; local production spec ready for `/to-tickets`

The synthesized production specification is:

`.scratch/batch-dkg/dkg-interface-refactor-production-spec.md`

This ledger records decisions made after the final architecture resolution in the newer production handoff at:

`/Users/adrian/Developer/miden/worktrees/golden-dkg/onyx-falcon/golden-dkg/.scratch/batch-dkg/dkg-interface-refactor-production-handoff.md`

For the decisions below, this ledger supersedes both that handoff and the older copies of the handoff and checkpoint in this worktree. Unmentioned final architecture decisions remain controlled by the newer production handoff.

## Resolved decisions

### Main Golden beta

- Use one protocol-wide beta shared by every DKG session under a protocol version.
- Derive beta in the full curve base field from a fixed versioned protocol string using domain-separated unbiased field sampling.
- Beta may be zero.
- Do not accept, store, serialize, or expose beta or a setup identifier through `DkgConfig`.
- This is a transparent random-oracle instantiation of the paper's uniformly sampled public setup coefficient; it is not the current caller-provided scalar-field beta.
- Accept this instantiation without a separate pre-release security-review gate.

### Mixed Random and Zero batching

- Preserve arbitrary ordered, nonempty Random and Zero instance batches, one atomic dealer message, and one joint proof.
- Require independent polynomials, nonces, effective messages, pads, commitments, encrypted shares, and proof randomness per instance.
- Bind instance kind and position into configuration, effective-message, dealer-message, and proof identities.
- Treat the joint construction as a repository extension rather than claiming direct coverage by Golden Theorem 3.
- A dedicated composition/security review gates a production security claim and release; it does not block `/to-spec` or implementation and does not reopen the fixed-string beta decision.

### Degenerate receiver pad

- If any final DKG receiver-pad scalar is zero and therefore has an identity commitment, `deal` returns a coarse dedicated error.
- Do not retry internally and do not return partial outbound bytes or `OwnDealing`.
- A caller may invoke `deal` again with fresh randomness.
- Parsing and verification reject identity pad commitments.
- The error does not expose an instance or receiver index, and the otherwise infeasible path receives deterministic test coverage.

### Participant and threshold edge cases

- Support every nonempty participant registry and every threshold in `1..=n`.
- Preserve `n = 1, t = 1`: core emits no receiver entries, uses a canonical empty proof suffix, and never calls `DealerProofSystem`.
- Proof-system preparation accepts this configuration with zero required proof capacity.
- Preserve `t = 1` Zero instances, whose physical commitment tail is empty while the logical constant is identity.

### Prepared generators

- Prepared generators are authenticated deployment-owned application state.
- Restoration validates canonical encoding, curve points, declared capacity, and exact logical prefix length.
- Restoration does not rederive and compare the deterministic generator prefix.
- A proof-system value may serve any configuration requiring no greater capacity; under-capacity configurations fail before proof work.

### Participant identity-key knowledge

- Assume the authenticated deployment process admitting a registry entry has established that its participant knows the corresponding Golden identity secret key.
- Core continues to validate canonical, nonidentity, unique identity public keys and binds every dealer proof to the registered key.
- Core does not carry or verify a separate identity-key proof of knowledge in this refactor.
- A future protocol version may require identity keys to carry a proof of knowledge; do not anticipate that interface now.

## Normative specification requirements already settled

- Core owns the exact Main Golden H1/H2 framing over an injectively encoded tuple of the effective message and the dealer/receiver public keys ordered lexicographically by canonical compressed encoding. The legacy message-only 32-byte-to-64-byte zero-padding rule does not define this input.
- `InsecureRevealedWitnessProof` is test infrastructure, not a default production export. Any non-test exposure requires an explicit non-default insecure feature and unmistakable naming.
- Ordinary serde is trusted application persistence and never protocol encoding, root input, transcript input, proof input, or untrusted dealer parsing.
- Completion identifies the common public result; exact board provenance and activation remain deployment-owned.
- Appendix K, eVRF-derived polynomial coefficients, concrete secret zeroization, a facade crate, and `AlgebraicTestCycle` remain out of scope.

## Remaining required user decisions

None. The remaining exact domains, versions, size bounds, type names, error names, capacity arithmetic, and migration order are specification or implementation work rather than user-owned architecture decisions.
