# Golden DKG production interface refactor

Status: ready for ticketing

## Problem Statement

The current batch-native Golden DKG implementation demonstrates the required Random and Zero sharing behavior, atomic completion, cross-dealer proof batching, and Secp/Secq proof, but its public architecture still exposes prototype-era concepts. Callers must provide beta in the scalar field, proof backends own receiver-pad evaluation, dealer messages and nested proof statements are public data structures, proof implementations are selected through static backend types, and prepared proof generators are coupled to the existing paper API. These seams make the cryptographic relation easier to vary accidentally than the proof mechanism and make it difficult for an application to persist and reuse the expensive production proof state cleanly.

From a caller's perspective, Golden should expose one small production workflow: construct a validated DKG configuration, prepare or restore a proof-system value, create one opaque dealer message with deal, and atomically complete from the final candidate dealer-message set. The caller should not need to understand parsed messages, receiver-pad internals, proof statement trees, proof identifiers, or proof-generator caches.

The refactor must preserve the batch-native behavior already in the repository while fixing the protocol boundaries. Main Golden is one fixed relation owned by golden-core. A proof system supplies evidence for that relation but does not redefine it. Random and Zero instances remain independently randomized, ordered, configuration-authenticated sharings inside one atomic dealer message and one joint proof. Persistence remains an application concern, and deployment continues to own message collection, agreement, activation, artifact authentication, and participant admission.

The resulting interface must be implementable without reopening architecture decisions. It must also state the actual security boundary: the fixed-string Main Golden setup coefficient is accepted as an explicit random-oracle instantiation, while the repository's arbitrary mixed-instance joint proof remains an extension whose composition review gates a production security claim and release.

## Solution

Refactor Golden DKG around free deal and complete functions in golden-core. Both functions receive an immutable validated DKG configuration and an explicitly injected, reusable, stateful DealerProofSystem. The public proof-system seam uses one flat core-owned statement and witness, opaque proof bytes, and no proof associated type.

Move the exact Main Golden semantics into golden-core: the protocol-wide setup coefficient, H1/H2 input framing, receiver-pad evaluation, public-relation checks, flat statement construction, and native relation checker. Keep the Secp/Secq Bulletproof implementation, its proof framing, and its prepared generators in golden-evrf. Replace the prototype share-opening backend with an unmistakably insecure witness-revealing test proof that checks the same core-owned relation.

Keep DKG configuration limited to the session identifier, public participant registry, threshold, and ordered nonempty Random/Zero instance policy. Derive beta from one fixed versioned protocol string in the full curve base field. Preserve opaque configuration-selected dealer-message bytes, direct application serde for persistent public values, a derived completion root over the common public result, and a hard compatibility cut from all legacy formats.

Use the public end-to-end workflow as the primary test seam:

configuration plus proof system → deal → opaque dealer bytes → complete → DKG output

Narrower tests exist only where the public workflow cannot efficiently or deterministically exercise a cryptographic primitive, malformed parser state, proof-system conformance rule, or prepared-generator invariant.

## User Stories

1. As a Golden DKG caller, I want one validated participant registry, so that participant ordering and identity-key checks are established once.
2. As a Golden DKG caller, I want one immutable DKG configuration containing only session public inputs, so that proof implementation state cannot change the identity of my session.
3. As a Golden DKG caller, I want to configure an arbitrary ordered nonempty sequence of Random and Zero instances, so that one DKG round can produce every sharing my application needs.
4. As a Golden DKG caller, I want convenience constructors for a single Random or single Zero instance, so that simple sessions remain concise.
5. As a Golden DKG caller, I want beta to be protocol-derived rather than caller-selected, so that I cannot accidentally choose the wrong field or create grindable configuration input.
6. As a Golden DKG caller, I want to supply a reusable proof-system value explicitly, so that expensive prepared state has clear ownership and lifetime.
7. As a Golden DKG caller, I want to call a free deal function, so that I do not need a session wrapper or backend-owned orchestration object.
8. As a dealer, I want deal to return the exact opaque bytes I must broadcast, so that transport code never constructs or mutates a protocol message.
9. As a dealer, I want deal to retain my private self shares in an OwnDealing value, so that I can later complete without recovering private state from public bytes.
10. As a dealer, I want OwnDealing to omit my long-lived identity secret, so that persisting a dealing does not persist that credential.
11. As a dealer, I want OwnDealing to be cloneable and serde-capable with redacted debug output, so that I can safely persist, restore, and retry completion.
12. As a dealer, I want a degenerate zero receiver pad to return one retryable coarse error before any result is published, so that I can rerun deal with fresh randomness.
13. As a dealer, I want deal to be all-or-nothing, so that a failure never exposes partial dealer bytes or partial OwnDealing state.
14. As a participant, I want peer dealer messages to remain opaque bytes, so that untrusted data cannot bypass session-bound parsing.
15. As a participant, I want the expected dealer supplied by transport to be treated only as routing metadata, so that Golden still verifies the dealer encoded and proven by the message.
16. As a participant, I want complete to consume one final candidate from every configured dealer, so that it can accept or reject a complete DKG result atomically.
17. As a participant, I want complete to borrow OwnDealing, so that I can retry against a corrected candidate board after a failed attempt.
18. As a participant, I want public relations checked before expensive proof verification and share decryption, so that malformed input fails early and predictably.
19. As a participant, I want valid dealer proofs batch-verified, so that production completion retains the existing verification optimization.
20. As a participant, I want every dealer individually checked after a batch failure, so that I receive canonical attribution for all invalid dealers.
21. As a participant, I want an unexplained batch failure preserved when every individual proof passes, so that a backend batch-verification defect is not misreported as dealer misconduct.
22. As a participant, I want share decryption and aggregation to occur only after all dealer evidence is accepted, so that no partial DKG output escapes.
23. As a participant, I want one output per configured instance in configuration order, so that applications can map results without another policy layer.
24. As a participant, I want my output to retain the originating configuration root, so that restored output remains bound to its DKG session.
25. As a participant, I want completion_root to identify the common public result, so that participants can compare results without revealing or hashing local secrets.
26. As a deployment operator, I want exact dealer-message-board provenance kept outside completion_root, so that I can apply deployment-specific agreement and audit policy separately.
27. As a deployment operator, I want Golden to stop at a pending cryptographic output, so that agreement and activation remain explicit deployment actions.
28. As a deployment operator, I want a fixed whole-message limit enforced before nested allocation, so that hostile bytes cannot select unbounded parser work.
29. As a deployment operator, I want prepared Secp/Secq generators to be explicit serializable state, so that preparation cost can be paid ahead of an online DKG round.
30. As a deployment operator, I want to authenticate prepared-generator artifacts using my storage system, so that Golden does not duplicate deployment key-management policy.
31. As a deployment operator, I want restored prepared generators structurally validated, so that truncation, invalid points, inconsistent capacity, and malformed encodings fail safely.
32. As a deployment operator, I want a larger prepared generator prefix to serve smaller compatible configurations, so that one prepared artifact can support a planned operating range.
33. As a deployment operator, I want under-capacity prepared state rejected before proving or verification work, so that the proof system never grows hidden state during an online operation.
34. As a deployment operator, I want a small prepared artifact to serialize only its declared logical prefix, so that prior process-wide warming cannot silently enlarge persisted state.
35. As an EHTDH1 integrator, I want the exact ordered Random and Zero pair to remain supported, so that decryption and context shares remain separately addressable.
36. As an EHTDH1 integrator, I want each instance to use an independent polynomial, nonce, effective message, pad, and proof randomness, so that combining the round does not correlate the two sharings.
37. As an EHTDH1 integrator, I want the bridge to check the expected aggregate public-key postconditions, so that EHTDH1 semantics remain outside generic DKG core.
38. As a proof-system implementer, I want one flat canonical DealerProofStatement and DealerProofWitness, so that I do not reproduce DKG shape validation or traverse nested policy-specific trees.
39. As a proof-system implementer, I want proof bytes to be opaque owned bytes with borrowed verification input, so that proof framing remains private and no proof serde contract leaks into core.
40. As a proof-system implementer, I want the configuration root supplied through the validated configuration, so that the proof transcript binds the session without a mutable duplicate field.
41. As a proof-system implementer, I want prove, verify, and optional optimized verify_batch operations on a stateful Send + Sync value, so that prepared parameters and caches have an ordinary owner.
42. As a proof-system implementer, I want receiver-pad evaluation excluded from my interface, so that alternate proof encodings cannot redefine the Main Golden relation.
43. As a Secp/Secq proof implementer, I want core-owned beta and H1/H2 helpers to be the source used by both native evaluation and the circuit, so that the two relations cannot drift.
44. As a test author, I want an insecure witness-revealing proof implementation that checks the exact relation, so that core orchestration can be tested quickly without pretending to provide privacy.
45. As a security reviewer, I want the insecure proof unavailable from the default production API, so that a witness-serializing proof cannot be selected accidentally.
46. As a security reviewer, I want every Main Golden H1/H2 input to bind the effective message and the canonically ordered identity-key pair, so that pads are tied to both protocol participants.
47. As a security reviewer, I want the setup coefficient sampled unbiasedly in the complete base field from a fixed versioned string, so that the implementation matches the chosen protocol-wide setup model.
48. As a security reviewer, I want Random constants to keep their extraction proof while Zero constants omit it only under authenticated configuration policy, so that untrusted bytes cannot select a weaker proof grammar.
49. As a security reviewer, I want Zero commitments represented logically with an identity constant even when its bytes are omitted, so that roots and transcripts preserve the complete relation.
50. As a security reviewer, I want mixed-instance batching described as a repository extension, so that documentation does not attribute a construction absent from the paper directly to Golden Theorem 3.
51. As a release manager, I want the mixed-instance composition review to gate the production security claim and release but not implementation, so that engineering can proceed without overstating assurance.
52. As a release manager, I want the fixed-string beta instantiation excluded from that special review gate, so that the settled setup choice is not reopened during the mixed-composition review.
53. As a curve-adapter author, I want a GoldenCurve capability that exposes only the base-field operations Main Golden needs, so that generic core need not depend on concrete curves or proof libraries.
54. As a curve-adapter author, I want GoldenHashToGroup retained as a smaller independent capability, so that EHTDH1 and protocol hashing do not become coupled to Bulletproof generator derivation.
55. As a single-participant caller, I want n = 1 and t = 1 to use a canonical empty proof and skip the proof system, so that the valid degenerate DKG shape remains supported.
56. As a Zero-instance caller, I want t = 1 to encode an empty physical commitment tail while retaining logical identity, so that zero sharing works for every valid threshold.
57. As an application developer, I want serde representations explicitly separated from protocol encoding, so that ordinary persistence cannot become an alternate dealer-message grammar.
58. As an application developer, I want public errors to be stable and coarse, so that I can handle failures without receiving secret-bearing or backend-specific diagnostics.
59. As a maintainer, I want the obsolete standalone one-receiver API and prototype backend removed, so that there is one production relation and one DKG proof seam to understand.
60. As a maintainer, I want a hard version cut with no fallback parser or cache migration, so that old artifacts cannot negotiate weaker semantics.
61. As a maintainer, I want examples, benchmarks, EHTDH1, and tests migrated to the same public workflow, so that no hidden legacy caller path survives.
62. As a future protocol designer, I want identity-key proof of knowledge left at the deployment admission boundary today, so that a future proof-bearing identity-key version can be designed deliberately rather than anticipated in the current interface.

## Implementation Decisions

### Ownership and crate boundaries

- Preserve the existing crate direction. golden-core owns generic DKG orchestration and the one fixed Main Golden relation. golden-evrf depends on core and owns concrete proof systems for that relation.
- Add no new crate, facade, session object, runtime wrapper, owning engine, borrowed wrapper, or backend-owned forwarding API.
- golden-core owns DkgConfig, ParticipantRegistry, Random and Zero policy, participant ordering, Shamir and Feldman algebra, dealer-message encoding and parsing, protocol roots, beta derivation, effective-message and H1/H2 framing, native receiver-pad evaluation, native relation checking, flat proof inputs, completion, outputs, and public errors.
- golden-evrf owns the Secp/Secq Bulletproof circuit, proof stream and transcript domains, proof parsing, proving, individual verification, optimized cross-dealer verification, prepared generators, proof-specific capacity calculation, and the insecure exact-relation test proof.
- golden-core may depend directly on the no-std ff field abstraction. It must not depend on golden-evrf, concrete curve implementations, Bulletproofs, or Secp/Secq types.

### Curve capabilities

- Retain GoldenGroup as the smaller prime-order group interface used by Shamir, Feldman, configuration, output, canonical encoding, and other non-Main-Golden code.
- Retain GoldenHashToGroup as a lower-level protocol hash-to-group capability. Its documentation must distinguish protocol H1/H2 hashing from proof-generator derivation.
- Replace GoldenEvrfCurve with GoldenCurve for DKG execution.
- GoldenCurve directly extends GoldenHashToGroup and supplies:
  - a BaseField implementing ff::PrimeField;
  - the byte order of the canonical BaseField representation;
  - affine x-coordinate extraction that returns an error for the identity or another unsupported point;
  - exact reduction of the canonical base-field integer into the group scalar field.
- Do not introduce a base-field wrapper, forwarding field trait, coordinate subtrait, relation-associated type, or marker-composition hierarchy.
- Keep persistence and public-data types such as ParticipantRegistry, DkgConfig, OwnDealing, and outputs bounded by the smallest algebra they need, normally GoldenGroup. Require GoldenCurve only for deal, complete, the flat proof inputs, Main Golden helpers, and DealerProofSystem.
- Update every curve and test adapter that participates in DKG execution to implement the new capability without implying that the Secp/Secq R1CS is generic over those adapters.

### Protocol-wide Main Golden setup coefficient

- Main Golden uses one public beta value for every DKG session under one protocol version.
- Derive beta from the fixed ASCII protocol string golden-dkg/main-golden-beta/v1. No configuration root, session identifier, setup identifier, caller input, registry value, or proof-system value enters this derivation.
- Use the separate ASCII expansion domain golden-dkg/base-field-candidate/v1. Attempt counters begin at zero. For each attempt, reset a block counter to zero and concatenate SHA-256 blocks until one BaseField representation's worth of bytes is available.
- Each SHA-256 preimage is exactly the ASCII expansion domain, followed by the big-endian u64 byte length of the beta protocol string, the beta protocol string bytes, the big-endian u32 attempt counter, and the big-endian u32 block counter, with no terminator or additional input. Increment the block counter for each expansion block and increment the attempt counter only after rejecting the completed candidate.
- Truncate the expansion to the exact BaseField representation length and interpret it as one fixed big-endian candidate integer. Reject candidates greater than or equal to the field modulus. Translate an accepted candidate into the concrete BaseField representation using GoldenCurve's declared representation byte order and require canonical BaseField decoding to succeed.
- Accept zero. Rejecting zero would change the intended uniform distribution over the full base field.
- Pin the domain framing, counter framing, candidate integer interpretation, representation conversion, and at least one Secp256k1 test vector.
- Select and review the fixed string as protocol nomenclature, not by searching candidate strings for a preferred beta value.
- Treat failure to find a field element after exhausting the counter space as an internal derivation error.
- Beta is not a DkgConfig constructor argument, field, accessor, serde field, configuration-root field, dealer-message field, DealerProofStatement field, DkgOutput field, or prepared-generator field.
- The new configuration/protocol version binds the beta-derivation version indirectly. A future beta derivation requires another hard protocol-version cut.
- This fixed-string derivation is an accepted random-oracle instantiation of the paper's sampled public setup coefficient and has no separate production review gate.

### Effective messages, H1/H2, and receiver-pad evaluation

- Each configured instance carries an independently sampled 32-byte dealer nonce.
- Core derives the instance's effective message with a versioned transcript over the configuration root, dealer participant index, instance position, configured instance kind, and nonce. The explicit kind is redundant with the configuration root by design and keeps the per-instance identity locally auditable.
- Core builds the H1 and H2 input as an injectively framed tuple containing:
  - the effective message;
  - the lexicographically smaller canonical compressed identity public-key encoding;
  - the lexicographically larger canonical compressed identity public-key encoding.
- Prefix each tuple element with its big-endian u64 byte length in the order above; add no ambiguous concatenation or intermediate fixed-length prehash.
- Use fresh, distinct, versioned H1 and H2 domain-separation tags. The legacy rule that zero-pads only the 32-byte message to 64 bytes is deleted and must not be retained as an intermediate prehash.
- The canonical key ordering makes the dealer and receiver evaluate the same relation while still binding both identities.
- Core's native Main Golden evaluator follows the fixed relation:
  - derive the shared identity-DH point from one identity secret and the peer identity public key;
  - take its base-field affine x-coordinate as k_base;
  - reduce the canonical BaseField integer k_base into the group scalar field through GoldenCurve and call the result k;
  - exponentiate the two core-derived H1/H2 points by the scalar k;
  - compute r as beta times the first resulting x-coordinate plus the second resulting x-coordinate in BaseField;
  - reduce the canonical BaseField integer r into the group scalar field;
  - use the reduced scalar as the receiver pad and bind its generator commitment.
- The Secp/Secq circuit must consume the same core-owned beta and H1/H2 derivation rules and prove the same relation. Proof-only chord witnesses, decompositions, correction generators, and prepared tables remain private to golden-evrf.
- Every affine-coordinate failure fails closed without panicking or substituting zero and is returned as a coarse relation-evaluation failure.
- If deal obtains a zero final reduced pad, and therefore an identity final pad commitment, it returns one dedicated coarse retryable degenerate-eVRF error. It performs no internal retry, does not invoke the prover, and returns no partial bytes or OwnDealing.
- A caller may retry the entire deal operation with fresh RNG. The error exposes no receiver or instance index.
- Parsing and verification reject an identity pad commitment as an invalid dealer message/public relation. Received invalid input is not reported as a retryable local generation failure.

### Random and Zero instance composition

- DkgInstanceKind retains exactly Random and Zero.
- Every Random instance independently samples a complete polynomial. Its constant may happen to be zero.
- Every Zero instance fixes only coefficient zero and independently samples all nonconstant coefficients. Its shares are generally nonzero except in valid degenerate threshold shapes.
- Every instance independently samples its polynomial coefficients and nonce and uses a separately position-bound and domain-separated effective-message input. Pads are independently derived from those per-instance messages. Proof commitments and blindings must not reuse randomness across instance slots. Accidental equality of independently generated values remains valid.
- One joint proof may reuse only relation-invariant computation, such as the dealer identity witness or the same dealer/receiver DH intermediate. It must not reuse a pad, effective message, polynomial, nonconstant coefficient vector, Feldman commitment vector, or proof blinding between instances.
- Bind instance kind and position through configuration identity, effective-message derivation, dealer-message root construction, statement order, and proof transcript order.
- The logical Feldman commitment always contains threshold coefficients. For Zero, logical coefficient zero is the group identity.
- The physical dealer-message commitment for Random contains all threshold points. The physical commitment for Zero omits coefficient zero and contains only the threshold-minus-one nonconstant tail.
- Parsing reconstructs the logical identity coefficient for Zero before Feldman evaluation, dealer-message-root derivation, statement construction, or transcript observation.
- Every Random slot must prove knowledge or extractability of its constant opening. A concrete production proof may integrate that obligation into its proof grammar differently, but no production DealerProofSystem may omit it. Zero omits the zero scalar witness and constant-opening proof because configuration already fixes the logical opening to zero.
- Configuration kind, never an untrusted flag or observed point, selects the physical commitment and proof grammar.
- Arbitrary ordered nonempty mixtures remain supported in one dealer message and one joint proof.
- Document the arbitrary mixed-instance joint proof as a repository extension. A dedicated soundness, zero-knowledge, pseudorandomness, and composition review gates the production security claim and release. It does not block specification, implementation, or testing and does not reopen beta.

### Participant registry and DKG configuration

- Retain ParticipantRegistry as a public validated value.
- Registry construction accepts participant-index and identity-public-key entries, rejects an empty registry, detects duplicate indexes before canonicalization, rejects duplicate public keys, rejects identity public keys, and stores entries in canonical participant-index order.
- Registry admission assumes the authenticated deployment process has established that each participant knows the corresponding identity secret. Core does not accept, store, or verify a separate identity-key proof of knowledge in this protocol version.
- DkgConfig contains only threshold, session identifier, ParticipantRegistry, and an ordered nonempty vector of DkgInstanceKind.
- The canonical general constructor is new. It accepts the complete ordered instance vector. new_random and new_zero construct one-instance convenience configurations. Do not retain batch as the canonical constructor or add new_batch.
- Validate every threshold in 1 through the participant count, inclusive.
- Expose read-only access to threshold, session identifier, registry, identity public key by participant, ordered instances, an instance by position, and the derived configuration root.
- Compute the configuration root from a fresh protocol version and the canonical immutable configuration fields. Do not serialize or accept an independently mutable cached root.
- An operation may calculate the root once and reuse it locally. Deserialization reconstructs validated values and rederives roots.
- The proof system and prepared-generator capacity are not DKG configuration inputs and do not affect configuration identity.

### Public workflow and proof-system state

- Expose free deal and complete functions from golden-core.
- deal receives a shared reference to the proof-system value, a shared reference to DkgConfig, the dealer participant index, the dealer identity secret, and a generic mutable CryptoRngCore.
- complete receives a shared reference to the same compatible proof-system value, a shared reference to DkgConfig, the completing participant's identity secret, a borrowed OwnDealing, and expected-dealer plus opaque-byte pairs for every peer.
- Retain generic RNG parameters. Do not replace them with a dyn CryptoRngCore interface.
- The proof-system value is explicitly stateful, reusable, Send + Sync, and reconstructible runtime state. It may own prepared generators, proof parameters, and private caches.
- The proof-system value is not stored in DkgConfig, OwnDealing, or DkgOutput and is not serialized as a runtime object.
- Expose no GoldenDkg, DkgSession, SecpSecqDkg, backend extension methods, type-alias architecture, or public standalone dealer-message verifier.

### DealerProofSystem and the flat proof seam

- Replace EvrfProofBackend with DealerProofSystem parameterized by GoldenCurve.
- DealerProofSystem has instance methods to:
  - prove with the validated DkgConfig, one flat statement, one flat witness, and generic RNG, returning owned proof bytes;
  - verify with the validated DkgConfig, one flat statement, and a borrowed proof byte slice;
  - verify_batch with the validated DkgConfig and an ordered collection of statement/proof references, with a default implementation that calls individual verification with that same configuration.
- DealerProofSystem is Send + Sync.
- There is no associated proof type, proof serde contract, public proof identifier, validate-config hook, receiver-pad method, relation-associated type, or selectable relation policy.
- Each concrete proof system privately versions and domain-separates its proof grammar. The caller-selected proof-system value determines how opaque proof bytes are interpreted; bytes cannot select or negotiate their verifier.
- Core constructs exactly one DealerProofStatement and DealerProofWitness for the complete dealer contribution.
- Statement and witness fields are not publicly mutable. Expose only the read access needed by proof-system implementations.
- For m configured instances, threshold t, and n participants, the flat statement and witness contain exactly m instance slots, exactly t logical commitment coefficients per slot, and exactly n − 1 receiver slots per instance. Receiver slots exclude the dealer and follow canonical registry order. The total receiver-slot count is m × (n − 1), using checked arithmetic.
- Expose read-only views for the dealer participant and public key, dealer-message root, instance count, one instance by position, each instance's effective message and t logical commitment coefficients, receiver count, and one receiver record by canonical position. A receiver record exposes its participant and public key, share commitment, pad commitment, and encrypted share.
- Expose corresponding read-only witness views for the dealer identity secret, one optional polynomial constant per instance, and each canonical receiver share/pad pair. Keep ordinary constructors and mutable fields private to core.
- Provide one narrowly scoped, doc-hidden validated witness-reconstruction operation for proof-system implementations. It accepts a validated DkgConfig, the core-built DealerProofStatement, and canonically decoded revealed witness parts; checks exact instance/receiver dimensions and Random/Zero optional-constant grammar; and returns an immutable DealerProofWitness. This is required only so the cross-crate insecure proof verifier can reconstruct the revealed witness before invoking the core checker. It is not serde, an application constructor, or an alternate statement-building seam.
- The complete public proof input is the validated DkgConfig paired with DealerProofStatement. The statement does not duplicate configuration root or beta as mutable fields.
- DealerProofStatement contains the dealer identity, proof-independent dealer-message root, per-instance effective messages, complete logical Feldman commitments in instance-major order, and receiver share commitments, pad commitments, and encrypted shares in canonical instance/receiver order.
- DealerProofWitness contains the dealer identity secret, an optional Random polynomial constant for each instance, and the shares and pads in the same canonical order.
- Core guarantees dimensions, configured kinds, and canonical ordering before invoking the proof system. A proof implementation does not repeat generic shape validation.
- Core supplies one exact native relation checker over the flat statement and witness. The production circuit and insecure test proof must agree with it.
- Expose beta derivation, H1/H2 framing, receiver-pad evaluation, and the native checker from a narrowly scoped, doc-hidden core Main Golden module so golden-evrf can reuse them across the crate boundary. Do not re-export these helpers as ordinary application workflow or place them on DealerProofSystem or GoldenCurve.
- Each concrete proof implementation absorbs config.root and the complete ordered flat public statement before emitting, parsing, or challenging nested proof components. Random constant-extraction records and the nested Main Golden proof continue on one unambiguous versioned transcript.
- Replace ShareOpeningBackend with InsecureRevealedWitnessProof. It serializes the actual dealer witness as proof bytes and invokes the core native checker during verification.
- InsecureRevealedWitnessProof verification canonically decodes the complete revealed witness, rejects malformed or trailing bytes, uses the validated doc-hidden witness-reconstruction operation, and then invokes the core native checker.
- InsecureRevealedWitnessProof is test infrastructure, is never in the default production export surface, and may be exposed outside tests only behind an explicitly named non-default insecure feature.
- Production proof bytes must not reveal the hidden shared identity-DH point, H1/H2 exponentiation intermediates, pad scalar, share scalar, identity secret, circuit bit decompositions, or chord witnesses.
- Paper-specific circuit statement, witness, and precomputation structures may remain as private golden-evrf implementation details. They do not form a second public seam.

### OwnDealing and local generation

- Rename the dealer-local result to OwnDealing.
- OwnDealing contains:
  - dealer participant index;
  - exact outbound dealer-message bytes;
  - private self share for every configured instance;
  - configuration/session binding sufficient to reject restoration or use with another configuration.
- OwnDealing contains no identity secret and no proof-system value.
- The initial public accessors are participant and dealer_message_bytes. Keep private shares inaccessible except to completion internals.
- OwnDealing implements Clone and direct application serde. Debug output redacts every private share and does not print outbound proof bytes as diagnostics.
- deal checks that the supplied identity secret matches the registered public key before sampling or publishing a result.
- deal constructs every instance independently, builds the complete message and flat proof inputs, and asks DealerProofSystem for exactly one proof over the whole dealer contribution.
- deal enforces the whole-message limit on its final encoding.
- deal returns only after it has encoded canonical bytes and assembled a complete OwnDealing.

### Dealer-message wire grammar and parser

- Dealer messages remain opaque and context-dependent outside golden-core.
- Adopt a fresh envelope magic, codec version, protocol/configuration version, concrete curve identifier, and private proof-framing version. Exact literals are implementation constants and must be pinned by canonical tests.
- The envelope does not contain a proof-system identifier. The injected proof-system value is trusted configuration of the caller, not data selected by the message.
- The configuration determines instance count and kinds, commitment lengths, canonical non-dealer receiver order, receiver count, and proof placement.
- The canonical body order is:
  - envelope;
  - configuration root;
  - encoded dealer participant;
  - each configured instance in position order;
  - instance nonce;
  - the configured physical Feldman commitment;
  - one pad commitment and encrypted share for every canonical non-dealer receiver;
  - the single opaque proof as the remaining suffix.
- Do not encode counts, Random/Zero discriminators, receiver indexes, or commitment lengths already fixed by configuration.
- Read and validate the envelope, configuration root, and encoded dealer before nested allocation.
- Enforce a fixed 16 MiB maximum for the entire dealer message before parsing or allocation. Expose max_dealer_message_bytes so callers can enforce the same transport limit.
- Use checked length and capacity arithmetic throughout parsing.
- Canonically decode every point and scalar and reject malformed, noncanonical, truncated, overlong, or trailing data.
- For Zero, reconstruct the logical identity coefficient before roots, Feldman evaluation, and proof inputs. For t = 1, the physical Zero commitment tail is empty.
- The dealer-message root is proof-independent to avoid a circular statement. It commits to the verified configuration and dealer identity plus every ordered logical public dealing value, including reconstructed Zero identities.
- Keep one private owned parsed hierarchy equivalent to dealer message, dealing, and encrypted share. Do not expose public parsed, verified, or accepted message types.
- Add no context-free parser, borrowed parser, zero-copy parser, streaming parser, or public byte-mutation API.

### Completion and proof attribution

- complete validates the supplied identity secret against the completing participant and validates OwnDealing's participant and configuration binding.
- The peer input contains exactly one candidate for every configured participant other than the completing participant. OwnDealing supplies the completing participant's own candidate.
- Reject missing, duplicate, unexpected, or self-duplicating candidates. Canonicalize all accepted candidates by participant index.
- Treat each supplied expected-dealer index as routing metadata. Compare it with the envelope dealer and the dealer identity bound by the statement.
- Enforce the whole-message bound independently for every candidate before parsing.
- Parse the exact configuration-selected grammar for all candidates.
- Validate all public relations before proof parsing, including configuration binding, dealer identity, commitment shape, Zero semantics, canonical receiver shape, Feldman share commitments, encrypted-share equations, and nonidentity pad commitments.
- Parse all proof suffixes canonically only after public-relation validation.
- Call optimized cross-dealer verify_batch once for the ordered dealer set.
- Run per-dealer fallback only when verify_batch returns the stable invalid-proof or batch-equation verdict. Configuration, capacity, malformed prepared-state, and other proof-system operational errors propagate unchanged and are never treated as dealer misconduct.
- After an invalid-proof/batch-equation verdict, individually verify every dealer rather than stopping at the first invalid proof.
- If individual verification identifies invalid proofs, return all invalid dealer participant indexes in canonical order. If an individual call instead returns an operational error, propagate that error unchanged rather than converting it into dealer attribution.
- If every individual proof passes, return BatchVerificationFailed and preserve the original batch-verification failure rather than inventing dealer attribution.
- Decrypt and aggregate shares only after every dealer proof is accepted.
- Reject a share-decryption or OwnDealing mismatch without returning a partial instance or output.
- Completion is atomic across every dealer and every configured instance.
- complete returns one DkgOutput or an error. There is no partially accepted message set or partially completed output.

### Degenerate supported shapes

- Support every nonempty participant registry and every threshold from one through n.
- For n = 1 and t = 1:
  - each instance has no public receiver entry;
  - the dealer-message proof suffix is canonically empty;
  - deal and complete never call DealerProofSystem;
  - a nonempty proof suffix is rejected;
  - proof-system preparation accepts zero required receiver-proof capacity.
- For t = 1 Random, the physical commitment contains its one logical constant.
- For t = 1 Zero, the physical commitment tail is empty and the reconstructed logical commitment is exactly the identity.
- Preserve identity share commitments as valid whenever a legitimate polynomial evaluates to zero. Only identity participant keys and identity receiver-pad commitments are invalid.

### Outputs and roots

- DkgOutput contains:
  - the completing participant;
  - the ordered DkgInstanceOutput values;
  - the originating 32-byte configuration root.
- DkgOutput does not store completion_root; it derives it from immutable output data.
- Each DkgInstanceOutput contains the aggregate public key, the completing participant's secret share, and the canonical map of every participant's public-key share.
- Store the local secret share as the curve scalar itself and return it by shared reference. The participant identity belongs once on DkgOutput rather than being duplicated in a Share wrapper for every instance.
- Expose read-only access to the completing participant, ordered instances, one instance by position, originating configuration root, aggregate public key, secret share, public-key-share map, and derived completion root.
- completion_root commits to:
  - a fresh root domain/version;
  - the configuration root;
  - every ordered instance aggregate public key;
  - every ordered canonical participant/public-key-share pair for every instance.
- completion_root excludes the completing participant, secret shares, dealer-message bytes, proof bytes, proof-system identity, proof-generator capacity, and exact board provenance.
- All honest participants completing the same accepted dealer set derive the same completion root.
- Deployment may separately hash exact board artifacts, compare participant-reported roots, decide agreement, and activate a pending output.
- Debug output for OwnDealing, DkgOutput, and DkgInstanceOutput redacts secret shares.

### Serde and trusted persistence

- Keep serde distinct from protocol encoding. Serde output is not canonical Golden wire format, carries no protocol compatibility promise, and never enters roots, transcripts, proofs, or untrusted dealer parsing.
- Under the existing serde feature, direct application serde applies to ParticipantIndex, SessionId, DkgInstanceKind, ParticipantRegistry, DkgConfig, OwnDealing, DkgInstanceOutput, DkgOutput, concrete scalar and point adapters needed by those values, and SecpSecqPreparedGenerators.
- Preserve the repository's existing optional serde and Miden serialization feature families where these public application values already participate. Both remain persistence representations and neither becomes dealer-message wire encoding.
- Do not add serde for runtime proof-system values, public errors, private parsed dealer-message trees, DealerProofStatement, or DealerProofWitness.
- Deserialization of registries and configurations routes through validated construction and rederives roots rather than accepting serialized cached roots.
- Deserialization of points, scalars, OwnDealing, outputs, and prepared generators rejects noncanonical encodings and structurally inconsistent lengths.
- The persistence threat model is trusted application storage. Do not add Golden-owned MACs, checkpoint authentication, session-bound restoration protocols, filesystem paths, cache directories, or storage policy.
- complete remains responsible for checking a restored OwnDealing against the supplied configuration and participant before it is used.
- Make a hard serde format cut. Do not restore values serialized by the legacy representation.

### Prepared Secp/Secq generators

- Replace BatchedEvrfPublicParams and fixed/global public cache APIs with SecpSecqPreparedGenerators plus a reusable SecpSecqBulletproofs proof-system value.
- SecpSecqPreparedGenerators is concrete, serde-capable proof-system state with an explicit declared logical capacity and exactly that deterministic generator prefix.
- Define capacity as the padded Bulletproof generator count, not an identity for a threshold/instance/receiver tuple. Expose a read-only capacity accessor.
- prepare_for computes the exact circuit multiplier requirement for a validated DkgConfig with checked arithmetic, rounds it to the smallest supported Bulletproof generator capacity, and accepts the n = 1 zero-capacity shape. Zero capacity is represented by an empty logical prefix and does not force construction of unused generators.
- SecpSecqBulletproofs may be built either by preparing directly for one configuration or by consuming a restored SecpSecqPreparedGenerators value.
- A proof-system value may serve any configuration whose calculated requirement is no greater than its declared capacity.
- Reject an under-capacity configuration before statement proving, proof parsing, verification, or lazy generator extension.
- Do not place prepared capacity or artifact identity in DkgConfig, configuration root, DkgOutput, or completion root.
- A private process-wide deterministic prefix memoization may remain an optimization, but it is not public policy and cannot change an artifact's declared logical length.
- Serialization emits exactly the declared logical prefix even when a larger prefix was previously generated in the process.
- Restoration validates artifact version, canonical nonidentity point encodings, curve identity, fixed supported party capacity, declared generator capacity, exact vector lengths, exact logical prefix length, and checked dimensions.
- Restoration does not regenerate and compare the deterministic points. Deployment is responsible for authenticating the artifact before passing it to Golden.
- Golden owns no artifact path, file I/O, cache naming, locking, or migration.

### Public errors

- Use one public Golden Error enum and coarse DealerMessageError reasons where message attribution needs a nested category.
- Preserve stable conceptual errors for:
  - participant and configuration validation;
  - identity-secret/public-key mismatch;
  - OwnDealing participant or configuration mismatch;
  - missing, duplicate, or unexpected dealer candidates;
  - expected-dealer/envelope-dealer mismatch;
  - whole-message size violation;
  - coarse invalid dealer-message attribution;
  - one or more individually invalid dealer proofs;
  - unexplained BatchVerificationFailed;
  - proof generation;
  - share decryption;
  - under-capacity or malformed prepared generators;
  - degenerate local eVRF output requiring a fresh deal attempt.
- Error names may be selected consistently during implementation, but their public information boundary is fixed.
- DealerProofSystem implementations translate proof parsing, proving, capacity, and verification failures into the stable core error categories; backend and circuit error types never escape the public DKG surface.
- Stable errors may identify a dealer participant when attribution is part of the public completion result.
- Stable errors do not expose an instance index, receiver index, proof byte offset, parsed secret, raw bytes, circuit detail, proof-system implementation detail, or prepared-generator contents.
- Add no separate public diagnostic method that weakens this boundary.

### EHTDH1 integration

- Migrate the EHTDH1 bridge to the public free-function workflow and the retained public ParticipantRegistry.
- EHTDH1 requests the exact ordered Random and Zero DKG configuration and receives two separately addressable output instances.
- The bridge maps the first output to the decryption sharing and the second to the context-zero sharing.
- The bridge continues to require the decryption aggregate public key to be nonidentity and the context aggregate public key to be identity.
- Generic DKG core does not know the application names decryption, context, or x, and does not replace EHTDH1's output postconditions.
- Preserve existing EHTDH1 online encryption/decryption behavior after the bridge migration.

### Security statement and batch verification

- State Main Golden's actual scope: static corruptions of at most t − 1 participants, the ideal eVRF/ZK hybrid and random-oracle setting, consistent authenticated registry/setup and broadcast semantics, and the additive-bias key-generation functionality—not adaptive security, fully unbiased key generation, or security with aborts.
- State the EHTDH1 assumptions separately, including its static-corruption scope, random-oracle model, LOMDH assumption, and semantic security of the symmetric cipher.
- State that authenticated participant admission establishes identity-secret knowledge for this version.
- State that the fixed beta derivation is an explicit protocol random-oracle instantiation rather than a caller- or session-sampled setup object.
- Never attribute arbitrary mixed Random/Zero joint-proof composition directly to the paper's single-instance theorem. The dedicated review may establish a separate composition argument supporting a production claim; it cannot make this construction textually covered by Golden Theorem 3.
- Optimized cross-dealer batch verification derives nonzero combining coefficients only after binding every ordered complete statement and proof. Fixed, input-independent, zero, or partially bound coefficients are invalid.
- Because DealerProofSystem verification has no verifier RNG parameter, the optimized Secp/Secq batch verifier derives its coefficients from a dedicated injectively framed transcript. Before any coefficient is drawn, absorb the protocol and proof versions, configuration root, batch length, and then, in canonical dealer order, each dealer participant index, complete canonical statement, proof length, and proof byte string.
- Production proofs keep all hidden receiver-pad intermediates inside the proof relation and bind the complete canonical public statement before any nested proof transcript.

### Compatibility and legacy deletion

- Make one hard compatibility cut for configuration roots, dealer envelopes, dealer-message grammar, private proof framing, prepared-generator artifacts, serde representations, test vectors, and cache state.
- Reject legacy artifacts. Do not add fallback parsing, dual verification, version negotiation, compatibility wrappers, or migration utilities.
- Remove the public parsed DealerMessage and DkgDealing workflow, create_dealing, standalone verify-dealing operations, and public nested Evrf statement/witness types.
- Remove EvrfProofBackend, ShareOpeningBackend, SecpSecqBackend, BatchedEvrfPublicParams, and the old nested/paper-specific statement adapters at the core/eVRF boundary.
- Remove the standalone one-receiver public functions, statement/witness types, proof identifier, fixed generator cache, dedicated test target, and old vector.
- Preserve the one-receiver behavior that still matters through the general one-instance, one-non-self-receiver shape.
- Migrate examples and benchmarks only enough to preserve their current purpose. Do not retain old public APIs solely to reduce migration work.
- Regenerate hard-cut dealer-message fixtures in the new opaque format. Validate cached fixture bytes through complete with matching OwnDealing rather than restoring a standalone verification method.
- Prepare SecpSecqBulletproofs outside timed deal/complete benchmark regions unless generator preparation is the operation explicitly being measured.

## Testing Decisions

### Test seams and quality

- The primary seam is the public free-function workflow: validated configuration plus proof system, deal, transfer only opaque bytes, complete, and inspect DkgOutput.
- Prefer assertions on public results, roots, errors, and opaque byte behavior over assertions on private parser trees, circuit witness structures, or cache implementation.
- Use one shared scenario builder and table-driven cases for participant counts, thresholds, and Random/Zero orderings rather than one test per obvious branch.
- Add a narrower core native-relation seam only for deterministic beta, H1/H2, receiver-pad, degenerate-output, and insecure-proof conformance tests.
- Add proof-system conformance tests at DealerProofSystem for opaque framing, individual verification, optimized batch verification, and exact native/circuit relation parity.
- Add private in-crate wire builders or encoded-byte mutation helpers for malformed states that honest public construction cannot produce. Do not make parsed message fields public for tests.
- Add prepared-generator tests through preparation, proof-system construction, and serde restoration rather than inspecting private cache internals.
- Keep TinyGroup for algebra, configuration, Shamir, and Feldman tests. Do not add a golden-core development dependency on golden-evrf and do not invent AlgebraicTestCycle to retain core-local workflow tests. Place complete DKG lifecycle coverage in golden-evrf integration tests over a real GoldenCurve using the fast exact-relation proof.
- Preserve focused production Secp/Secq proof tests. Do not multiply expensive proof generation across every parser or configuration error case when the insecure exact-relation proof exercises the same orchestration.
- Existing batch-native core completion tests, golden-evrf DKG integration tests, batched dealer-proof tests, one-receiver tests, prepared-parameter serde tests, and the EHTDH1 bridge are the prior art to migrate and consolidate.

### Configuration, registry, and deterministic protocol values

- Test registry rejection of empty input, duplicate indexes, duplicate canonical public keys, identity public keys, and noncanonical encodings.
- Test canonical registry ordering and stable registry roots independent of input entry order.
- Test threshold boundaries with a table covering zero, one, n, and n + 1.
- Test rejection of an empty instance vector and preservation of every ordered Random/Zero sequence.
- Test that configuration roots change with session identifier, threshold, registry, participant key, instance kind, instance position, and protocol version.
- Test that proof-system implementation, prepared capacity, and runtime cache state do not change configuration roots.
- Pin beta derivation with exact vectors, including domain string, counter framing, candidate byte order, canonical decoding, and zero acceptance behavior.
- Add a deterministic sampler test in which attempt zero produces an out-of-field candidate and attempt one is accepted, so rejection and counter reset behavior are exercised rather than merely specified.
- Test that beta has the BaseField type and cannot be supplied through configuration or restored from serde.
- Pin effective-message vectors and prove sensitivity to configuration root, dealer, instance position, instance kind through configuration identity, and nonce.
- Pin H1/H2 input framing and distinct domain tags.
- Test H1/H2 key-order symmetry: dealer/receiver and receiver/dealer inputs derive the same ordered tuple.
- Test that changing either identity key or the effective message changes both relation inputs.
- Test that the removed message-only zero-padding rule does not reproduce the new H1/H2 points.

### Random, Zero, and mixed-instance behavior

- Test Random, Zero, Random/Zero, Zero/Random, repeated-kind, and longer mixed orderings through one table-driven public workflow.
- Test that one dealer message carries one proof suffix for the complete configured batch.
- Test independent nonces and effective messages for every instance.
- With an instrumented deterministic test RNG and domain checkpoints, prove that every instance receives fresh draws or distinct domains for polynomial coefficients, nonce, effective message, and proof commitments/blindings. Do not reject accidental equality of independently generated outputs; independence is distributional, not an inequality invariant.
- Test that a Random constant may legitimately be zero while retaining Random physical and proof grammar.
- Test that Zero omits the physical identity coefficient and constant-opening proof but reconstructs the complete logical commitment.
- Test full logical commitment equivalence between the reconstructed Zero form and explicit identity-plus-tail evaluation.
- Test transcript and dealer-message-root binding of the reconstructed logical identity.
- Test that changing configuration kind, moving a Zero tail to another position, reordering dealings, or supplying Random grammar under Zero configuration is rejected.
- Construct multiple malicious Zero dealer contributions with nonzero constants that cancel in aggregate and require each dealer contribution to be rejected; aggregate identity alone is insufficient.
- Test t = 1 Zero with an empty physical tail, logical identity, identity public-key shares, and successful completion.
- Test all valid n and t boundary shapes needed to demonstrate support for n greater than or equal to one and t in one through n.

### deal, OwnDealing, and local failures

- Test identity-secret mismatch before a dealer result is returned.
- Test exact outbound bytes from OwnDealing against the public bytes passed to peers.
- Test OwnDealing accessors, Clone, serde round trip, and redacted Debug without exposing self shares or identity secret.
- Test restored OwnDealing rejection under another configuration or participant.
- Exercise a deterministic test-only relation/curve path that produces a zero final reduced pad.
- Assert that degenerate deal returns the dedicated coarse retryable error, reveals no instance or receiver index, calls no internal retry loop, and yields no bytes or OwnDealing.
- Test that a fresh external deal attempt can succeed after the deterministic zero-pad failure path is removed or RNG advances.
- Test other affine-coordinate failures separately and assert fail-closed coarse errors without a panic or zero substitution.
- Test final encoded size enforcement on locally generated messages.

### Opaque bytes and parser hardening

- Pin the new envelope, protocol, codec, concrete-curve, proof-framing, and prepared-artifact versions.
- Test rejection of every legacy message/proof/artifact/vector version.
- Test a message exactly at the 16 MiB limit and rejection before nested allocation at one byte over the limit.
- Test truncated and overlong envelope fields, wrong magic/version/codec/curve, wrong configuration root, wrong dealer, and noncanonical participant encoding.
- Test checked-arithmetic failure paths for computed lengths and capacities using deterministic boundary and property cases.
- Test config-selected commitment and receiver dimensions without trusting counts from bytes.
- Test malformed and noncanonical point/scalar encodings, invalid subgroup points where applicable, identity participant keys, and identity pad commitments.
- Test valid identity share commitments remain accepted.
- Test missing, extra, reordered, and duplicated receiver material through opaque-byte mutations.
- Test malformed, truncated, replayed, reordered, and trailing proof bytes.
- Test proof replay across configuration roots, dealer keys, receiver keys, instance kinds, instance positions, and dealer-message roots.
- Test that the proof suffix is the only remaining bytes after exact configured parsing.
- Test that public parser internals remain private and no context-free decode path is exported.

### Completion, attribution, and atomicity

- Test missing, duplicate, unexpected, self-duplicating, and expected-dealer/envelope-dealer mismatches.
- Test canonical ordering of an otherwise arbitrarily ordered caller candidate list.
- Test that every public relation is checked before proof verification and every proof is accepted before decryption.
- Test optimized cross-dealer batch verification success with complete ordered statements and proofs.
- Force batch failure with one and multiple invalid dealer proofs and assert all invalid dealers are reported once in canonical order.
- Force a batch-verifier failure while every individual proof passes and assert BatchVerificationFailed is preserved.
- Force capacity/configuration/prepared-state operational errors from batch and individual verification and assert they propagate without per-dealer blame or fallback-driven reclassification.
- Test transcript-derived combining coefficients are nonzero and sensitive to every statement and proof.
- Test share-decryption failure returns no DkgOutput.
- Test one invalid dealer or one invalid instance prevents every output instance from being returned.
- Test successful completion for every participant yields equal aggregate public keys, public-key-share maps, and completion roots while secret shares and participant fields remain local.
- Test completion retry with the same borrowed OwnDealing and a corrected peer candidate set.

### Single-participant and one-receiver coverage

- Use a spy DealerProofSystem to prove n = 1, t = 1 invokes neither prove, verify, nor verify_batch.
- Test n = 1 accepts only the canonical empty proof suffix and rejects forged nonempty proof bytes.
- Test prepared-generator construction accepts the n = 1 zero-capacity requirement.
- Transfer the standalone one-receiver honest proof, wrong-key, wrong-message, derived-beta/protocol-version mismatch, framing, canonical parse, tamper, and trailing-byte behaviors into the general one-instance, one-non-self-receiver proof path. Exercise a mismatched beta only inside private native/circuit conformance scaffolding; do not reintroduce beta as mutable public statement data.
- Delete the old standalone vector only after equivalent behavior is protected in the new versioned path.

### Production and insecure proof systems

- Test InsecureRevealedWitnessProof against the exact native relation for honest and tampered public/witness data.
- Test that the insecure proof is absent from default production exports and available only to tests or the explicit non-default insecure feature.
- Test the Secp/Secq circuit and native core checker accept the same honest statements and reject the same public-relation mutations.
- Preserve regression coverage that the production proof grammar has no explicit records for hidden shared points, H1/H2 exponentiation intermediates, pad scalars, shares, or identity secrets and that each remains a private circuit witness. Do not use accidental absence of a secret's raw byte substring as evidence of zero knowledge.
- Test the complete canonical public statement is observed before nested proof data and that all proof components continue on one transcript.
- Test canonical proof parsing and rejection of alternative encodings or trailing data.
- Test optimized Secp/Secq cross-dealer verification binds the entire ordered statement/proof collection.

### Output, roots, and serde

- Test DkgOutput and DkgInstanceOutput accessors and redacted Debug.
- Test output serde round trips for one and multiple instances, every participant, and identity-valued legitimate public outputs.
- Test malformed scalar/point encodings and inconsistent output dimensions are rejected on restoration.
- Test configuration_root is retained after persistence and mismatch with supplied configuration is rejected where relevant.
- Test completion_root is derived, stable after serde, and never accepted as an independent serialized cache.
- Test completion_root changes with configuration root, instance order, aggregate public key, participant index in a public-share map, or public-key-share value.
- Test completion_root does not change with the completing participant, local secret share, proof-system implementation, proof bytes, prepared capacity, or board ordering when the common public result is unchanged.

### Prepared generators and persistence

- Test prepare_for chooses the exact minimum padded capacity for representative configurations and uses checked arithmetic.
- Test a prepared value is reusable for equal and smaller requirements.
- Test an under-capacity value fails before proof work and never lazily extends.
- Test serde round trip preserves declared capacity, curve/artifact version, and exactly the logical prefix.
- Test restoration rejects wrong version, curve, capacity, point count, logical length, truncated bytes, extra bytes, and noncanonical or invalid points.
- Warm a large private/process prefix, then prepare and serialize a smaller declared value; assert the artifact contains exactly the smaller logical prefix.
- Test restoration does not trigger deterministic prefix rederivation.
- Keep authentication outside these tests except for documenting that callers must authenticate before restoration.

### EHTDH1 and migration

- Migrate the EHTDH1 bridge test through an exact ordered Random/Zero DKG and preserve distinct decryption/context shares.
- Test the bridge rejects an identity decryption aggregate public key or nonidentity context aggregate public key.
- Preserve existing online EHTDH1 encryption, partial decryption, combination, and failure behavior.
- Migrate benchmarks and examples to free deal/complete and explicit SecpSecqBulletproofs state without restoring legacy APIs.
- Remove or rewrite tests that mutate public dealer-message or output fields; use encoded-byte tampering, private builders, or observable public construction instead.

## Out of Scope

- Appendix K and eVRF-derived polynomial coefficients.
- Fully unbiased key generation or the paper's security-with-aborts variant.
- Any relation selector, coefficient policy, DealerVrf abstraction, MainGoldenRelation type, or public associated type anticipating another relation.
- The mixed-instance composition/security review itself. It is a later release gate.
- A separate security review of the fixed-string beta instantiation.
- Identity-key proof-of-knowledge artifacts in ParticipantRegistry or DkgConfig. Deployment admission supplies this assumption for the current version.
- Concrete secret-memory or Drop zeroization for Halo2 and other scalar types. Debug redaction remains required.
- A facade crate, GoldenDkg object, runtime/session wrapper, or backend extension-method workflow.
- AlgebraicTestCycle or another prototype cycle.
- Additional prepared-generator constructors for multiple configurations or operator-selected raw capacities.
- Shape-derived per-configuration message limits, streaming parsing, zero-copy parsing, and public parsed dealer-message values.
- A standalone public dealer-message verification workflow.
- Golden-owned incremental collection, deduplication, message-board storage, agreement protocol, activation policy, exact-board provenance, artifact paths, filesystem I/O, cache directories, or storage authentication.
- Legacy dealer-message, proof, serde, vector, cache, or prepared-generator migration and compatibility.
- New proof systems, curves beyond those required to preserve existing adapters/tests, FROST, fuzzing campaigns, performance targets, or benchmark claims beyond migrating the current benchmark purpose.

## Further Notes

- The resolution ledger overrides older handoff language in four important places:
  - beta is fixed-string and protocol-wide, not derived from configuration identity or supplied through a setup identifier;
  - H1/H2 bind the effective message and ordered identity-key pair, not only a zero-padded 32-byte message;
  - zero final pads return a local coarse error rather than relying on verifier rejection;
  - authenticated registry admission supplies identity-key knowledge without a core proof-of-knowledge artifact.
- Main Golden's beta derivation is accepted under the explicit random-oracle model and is not part of the later mixed-composition review gate.
- The arbitrary ordered Random/Zero joint proof may be implemented and tested now and must always be labeled as a repository extension. After its dedicated review, production documentation may rely on the resulting composition argument but must not describe the construction as directly covered by Golden Theorem 3.
- Prepared-generator and ordinary serde inputs are trusted application persistence, not untrusted protocol messages. Structural and canonical validation still protect invariants, while authenticity remains deployment-owned.
- The specification deliberately chooses one high public test seam. Private parser, relation, and prepared-artifact seams exist only where security properties cannot be exercised reliably or affordably through a full production proof.
- No user-owned architecture decision remains. Exact Rust error variant spelling and fresh version/tag byte literals may be chosen during implementation as long as they preserve the contracts and hard-cut requirements above.
