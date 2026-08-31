# Golden DKG interface refactor — authoritative checkpoint

## Purpose

Continue the `/grill-with-docs` design interview in a fresh smart-zone context. Do not implement production changes yet. Ask one decision question at a time, recommend an answer, look up codebase facts rather than asking factual questions, update `CONTEXT.md` immediately when domain terminology settles, and add ADRs only for durable non-obvious trade-offs.

This checkpoint supersedes the older handoff at:

`/var/folders/52/5ych7qyd6sx5s2vmv1lvnqsc0000gn/T/golden-dkg-handoff/dkg-interface-refactor.md`

The older handoff remains useful only for historical and deployment/prototype evidence. Where it conflicts with this checkpoint, this checkpoint controls.

## Suggested skills

- Start with `/grill-with-docs` using `/codebase-design` vocabulary.
- The immediate question is an interface/module-seam question, not implementation.
- After the proof architecture is settled, finish versioning, migration, tests, and zeroization decisions.
- Before `/to-spec`, branch `AlgebraicTestCycle` through `/handoff` into a fresh `/prototype` session, then hand the result back.
- This is not `/wayfinder`: the destination is visible.

## Repository artifacts that control

Read these first and do not duplicate them:

- `CONTEXT.md`
- `docs/adr/0001-separate-serde-from-protocol-encoding.md`
- `docs/adr/0002-configuration-owns-instance-policy.md`
- `docs/adr/0003-configuration-determines-dealer-message-grammar.md`
- `resources/notes/fixed-zero-constant-elision.md`
- `resources/notes/2026-08-06-x-zero-dkg-batching.md`

The configured `resources/context/INDEX.md` and `resources/context/REPO_CONTEXT.md` are absent from this worktree.

## Current working state

```text
## adr1anh/batch-dkg...origin/adr1anh/batch-dkg
 M CONTEXT.md
?? docs/
```

No production Rust code has been edited by the design sessions. `docs/` contains ADRs 0001–0003 and is still untracked. No tests/builds were run because this was design-only.

## Final architecture resolution

This section and the consolidated production handoff supersede the older architecture/configuration sections below. The remaining checkpoint content is historical evidence when it conflicts.

- Keep the existing crate direction. `golden-core` owns free `deal` and `complete` orchestration plus the one fixed Main Golden relation; `golden-evrf` owns concrete proof systems for that relation. Add no session/runtime wrapper or facade crate.
- DKG execution is generic over `G: GoldenCurve` and an explicitly injected reusable stateful `P: DealerProofSystem<G>`. `DkgConfig` remains a separate immutable public value and is always passed by reference.
- `GoldenCurve: GoldenHashToGroup` exposes `BaseField: ff::PrimeField`, base-field representation byte order, affine x-coordinate extraction, and exact base-field-integer-to-scalar reduction. Core owns beta derivation, H1/H2 domains and framing, receiver-pad evaluation, and the exact native relation checker.
- `DealerProofSystem<G>` contains only instance methods `prove`, `verify`, and optional optimized `verify_batch`. Proofs are opaque `Vec<u8>` values and verification borrows `&[u8]`; there is no proof associated type, `validate_config`, or `evaluate_receiver_pad` method.
- Retain public `ParticipantRegistry`.
- Beta is not stored in `DkgConfig`, exposed by an accessor, duplicated in `DealerProofStatement`, or separately stored in messages/output. It is derived internally in the full base field from canonical configuration identity; the setup-security/grinding assumption remains the sole blocking decision before `/to-spec`.
- `deal` returns serde-capable, secret-bearing `OwnDealing` containing exact outbound bytes and private self shares but no identity secret. `complete` borrows it so callers may retry after restoring it.
- Dealer messages remain opaque, configuration-selected bytes outside Golden. The public lifecycle is `deal`/`complete`; there is no standalone public verification workflow.
- Delete `ShareOpeningBackend`. Use an unmistakably insecure witness-revealing proof that verifies the exact fixed relation through core's native checker.
- Main Golden is the only semantic relation. Appendix K and eVRF-derived Feldman coefficients are out of scope; do not anticipate relation/policy types or associated types.
- `completion_root` identifies configuration plus canonical common public output and excludes local participant, secrets, dealer messages, proof bytes, and proof-system identity. Exact board provenance remains deployment-owned.
- Prepared Secp/Secq generators are concrete serde-capable state owned by `SecpSecqBulletproofs`, reusable across compatible configurations, and excluded from configuration/completion identity.

## Superseded post-checkpoint architecture resolution

This section formerly superseded the unresolved proof/session architecture below. It is now historical and must not override the final resolution above or the consolidated production handoff.

- Preserve the existing crate direction: `golden-core` owns generic DKG orchestration and `golden-evrf` supplies concrete eVRF evaluation and proof adapters. Do not add a new crate or facade in this refactor.
- Do not add `GoldenDkg`, `DkgSession`, `SecpSecqDkg`, or a borrowed/owning session wrapper.
- The caller-facing module is the stateful backend value itself. Its generic DKG methods receive `&DkgConfig` explicitly; the documented workflow is `backend.deal(...)` and `backend.complete(...)` only.
- Implement generic orchestration once in `golden-core` as backend methods backed by private helpers. Concrete backends must not duplicate forwarding orchestration.
- Make the backend instance-based, `Send + Sync`, and explicitly stateful so it can own prepared setup, caches, and proof-specific configuration. Retain `&mut impl CryptoRngCore`; do not change the RNG path to `dyn CryptoRngCore`.
- The cross-crate adapter retains a narrowly documented `evaluate_receiver_pad` hook because generic core cannot name the concrete Secp/Secq relation. Within `golden-evrf`, native relation evaluation remains separate from proof construction, and all proof adapters for the same policy must delegate to the same evaluator.
- Proving, individual verification, and cross-dealer batch verification receive the validated `&DkgConfig` and must observe `config.root()` themselves. The flat `DealerProofStatement<G>` / `DealerProofWitness<G>` seam remains authoritative.
- No public proof ID is required from the backend. Each implementation privately versions and domain-separates its proof transcript and framing. Proof bytes never select or negotiate a backend.
- Main Golden is the only policy implemented now. Appendix K's eVRF-derived coefficients are a future distinct proof relation/R1CS, tentatively expressible as a concrete backend policy parameter such as `SecpSecqBackend<P>`. Do not add `P` to public core types before a second policy exists. A future policy must be bound into configuration bytes/root.
- Keep the fast share-opening backend as explicit test infrastructure. It may remain weaker evidence, but adapters for the same production policy should ultimately use the production receiver-pad evaluator. Do not claim that it implements Appendix K or the paper relation.
- `SecpSecqPreparedGenerators` is a concrete serde-capable deterministic generator prefix supplied to backend construction, not publicly installed into process-global policy. `prepare_for(&config)` prepares exactly the required capacity; the resulting backend may serve any configuration requiring no larger prefix. Larger configurations fail before proof work. Additional constructors may be added later for demonstrated multi-config needs.
- `DkgConfig::root()` is derived from its immutable fields. `DkgOutput` retains the originating 32-byte configuration root, but `completion_root()` is derived rather than stored.
- The completion root commits to the configuration root and canonical common public DKG output (ordered instance public keys and participant public-key shares). It excludes participant-local identity, secret shares, dealer proof bytes, and backend identity.
- Make a hard compatibility cut: no old dealer-message, proof, prepared-generator, or serde compatibility path. Use one new fail-closed grammar and fresh private transcript/version domains.
- Defer concrete Halo2 scalar zeroization mechanics. Do not block interface design or overstate current guarantees.

A separate standalone dealer-message verification method is not part of the documented workflow. Deployment completes to a pending output, performs agreement externally using the derived completion root, and controls activation.

## Historical unresolved question: choose a boring proof/session architecture

The conversation ran out of smart-zone while reconsidering the proof implementation seam.

The user explicitly asked for something “less smart”: minimize wrappers, traits, hypothetical extensibility, and migration churn.

Facts:

- `bulletproofs-cycle` is genuinely generic over its low-level `Cycle` trait.
- `golden-evrf::paper::secp_secq` is not generic. Its Golden relation is concretely hard-coded to Secp256k1 input, `Fp` R1CS, and Secq256k1 output/commitment group.
- `golden-core` currently uses two generic axes: `G: GoldenGroup` plus `B: EvrfProofBackend<G>`.
- `golden-evrf` depends on `golden-core`; core cannot name the concrete Secp/Secq implementation without creating a dependency cycle.
- The current crate split must remain for this refactor; a facade crate is deferred.
- The prototype backend must remain temporarily for fast tests.
- `AlgebraicTestCycle` is only a proposed test implementation and requires a runnable prototype before its internal genericization is designed.
- Prepared generator persistence is concrete Secp/Secq cache machinery and must not force a generic parameter-cache trait.

A prior recommendation was a public-but-unstable `DkgCycle` trait with `GoldenDkg<Cycle>`. The user initially said “sure,” then correctly pointed out the R1CS is not generic and reopened the architecture. Treat that decision as unresolved.

A fresh architecture agent recommended:

- concrete public `SecpSecqDkg` in `golden-evrf`;
- generic doc-hidden `Engine<I>` and `DealerProofImplementation` in `golden-core`;
- fixed prototype/algebraic test wrappers;
- generic `DkgConfig<G>` and `DkgOutput<G>` remain in core.

The user then asked the agent for a less clever alternative; that follow-up agent call was canceled. The concrete-wrapper/hidden-engine proposal is advice, not a confirmed decision.

The fresh interview should compare the genuinely boring options, especially:

1. Keep `GoldenDkg<G, B>` in `golden-core`, using the existing group/backend axes, and expose `SecpSecqDkg` as a type alias from `golden-evrf`.
2. Use a single doc-hidden implementation marker generic internally, but expose a type alias rather than nominal wrapper types.
3. Use the architecture agent’s concrete `SecpSecqDkg` wrapper over hidden `Engine<I>`.
4. Move more session code into `golden-evrf` and keep only generic data/algebra in core.

Optimize for:

- the smallest caller interface;
- the fewest new types and forwarding wrappers;
- minimal changes from current code;
- no claim of generic R1CS support that does not exist;
- keeping test backends possible without making third-party proof extensibility a product promise;
- one flat proof statement/witness representation across the crate seam.

Ask one decision question after inspecting the actual type/dependency constraints. Do not assume the architecture agent’s recommendation is correct.

## Authoritative confirmed decisions

### Public workflow

- Received dealer messages are opaque bytes outside Golden.
- There is no public decoded, parsed, verified, or accepted `DealerMessage` value.
- Deployment supplies `(expected dealer, opaque bytes)`; the expected dealer is routing metadata, not protocol evidence.
- Golden independently checks the encoded/proven dealer.
- Deployment collects/deduplicates/persists incrementally; Golden receives the final complete candidate set.
- Completion is atomic across all configured instances and all dealers.
- Deployment agreement and activation remain outside Golden.

Confirmed completion input shape:

```rust
complete(
    &self,
    identity_secret: &InputScalar,
    own_dealing: &OwnDealing,
    peer_dealer_messages: &[(ParticipantIndex, Vec<u8>)],
) -> Result<DkgOutput>
```

Exact generic type spelling depends on the unresolved architecture.

### Configuration

- The DKG session owns one immutable `DkgConfig` and one proof implementation/policy.
- `DkgConfig` alone owns ordered Random/Zero policy.
- Public `ParticipantRegistry` is removed.
- `DkgConfig` accepts participant entries as:

  ```rust
  Vec<(ParticipantIndex, InputPoint)>
  ```

  and canonicalizes them internally into a `BTreeMap` so duplicate indexes remain detectable.
- Configuration validates nonempty participants, duplicate indexes, duplicate identity public keys, identity public keys equal to identity, threshold, and nonempty instances.
- Identity keys use existing scalar/point adapter types; no `IdentitySecretKey`/`IdentityPublicKey` wrappers.

Confirmed constructors:

```rust
DkgConfig::new(..., instances: Vec<DkgInstanceKind>)
DkgConfig::new_random(...)
DkgConfig::new_zero(...)
```

There is no `new_batch`; canonical `new` is batch-native.

Confirmed accessors:

```rust
threshold()
session_id()
beta()
participants() -> &BTreeMap<ParticipantIndex, InputPoint>
identity_public_key(participant) -> Option<&InputPoint>
instances() -> &[DkgInstanceKind]
instance(position) -> Option<DkgInstanceKind>
root() -> TranscriptRoot
```

### Random and Zero

- Keep public/internal terms `Random` and `Zero`.
- Random samples an independent constant; it may happen to be zero.
- Zero fixes only polynomial coefficient zero; other coefficients/shares are generally nonzero.
- Internally commitments always retain the complete logical coefficient vector.
- Zero coefficient zero is synthesized as identity.
- Zero omits coefficient zero on the wire.
- Constant PoK is required for Random and absent for Zero.
- Transcripts observe the complete logical commitment.

### Own dealing

`OwnDealing` contains:

- participant;
- exact outbound dealer-message bytes;
- private self shares;
- session/configuration binding;
- no identity secret.

Initial accessor surface, confirmed “for now”:

```rust
participant() -> ParticipantIndex
dealer_message_bytes() -> &[u8]
```

It supports direct serde, `Clone`, redacted `Debug`, and automatic best-effort zeroization of private self shares on drop.

### DKG output

```rust
DkgOutput {
    participant,
    instances,
    configuration_root,
    completion_root,
}

DkgInstanceOutput {
    public_key,
    secret_share: InputScalar,
    public_key_shares: BTreeMap<ParticipantIndex, InputPoint>,
}
```

Confirmed accessors:

```rust
DkgOutput::participant()
DkgOutput::instances()
DkgOutput::instance(position)
DkgOutput::configuration_root()
DkgOutput::completion_root()

DkgInstanceOutput::public_key()
DkgInstanceOutput::secret_share()
DkgInstanceOutput::public_key_shares()
```

Both output types directly support serde; use derives when practical, even though this makes `DkgInstanceOutput` independently serializable. `Debug` redacts secret shares. Owned secret shares zeroize on drop.

### Serde policy

Trusted application storage is the persistence threat model. Do not introduce checkpoint/MAC/session-bound restoration machinery.

Direct serde applies to:

- `ParticipantIndex`
- `SessionId`
- `DkgInstanceKind`
- `DkgConfig`
- `OwnDealing`
- `DkgInstanceOutput`
- `DkgOutput`
- concrete scalar/point adapter types needed by those values
- concrete Secp/Secq prepared-generator artifact

No serde for:

- runtime DKG session;
- stable errors;
- private dealer-message tree;
- proof statement/witness plumbing.

Serde is never the protocol wire grammar and never feeds roots/proofs/transcripts.

### Errors and automatic proof attribution

Use one public Golden `Error` enum plus one coarse `DealerMessageError`, rather than operation-specific error enums.

Conceptual stable variants:

```rust
EmptyParticipants
DuplicateParticipant { participant }
DuplicateIdentityPublicKey { first, second }
IdentityPublicKeyIsIdentity { participant }
InvalidThreshold { threshold, participants }
EmptyInstances
UnsupportedConfiguration
IdentityKeyMismatch { participant }
OwnDealingMismatch
MissingDealer { dealer }
DuplicateDealer { dealer }
UnexpectedDealer { dealer }
InvalidDealerMessage { dealer, reason }
InvalidDealerProofs { dealers: Vec<ParticipantIndex> }
BatchVerificationFailed
ShareDecryptionFailed { dealer }
ProofGenerationFailed
```

Coarse message reasons:

```rust
TooLarge { actual, maximum }
Malformed
ConfigurationMismatch
DealerMismatch { encoded }
InvalidPublicRelations
```

Do not expose dealing indexes, receiver indexes, proof offsets, backend internals, raw bytes, or secrets in stable errors.

There is no separate diagnostic method.

`complete`:

1. batch-verifies proofs;
2. on batch failure, verifies every dealer proof individually;
3. returns all invalid dealers in canonical order;
4. returns `BatchVerificationFailed` if every individual proof passes despite batch failure.

This intentionally pays batch plus individual verification cost on invalid input.

### Parsing and wire grammar

Confirmed pipeline:

1. Validate complete expected-dealer collection and canonicalize order.
2. Enforce whole-message byte limit before parsing/allocation.
3. Parse/check envelope, version, tag, codec, curve/backend identity.
4. Read and check configuration root and encoded dealer before nested allocation.
5. Parse exact configured shape.
6. Validate all public algebraic relations for all messages.
7. Parse all proof streams only after public relations pass.
8. Batch verify, with automatic individual fallback.
9. Decrypt and aggregate.
10. Return atomic output or no output.

ADR 0003 confirms the next dealer-message wire format omits all values already determined by config:

- dealing count;
- Random/Zero discriminator;
- commitment coefficient count;
- encrypted-share count;
- receiver indexes;
- terminal proof length when proof is the remaining suffix.

Conceptual grammar:

```text
envelope
configuration root
dealer
for configured instance in order:
    nonce
    configured commitment points
    for canonical non-dealer receiver:
        pad commitment
        encrypted share
remaining suffix:
    proof
```

The internal owned tree is exactly:

```text
DealerMessage -> Dealing -> EncryptedShare
```

No borrowed/zero-copy parser and no parsed/verified variants.

### Message-size bound

For now, do the simple thing:

- one fixed whole-dealer-message constant;
- enforce before parsing;
- expose `max_dealer_message_bytes()`;
- improve to a shape-derived bound later.

A 16 MiB whole-message constant was recommended because the old proof-only bound was 16 MiB and node’s outer board bound is 64 MiB. The user did not explicitly care about the exact number, only that there is a simple bound now. Confirm the numeric constant during specification/implementation if needed; do not reopen derived-size machinery.

### Proof statement/witness seam

Confirmed:

- delete generic nested `Evrf*Statement`/`Evrf*Witness` trees;
- delete paper-specific `Batched*Statement`/`Batched*Witness` trees;
- exactly one opaque `DealerProofStatement` and one `DealerProofWitness` cross the core/evrf seam;
- core constructs them with guaranteed dimensions;
- proof backend consumes read-only accessors and does not revalidate generic shape;
- no serde.

Use flat canonical arrays, not nested owned or borrowed view types.

Statement data is conceptually:

```text
dealer public key
beta
dealer-message root
threshold
instance kinds
effective messages
full logical commitment coefficients, instance-major
canonical receiver indexes and public keys
share commitments, instance-major then receiver-major
pad commitments, same order
encrypted shares, same order
```

Witness data is conceptually:

```text
identity secret
one optional polynomial constant per instance
shares, instance-major then receiver-major
pads, same order
```

### Standalone one-receiver path

Confirmed final decision:

- delete the legacy standalone one-receiver protocol entirely;
- delete `SecpSecqEvrfStatement`, `SecpSecqEvrfWitness`, `evrf_prove`, `evrf_verify`, the dedicated proof ID, fixed generator cache, test target, and `paper-one-receiver-v3.bin`;
- preserve single-receiver functionality as the production dealer-proof framework’s `1 dealing × 1 receiver` shape;
- transfer relevant behavioral tests: honest proof, zero output, wrong beta/message/key, witness mismatch, wrong proof ID, malformed framing, trailing bytes.

The old proof bytes/API are intentionally not compatible.

### Prepared Secp/Secq generators

This decision supersedes the earlier generic `PreparedProofParameters<Cycle>` design.

Use a concrete serde-capable artifact in `golden-evrf`, tentatively named:

```rust
SecpSecqPreparedGenerators
```

It stores a logical deterministic Bulletproof generator prefix and capacity. It is not tied to a config/session. A bigger installed table serves any smaller required proof shape.

Minimal interface:

```rust
SecpSecqPreparedGenerators::prepare_for(&config)
SecpSecqPreparedGenerators::capacity()
SecpSecqPreparedGenerators::install()
Serialize + Deserialize
```

Behavior:

- normal operation uses existing process-wide `OnceLock`/prefix cache automatically;
- deployment may serialize the artifact to disk;
- another process deserializes and explicitly installs it;
- install is monotonic: install/extend matching prefix, no-op for equal/larger matching cache, reject overlap mismatch or unsupported capacity;
- prepared generators do not enter config/completion roots;
- no generic parameter trait/provider;
- no Golden-owned paths, file I/O, cache directory, eviction, or automatic disk policy;
- deployment owns trusted storage/authentication.

Important existing bug to fix when preserving serde:

- warming a larger cached prefix and then serializing a smaller logical `BulletproofGens` can serialize the larger backing vector with the smaller capacity;
- serialization must emit exactly the declared logical prefix;
- add a regression test for large-warmed-before-small serialization.

Exact artifact magic/version/compatibility remains unresolved and belongs in the versioning branch.

### Crate/facade decision

- Keep the current crate split for this refactor.
- Do not add a `golden-dkg` facade in this PR.
- A future facade is a separate PR and should mechanically re-export the settled concrete production interface.
- Exact placement of the public session (`golden-core` generic versus `golden-evrf` concrete wrapper/alias) is reopened and is the immediate next decision.

## Prototype and AlgebraicTestCycle

### Existing prototype

Keep it for now as temporary fast test infrastructure.

It originally existed to exercise witness-dependent, transcript-bound proof plumbing while the paper backend was too slow. It still supplies fast:

- witness-dependent proof generation;
- proof-stream corruption coverage;
- opaque dealer-message handling;
- generic DKG integration;
- EHTDH1 bridge tests;
- per-commit CI/examples.

Delete only when replacement tests cover all five roles above at acceptable per-commit runtime.

### Proposed AlgebraicTestCycle

Separate runnable prototype question, not production implementation.

Formal output group over production Secp `Fp`:

```text
Point = Fp exponent
identity = 0
generator = 1
addition = field addition
scalar multiplication = field multiplication
MSM = field dot product
compressed point = canonical Fp bytes
```

Retains:

- real Secp input group;
- exact `Fp` R1CS;
- production bit decompositions/modulus/chord gadgets/circuit shape;
- real Bulletproof prover/verifier;
- proof-stream logic.

Does not test:

- Secq encodings;
- hash-to-curve;
- production MSM;
- production vectors;
- cryptographic binding/soundness.

Known generator relations make it intentionally unsound. Keep real vectors, at least one production smoke test, production encoding tests, and nightly scenarios.

Do not design its trait seam in the main interview. After the boring production architecture is settled, create a narrow `/handoff`, run `/prototype`, benchmark/verify feasibility, and hand the verdict back before `/to-spec`.

## Deployment evidence that controls

From `~/Developer/miden/node` refs inspected during the design sessions:

- validator signing, Golden identity, Iroh endpoint identity, and participant upload tickets are distinct;
- upload admission uses participant ticket/slot, not transport endpoint as Golden evidence;
- board slots store opaque artifacts by participant/kind;
- same-content duplicates are idempotent;
- conflicting content poisons a slot/fails closed;
- board limit is coarse 64 MiB, upload concurrency three, timeout 30 seconds;
- core still needs its own tighter bound;
- current CLI is multi-turn (`identity`, `prepare`, `deal`, `accept`, `finalize`);
- current `deal` persists deployment-owned private state and reconstructs `DkgDealing` later, which motivated direct `OwnDealing` serde;
- current node verifies before agreement and again during completion;
- target can produce a pending output once, persist it, then let deployment agreement control activation.

## Superseded/rejected designs

Do not revive these without explicitly reopening them:

- public parsed/verified dealer messages;
- context-free dealer-message parser;
- borrowed/zero-copy parser;
- streaming transport parser in Golden;
- public `ParticipantRegistry`;
- identity key wrappers;
- `FeldmanCommitment` Random/Zero enum;
- message-selected Random/Zero grammar;
- passing config into every operation instead of session ownership;
- activation modeled by Golden;
- no serde for `OwnDealing`/`DkgOutput`;
- checkpoint/MAC/session-bound restoration layer;
- only whole-output serde with custom nested representation;
- separate diagnostic method;
- no automatic proof-attribution fallback;
- self-describing wire counts/indexes;
- nested proof seam views;
- retaining paper `Batched*` models internally;
- retaining standalone one-receiver protocol;
- generic `PreparedProofParameters<Cycle>` stored in `GoldenDkg`;
- Golden-owned filesystem parameter cache;
- adding a facade in the current refactor.

## Remaining decisions after architecture

After settling the boring session/proof implementation architecture, continue one question at a time:

1. Exact dealing creation method name/signature (`deal` versus `create_dealing`).
2. Exact generic/concrete spelling of `DkgConfig`, `OwnDealing`, and output types under the chosen architecture.
3. Zeroization mechanics for Halo2 `Secp256k1Scalar`, which is currently `Copy` and lacks zeroization.
4. Protocol version bump.
5. Dealer-message wire magic/codec/version.
6. Proof ID/version.
7. Prepared-generator artifact magic/version/compatibility and trusted loading contract.
8. Hard-cut compatibility policy for old messages/proofs/serde/cache artifacts.
9. Migration/tracer-bullet order.
10. Test replacements for public struct mutation.
11. ADR candidates for session ownership, proof seam, automatic fallback, and global prepared-generator cache.
12. Separate AlgebraicTestCycle prototype.
13. `/to-spec`, then `/to-tickets` in the same fresh design context after all decisions/prototype results are back.

## Ready-to-paste prompt for the fresh session

Continue the Golden DKG interface-refactor `/grill-with-docs` interview from this authoritative checkpoint:

`.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`

Read `CONTEXT.md` and ADRs 0001–0003, but do not duplicate decisions already captured there or in the checkpoint. The older `dkg-interface-refactor.md` handoff is superseded when it conflicts.

Start by resolving the reopened proof/session architecture. The current Secp/Secq Golden R1CS is concrete, not cycle-generic. I want a boring architecture: minimal wrappers, traits, hypothetical extensibility, and migration churn. Inspect the actual crate dependency/coherence constraints and compare the simplest viable alternatives, especially retaining a config-owning `GoldenDkg<G, B>`/type-alias model versus a hidden implementation marker or concrete wrapper. Preserve the flat `DealerProofStatement`/`DealerProofWitness` seam, fixed prototype tests, concrete `SecpSecqPreparedGenerators`, and the confirmed caller workflow.

Ask one decision question at a time and recommend an answer. Look up codebase facts rather than asking me factual questions. Do not implement production changes. Update `CONTEXT.md` immediately only when domain terminology settles, and add ADRs only for durable non-obvious trade-offs.

After the production architecture is settled, finish the listed unresolved error/versioning/migration/test/zeroization decisions. Then create a narrow `/handoff` for a fresh `/prototype` session to test `AlgebraicTestCycle`; bring its result back before `/to-spec` and `/to-tickets`.
