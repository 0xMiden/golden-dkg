# Golden DKG interface refactor — consolidated production handoff

Status: ready for `/to-spec`

## Purpose

This file consolidates the Golden DKG interface-refactor decisions made across the prior design sessions and the continuation from `.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`.

Use it to start a fresh `/to-spec` session. Do not implement directly from the older `.scratch/batch-dkg/spec.md`; that spec describes the batch-native implementation already present on this branch and is historical input only.

## Precedence

When sources disagree, use this order:

1. This consolidated production handoff.
2. The `Post-checkpoint architecture resolution` section in `.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`.
3. The confirmed decisions elsewhere in that checkpoint.
4. `CONTEXT.md` and ADRs 0001–0003 for domain language and their specific durable decisions.
5. Research notes under `resources/notes/` as evidence.
6. `.scratch/batch-dkg/spec.md` and the historical architecture discussion in the checkpoint only as background.

The superseded temporary handoff at `/var/folders/52/5ych7qyd6sx5s2vmv1lvnqsc0000gn/T/golden-dkg-handoff/dkg-interface-refactor.md` must not override any source above.

## Controlling artifacts from all sessions

- `CONTEXT.md`
- `docs/adr/0001-separate-serde-from-protocol-encoding.md`
- `docs/adr/0002-configuration-owns-instance-policy.md`
- `docs/adr/0003-configuration-determines-dealer-message-grammar.md`
- `.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`
- `resources/notes/fixed-zero-constant-elision.md`
- `resources/notes/2026-08-06-x-zero-dkg-batching.md`
- `resources/notes/evrf-derived-feldman-coefficients.md`

The configured local research index is absent from this worktree. The notes above contain the primary-source citations used by the design sessions.

## Scope and process decisions

- Implement the production refactor directly; do not run the proposed `AlgebraicTestCycle` prototype first.
- This is a multi-session build. Run `/to-spec`, then `/to-tickets`, then `/implement` blockers-first in fresh contexts per ticket.
- Preserve the existing crate split. Do not add a new crate or facade in this refactor.
- Do not add a runtime session wrapper or alias architecture.
- Make a hard compatibility cut. No old wire, proof, prepared-generator, or serde migration path is required.
- Defer concrete secret-zeroization mechanics. Do not block the interface refactor or claim guarantees not implemented.
- Appendix K eVRF-derived polynomial coefficients are future work. The current production policy remains main Golden with sampled coefficients.

## Crate and module architecture

### `golden-core`

Owns generic DKG orchestration and protocol-independent data/algebra:

- validated `DkgConfig`;
- participant ordering;
- Random/Zero instance policy;
- Shamir/Feldman algebra;
- dealer-message grammar and parsing;
- flat proof statement/witness construction;
- DKG collection validation;
- atomic completion and output construction;
- configuration, dealer-message, and completion root derivation;
- stable public errors.

It remains curve- and proof-system-agnostic and must not depend on `golden-evrf`, concrete curves, or Bulletproofs.

### `golden-evrf`

Owns concrete eVRF evaluation and proof implementations:

- native Secp/Secq receiver-pad evaluation;
- the Main Golden R1CS relation;
- private proof framing and transcript domains;
- proof parsing, proving, individual verification, and optimized cross-dealer batch verification;
- stateful prepared generators and proof parameters;
- the fast share-opening test backend.

Internally, native receiver-pad evaluation should remain separate from proof construction even though the cross-crate backend adapter exposes the evaluator to generic core.

## Stateful backend as the caller-facing module

The stateful backend value is the caller-facing DKG module. There is no `GoldenDkg`, `DkgSession`, `SecpSecqDkg`, borrowed facade, or owning session object.

Conceptual usage:

```rust
let backend = SecpSecqBackend::prepare_for(&config)?;

let own_dealing = backend.deal(
    &config,
    participant,
    &identity_secret,
    &mut rng,
)?;

let output = backend.complete(
    &config,
    &identity_secret,
    &own_dealing,
    &peer_dealer_messages,
)?;
```

The documented caller workflow exposes `deal` and `complete` only. Do not add a separate standalone dealer-message verification method. Deployment completes to a pending output, performs agreement externally, and controls activation.

Generic orchestration is implemented once in `golden-core` as backend methods backed by private helpers. Concrete backends must not duplicate forwarding implementations.

The backend:

- is instance-based and `Send + Sync`;
- is explicitly injected through method dispatch;
- may own prepared setup, caches, and proof-specific configuration;
- remains reusable across compatible configurations;
- receives `&DkgConfig` explicitly on DKG/proof operations;
- retains the generic `&mut impl CryptoRngCore` path, not `dyn CryptoRngCore`.

## eVRF adapter responsibilities

The cross-crate adapter exposes a narrowly documented native evaluator, tentatively `evaluate_receiver_pad`.

This hook exists because generic `golden-core` cannot name the concrete Secp/Secq relation. It is not permission for proof mechanisms implementing the same policy to invent different pad semantics. Production and fast adapters for the same policy should ultimately delegate to the same native evaluator in `golden-evrf`.

The proof-facing operations receive:

- the validated `&DkgConfig`;
- one flat `DealerProofStatement<G>`;
- one flat `DealerProofWitness<G>` for proving;
- opaque proof bytes;
- generic RNG for proving.

The backend itself observes `config.root()` in its proof transcript. The configuration root is not duplicated as a mutable field in the proof statement.

There is no public backend proof ID requirement. Every backend privately versions and domain-separates its proof relation and proof framing. Proof bytes never select or negotiate their verifier.

## Future proof policy parameter

Main Golden is the only implemented policy now. Appendix K is a future distinct relation/R1CS because it proves that all Feldman coefficients are outputs of a session/index-bound single-party eVRF.

A future concrete backend may be parameterized conceptually as:

```rust
SecpSecqBackend<MainGolden>
SecpSecqBackend<AppendixK>
```

Do not add this policy parameter to public core types before a second policy exists. When another policy is implemented, its semantic policy must be represented in canonical configuration bytes/root; Rust type parameters alone are not protocol binding.

The current fast share-opening backend remains explicit test infrastructure. It proves weaker opening relations and must not be represented as implementing the paper or Appendix K security claims.

## Flat proof seam

Delete the generic nested `Evrf*Statement` / `Evrf*Witness` trees and paper-specific `Batched*Statement` / `Batched*Witness` trees at the core/eVRF seam.

Exactly one opaque flat `DealerProofStatement<G>` and one `DealerProofWitness<G>` cross the seam. Core constructs them with guaranteed dimensions and canonical ordering. The backend consumes read-only accessors and must not repeat generic shape validation already guaranteed by core. Neither type supports serde.

The complete public proof input is the pair:

```text
(DkgConfig<G>, DealerProofStatement<G>)
```

Configuration supplies session-wide values such as threshold, beta, instance kinds, participant order, and identity public keys. The flat statement supplies dealer-dependent public values, including:

- dealer identity;
- dealer-message root;
- effective messages;
- full logical commitment coefficients in instance-major order;
- share commitments;
- pad commitments;
- encrypted shares in canonical instance/receiver order.

The witness supplies domain secrets only, including:

- dealer identity secret;
- one optional polynomial constant per instance where the current relation needs it;
- shares and pads in matching canonical order.

Circuit-specific intermediates, bit decompositions, chord witnesses, and prepared tables stay private to `golden-evrf`.

## Configuration

`DkgConfig<G>` owns immutable validated public inputs:

- threshold;
- session ID;
- beta;
- participants and Golden identity public keys;
- ordered nonempty `Vec<DkgInstanceKind>`.

Public `ParticipantRegistry` is removed. Construction accepts:

```rust
Vec<(ParticipantIndex, InputPoint)>
```

and canonicalizes to a `BTreeMap`, preserving duplicate-index detection.

Validation covers:

- nonempty participants;
- duplicate participant indexes;
- duplicate identity public keys;
- identity public keys equal to group identity;
- threshold range;
- nonempty instances.

Constructors:

```rust
DkgConfig::new(..., instances: Vec<DkgInstanceKind>)
DkgConfig::new_random(...)
DkgConfig::new_zero(...)
```

There is no `new_batch`; `new` is batch-native.

Accessors:

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

`DkgConfig::root()` is derived from immutable configuration fields rather than serialized as an independently mutable cached value. An operation may compute it once locally and reuse it.

## Random and Zero instances

Keep the terms `Random` and `Zero`.

- Random independently samples a polynomial constant; it may happen to be zero.
- Zero fixes only coefficient zero; nonconstant coefficients and shares remain generally nonzero.
- Logical Feldman commitments always have the full coefficient vector.
- Zero synthesizes logical coefficient zero as identity.
- Zero omits coefficient zero on the wire.
- Random carries the constant-term proof required by the current extraction argument.
- Zero omits that proof.
- Transcripts observe the complete logical commitment, including synthesized zero identity.
- The configured instance kind—not untrusted bytes—selects wire/proof grammar.

## `OwnDealing`

`deal` returns `OwnDealing<G>` containing:

- participant;
- exact outbound dealer-message bytes;
- private self shares;
- configuration/session binding;
- no identity secret.

Initial public accessors:

```rust
participant() -> ParticipantIndex
dealer_message_bytes() -> &[u8]
```

It supports direct serde, `Clone`, and redacted `Debug`. Concrete best-effort drop zeroization mechanics are deferred.

## Public completion workflow

Conceptual method:

```rust
backend.complete(
    &config,
    identity_secret: &InputScalar,
    own_dealing: &OwnDealing,
    peer_dealer_messages: &[(ParticipantIndex, Vec<u8>)],
) -> Result<DkgOutput>
```

Received peer messages remain opaque bytes outside Golden. The supplied expected dealer is routing metadata only. Golden independently checks the encoded/proven dealer.

Deployment handles incremental collection, deduplication, persistence, agreement, and activation. Golden receives the final candidate set and accepts or rejects exactly one candidate per configured dealer atomically.

`complete`:

1. validates complete expected-dealer coverage and canonicalizes order;
2. enforces a fixed whole-message size limit before parsing/allocation;
3. parses the exact config-selected grammar;
4. validates all public algebraic relations before proof parsing;
5. parses all proof streams;
6. batch-verifies proofs;
7. on batch failure, verifies every dealer individually;
8. reports all invalid dealers in canonical order;
9. returns `BatchVerificationFailed` if all individual proofs pass despite batch failure;
10. decrypts and aggregates only after proof acceptance;
11. returns one atomic output or no output.

## Dealer-message grammar

Dealer messages are not self-describing. Configuration determines counts, instance kinds, commitment lengths, receiver indexes, and proof placement.

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

The envelope checks version, tag, codec, and concrete curve/backend identity. Read and verify configuration root and encoded dealer before nested allocation.

The internal owned parsed tree remains:

```text
DealerMessage -> Dealing -> EncryptedShare
```

It is private. There is no public parsed/verified/accepted dealer-message value, borrowed parser, zero-copy parser, streaming parser, or context-free parser.

Use one fixed whole-dealer-message bound for this refactor and expose `max_dealer_message_bytes()`. The prior recommendation was 16 MiB, but the exact numeric constant may be selected during specification/implementation without reopening shape-derived limits.

## Output and roots

Conceptual output:

```rust
DkgOutput {
    participant,
    instances,
    configuration_root,
}

DkgInstanceOutput {
    public_key,
    secret_share: InputScalar,
    public_key_shares: BTreeMap<ParticipantIndex, InputPoint>,
}
```

Accessors:

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

`DkgOutput` retains the originating 32-byte configuration root because the output does not contain enough information to rederive it and must remain bound after persistence.

`completion_root` is not stored. It is derived from:

- configuration root;
- ordered instance aggregate public keys;
- canonical participant/public-key-share maps for every instance.

It excludes:

- completing participant;
- secret shares;
- dealer messages and proof bytes;
- proof backend identity.

It identifies the common public DKG result, not exact proof artifacts or dealer-message provenance. Deployment may separately hash exact board artifacts when needed.

Both output types support direct serde. Debug redacts secret shares. Concrete drop-zeroization mechanics are deferred.

## Serde policy

Trusted application storage is the persistence threat model. Do not add checkpoint MACs, session-bound restoration machinery, or Golden-owned storage authentication.

Direct serde applies to:

- `ParticipantIndex`;
- `SessionId`;
- `DkgInstanceKind`;
- `DkgConfig`;
- `OwnDealing`;
- `DkgInstanceOutput`;
- `DkgOutput`;
- concrete scalar/point adapters needed by those values;
- `SecpSecqPreparedGenerators`.

No serde for:

- runtime backend values;
- errors;
- private parsed dealer-message trees;
- proof statement/witness plumbing.

Serde is never protocol encoding and never feeds roots, transcripts, proofs, or untrusted dealer parsing. ADR 0001 controls.

## Prepared Secp/Secq generators

`SecpSecqPreparedGenerators` is a concrete serde-capable deterministic generator prefix with a declared logical capacity.

Preparation is explicit:

```rust
let prepared = SecpSecqPreparedGenerators::prepare_for(&config)?;
let backend = SecpSecqBackend::from_prepared(&config, prepared)?;
```

or an equivalent direct constructor:

```rust
let backend = SecpSecqBackend::prepare_for(&config)?;
```

Rules:

- prepare exactly the minimum padded capacity required by the supplied config;
- a backend may serve any other configuration requiring no larger prefix;
- a larger configuration fails before proof work rather than lazily extending;
- additional multi-config/capacity constructors may be added later for demonstrated needs;
- generators are backend state, not publicly installed process-global policy;
- lower-level process-wide deterministic prefix memoization may remain a private optimization;
- prepared capacity does not enter configuration or completion roots;
- deployment owns paths, file I/O, authentication, and persistence policy;
- serialization emits exactly the declared logical prefix even if a larger lower-level prefix was previously warmed;
- add a regression test for large-warmed-before-small serialization.

## Errors

Use one public Golden `Error` enum plus coarse `DealerMessageError` reasons. Preserve the stable conceptual variants recorded in the checkpoint, including configuration errors, identity mismatch, own-dealing mismatch, complete-set errors, coarse invalid-message attribution, all-invalid-dealer proof attribution, `BatchVerificationFailed`, share decryption failure, and proof generation failure.

Do not expose dealing indexes, receiver indexes, proof offsets, backend internals, raw bytes, or secrets in stable errors. There is no separate diagnostic method.

## Legacy deletion and compatibility

Delete the standalone one-receiver protocol and its public functions/types, dedicated proof identifier, fixed cache, test target, and vector. Preserve its relevant behavioral coverage through the production dealer-proof framework's `1 dealing × 1 receiver` shape.

Make a hard cut:

- new configuration/transcript version;
- new dealer envelope magic/codec/version;
- new private proof transcript/framing domain;
- new prepared-generator artifact version;
- no fallback parser;
- no old proofs/messages/serde/cache restoration;
- no compatibility wrappers.

Exact byte tags are implementation details to choose once and test canonically.

## Testing requirements

Use the public backend workflow as the main test surface:

```text
config -> backend.deal -> opaque bytes -> backend.complete -> output
```

Required coverage includes:

- configuration validation and root sensitivity;
- Random/Zero ordering and zero constant elision;
- one proof over the whole dealer batch;
- exact opaque outbound bytes and OwnDealing serde;
- whole-message size rejection before parsing;
- config-driven parser dimensions and canonical order;
- malformed envelope/root/dealer/public relations/proof/trailing bytes;
- batch verification success;
- all-invalid-dealer canonical attribution after batch failure;
- original batch failure when every individual proof passes;
- share decryption and atomic aggregation;
- common public output and derived completion-root agreement;
- output/configuration mismatch detection;
- output and scalar/point serde;
- fast share-opening adapter plumbing;
- production Secp/Secq proof for the new flat seam;
- prepared-generator construction, reuse for smaller configs, under-capacity rejection, serde, malformed artifacts, and exact-prefix regression;
- transfer of one-receiver honest/tamper/framing/trailing-byte coverage;
- EHTDH1 `[Random, Zero]` bridge and existing online behavior;
- benchmarks/examples migrated only enough to preserve their existing purpose.

Tests that currently mutate public message/output structs must move to encoded-byte tampering, private in-crate builders, or observable construction paths. Do not re-expose mutable fields for tests.

## Deferred and open implementation details

These do not block `/to-spec`:

- exact trait/type naming where behavior is fixed;
- exact private proof/wire/artifact byte domains after the hard cut;
- exact whole-message constant, with 16 MiB as the prior recommendation;
- concrete Halo2 scalar/drop zeroization mechanics;
- future Appendix K policy parameter and relation;
- future facade crate;
- future `AlgebraicTestCycle` prototype;
- additional prepared-generator constructors for multiple configs.

## Ready-to-paste `/to-spec` prompt

```text
/to-spec

Produce a buildable production specification for the Golden DKG interface refactor using:

.scratch/batch-dkg/dkg-interface-refactor-production-handoff.md

This consolidated handoff supersedes `.scratch/batch-dkg/spec.md` and the historical unresolved architecture in the older checkpoint. Read the controlling CONTEXT/ADR/research artifacts it lists, but do not reopen confirmed decisions.

Skip AlgebraicTestCycle and defer concrete zeroization mechanics. Keep the existing crate split, stateful backend-method workflow, flat proof seam, explicit prepared-generator backend state, config-selected wire grammar, derived public-output completion root, and hard compatibility cut.

After producing the spec, remain in the same fresh context for `/to-tickets`.
```
