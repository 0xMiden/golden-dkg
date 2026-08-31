# Golden DKG interface refactor — consolidated production handoff

Status: type architecture consolidated; resolve the beta setup-security decision before `/to-spec`

## Purpose

This file consolidates the Golden DKG interface-refactor decisions made across the prior design sessions and the continuation from `.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`.

Use it to start a fresh `/to-spec` session. Do not implement directly from the older `.scratch/batch-dkg/spec.md`; that spec describes the batch-native implementation already present on this branch and is historical input only.

## Final type and relation architecture

- The fixed Main Golden dealer relation is protocol behavior owned by `golden-core`; it is not a selectable relation, VRF adapter, or proof policy.
- Use `GoldenCurve` as the capability trait required by DKG execution. Do not use `GoldenEvrfCurve`, `MainGoldenCurve`, or a relation-associated type.
- Retain `GoldenGroup` as the smaller prime-order group algebra used by Shamir, Feldman, configuration/output data, encoding, and other generic code.
- Retain `GoldenHashToGroup` in `golden-core` as a lower-level group capability because EHTDH1 also consumes it independently. Its documentation must not conflate protocol hash-to-curve with Bulletproof generator derivation.
- `GoldenCurve` directly extends `GoldenHashToGroup`; a separate coordinate facet plus marker-composition trait would introduce an unused seam.
- `golden-core` may depend directly on the existing no-std `ff` abstraction. No base-field newtype or core-owned forwarding field trait is required.

Conceptual trait:

```rust
pub trait GoldenCurve: GoldenHashToGroup {
    type BaseField: ff::PrimeField;

    const BASE_FIELD_BYTE_ORDER: FieldByteOrder;

    fn affine_x(point: &Self::Element) -> Result<Self::BaseField>;

    /// Interpret the canonical base-field integer and reduce it modulo the
    /// group scalar order.
    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar;
}
```

The byte-order constant is required because `ff::PrimeField::Repr` does not prescribe endianness. Deterministic beta derivation must define one canonical integer interpretation and translate into the concrete field representation before canonical decoding.

Core owns the fixed semantic composition:

- domain-separated beta derivation from the configuration root in the full base field, with zero permitted if the final protocol decision retains uniform `Fp` sampling;
- exact Main Golden H1/H2 domains and 32-byte-to-64-byte zero padding;
- native receiver-pad evaluation;
- the exact native relation checker used by the insecure witness-revealing test proof.

Curve adapters supply only the mathematical primitives: concrete base-field type, affine x-coordinate extraction, exact base-field-integer-to-scalar reduction, and the existing hash-to-group primitive. The replaceable proof-system seam does not contain receiver-pad evaluation.

This architecture does not settle the remaining cryptographic question of whether configuration-derived beta is acceptable under configuration grinding or requires an externally ungrindable setup input.

## Precedence

When sources disagree, use this order:

1. This consolidated production handoff.
2. The `Final architecture resolution` section in `.scratch/batch-dkg/dkg-interface-refactor-checkpoint.md`.
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
- Appendix K and eVRF-derived Feldman coefficients are out of scope. Do not anticipate them with a public relation/policy seam. Random and Zero polynomial coefficients remain normally sampled.

## Crate and module architecture

### `golden-core`

Owns generic DKG orchestration, the fixed Main Golden semantics, and protocol data/algebra:

- validated `DkgConfig`;
- participant ordering;
- Random/Zero instance policy;
- Shamir/Feldman algebra;
- dealer-message grammar and parsing;
- canonical beta derivation and Main Golden H1/H2 framing;
- native receiver-pad evaluation and the exact native dealer-relation checker;
- flat proof statement/witness construction;
- DKG collection validation;
- atomic completion and output construction;
- configuration, dealer-message, and completion root derivation;
- stable public errors.

It remains generic over `G: GoldenCurve` and `P: DealerProofSystem<G>`. It may depend on `ff`, but must not depend on `golden-evrf`, concrete curves, or Bulletproofs.

### `golden-evrf`

Owns concrete proof implementations for the fixed relation:

- the Secp/Secq Main Golden R1CS encoding;
- private proof framing and transcript domains;
- proof parsing, proving, individual verification, and optimized cross-dealer batch verification;
- stateful prepared generators and proof parameters;
- the explicitly insecure witness-revealing exact-relation test proof.

The circuit must consume core-owned beta derivation and H1/H2 framing helpers so its fixed relation cannot drift from native core evaluation. Proof-generator derivation remains private proof-system machinery.

## Free-function caller workflow

There is no `GoldenDkg`, `DkgSession`, `SecpSecqDkg`, borrowed facade, owning session object, or backend-owned orchestration. `golden-core` exposes free `deal` and `complete` functions. The caller explicitly supplies a reusable stateful proof-system value and `&DkgConfig`.

Conceptual usage:

```rust
let proofs = SecpSecqBulletproofs::prepare_for(&config)?;

let own_dealing = deal(
    &proofs,
    &config,
    participant,
    &identity_secret,
    &mut rng,
)?;

let output = complete(
    &proofs,
    &config,
    &identity_secret,
    &own_dealing,
    &peer_dealer_messages,
)?;
```

Conceptual signatures:

```rust
pub fn deal<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    participant: ParticipantIndex,
    identity_secret: &G::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<OwnDealing<G>>
where
    G: GoldenCurve,
    P: DealerProofSystem<G>;

pub fn complete<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    identity_secret: &G::Scalar,
    own_dealing: &OwnDealing<G>,
    peer_dealer_messages: &[(ParticipantIndex, Vec<u8>)],
) -> Result<DkgOutput<G>>
where
    G: GoldenCurve,
    P: DealerProofSystem<G>;
```

`complete` borrows `OwnDealing`, allowing retry against a corrected candidate board. The proof-system value is reconstructible runtime state, not session/configuration state. It:

- is instance-based and `Send + Sync`;
- may own prepared setup, caches, and proof-specific configuration;
- remains reusable across compatible configurations;
- retains the generic `&mut impl CryptoRngCore` path, not `dyn CryptoRngCore`.

The documented caller workflow exposes `deal` and `complete` only. Do not add a separate standalone dealer-message verification method. Deployment completes to a pending output, performs agreement externally, and controls activation.

## Dealer proof-system seam

The only replaceable semantic seam is how evidence for the one fixed dealer relation is produced and checked. Receiver-pad evaluation, beta derivation, configuration validation, statement construction, and relation semantics are not proof-system methods.

The proof-facing operations receive:

- the validated `&DkgConfig`;
- one flat `DealerProofStatement<G>`;
- one flat `DealerProofWitness<G>` for proving;
- opaque proof bytes;
- generic RNG for proving.

Proofs are owned opaque `Vec<u8>` values and borrowed as `&[u8]` for verification. There is no associated proof type and no proof serde contract.

Conceptual trait:

```rust
pub trait DealerProofSystem<G: GoldenCurve>: Send + Sync {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>>;

    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()>;

    fn verify_batch(
        &self,
        config: &DkgConfig<G>,
        proofs: &[DealerProofRef<'_, G>],
    ) -> Result<()> {
        for item in proofs {
            self.verify(config, item.statement, item.proof)?;
        }
        Ok(())
    }
}
```

The proof system observes `config.root()` in its private transcript. The configuration root is not duplicated as a mutable statement field. There is no public proof-system ID requirement. Each proof system privately versions and domain-separates its framing; proof bytes never select or negotiate their verifier.

Delete `ShareOpeningBackend`. Replace it with an unmistakably named `InsecureRevealedWitnessProof` that encodes the actual dealer witness into proof bytes and verifies it with core's exact native relation checker. It changes privacy/security, not relation semantics.

Main Golden is the only semantic relation. Do not add `MainGoldenRelation`, `DealerVrf`, Appendix K policy types, or relation-associated types.

## Flat proof seam

Delete the generic nested `Evrf*Statement` / `Evrf*Witness` trees and paper-specific `Batched*Statement` / `Batched*Witness` trees at the core/eVRF seam.

Exactly one opaque flat `DealerProofStatement<G>` and one `DealerProofWitness<G>` cross the seam. Core constructs them with guaranteed dimensions and canonical ordering. The proof system consumes read-only accessors and must not repeat generic shape validation already guaranteed by core. Neither type supports serde.

The complete public proof input is the pair:

```text
(DkgConfig<G>, DealerProofStatement<G>)
```

Configuration supplies session-wide values such as threshold, instance kinds, participant order, and identity public keys. Beta is derived internally from `config.root()` in the full base field and is neither stored nor duplicated in the statement. The flat statement supplies dealer-dependent public values, including:

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
- public `ParticipantRegistry<G>`;
- ordered nonempty `Vec<DkgInstanceKind>`.

Retain public `ParticipantRegistry`. Its validated constructor accepts participant entries, canonicalizes them, and preserves duplicate-index detection. `DkgConfig` receives or constructs that validated registry without duplicating participant-map validation.

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
participants() -> &ParticipantRegistry<G>
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

Conceptual call:

```rust
complete(
    &proofs,
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

The envelope checks version, tag, codec, and concrete curve/protocol identity. Proof-system-specific framing remains inside the opaque proof suffix. Read and verify configuration root and encoded dealer before nested allocation.

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
- proof-system identity.

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

- runtime proof-system values;
- errors;
- private parsed dealer-message trees;
- proof statement/witness plumbing.

Serde is never protocol encoding and never feeds roots, transcripts, proofs, or untrusted dealer parsing. ADR 0001 controls.

## Prepared Secp/Secq generators

`SecpSecqPreparedGenerators` is a concrete serde-capable deterministic generator prefix with a declared logical capacity.

Preparation is explicit:

```rust
let prepared = SecpSecqPreparedGenerators::prepare_for(&config)?;
let proofs = SecpSecqBulletproofs::from_prepared(prepared)?;
```

or an equivalent direct constructor:

```rust
let proofs = SecpSecqBulletproofs::prepare_for(&config)?;
```

Rules:

- prepare exactly the minimum padded capacity required by the supplied config;
- a proof-system value may serve any other configuration requiring no larger prefix;
- a larger configuration fails before proof work rather than lazily extending;
- additional multi-config/capacity constructors may be added later for demonstrated needs;
- generators are proof-system state, not configuration state or publicly installed process-global policy;
- lower-level process-wide deterministic prefix memoization may remain a private optimization;
- prepared capacity does not enter configuration or completion roots;
- deployment owns paths, file I/O, authentication, and persistence policy;
- serialization emits exactly the declared logical prefix even if a larger lower-level prefix was previously warmed;
- add a regression test for large-warmed-before-small serialization.

## Errors

Use one public Golden `Error` enum plus coarse `DealerMessageError` reasons. Preserve the stable conceptual variants recorded in the checkpoint, including configuration errors, identity mismatch, own-dealing mismatch, complete-set errors, coarse invalid-message attribution, all-invalid-dealer proof attribution, `BatchVerificationFailed`, share decryption failure, and proof generation failure.

Do not expose dealing indexes, receiver indexes, proof offsets, proof-system internals, raw bytes, or secrets in stable errors. There is no separate diagnostic method.

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

Use the public free-function workflow as the main test surface:

```text
config + proofs -> deal -> opaque bytes -> complete -> output
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
- insecure witness-revealing exact-relation proof plumbing;
- production Secp/Secq proof for the new flat seam;
- prepared-generator construction, reuse for smaller configs, under-capacity rejection, serde, malformed artifacts, and exact-prefix regression;
- transfer of one-receiver honest/tamper/framing/trailing-byte coverage;
- EHTDH1 `[Random, Zero]` bridge and existing online behavior;
- benchmarks/examples migrated only enough to preserve their existing purpose.

Tests that currently mutate public message/output structs must move to encoded-byte tampering, private in-crate builders, or observable construction paths. Do not re-expose mutable fields for tests.

## Deferred and open implementation details

These do not block `/to-spec` after the beta setup-security decision is resolved:

- exact private proof/wire/artifact byte domains after the hard cut;
- exact whole-message constant, with 16 MiB as the prior recommendation;
- concrete Halo2 scalar/drop zeroization mechanics;
- future facade crate;
- future `AlgebraicTestCycle` prototype;
- additional prepared-generator constructors for multiple configs.

One decision still blocks `/to-spec`:

- whether domain-separated beta derivation from `config.root()` is accepted under an explicit non-grinding/random-oracle setup assumption, or configuration must contain an externally ungrindable setup input. In either case beta itself is derived, not stored.

## Ready-to-paste `/to-spec` prompt

```text
/to-spec

Produce a buildable production specification for the Golden DKG interface refactor using:

.scratch/batch-dkg/dkg-interface-refactor-production-handoff.md

This consolidated handoff supersedes `.scratch/batch-dkg/spec.md` and the historical unresolved architecture in the older checkpoint. Read the controlling CONTEXT/ADR/research artifacts it lists, but do not reopen confirmed decisions.

Do not run this prompt until the beta setup-security decision in the handoff is resolved.

Skip AlgebraicTestCycle and defer concrete zeroization mechanics. Keep the existing crate split, free `deal`/`complete` workflow with an explicitly injected stateful `DealerProofSystem<G>`, flat proof seam with opaque bytes, fixed core-owned Main Golden relation, explicit prepared-generator proof-system state, retained public `ParticipantRegistry`, config-selected wire grammar, derived public-output completion root, and hard compatibility cut.

After producing the spec, remain in the same fresh context for `/to-tickets`.
```
