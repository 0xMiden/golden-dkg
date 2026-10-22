# Issue 71 implementation contract

Baseline: `0e3168f74845323cec29346856f6db7c009a8249`.
Requirements: <https://github.com/0xMiden/golden-dkg/issues/71>.
Reference implementation: PR 47 at `a9ca23033a9ca4a98d73a5ce31ef7fc4c695608b`.
The older `adr1anh/batch-refactor` branch is reusable reference work, not the target.

All existing configuration, own state, keys, ciphertexts and prepared artifacts are
disposable. This is one hard compatibility cut. No compatibility layer ships.
Engineering completion does not establish the independently reviewed security claims.

## Final packages

* `golden-core`: native algebra, configuration, fixed Main Golden relation, opaque
  broadcasts, public verification/aggregation, atomic completion, persistence and
  proof-only extension interface. No concrete curve or Bulletproof dependency.
* `golden-curves`: proof-free Secp256k1 and Jubjub adapters and fixed-base operations.
* `golden-bulletproofs`: both concrete proof systems, typed preparation, circuits,
  outer Cycle adapters and optimized MSM code.
* `bulletproofs-cycle`: generic engine with explicitly owned generators.
* `golden-ehtdh1`: online encryption/decryption and the single-batch bridge.

Remove golden-rustcrypto, golden-evrf, golden-halo2curves and golden-bls-jubjub
after moving reusable implementations. Keep public scalar-generic sharing/Feldman
utilities. Keep protocol parsing and concrete circuit gadgets private.

## Caller interface

The flat `DkgGroup` has native `Scalar: ff::PrimeField`,
`Point: group::prime::PrimeGroup<Scalar = Self::Scalar>` and
`BaseField: ff::PrimeField`; group identity, strict protocol codecs, hash-to-point,
affine-x extraction, integer base-to-scalar reduction and fixed-base multiplication
hooks. Inner and outer groups stay distinct.

`DkgConfig::new(threshold, session_id, registry, ordered_kinds)` validates private
configuration fields. Random samples every coefficient, including a possibly zero
constant; Zero fixes the constant to zero and physically omits it.

`DealerMessageRef<'a> { expected_dealer: ParticipantIndex, bytes: &'a [u8] }`
associates transport input with an expected dealer; it is not a parsed message.
All functions borrow an injected `P: DealerProofSystem<G>` and configuration.

* `deal(proofs, config, dealer, &identity_secret, rng) -> Result<OwnDealing<G>>`
* `verify_dealer_message(proofs, config, expected_dealer, bytes) -> Result<()>`
* `verify_dealer_messages(proofs, config, messages) -> Result<()>`: nonempty unique
  partial/full board.
* `aggregate_public(proofs, config, messages) -> Result<DkgPublicOutput<G>>`:
  exactly every registered dealer.
* `complete(proofs, config, &identity_secret, &own, peers) -> Result<DkgOutput<G>>`:
  exactly the other dealers; retry does not consume own state.

`OwnDealing` exposes participant/config binding and `broadcast_bytes()`. It is
cloneable, with no production identity secret. `DkgOutput` and proof witnesses
are not Clone or Copy. Public configurations/outputs may be Clone.

`DkgPublicOutput::instance(usize)` and ordered exact-size iterators expose borrowed
public instance views. `DkgOutput::public()` borrows the public result;
`secret_share(usize) -> Option<&G::Scalar>`. Positions are zero-based; identity is
configuration root plus position, so repeated kinds remain distinct.

The proof trait has `prove`, `verify`, and default/optimized `verify_batch`, each
using core Result and immutable core-constructed statements/witnesses. Keep
read-only getters public; share native evaluation/exact checking through one
narrow doc-hidden interface. No byte-selected implementation or runtime serde.

## Encodings and identities

All U32/U64 are big-endian; `F(x) = U64(len(x)) || x`;
`H(domain, payload) = SHA256(F(domain) || payload)`. Checked conversions only.
Protocol version 3; Random=0, Zero=1; group IDs `secp256k1`, `jubjub`.

Scalars: canonical LE32. Secp points: SEC1 compressed 33 bytes for nonidentity;
identity exactly 33 zero bytes. Jubjub: native compressed 32 bytes, identity
`01 || 00*31`. Strict round-trip, subgroup-checked decoding, no cofactor clearing.
Hash-to-point retains existing native adapter mappings, pinned by new vectors.
Cofactor clearing is allowed inside the Jubjub hash map, not point decoding.

Configuration payload C: version, framed group ID, U32 threshold, 32-byte session,
U32 registry size, canonical (U32 participant, point key) entries, U32 instance
count, kind bytes. Root domain `golden-dkg/config-root/v3`.

Effective message is H(`golden-dkg/effective-message/v3`, config root, U32 dealer,
U32 position, kind byte, 32-byte nonce). Main Golden beta/H1/H2 domains and
sorted/framed key input are exactly those in issue 71.

Logical dealer payload L: config root, dealer/key, base-field beta, ordered instance
positions/kinds/nonces/effective messages, logical coefficients including Zero's
identity constant, then canonical nonself receiver IDs/keys/evaluated share
commitments/pad commitments/ciphertext scalars. Counts use U32. Dealer root domain
`golden-dkg/dealer-root/v3`; proof bytes are excluded.

Broadcast: F(`golden-dkg-wire-v4`), config root, U32 dealer, configured instances
(nonce, physical coefficients, canonical nonself pad commitments/ciphertext
scalars), F(proof). No configuration-derived counts, kinds or receiver indexes.
Limit the complete envelope to 16 MiB before nested allocation and after proving.

Public result payload P: config root, U32 instance count, ordered (U32 position,
kind, aggregate key, U32 participant count, canonical participant/public-share
pairs). Completion root domain `golden-dkg/completion-root/v3`. Exclude local
identity/secrets, broadcasts/proofs, proof system and capacity.

## Proofs and preparation

One joint R1CS proof per dealer, with one canonical dealer-secret decomposition,
public-key relation and compatible shared secret-bit/window products. Instance-
major receiver slots constrain the exact native relation. Initially repeat DH
constraints across instances; further sharing requires separate review.

Integer reductions must constrain range and exclude circuit-field wrap aliases;
field equality alone is insufficient. Test modulus boundaries on both curves.

One transcript binds full C and L before challenges, continues through R1CS and
one constant-opening proof per Random instance, including zero constants. Zero
has no constant proof. Proof bytes: F(fresh proof-family ID), F(R1CS bytes), then
Random constant proofs in configuration order with positions transcript-bound.

Concrete prepared types expose `prepare_for`, `capacity` and validated byte/serde
persistence. Runtime proof systems own/share immutable prepared state. Larger
compatible prefixes serve smaller shapes; insufficient capacity fails before
proof interpretation. No lazy growth or global generator cache at either layer.
Keep existing deterministic public fixed-base tables.

Artifact envelope: F(`golden-dkg-prepared`), version 1, protocol version, framed
group/cycle/proof IDs, U32 party capacity=1, U64 declared capacity, then (when
nonzero) Pedersen bases and exactly declared G/H prefixes. Zero contains no points.
Restoration checks exact dimensions and canonical nonidentity subgroup points
without regenerating generators. Approved generation plus authenticated storage
is an application obligation on both byte and serde restoration.

## Validation and persistence

One private pipeline: associations/coverage/local binding; all public validation;
proofs; recovered/self share checks; aggregation. Return no partial output.
Collect all public-invalid dealer indexes before interpreting any proof.
Only InvalidProof triggers batch fallback; individually check every dealer,
collect all invalid proofs, or return BatchVerificationFailed if all pass.
Operational errors propagate without dealer attribution or backend diagnostics.

Zero pads fail locally with one coarse retryable error before proving/state return.
Zero-reduced DH exponents/unavailable coordinates fail non-retryably. Received
identity pad commitments are public-invalid; identity share commitments are valid.
For n=1,t=1 require empty proof bytes and make no proof/preparation calls. This
explicitly overrides the ordinary Random constant-proof requirement.

Persistence envelope: F(`golden-dkg-state`), version 1, type tag, F(group), F(payload).
Tags 1=config, 2=own, 3=public output, 4=local output. Reconstruct checked values
with caller-supplied configuration and expected local participant where required.
Derive cached roots again. Use dedicated serde snapshot representations for values
requiring context. Restoring outputs requires authenticated trusted completion
provenance; untrusted imports replay a complete board. Own restoration needs no
proof system because completion verifies the board again.

Secret storage uses private zeroizing native-field storage; redact Debug explicitly.
Guard buffers before filling and allocate checked final capacity. Do not promise
erasure of every arithmetic temporary, caller copy or application-owned bytes.

EHTDH1 accepts exactly [Random,Zero], checks binding/interpolation and nonidentity
Random/identity Zero keys, and uses one session/configuration/completion identity
plus epoch. Its separate new envelope uses native protocol codecs. Preserve online
algorithms and operations. Recompute completion identity from its two public-share
columns when checking key-set/setup-context consistency.

## Commit and validation sequence

1. Freeze this contract and reusable references.
2. Native algebra and proof-free curve adapters.
3. Opaque core workflow, result identity and contextual persistence.
4. Explicit engine generators and typed concrete proof systems.
5. Both reviewed joint circuits and optimized dealer batching.
6. EHTDH1, consumer/artifact/feature/CI/docs migration and final cut.

Reuse or refactor existing code before adding another helper or representation.
Only the integrating parent formats, lints, tests and commits. Do not run expensive
tests before the final integrated tree. Cheap compile checks may locate interface
errors. Check power before Rust compilation. Preserve SSH-signed commits; if signing
fails, stop all work and report the actual error. Do not push or publish.

Final gates: relation/interface review on both curves; single-instance proof and
restoration checks; mixed-instance construction review before joint work; independent
Standards/Spec review; reconciled MSRV/features/WASM/CI/nightly/docs checks on one
fixed HEAD; separately owned final composition/security release approval. Automated
engineering reviews do not replace cryptographic approval.
