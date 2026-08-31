# Batching the EHTDH1 `x`-sharing and `0`-sharing DKGs

- **Date:** 2026-08-06
- **Status:** Research note; no production-code change
- **Question:** Can the Golden DKG operations used to share EHTDH1's secret `x` and its context secret `0` be combined into one batch?

## Executive answer

**Yes. If transcript and wire compatibility may break and optimization is the goal, the preferred design is a native multi-lane Golden DKG: one configuration, one dealer message, and one joint proof covering several separately addressable polynomial sharings.**

The core DKG should model a homogeneous batch of ordinary DKG instances rather than EHTDH1 roles or lane policies. The caller chooses each dealer's polynomial constant for each instance—random for the ordinary key instance and zero for the context instance—and later checks application postconditions such as an identity aggregate public key. Every instance still needs an independent polynomial, commitment vector, effective eVRF message/pads, and instance-specific proof witnesses. The batch may share the dealer identity witness, registry and receiver context, and—inside the Secp/Secq relation—the hidden dealer/receiver DH computation.

A compatibility-preserving outer envelope containing two old `DealerMessage`s remains a lower-risk fallback, but it retains duplicate proof work and is no longer the recommendation when protocol breakage is acceptable. The optimized construction requires a new multi-lane proof relation; concatenating statements into the current `prove_batch` interface is insufficient.

## Evidence and method

The local research corpus is uncommitted and was absent from this feature worktree. The repository's primary worktree copy was used read-only:

- `resources/context/INDEX.md`
- `resources/context/REPO_CONTEXT.md`
- indexed primary-source chunks in `resources/.index/resources.sqlite`
- searches via `python3 resources/scripts/search_index.py "<query>" --limit <n> --full`

Exact claims below were checked against primary-source page chunks. Page numbers are **physical PDF pages**, not printed section/page labels. Summaries and context maps were used only for routing.

## What the two sharings mean

EHTDH1 key generation does two distinct Shamir sharings:

1. sample the ordinary decryption secret `x` and a random threshold sharing `(x_i)` of `x`;
2. independently generate a random threshold sharing `(z_i)` whose secret is `0`;
3. give party `i` the pair `sk_i = (x_i, z_i)`, with verification values `X_i = x_i G` and `Z_i = z_i G`.

Source: `2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`, physical PDF pp. 14–16.

The zero-sharing is not an ignorable setup artifact. An online decryption share has the form

```text
W_i = x_i R + z_i S.
```

Threshold interpolation gives

```text
Σ_i λ_i W_i = xR + 0·S = xR.
```

The individual `z_i` values therefore contribute to each contextual decryption share even though their interpolation is zero. A construction that exposes only a sharing of `x + 0`, or only one scalar share per party, does not provide the separately addressable `(x_i, z_i)` pair required by EHTDH1.

Source: `2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`, physical PDF pp. 16–18.

## Golden's current rounds and messages

Golden assumes registered identity public keys and proofs of knowledge of the corresponding secret keys. Each dealer chooses a polynomial contribution and a random dealer message, then broadcasts a dealing containing the polynomial commitment, encrypted/committed receiver shares, and proofs. The paper presents this as one interaction round: the broadcast occurs in Round 0; Round 1 consists of local verification, decryption, and completion.

Source: `2025-bunz-choi-komlo-golden-dkg`, physical PDF pp. 27–30.

For a sharing of zero, every dealer fixes its polynomial constant coefficient to zero. Verification must additionally check that **each dealer's constant polynomial commitment** is the group identity. Checking only that the aggregate public key is the identity is weaker because malicious nonzero constants can cancel in aggregate.

Source: `2025-bunz-choi-komlo-golden-dkg`, physical PDF pp. 30–32.

Golden already batches a dealer's receiver relations: one conjunction proof covers the `n-1` non-self receiver statements, allowing common identity-secret/key gadgets to be reused. The statement still grows linearly while proof size is logarithmic. The paper also describes batch verification that amortizes multi-scalar-multiplication work across independent proofs.

Source: `2025-bunz-choi-komlo-golden-dkg`, physical PDF pp. 30–32.

## Relevant implementation

### Two independent logical dealings

In `crates/golden-core/src/dkg.rs`:

- `create_dealing` samples a dealing with a random polynomial constant.
- `create_dealing_with_secret(..., zero(), ...)` is the intended entry point for EHTDH1's context/zero lane.
- Separate calls sample separate polynomial coefficients, `DealerMessageNonce`s, receiver pads, and proof randomness.
- `DealerMessage` carries one Feldman commitment vector, one encrypted-share map, one receiver-batched proof, and one transcript root.
- `complete` verifies/decrypts the configured dealers' messages and aggregates them locally.

The example `crates/golden-ehtdh1/examples/threshold_records.rs` runs the decryption and context DKGs sequentially, but the context session identifier is derived before either result is available. There is no output dependency forcing the two broadcasts to occur serially; they can be launched concurrently.

### EHTDH1 bridge keeps both outputs distinct

`crates/golden-ehtdh1/src/dkg_bridge.rs::material_from_dkg_outputs`:

- requires matching threshold, registry, and participant configuration;
- validates the expected derived context session;
- requires the context aggregate public key to be the identity and the decryption public key to be non-identity;
- constructs `SecretShare { decryption: x_i, context: z_i }`;
- binds both logical session identifiers and both completion transcript roots into `SetupContext`.

Related types and usage are in:

- `crates/golden-ehtdh1/src/lib.rs`
- `crates/golden-ehtdh1/src/context.rs`
- `crates/golden-ehtdh1/examples/threshold_records.rs`

### Current proof batching is single-lane

In `crates/golden-evrf/src/paper.rs`, `BatchedEvrfStatement` contains one dealer message, one commitment vector, one threshold/dealer context, and one receiver list.

In `crates/golden-evrf/src/paper/secp_secq/dkg_backend.rs`, `ensure_same_batch_context` requires statements in a current proof batch to agree on shared context including the session, dealer, dealer message, commitment coefficients, and transcript root. Consequently, concatenating statements from the `x` and zero sessions into the existing `prove_batch` call is rejected. A joint proof needs a new two-lane statement and relation.

## Security assumptions and composition boundary

The EHTDH1 result relevant here is high-threshold CCA security against **static** corruptions with `f = t - 1`. It models the relevant hashes as random oracles, assumes semantic security of the symmetric cipher, and relies on LOMDH; the paper notes that DDH implies LOMDH. The core result is not an adaptive-corruption theorem.

Source: `2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`, physical PDF pp. 13–19.

Golden's theorem is in the ideal eVRF/ZK hybrid against a static adversary corrupting up to `t-1` parties. Its one-round protocol realizes the weaker additive-bias functionality `F^B_KeyGen`, rather than fully unbiased key generation.

Source: `2025-bunz-choi-komlo-golden-dkg`, physical PDF pp. 8–10 and 32–34.

Running two independently randomized instances in parallel does not create an algebraic dependency between them. A purpose-built joint proof or shared-pad construction, however, changes the relation and requires a new soundness/zero-knowledge and pseudorandomness argument; it is not established merely by either paper's single-instance theorem.

## Meanings of “combine into one batch”

| Construction | Preserves EHTDH1 inputs? | Assessment |
|---|---:|---|
| Bundle two independent `DealerMessage`s in one network envelope/round | Yes | **Recommended now** |
| Keep two proofs but batch verifier equations/MSMs | Yes | **Safe with sound verifier-side random coefficients**; saves verification work, not proof bytes |
| New conjunction proof for both lanes | Yes, if it retains separate lane commitments/shares/pads | **Viable new protocol work** |
| Aggregate the two PVSS/DKG transcripts into a sharing of their sum | No | **Insufficient**: loses separately usable `(x_i, z_i)` |
| Reuse one polynomial/commitment/pad/proof across both roles | No | **Unsafe** |

Aggregatable PVSS combines transcripts for polynomials `f_1` and `f_2` into a transcript for `f_1 + f_2`. That aggregation is useful in conventional DKG but does not retain two independently addressable outputs for EHTDH1.

Source: `2025-bacho-kavousi-sok-dlog-dkg`, physical PDF pp. 3–4. The same survey discusses DKG parallelism and rushing/bias limitations of one-round designs at physical PDF pp. 5–7.

## Safe batching constructions

### 1. One outer envelope, two logical Golden instances

For each dealer, generate:

```text
F_d(X) = ω_d + a_{d,1}X + … + a_{d,t-1}X^(t-1)
Z_d(X) =         b_{d,1}X + … + b_{d,t-1}X^(t-1)
```

with independent nonconstant coefficients. Broadcast one outer object containing:

```text
{
  decryption_dealing: DealerMessage(F_d),
  context_dealing:    DealerMessage(Z_d)
}
```

Both inner messages are created and verified using the existing APIs and are accepted atomically. This gives one physical broadcast round while preserving two logical sessions, two transcripts, and the distribution expected by EHTDH1.

Required invariants:

- independent polynomials;
- independent dealer messages/nonces and pads, or rigorously domain-separated effective messages;
- independent proof randomness;
- distinct lane tags and logical session identifiers;
- separate commitment vectors and encrypted-share vectors;
- binding of the ordered pair of lane statements into the outer setup transcript;
- verification that every context-lane dealer commitment has constant term equal to the group identity.

### 2. Independent proofs with verifier batching

Retain the two existing proof statements and proof objects. Verify their algebraic equations in a randomized batch, using fresh verifier-side coefficients chosen after all statements/proofs are fixed. This is the narrowest cryptographic optimization and follows the paper's described batch-verification direction. It does not reduce transmitted proof bytes.

### 3. Purpose-built two-lane conjunction proof

Define one dealer proof over all `2(n-1)` receiver/lane relations. The public statement must bind, in a canonical order:

- both logical session/setup identifiers;
- lane labels (`decryption`, `context`);
- both commitment vectors;
- both dealer messages/eVRF inputs;
- both encrypted-share vectors;
- all receiver identities;
- both transcript roots;
- the context-lane zero-constant condition.

The proof may amortize the dealer's identity-secret witness/gadgets, as Golden already does across receivers. Depending on the revised relation, it may also share computation involving the hidden identity DH key. It must not reuse one output pad for both lanes. This option needs a new API and cryptographic review because the current `BatchedEvrfStatement`/`ensure_same_batch_context` model is deliberately single-context.

### 4. Advanced vector-output eVRF

A revised eVRF could use the same hidden identity-DH material to derive two independently domain-separated outputs, then jointly prove both. This is viable only with a relation and security argument for multi-output pseudorandomness/composition. The outputs should be derived as independent domain-separated PRF/eVRF outputs, not by copying or applying a public linear transformation to one pad.

## Unsafe reuse

### Reusing a masking pad reveals polynomial differences

The current paper backend derives a receiver pad from the dealer message, identity-key material, and public receiver input; the logical DKG session identifier is not itself an input to that pad derivation. Therefore changing only the session ID does not make reuse of the same effective dealer message safe.

If dealer `d` uses the same pad `r_{d,j}` for receiver `j` in both lanes, the public masked values are

```text
c^x_{d,j} = r_{d,j} + F_d(j)
c^z_{d,j} = r_{d,j} + Z_d(j).
```

Anyone can subtract them:

```text
c^x_{d,j} - c^z_{d,j} = F_d(j) - Z_d(j).
```

These are evaluations of a degree-`t-1` polynomial whose constant is `ω_d`. Whenever the public non-self receiver slots provide at least `t` evaluations (`n-1 >= t`), an observer can interpolate the difference polynomial and recover the dealer's secret contribution. At `t = n`, publishing `n-1` unmasked difference evaluations still violates the independent-mask security model even though it is one point short of interpolation.

Known public linear relations between pads are also unsafe. If `r^z = αr^x`, then

```text
c^z - αc^x = Z(j) - αF(j),
```

and threshold-many values reveal constant `-αω_d`.

Safe choices are independent random effective messages for the lanes, or a revised proof-bound derivation such as `Encode(batch_id, "decryption")` and `Encode(batch_id, "context")` that is covered by the relation's multi-output pseudorandomness argument.

### Reusing proof randomness can reveal witnesses

Do not restart the same prover random tape/seed for the two proofs. In a Schnorr-style component, nonce reuse across challenges gives

```text
s_1 = k + c_1 w
s_2 = k + c_2 w
w   = (s_1 - s_2) / (c_1 - c_2).
```

Passing one mutable CSPRNG sequentially is fine because its state advances; reproducing the same random stream for each lane is not.

### Reusing polynomials or commitments changes the required distribution

EHTDH1 specifies a random sharing of `x` and a random sharing of `0`. Reusing nonconstant coefficients correlates the two sharings and is not covered by the cited EHTDH1 result. One Feldman commitment vector commits to one polynomial; adding two vectors commits only to the sum polynomial and no longer authenticates separate `X_i` and `Z_i` values.

## Implementation implication: strengthen zero-lane validation

Honest `create_dealing_with_secret(..., zero(), ...)` creates an identity constant commitment. However, the generic dealing verifier does not know that it is processing a zero-sharing lane, while `material_from_dkg_outputs` checks only that the **aggregate** context public key is the identity.

A combined setup design should add a lane-specific invariant equivalent to

```text
for every context dealer d: C^z_{d,0} = O
```

before accepting the batch. Aggregate identity alone permits nonzero malicious dealer constants that cancel. This requirement comes directly from Golden's zero-sharing variant (physical PDF pp. 30–32), rather than being merely a defense-in-depth preference.

## Recommendation

Given permission to break transcript and wire compatibility in order to optimize:

1. **Batch ordinary DKG instances, not semantic lanes.** A configuration contains an ordered, nonempty set of DKG instance identifiers under one threshold, registry, setup coefficient, and batch session. Core assigns no constant-term policy or application meaning to an instance.
2. **Let the dealer caller choose each instance's constant.** Honest EHTDH1 setup requests two instances and supplies a random contribution for the first and scalar zero for the second. This is the generic equivalent of today's `create_dealing` and `create_dealing_with_secret` paths.
3. **Broadcast one atomic dealer batch with one joint proof.** Each instance carries its own nonce, Feldman commitment, and encrypted-share vector. The dealer batch carries one proof and one root binding the config, dealer, ordered instances, and canonical receiver matrix.
4. **Use one uniform R1CS relation.** Prove the dealer identity secret once; compute and constrain the hidden dealer/receiver DH value once per receiver; retain instance-specific hash bases, pads, polynomial coefficients, shares, and proof blindings. There is no zero-instance branch or zero check in the R1CS. The current `BatchedEvrfStatement` must be replaced by a homogeneous instance-by-receiver statement.
5. **Treat identity as an application postcondition.** After completion, the EHTDH1 adapter checks that the second instance's aggregate public key is identity and that the first is non-identity. Since the ordinary proof binds every dealer polynomial to its Feldman commitments, aggregate identity implies that the aggregate polynomial constant is zero in the prime-order group.
6. **Document the protocol deviation.** Golden's paper-specified zero-sharing variant checks every dealer's constant commitment for identity. Aggregate-only validation permits malicious nonzero dealer constants that cancel. The completed polynomial still has constant zero, but this behavior is outside that exact paper-described variant and needs an explicit composition/security argument.
7. **Expose a small core protocol interface:** `deal`, `verify`, and `complete`. `verify` should return an immutable verified dealing so `complete` does not repeat expensive public proof verification. Completion returns one separately addressable output per DKG instance plus an outer root binding the atomic batch.
8. **Keep application semantics outside core.** The EHTDH1 adapter selects two instance IDs, maps their outputs to `(x_i, z_i)`, validates aggregate public keys, and builds `SetupContext`. Core does not know the words `zero`, `decryption`, or `context`.
9. **Make a clean protocol break.** Introduce new batch config, dealer-batch, proof-stream, transcript, and wire versions. Use one shared canonical receiver order and strict canonical instance order.
10. **Keep one threshold and registry per batch initially.** DKGs with different participant sets or thresholds use separate batches. Reject sum-polynomial aggregation, reused or linearly related pads, reused nonconstant coefficients, replayed proofs, or shared proof nonces.

This design keeps the core abstraction at “several ordinary, independently randomized DKG instances sharing one atomic dealing and proof,” without turning the DKG interface into a policy language.

## Primary sources

- `2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`
  - physical PDF pp. 14–16: independent sharings of `x` and `0`, key-share form
  - physical PDF pp. 16–18: contextual share equation and interpolation
  - physical PDF pp. 13–19: corruption model and cryptographic assumptions
- `2025-bunz-choi-komlo-golden-dkg`
  - physical PDF pp. 27–30: initialization, dealing messages, and one-round flow
  - physical PDF pp. 30–32: sharing zero, per-dealer constant checks, conjunction proofs, batch verification
  - physical PDF pp. 8–10 and 32–34: additive-bias functionality and static-security theorem
- `2025-bacho-kavousi-sok-dlog-dkg`
  - physical PDF pp. 3–4: aggregatable PVSS produces a sum sharing
  - physical PDF pp. 5–7: parallelism, rushing/bias, and one-round limitations
