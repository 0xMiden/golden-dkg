# Fixed-zero polynomial constants in Golden DKG

Date: 2026-08-13

## Question

For a DKG instance whose polynomial constant is fixed publicly to zero, can the implementation omit:

1. the zero scalar from the proof witness;
2. the identity Feldman coefficient from storage, wire encodings, and transcripts; and
3. the Schnorr proof of knowledge for that constant coefficient;

without weakening the Golden DKG / two-party eVRF security claim?

## Executive conclusion

**Yes, conditionally, for instances whose zero-constant policy is authenticated and unambiguously bound to the protocol transcript.** The three objects are redundant representations or proofs of the public fact

\[
a_0 = 0, \qquad A_0 = a_0 G = \mathcal O.
\]

The safest design is:

- omit `a_0 = 0` from the private eVRF witness;
- omit the encoded/stored `A_0 = O` from a zero-instance commitment, while retaining a *logical* coefficient-zero accessor or canonical reconstruction rule;
- omit that instance's constant-term Schnorr proof; and
- continue binding the instance kind, position, threshold, and logical zero coefficient to all relevant transcript identities, either by transcript-synthesizing the identity coefficient or by introducing an explicitly versioned transcript grammar for compressed zero commitments.

This does **not** change the paper's two-party eVRF relation or Theorem 2: Feldman coefficients and their openings are not inputs or witnesses of `R_T-eVRF-DH`. The repository's constant-term Schnorr proof is an additional DKG extraction mechanism, not part of the paper eVRF construction.

There are two important qualifications:

1. **Do not generalize the omission to random-constant instances.** In the repository's `n-of-n` message shape, only `n - 1` non-self shares are public. For a random degree-`n - 1` polynomial, the constant opening supplies the missing point needed by a straight-line extractor. For a zero polynomial, `(0, 0)` supplies that point publicly, so no proof is needed.
2. **The paper does not prove the mixed `[Random, Zero]` batch implemented here.** Theorem 3 proves ordinary Golden with random dealer contributions. The paper describes zero sharing for resharing and requires checking `A_{j,0} = O`, but does not restate a separate ideal functionality or theorem for the zero-sharing extension. Therefore the defensible claim is that elision preserves the same zero-sharing relation and the same eVRF security assumptions; a formal end-to-end claim for the repository's mixed batch still needs a composition/reduction argument.

## Sources and scope

### Paper

Primary paper used:

- **`GOLDEN-2025-1924`** — Benedikt Bünz, Kevin Choi, Chelsea Komlo, *Golden: Lightweight Non-Interactive Distributed Key Generation*, Cryptology ePrint 2025/1924, current ePrint revision dated 2026-03-24, <https://eprint.iacr.org/2025/1924>.

The repository-local research corpus described by `AGENTS.md` was not present in this worktree: `resources/` contained only the empty `resources/notes/` directory, and `resources/context/INDEX.md`, `resources/context/REPO_CONTEXT.md`, the index scripts, and PDFs were absent. The current primary PDF was therefore obtained directly from ePrint and read with page boundaries preserved. Paper citations below use PDF page numbers.

### Current code

The analysis covers the current branch at `9844798` and, where useful, repository history showing why the constant proof was removed and reintroduced (`39c5e90`, `5cbe7df`). No production code was modified.

## What the paper actually requires

### Feldman commitment and zero sharing

For a degree-`t - 1` Shamir polynomial

\[
f(x) = s + \sum_{i=1}^{t-1} a_i x^i,
\]

Feldman commits as

\[
A_0 = g^s, \qquad A_i = g^{a_i}, \qquad \bar C = (A_0,\ldots,A_{t-1}).
\]

A share commitment is evaluated in the exponent from that vector. [`GOLDEN-2025-1924`, PDF p. 16]

Golden broadcasts the Feldman vector and, for each non-self receiver, an eVRF pad commitment and encrypted scalar. Receivers check

\[
\bar X_{j,k} = \prod_{\ell=0}^{t-1} A_{j,\ell}^{k^\ell}
             = g^{f_j(k)}
\]

and

\[
g^{z_{j,k}} \stackrel{?}= R_{j,k}\,\bar X_{j,k}.
\]

[`GOLDEN-2025-1924`, PDF pp. 29–30]

For key resharing, the paper explicitly changes each dealer contribution to `ω_i = 0` and adds the verifier check `A_{j,0} = O`, thereby checking `f_j(0) = 0`. [`GOLDEN-2025-1924`, PDF pp. 30–31]

Thus, at the protocol-relation level, a fixed-zero instance needs the *fact* `A_0 = O`, but it does not require that the identity have a physical byte representation in every commitment. The verifier may reconstruct it from an authenticated zero-instance policy.

### The eVRF relation does not contain Feldman coefficients

The paper's relation `R_T-eVRF-DH` has public inputs consisting of the two identity keys, message-derived hash points, eVRF output commitment `R`, and `β`; its witness is the eVRF identity secret `sk_1`. Its equations are steps (0)–(9):

\[
\begin{aligned}
(0)&\quad PK_1 = g_{in}^{sk_1},\\
(1)&\quad S = PK_2^{sk_1},\\
(2)&\quad k_0 = S.X,\\
(3)&\quad k = \operatorname{int}(k_0),\\
(4)&\quad T_1 = H_{G_{in},1}(msg,PK_1,PK_2)^k,\\
(5)&\quad T_2 = H_{G_{in},2}(msg,PK_1,PK_2)^k,\\
(6)&\quad r_1 = T_1.X,\\
(7)&\quad r_2 = T_2.X,\\
(8)&\quad r = \beta r_1 + r_2,\\
(9)&\quad R = g_{out}^{r}.
\end{aligned}
\]

[`GOLDEN-2025-1924`, PDF p. 22, Figure 3]

Theorem 2 assumes a NIZK argument for exactly this relation and concludes correctness, pseudorandomness, verifiability, and simulatability of `T-eVRF-DH`. [`GOLDEN-2025-1924`, PDF pp. 22–23]

The separate discrete-log PoK discussed by the paper is for step (9), `R = g_out^r`; it is not a PoK for a Feldman coefficient. [`GOLDEN-2025-1924`, PDF pp. 24, 27–28]

Therefore removing a zero Feldman opening or its Schnorr proof cannot weaken Theorem 2's eVRF statement: those objects are outside the theorem's relation.

### Golden's DKG theorem and extraction

Theorem 3 states that `Π_Golden-PKI` realizes the additive-bias key-generation functionality in the `(F_zk^REF, F_T-eVRF)` hybrid model against static corruption of up to `t - 1` parties. [`GOLDEN-2025-1924`, PDF p. 32]

The simulator extracts a corrupt dealer's eVRF identity secret from initialization, derives every pad, decrypts the dealer's shares, and uses `Feldman.Recover` on `t` shares to recover the dealer constant and remaining polynomial coefficients. [`GOLDEN-2025-1924`, PDF pp. 53–57]

The paper's Figure 4 conceptually includes all `n` encrypted-share/eVRF slots in the broadcast notation, while the prose and algorithm omit the self receiver and retain the dealer's self share locally. [`GOLDEN-2025-1924`, PDF pp. 28–30] The current repository concretely broadcasts only non-self encrypted shares. This matters at `t = n`:

- public/decryptable non-self shares provide only `n - 1` points;
- a random degree-`n - 1` polynomial remains underdetermined by those points;
- an extracted constant `a_0` supplies point `(0, a_0)`, completing `n` points;
- for a fixed-zero polynomial, `(0, 0)` is already public, so an extractor can reconstruct the whole polynomial and missing self share without interacting with or rewinding the dealer.

This is the exact reason that the current random-instance constant PoK remains useful while a zero-instance constant PoK is redundant.

## Current repository behavior

### Zero policy and commitment checks

`DkgInstanceKind::Zero` is part of immutable configuration and is bound into `config_root` by ordered instance kind (`0` for random, `1` for zero) in `crates/golden-core/src/dkg.rs:861-885`.

Dealer construction selects `G::Scalar::zero()` for a zero instance, constructs a full polynomial, and commits to every coefficient in `crates/golden-core/src/dkg.rs:530-590`.

Verification checks the physical first coefficient is identity before invoking the proof backend:

```text
kind == Zero  =>  is_identity(body.commitment.coefficients()[0])
```

in `crates/golden-core/src/dkg.rs:648-665`. This correctly enforces the paper's zero-sharing condition before expensive proof work.

### Where the physical identity currently appears

The same identity coefficient is currently duplicated across several layers:

1. `FeldmanCommitment.coefficients[0]` in memory (`crates/golden-core/src/feldman.rs`).
2. The dealer wire commitment vector (`crates/golden-core/src/wire.rs:319-379`).
3. `dealer_message_root`, which absorbs the coefficient count and every coefficient (`crates/golden-core/src/dkg.rs:901-919`).
4. `EvrfDealingStatement.commitment_coefficients[0]` (`crates/golden-core/src/dkg.rs:583-590`, `688-692`).
5. `statement_root`, which again absorbs every coefficient (`crates/golden-core/src/dkg.rs:922-945`).
6. The paper proof-stream statement, which observes `commitment-len` and every coefficient, allowing identity (`crates/golden-evrf/src/paper.rs:1893-1946`).
7. The Feldman public relation
   \[
   X_j = \sum_{\ell=0}^{t-1} j^\ell A_\ell
   \]
   checked outside R1CS (`crates/golden-evrf/src/paper.rs:1838-1890`).
8. The constant-term Schnorr verifier, which indexes coefficient zero (`crates/golden-evrf/src/paper.rs:2336-2351`).

The nested Bulletproofs R1CS does **not** open or otherwise constrain any Feldman coefficient. It proves the shared dealer identity/eVRF pad relations, while Feldman evaluation and encrypted-share consistency are public checks (`crates/golden-evrf/src/paper.rs:1953-2334`).

### Current constant-term Schnorr equation

For each dealing, current `v7` emits a native Schnorr proof for

\[
A_0 = a_0 G.
\]

The prover samples nonzero `ρ`, sends `Q = ρG`, derives challenge `c`, and sends

\[
t = \rho + c a_0.
\]

The verifier checks

\[
tG \stackrel{?}= Q + cA_0.
\]

Code: `crates/golden-evrf/src/paper.rs:1300-1349`, called once per dealing at `2235-2265` and `2336-2351`.

For a zero instance, `a_0 = 0` and `A_0 = O`, so this reduces to

\[
t = \rho, \qquad tG \stackrel{?}= Q.
\]

The proof establishes knowledge of a witness already fixed publicly and uniquely to zero. In a prime-order group, an extractor can output `0` without examining a proof. Consequently this Schnorr proof adds neither computational soundness nor knowledge soundness for that instance.

The repository's `GoldenGroup` contract explicitly models a prime-order discrete-log group, and concrete encodings are canonical (`crates/golden-core/src/group.rs:116-160`). The conclusion would need re-evaluation for a non-prime-order group, unchecked subgroup points, or ambiguous/noncanonical identity encodings.

## Decision by item

### (a) Omit the zero scalar witness: yes

`EvrfDealingWitness.polynomial_constant` and `BatchedEvrfWitness.polynomial_constants` currently carry a scalar zero solely for the trailing constant-term Schnorr proof (`crates/golden-core/src/dkg.rs:289-305`; `crates/golden-evrf/src/paper.rs:422-439`). The R1CS does not consume it.

For a zero instance the prover can derive `0` from the statement/configuration if an internal arithmetic operation needs it. It need not be stored in the proof witness or supplied through the backend API.

This is a witness/API simplification, not a protocol change. Polynomial construction still has the logical constant zero, but it need not allocate a separate secret-bearing field for it.

### (b) Omit the identity Feldman coefficient: yes from storage/wire, conditionally from transcripts

#### Protocol necessity

The protocol requires verifiers to enforce `f(0) = 0`. It does not require transmitting a byte string for `O` when the zero policy already determines that value.

For receiver `j`, replace the full evaluation

\[
X_j = A_0 + \sum_{\ell=1}^{t-1} j^\ell A_\ell
\]

with the equivalent zero-instance evaluation

\[
X_j = \sum_{\ell=1}^{t-1} j^\ell A_\ell,
\]

because `A_0 = O`.

The aggregate public key contribution is similarly derived as `O`, not loaded from a stored element.

#### Encoding and API choice

The omission needs a representation that distinguishes:

- random commitment: logical coefficients `[A_0, A_1, ..., A_{t-1}]`;
- zero commitment: stored tail `[A_1, ..., A_{t-1}]`, with logical `A_0 := O` and logical length `t`.

That distinction is already available from ordered `DkgInstanceKind`, but the current generic `FeldmanCommitment` and context-free `WireDecode for DealingBody` assume a nonempty physical vector whose first entry is `A_0`. In particular, threshold-one zero sharing would have an empty stored tail, which `FeldmanCommitment::from_coefficients` currently rejects. Those are API/encoding constraints, not protocol constraints.

A standalone `FeldmanCommitment` encoding cannot silently change to “tail only” because it lacks the zero/random context. Either retain full encoding for standalone generic commitments, or introduce an explicitly tagged/versioned zero-commitment representation.

#### Transcript choices

Two sound choices exist:

1. **Recommended: canonical logical expansion.** Omit the identity in storage and wire, but synthesize `O` when computing `dealer_message_root`, `statement_root`, and the paper proof-stream statement. Continue absorbing logical coefficient length `t` and logical sequence `[O, A_1, ..., A_{t-1}]`. This preserves transcript meaning and keeps the nested R1CS challenges unchanged for the same logical statement.
2. **Compressed transcript grammar.** Absorb a zero-commitment/domain tag, logical threshold, tail length, and tail coefficients, but not a synthesized identity. This is also sound because the configuration root binds ordered instance kinds, but it changes every downstream challenge and root and therefore requires explicit protocol/proof versioning and new vectors.

Simply dropping vector element zero from the current loops is unsafe engineering: it changes physical length into logical threshold, shifts coefficient degrees unless evaluation is changed, and can create parser/statement disagreement.

### (c) Omit the constant-coefficient Schnorr PoK: yes for zero instances only

For relation

\[
R_{const} = \{(A_0; a_0): A_0 = a_0G\},
\]

fixing the statement to `A_0 = O` in a prime-order group fixes the only scalar witness to `a_0 = 0 mod q`. Knowledge is public, so the empty proof is a valid proof system for this singleton public relation: verification consists of enforcing the authenticated zero policy.

This does not remove any paper eVRF equation. It removes only the repository-added equation

\[
tG = Q + cA_0
\]

for zero dealings. Random dealings must retain it unless another straight-line extraction path is provided.

For a mixed batch, proof parsing must be driven by the authenticated ordered instance-kind vector: consume one constant PoK for each random dealing and none for each zero dealing. Never infer omission merely from receiving an identity point in an untyped commitment; that would let an attacker choose the proof grammar through malleable message contents.

## Soundness, transcript, and downgrade concerns

### 1. Bind zero policy before choosing the grammar

The current configuration root binds version, backend, session, threshold, `β`, registry root, dealing count, and ordered instance kinds. Dealer verification rejects a mismatched configuration root before proof verification (`crates/golden-core/src/dkg.rs:627-700`). This is the right trust boundary.

A compressed implementation must select “zero tail / no constant PoK” from the verified configuration position, not from an unauthenticated wire flag or observed identity coefficient.

### 2. Preserve degree and logical length

A stored tail of length `t - 1` still represents a degree-at-most-`t - 1` polynomial with logical coefficient zero. Parameter setup and shape validation must continue using threshold `t`, not tail length. For `t = 1`, the valid zero commitment has no stored points and evaluates to identity for every receiver.

### 3. Version every changed byte grammar

Current identifiers include:

- core protocol transcript version `PROTOCOL_VERSION = 3`;
- wire magic `golden-dkg-wire-v4`;
- dealer codec `dealer-message-v4`;
- paper proof ID `golden-paper-evrf-batched-v7`.

If dealer wire bytes omit `A_0`, bump the dealer/wire grammar. If the proof stream conditionally omits Schnorr records, bump `BATCHED_PROOF_ID` even if the nested R1CS transcript is otherwise preserved. If core roots change rather than synthesize the logical identity, bump `PROTOCOL_VERSION` as well. Old and new decoders/verifiers should reject each other's artifacts, not negotiate a weaker mode.

The completion root binds `B::PROOF_ID` (`crates/golden-core/src/dkg.rs:948-963`), so a new proof ID also prevents outputs accepted under the two proof policies from sharing a completion identity.

### 4. Account for sequential Schnorr transcript effects

Current per-dealing Schnorr proofs run sequentially after the nested R1CS proof. Omitting a zero proof changes the transcript prefix seen by every later random-dealing constant proof. For example, `[Zero, Random]` changes the random proof's challenge, while `[Random, Zero]` does not change the earlier random proof's challenge but shortens the trailing stream.

This is safe under a new proof ID and canonical parser, but test vectors must cover both orders and repeated kinds. A design that wants stable later challenges could absorb an explicit zero-instance marker in lieu of proof bytes, but that is an encoding choice, not a security requirement.

### 5. Canonical identity and subgroup checks remain mandatory

If transcript-synthesizing identity, use the group's canonical identity encoding. All transmitted tail coefficients still need canonical decoding and subgroup membership checks. The argument “identity implies scalar zero” relies on the prime-order subgroup model.

### 6. Do not conflate the two Schnorr proofs

The paper's `π_DL` for eVRF output `R = g_out^r` remains necessary for the paper proof construction. The proposed omission concerns only the repository's extra Schnorr PoK for Feldman `A_0`. Removing or weakening the eVRF output PoK would alter `R_T-eVRF-DH` step (9) and Theorem 2's premise. [`GOLDEN-2025-1924`, PDF pp. 24, 27–28]

### 7. Batch verification

Current code verifies constant-term Schnorr proofs individually and batches only R1CS equations (`crates/golden-evrf/src/paper.rs:2371-2406`). Removing zero-instance equations therefore does not alter the random coefficients or soundness analysis of the R1CS MSM batch, except indirectly through proof bytes/transcript seed. The batch seed already binds complete ordered statements and proof bytes; a new proof ID and canonical conditional grammar preserve this property.

## Security-statement assessment

| Claim | Assessment after zero elision |
|---|---|
| Paper Theorem 2: two-party eVRF correctness, pseudorandomness, verifiability, simulatability | **Unchanged.** Feldman constants are outside `R_T-eVRF-DH`. |
| Paper Theorem 3: ordinary random-contribution Golden | **Do not remove random constant extraction.** Zero elision is not relevant to random instances. |
| Paper zero-sharing resharing condition | **Unchanged if verifier derives/enforces `A_0 = O` from authenticated instance policy.** The paper's required check remains logically present. |
| Repository `n-of-n` extraction for a zero dealer polynomial | **Unchanged.** Public `(0,0)` plus `n-1` decrypted non-self shares determines a degree-`n-1` polynomial. |
| Repository mixed `[Random, Zero]` atomic batch | **Plausibly unchanged, but not directly covered by Theorem 3.** Needs an explicit composition/ideal-functionality argument before claiming theorem-equivalent end-to-end security. |

## Experiments and tests that would settle remaining implementation questions

No production experiment was implemented as part of this research task. The following focused branch/tests would provide strong evidence.

### A. Algebraic extraction tests

1. For every representative `(n, t)` including `t = n`, generate a zero-constant degree-`t - 1` polynomial, expose all non-self shares, and show that `(0,0)` plus any required `t - 1` shares reconstructs the polynomial, constant, and missing self share.
2. At `t = n`, demonstrate the contrast: the same `n - 1` shares admit multiple random-constant degree-`n - 1` polynomials, but become unique after adding either extracted `(0,a_0)` or fixed `(0,0)`.
3. Cover `t = 1`, where a zero commitment tail is empty and every share/public-share commitment must be zero/identity.

These tests settle the extraction rationale independently of proof implementation.

### B. Full-versus-compressed commitment equivalence

For zero instances, property-test that full `[O,A_1,...,A_{t-1}]` and compressed `[A_1,...,A_{t-1}]` representations produce identical:

- public key contribution (`O`);
- `public_key_share(i)` for every participant;
- share-verification decisions;
- aggregate DKG public keys/public shares;
- EHTDH1 context-sharing material.

If canonical logical transcript expansion is selected, also assert identical `dealer_message_root`, `statement_root`, and proof statement checkpoint for equivalent logical messages.

### C. Conditional proof grammar tests

Run the paper backend for at least:

- `[Zero]`;
- `[Random]`;
- `[Random, Zero]`;
- `[Zero, Random]`;
- `[Zero, Zero]`;
- `[Random, Zero, Random]`.

Assert exactly one constant Schnorr record per random instance and none per zero instance. Verify that truncation, extension, reordering, an unexpected proof in a zero slot, or a missing proof in a random slot is rejected.

The existing v7 vector increased by 65 bytes when one Secp256k1 constant proof was reintroduced (`5cbe7df` changed the vector from 1323 to 1388 bytes). A zero instance should recover that per-dealing proof-size saving on this backend (one compressed Secp256k1 point plus one scalar), while omitting the wire identity saves one compressed point per zero commitment.

### D. Tampering and downgrade tests

1. Decode old full-identity messages under only the old codec and new compressed messages under only the new codec.
2. Reject old `v7` proofs under the new proof ID and new proofs under `v7`.
3. Reject changing configuration kind `Zero ↔ Random`, changing dealing order, or moving a compressed commitment to another position.
4. Reject a nonzero constant smuggled into a zero slot, including malformed length tricks and duplicate/ambiguous encodings.
5. Pin roots and challenge checkpoints for both instance orders.
6. Ensure completion roots differ across proof-policy versions.

### E. Existing relation regressions

For a compressed zero commitment, retain tests that reject changes to:

- any tail coefficient;
- receiver index/order;
- receiver identity key;
- share commitment;
- pad commitment;
- encrypted share;
- effective eVRF message/nonce;
- configuration root and dealer-message root;
- nested R1CS proof bytes.

This confirms that only the tautological constant proof was removed.

### F. Fuzzing and malformed inputs

Fuzz the new dealer decoder and conditional proof parser with special attention to:

- zero tail length at `t = 1`;
- claimed threshold versus physical tail length;
- integer-overflowing counts;
- mixed batches with alternating kinds;
- canonical identity and noncanonical point encodings;
- trailing proof bytes and cross-version prefixes.

## Recommended implementation direction (not implemented here)

1. Model a commitment's **logical constant policy** separately from its physically stored coefficient tail.
2. Keep threshold as an explicit logical dimension; never derive it from compressed tail length.
3. For zero instances, make `public_key()` return identity and evaluate shares beginning at degree one.
4. Prefer transcript-synthesizing logical `A_0 = O` so storage/wire compression does not silently alter statement identity; if transcript compression is desired, define and version it explicitly.
5. Change the backend witness to carry a constant only for random dealings (for example, an ordered optional/typed witness whose shape is validated against instance kinds), rather than carrying literal zeros.
6. Emit/verify constant Schnorr proofs only for random dealings, selected from the already-verified ordered configuration.
7. Bump wire/proof identifiers and regenerate vectors. Do not provide implicit fallback to the old or weaker grammar.
8. Document the security split: paper eVRF proof, random-DKG extraction, and zero-sharing public-constant enforcement are separate obligations.

## Bottom line

A public fixed zero is not a secret witness and its identity commitment carries no information. In the repository's prime-order group model, the constant-opening Schnorr proof for `A_0 = O` proves only a fact the verifier already knows. The zero scalar, identity encoding, and Schnorr record can therefore all be elided **provided the implementation preserves the logical `A_0 = O` relation through authenticated instance typing, canonical reconstruction, transcript binding, and strict version separation**.

The optimization is protocol-sound for zero instances and leaves the paper eVRF theorem untouched. It must remain conditional—random constants still require an extraction mechanism—and the mixed-batch end-to-end theorem should be documented as a repository extension rather than attributed directly to the paper's Theorem 3.
