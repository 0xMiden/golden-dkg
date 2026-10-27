# Group-key resharing contract

Baseline: `e243584e6565af9064cec3b1ccd7f710d50fc642` (PR 74).
Plain contract: [issue-71.md](issue-71.md); everything this contract does not name is
unchanged from it. Protocol: share-of-shares resharing (Groth, ePrint 2021/339).

A reshare moves the group key X of a completed sharing from an old committee
(I_old, t_old) to a new committee (I_new, t_new) with 1 ≤ t_new ≤ n_new. The
committees may overlap or be disjoint and the threshold may rise or fall; a refresh is
a reshare onto the same members at the same threshold. Each dealer i of a declared set
Q ⊆ I_old with |Q| ≥ t_old samples f_i of degree t_new − 1 with f_i(0) = s_i, its live
old share, and encrypts f_i(j) to every receiver j ∈ I_new. Receiver j outputs
x'_j = Σ_{i∈Q} λ^Q_i·f_i(j), where λ^Q are the Lagrange coefficients at zero over the
old indices of Q. X does not change, so records sealed under X open with the new
committee.

Plain configurations keep byte-identical C, L, broadcasts, effective messages,
completion roots and RNG draw order. The supported claim is membership and threshold
change under static corruption, not proactive security. A reshare never revokes an
old share: X stays secure only while every committee that ever held it stays below its
own threshold until its shares are erased, and only a fresh DKG recovers from a
compromised x. Engineering completion does not establish these claims.

Nodes own agreement on Q and the configuration; admission, including proof of
possession, and predecessor authenticity; retries, meaning a replaced dealer, a fresh
session and keys and an attempt cap, because completion requires every declared dealer
and withholding is not attributable; activation; retirement of the predecessor setup,
which stops answering decryption requests once the new committee activates; erasure of
old shares, dealer secrets and backups; and lineage tracking of generations, the chain
of predecessor setups and each record's setup after later reshares.

## Caller interface

`ResharePredecessor<G>` is the predecessor's public key set: threshold t_old, key X,
the full public-share column Y_i, configuration root and completion root. It holds no
secrets; applications establish its authenticity.

* `ResharePredecessor::new(threshold, public_key, public_key_shares, config_root, completion_root) -> Result<Self>`
  takes the shares as `Vec<(ParticipantIndex, G::Point)>`.
* `ResharePredecessor::from_output(config, output, position) -> Result<Self>` reads the
  Random or Reshare instance at `position` of an output that validates against
  `config`, with t_old = `config.threshold()`. Reshare outputs qualify, so reshares
  chain.
* `threshold()`, `public_key()`, `public_key_share(index)`, `public_key_shares()`,
  `config_root()` and `completion_root()` read it back.

`DkgConfig::new_reshare(threshold, max_corrupt_receivers, session_id, dealers, receivers, predecessor, instances) -> Result<Self>`
takes t_new, the declared bound on corrupt receivers in every attempt, Q keyed by old
index, the new committee keyed by new index, and one Reshare with every other instance
Zero. `registry()` holds the receivers and `dealers()` holds Q.

* `deal_reshare(proofs, config, dealer, &identity_secret, &predecessor_share, rng) -> Result<OwnDealing<G>>`:
  dealer i ∈ Q with its dealer key and s_i; the dealing holds no self shares.
* `complete_reshare(proofs, config, &identity_secret, receiver, messages) -> Result<DkgOutput<G>>`:
  exactly every declared dealer. It takes no own dealing: a member of both committees
  completes with its receiver key, and its own dealing is on the board like any other.
* `verify_dealer_message`, `verify_dealer_messages` and `aggregate_public` take reshare
  configurations unchanged. `aggregate_public` requires every declared dealer and
  returns the output whose Reshare key is X, so leaving members confirm the result
  without a receiver key.
* `DkgConfig::new` rejects Reshare with `InvalidReshareConfiguration`. `deal` and
  `complete` return `ConfigurationKindMismatch` on a reshare configuration, as
  `deal_reshare` and `complete_reshare` do on a plain one.

## Encodings and identities

Reshare=2. Reshare pins its constant commitment C_{i,0} to the dealer's predecessor
share Y_i as Zero pins the identity: broadcasts omit it, so a Reshare or Zero instance
carries t_new − 1 physical coefficients, and the parser inserts it from the
configuration. L contains every logical coefficient, so each dealer root and proof
transcript binds Y_i.

Reshare configuration payload C': version, F(`golden-dkg/reshare`), F(group ID), U32
t_new, U32 `max_corrupt_receivers`, 32-byte session, U32 receiver count and canonical
(U32 participant, point key) entries, the same for dealers, U32 predecessor threshold,
predecessor key, 32-byte predecessor configuration root, 32-byte predecessor
completion root, U32 share count and canonical (U32 participant, point) entries, U32
instance count, kind bytes. Root domain `golden-dkg/reshare-config-root/v3`.

The field after the version selects the grammar. A plain payload has the group ID
there, and `DkgGroup::GROUP_ID` never equals `golden-dkg/reshare`, so the grammars
cannot be confused. The parser compares each broadcast's configuration root with this
root before reading any instance, so a plain dealing, or one for another predecessor or
session, does not parse. Effective messages bind the same root, the old dealer index,
the position, the kind and a fresh nonce.

Index spaces never mix. Old indices select dealer keys, pinned constants, effective
messages and λ^Q; new indices select receiver keys, evaluation points and outputs. One
integer may name different parties in the two spaces, and no old index is compared
with a new one.

## Proofs and preparation

The Main Golden relation, both circuits, proof IDs and transcript labels are
unchanged. Every dealer has exactly n_new receiver slots, with no self-exclusion.
Reshare has no constant-opening proof: the constant is fixed before the run, and each
dealing's n_new ≥ t_new encrypted evaluations determine it (Q3).

Capacity comes from the instance count and `receiver_count()`, which is n_new for a
reshare: the requirement of a plain configuration with the same instances over
n_new + 1 participants. Prepare for the reshare configuration itself; a proof system
prepared for the predecessor can fail with `InsufficientProofCapacity`. Only
configurations with `receiver_count() == 0`, exactly the plain single-participant ones,
skip proofs; a one-receiver reshare carries a proof.

## Validation and persistence

`new_reshare` checks, in order:

1. `1 ≤ threshold ≤ receivers.len()`, else `InvalidThreshold`;
2. `max_corrupt_receivers < threshold`, else `InsecureReshareThreshold`;
3. nonempty instances (`EmptyDkgBatch`) holding one Reshare and otherwise Zero;
4. every dealer index in the predecessor column, and |Q| ≥ t_old;
5. no key in the union of both registries equal to another or to its negation, else
   `ReshareKeyCollision`;
6. dimensions without overflow, else `ArithmeticOverflow`.

Checks 3 and 4 otherwise fail with `InvalidReshareConfiguration`.
`ResharePredecessor::new` requires t_old ≥ 1, at least t_old shares with valid unique
indices, a canonical nonidentity X, canonical Y_i, and every share on the degree
t_old − 1 polynomial that the first t_old shares in index order interpolate to X;
otherwise `InvalidPredecessor`. A Y_i may be the identity: a corrupt dealer cooperating
with a corrupt receiver can force that receiver's share to zero, and that member then
reshares s_i = 0 under an identity pinned constant.

`deal_reshare` checks the dealer key and g^{s_i} == Y_i (`PredecessorShareMismatch`)
before drawing randomness. Association runs over `dealers()`: verification accepts a
nonempty partial board, while completion and `aggregate_public` require every declared
dealer exactly once. The pipeline is the plain one: public validation, proofs with the
usual blame, the receiver's slot decrypted and checked in every dealing, then
aggregation. Aggregation computes A'_k = Σ_{i∈Q} λ^Q_i·C_{i,k} and weights shares
alike, asserts A'_0 == X for Reshare and the identity for every Zero through the
predicate that public-output restore also runs, and evaluates Y'_j = A'(j) at the new
indices. Zero instances are fresh zero-sharings dealt by Q at t_new; any linear
combination of zero-sharings is one.

The state envelope, its version and its tags are unchanged; C' identifies itself.

* Tag 1: C', restored by rerunning `new_reshare` with every predecessor check.
* Tag 2: `expected_participant` in `dealers()`, zero held shares and a broadcast that
  parses for it. A dealer that crashes after persisting resends the identical bytes.
* Tags 3 and 4: participants from `registry()`, interpolation with t_new, the pinned
  Reshare and Zero keys and a recomputed completion root; a local output also needs a
  receiver whose shares open its public shares.

Restores check structure and algebra only, not proofs or the board. Restored outputs
need authenticated storage with trusted completion provenance; untrusted imports
replay the complete board through `complete_reshare` or `aggregate_public`.

## EHTDH1

`material_from_dkg_output` accepts exactly `[Random, Zero]` or `[Reshare, Zero]`. A
Reshare decryption key must equal the predecessor key, so the `SealingKey` stays X;
participants are the `registry()` indices and the threshold is `config.threshold()`.
The decryption column x is reshared; the context column z is fresh, dealt by Q as the
batch's Zero instance.

The doc-hidden `golden_core::output::ehtdh1_completion_root` takes the decryption kind
first, accepts Random or Reshare and returns `InvalidEncoding` for any other kind.
`SetupContext` does not record the kind, so `Combiner::new` accepts a setup whose
completion root matches under Random or under Reshare. This is safe: the check only
ties the key set to the completion identity the setup names, and the kind byte is
hashed into the root, so for one configuration root and key set at most one candidate
matches. Decryption shares bind `SetupContext::root()` through Hdgd and Hdcd, so shares
from two generations neither combine nor verify across setups, and quorum rules apply
per generation. Records sealed under X open with t_new shares of the new committee
after each reshare in a chain.

## Deployment requirements

1. **Static corruption bounds per attempt.** At most `max_corrupt_receivers` new
   receivers are corrupt in every attempt, aborted ones included, and at most
   t_old − 1 old members while any old share survives; a member of both committees
   counts against both. Keep n_new − `max_corrupt_receivers` ≥ t_new; `new_reshare`
   enforces only t_new > `max_corrupt_receivers`. Never lower t_new or relax the bound
   to push a stalled reshare through, and log an explicit operator override for any
   t_new < t_old, which lowers fault tolerance at once; raising t_new protects nothing
   until old shares are erased. Reason: t_new corrupt receivers of any attempt learn
   every s_i in Q once its dealings are broadcast, and after erasure only honest new
   members reconstruct x.
2. **Proof of possession at admission.** Admission verifies a proof of possession for
   every identity key in both registries, bound to the session, role and index; the
   library only rejects duplicate and negated keys. Reason: Golden's security argument
   assumes it, and a copied key can otherwise take an honest party's seat or leave a
   seat nobody can use.
3. **Distinct per-role keys.** A member of both committees registers a dealer key and a
   separate receiver key; `new_reshare` rejects a key in both registries, and the
   library never infers that two seats belong to one party. Reason: every dealing keeps
   one shape with no self slot, and seats cannot be confused across roles.
4. **Q declared and agreed before dealing.** Every participant confirms the reshare
   configuration root, which binds Q, both registries and the predecessor, with every
   peer before anyone deals. Each member builds the predecessor from its own trusted
   output or an authenticated source, never from a broadcast, and the dealer key at old
   index i belongs to the holder of s_i. Reason: receivers that combine over different
   Q hold shares of different polynomials with the same X, and the key does not show it.
5. **Fresh attempts.** Each attempt uses a fresh `SessionId` and fresh keys. Reason:
   the library does not detect a reused configuration root.
6. **Dealer secrets are share-equivalent.** Zeroize a dealer's identity secret, encrypt
   it at rest if it is persisted to resend after a crash, and erase it together with
   s_i; a long-lived key reused as a dealer key keeps a copy of s_i for every reshare it
   dealt. Reason: that secret and the public board recompute every pad, hence every
   f_i(j), hence s_i.
7. **No erasure before attested activation.** Old members erase s_i, their dealer
   secrets and every backup only after a globally consistent activation of the new
   committee, for example an event at an agreed block height that every validator sees.
   It carries signed attestations over the completion root from every new member, or
   from at least t_new + `max_corrupt_receivers`, since the root is public and only
   honest members' attestations show a held share. A member that has attested never
   discards its output. Reason: one corrupt member can make confirmation succeed for
   some members and fail for others, so erasing on local success can leave fewer than
   t_new holders and lose X.
8. **Never discard a pending output on local failure.** A new member persists its
   output as pending until a globally visible activation or cancel; "failed" means "not
   activated", never "safe to delete". Reason: the split-brain attack of requirement 7.
9. **t_new = 1 only with `max_corrupt_receivers` = 0.** Requirement 1's check enforces
   this. Reason: each dealing polynomial is then constant, so every receiver decrypts
   each dealer's s_i and holds x (Q9).
10. **No insecure proofs.** Never deploy `InsecureRevealedWitnessProof`; `deal_reshare`
    does not refuse it. Reason: it publishes every share and pad, so a reshare
    broadcast under it reveals f_i at n_new ≥ t_new points, hence s_i, to anyone
    reading the board.

## Open cryptographic questions

These need sign-off before production use.

* **Q1. Reshare functionality.** Define an ideal reshare functionality that outputs a
  sharing f' with f'(0) = x plus an adversarial shift Δ with Δ(0) = 0, including the
  adversary's ability to abort attempts and choose which one completes. Prove that this
  protocol realises it. Golden's only resharing text is a paragraph on same-committee
  refresh, with no proof.
* **Q2. Composition.** Does security hold when the predecessor is itself the biased
  output of key generation or of an earlier reshare, along a chain of reshares?
* **Q3. Omitted constant proof.** Is a pinned constant with no constant-opening proof
  sound, with extraction through the n_new ≥ t_new encrypted evaluations?
* **Q4. Retries.** Does per-attempt secrecy hold across adversary-driven aborts,
  including when the new committee changes between attempts?
* **Q5. Proof of possession.** This library does not include one; deployments verify
  it at admission. Which form is required (Golden asks for online extraction), and what
  must it bind?
* **Q6. EHTDH1.** EHTDH1 is proven under trusted key generation. Does its reduction
  tolerate known additive shifts in the x and z columns? The gap exists for fresh
  setups too. What is the joint corruption and query budget while both generations
  answer decryption requests?
* **Q7. Generation binding.** `SetupContext` has no generation field; generations are
  distinguished by the configuration root, which binds the predecessor's roots. Is
  that sufficient?
* **Q8. Mixed-shape batching.** Moot: with per-role keys every dealing in a reshare has
  n_new receiver slots, so proofs on one board share one shape.
* **Q9. t_new = 1.** Accepted for any n_new when `max_corrupt_receivers` is 0. Every
  receiver then opens each dealer's s_i and derives every other receiver's raw pad in
  that dealing. Should t_new = 1 be restricted to n_new = 1?

## Commit and validation sequence

1. Freeze this contract.
2. Pin plain DKG wire vectors on both curves.
3. Read dealer and receiver sets through the configuration, with no behaviour change.
4. Reshare configuration, dealing, completion and persistence in golden-core, with
   pinned reshare wire vectors.
5. Real-proof reshares in golden-bulletproofs.
6. The EHTDH1 bridge.

Final gates on one fixed HEAD: unchanged plain wire vectors, so bench and proof
fixtures stay valid and are never regenerated; `cargo fmt --all --check`; workspace
clippy with `-D warnings` over every adapter, proof and serde feature; nextest for
golden-core with `insecure-revealed-witness`, golden-ehtdh1 and golden-bulletproofs;
the ignored real-proof suites in release; rustdoc with `-D warnings`; and independent
cryptographic sign-off on the open questions. Automated engineering reviews do not
replace cryptographic approval.
