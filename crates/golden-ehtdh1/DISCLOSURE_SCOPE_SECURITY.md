# Disclosure-scope protocol and security model

This document describes the disclosure-scope extension in `golden-ehtdh1`, its
relationship to exact-ciphertext EHTDH1, and the obligations that remain outside
the crate. The extension is not the exact construction proved in the EHTDH1
paper. Paper-backed statements below cite the primary source by document ID and
PDF page; statements about the extension are identified as construction facts,
assumptions, security intuition, or open review questions.

Primary source: Dan Boneh, Benedikt Bünz, Kartik Nayak, Lior Rotem, and Victor
Shoup, *Context-Dependent Threshold Decryption and its Applications*,
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`](https://eprint.iacr.org/2025/279).

## 1. Exact mode versus disclosure-scope mode

> Exact mode authorizes one complete ciphertext. Disclosure mode binds released
> shares to an application-declared scope and request, while reconstruction still
> produces the broader `(R, xR)` capability.

In exact-ciphertext EHTDH1, a share uses

```text
S = Hdgd(ad, dc, ctxt)
W_i = x_iR + z_iS
```

where `ctxt = (R, V, e, r-response, c)` is the complete ciphertext. The paper
therefore binds each share to associated data, decryption context, and one
complete ciphertext. [`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF pp. 15–16 (paper pp. 13–14)]

Disclosure-scope mode is a separate extension. It replaces exact-ciphertext
share binding with scope-and-request share binding. This changes the
application authorization semantics and the granularity at which shares are
isolated; it does not change the interpolation correctness that recovers `xR`.

The modes remain visibly separate:

| Property | Exact-ciphertext mode | Disclosure-scope mode |
| --- | --- | --- |
| Share binding | Complete ciphertext, associated data, decryption context, and setup | Stable scope, request context, and setup |
| Released share type | `DecryptionShare` | `DisclosureDecryptionShare` |
| Combining | `combine_exact` / `combine_quorum` | `combine_disclosure_exact` / `combine_disclosure_quorum` |
| Wire tag | `0x26` | `0x27` |
| Codec ID | `ehtdh1-decryption-share-v1` | `ehtdh1-disclosure-group-decryption-share-v1` |

The distinct transcript domains, types, and wire allocations prevent an exact
share from being treated as a disclosure share or vice versa. No mode boolean
or shared wire representation is used.

## 2. Protocol description

Let participant `i` hold decryption share `x_i` and zero-sharing share `z_i`,
with public verification points `X_i = x_iG` and `Z_i = z_iG`. The paper's
EHTDH1 setup uses a Shamir sharing of the decryption secret `x` and an
independent Shamir sharing of zero; released shares have a linked
representation proof against `(X_i, Z_i)`. [`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF p. 16 (paper p. 14), equation (2)]

For a stable disclosure scope, participant `i` may compute and cache:

```text
A_i = x_iR
```

For one request, derive the request-specific group point and release:

```text
S_scope,request = HashToGroup(setup, ad, request context, scope ID, R)
W_i = A_i + z_iS_scope,request
```

A homogeneous threshold set interpolates as follows:

```text
sum lambda_i W_i
  = (sum lambda_i x_i)R
    + (sum lambda_i z_i)S_scope,request
  = xR
```

This is the same cancellation used by exact EHTDH1: interpolation reconstructs
`x`, while the sharing of zero reconstructs `0`. The paper gives this
correctness calculation for its exact-ciphertext `S`.
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF pp. 16–17 (paper pp. 14–15)]

> **Scope ID and request context determine which shares can reconstruct `xR`;
> they do not restrict what `xR` can open after reconstruction.**

The payload mask depends only on `(R, xR)`:

```text
mask = Hkd(R, xR)
```

The paper's encryption derives its payload key from `Hkd(R, U)` with `U = rX =
xR`. [`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF p. 15 (paper p. 13)] Scope ID, request context, associated data, the
request-specific point, the zero-sharing term, and the share proofs are not
inputs to this payload-mask derivation.

### Historical transcript allocation

The source-level application term is now “scope,” but all existing transcript
bytes remain unchanged. In particular, the historical `disclosure-group`
strings are protocol allocations and **must not be renamed**.

Disclosure group-point transcript:

```text
prefix:    golden-ehtdh1-v1
operation: hdgd-disclosure-group
domain:    golden-ehtdh1-hdgd-disclosure-group-v1

field order:
    backend
    setup-context-root
    ad
    dc
    disclosure-group-id
    R
```

The source value named `scope_id` is still encoded under the historical field
label:

```text
disclosure-group-id
```

Disclosure share-proof challenge transcript:

```text
prefix:    golden-ehtdh1-v1
operation: hdcd-disclosure-group
domain:    golden-ehtdh1-hdcd-disclosure-group-v1

field order:
    backend
    setup-context-root
    S
    X-i
    Z-i
    W-i
    X-i-prime
    Z-i-prime
    W-i-prime
```

The disclosure share's historical wire allocation is also unchanged:

```text
tag:      0x27
codec ID: ehtdh1-disclosure-group-decryption-share-v1
```

The exact share remains:

```text
tag:      0x26
codec ID: ehtdh1-decryption-share-v1
```

Exact and disclosure share bytes are intentionally non-interchangeable. Raw
`xR`, `DecryptionPrecomputation`, `DisclosureScope`, `DisclosureRequest`, and
`DisclosureKey` have no public wire encoding.

## 3. Request construction is not authorization

`DisclosureScope::request` constructs a public transcript-input descriptor. It
does not authenticate a caller, establish ciphertext membership, evaluate a
policy, or authorize release.

Golden cannot determine which records an application intended to place in a
scope. Before issuing a participant share, the **application release
authorizer** must authenticate the complete ciphertext or record envelope,
confirm its intended scope membership, and decide that the request is
permitted. A record ID, scope ID, or request context alone is not membership
evidence. Complete-envelope authentication can be implemented through trusted
storage, a manifest of authenticated envelope digests, or another application
mechanism.

A TEE is one possible release authorizer in the motivating deployment, but TEE
custody and policy are not part of Golden's generic interface. Constructing the
request before or after the external policy decision does not itself make that
decision.

## 4. Repeated and adaptive requests

For fixed `R`, repeated requests expose, for participant `i`:

```text
W_i^(j) = x_iR + z_iS_j

W_i^(1) - W_i^(2) = z_i(S_1 - S_2)
```

For fixed `R`, repeated requests expose `x_iR + z_iS_j` for adaptively selected
hash-to-group points `S_j`. Under the model that each domain-separated `S_j`
behaves as an independent random group element and exploitable discrete-log
relations remain unknown, subtracting releases does not directly reveal `z_i`
or `x_iR`. This is security intuition for the disclosure extension, not a claim
that the original EHTDH1 proof directly covers the modified statement.

The paper's security notion supports decryption contexts selected at decryption
time and isolates exact-ciphertext shares by context, but its concrete EHTDH1
construction hashes `(ad, dc, ctxt)`, including the complete ciphertext.
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF pp. 5–6 (paper pp. 3–4) and PDF pp. 15–16 (paper pp. 13–14)] The disclosure
extension instead hashes stable scope state plus request context. The available
primary evidence does not establish that the paper's proof automatically
carries over to that modified statement.

The following remain explicit extension review questions rather than proved
consequences of the original EHTDH1 analysis:

1. security under many adaptively selected requests for one fixed `R`;
2. scope-level, rather than complete-ciphertext, share binding;
3. retaining participant-local `x_iR` across those requests; and
4. composition of those properties with application membership and release
   authorization.

## 5. Hash-to-group assumption

The primary disclosure-extension assumption is:

> Each domain-separated `S_scope,request` behaves as an independent random group
> element.

Concretely, an adversary must not know an exploitable scalar or linear relation
between `S_scope,request`, the generator, `R`, or another selected point. Domain
separation and hashing the complete scope/request transcript are necessary, but
the extension's security argument also relies on the backend hash-to-group
output not exposing such a relation.

The following is an unsafe replacement when the scalar is publicly computable:

```text
S_j = hash_to_scalar(inputs) * G
```

Writing the public verification point as `Z_i = z_iG` and the known scalar as
`s_j`, a released share immediately gives:

```text
x_iR = W_i - s_jZ_i.
```

This conclusion is a direct algebraic consequence of the EHTDH1 share form and
public `Z_i` values described by the paper.
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF pp. 15–16 (paper pp. 13–14)] It would expose the cached contribution from
each participant release and destroy the intended request/scope isolation.

This document does not claim a formal proof for repeated adaptive requests or
proof carryover to the disclosure extension. Backend review must establish the
required random-oracle-style, unknown-relation behavior for every supported
group implementation.

## 6. Capability model

`DisclosureKey` intentionally represents an opaque, reusable `(R, xR)`
capability:

- the motivating application reconstructs once;
- it intentionally opens multiple authenticated sibling wrappers;
- forcing repeated threshold reconstruction would produce the same underlying
  capability and would not narrow it;
- the raw DH point has no accessor or public encoding; and
- secret-bearing debug output is redacted.

The ordinary `open` path verifies the ciphertext proof, requires matching `R`,
and requires the expected associated data. These checks reduce accidental
misuse but do not change the cryptographic capability. In particular,
associated-data equality in `DisclosureKey::open` is a defensive API policy,
not a cryptographic restriction on raw `xR`. Extraction or disclosure of that
point would permit derivation of the mask for any valid wrapper sharing `R`,
regardless of scope ID, request context, or associated data.

Applications must therefore handle `DisclosureKey` as a sharp capability for
the entire underlying capability domain, not as proof that any particular
ciphertext belongs to the declared disclosure scope.

## 7. Seeded sealing and payload contract

For a fixed sealing key, seeded sealing deterministically derives `r`; repeated
use of that seed therefore repeats:

```text
R = rG
xR = rX
mask = Hkd(R, xR)
```

The paper defines encryption using `R = rG`, `U = rX`, and `Hkd(R, U)`.
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF p. 15 (paper p. 13)] The deterministic derivation of `r` is a crate
extension and is not changed by disclosure-scope mode.

Golden binds the backend and joint public key internally. The application must
derive the supplied seed using inputs that bind, as relevant:

- an application/protocol/version domain;
- transaction or disclosure-scope identity;
- a high-entropy nonce;
- a private-payload commitment; and
- setup epoch or setup identity.

Validators cannot verify caller-provided entropy. Because `R = rG` is public,
an observer can test weak seed candidates offline. Anyone who learns or guesses
the seed can derive `r`, compute `rX` from the public sealing key, and bypass
threshold release for every payload using that derived `r`.

Seeded siblings reuse a stream mask:

```text
c_1 = m_1 XOR mask
c_2 = m_2 XOR mask

c_1 XOR c_2 = m_1 XOR m_2
```

Intentional mask reuse is therefore limited to independently uniform,
fixed-length content keys. It is not safe for arbitrary, biased, correlated,
structured, variable-length, or repeated plaintexts. Even for uniform content
keys, this protects only against ciphertext-only structure leakage: a known
wrapped plaintext reveals the common mask and every sibling plaintext.

Encryption must use a fresh proof nonce `r'` for every statement. The paper's
response is:

```text
r-response = r' + re
```

For two distinct challenges using the same seeded `r` and the same `r'`:

```text
r = (r-response_1 - r-response_2) / (e_1 - e_2)
```

Thus nonce reuse can disclose `r` and break payload confidentiality, not merely
proof soundness. The response equation is defined in
[`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF p. 15 (paper p. 13)].

The generic seeded API is deliberately sharp: it cannot enforce seed entropy,
application domain separation, payload uniformity, plaintext independence, or
fresh caller RNG state.

## 8. Cached precomputation lifecycle

A `DecryptionPrecomputation` contains participant-local `x_iR`. Its generic
lifecycle is:

1. create `x_iR` during the transaction stage, before a release request needs to
   exist;
2. keep it in protected participant-local storage and never serialize or
   disclose it;
3. reuse it only for legitimate requests whose scope has the same participant
   and `R`;
4. retain it only while legitimate later requests may occur;
5. invalidate it when the corresponding Golden setup rotates;
6. evict protected-storage copies after the disclosure window or applicable
   record-retention period expires.

Dropping the Rust value does **not** guarantee cryptographic erasure:
`GoldenGroup` does not require group-element zeroization. A TEE deployment may
store the value in sealed or otherwise protected storage, but TEE custody,
rollback protection, backup deletion, and physical erasure remain application
and platform responsibilities.

No proof is cached. The precomputation is internal participant state and is
never independently accepted by another party. Only released `W_i` values cross
the trust boundary, so each request-specific release receives a freshly
generated proof.

The lifecycle requires two independent freshness rules:

- every encryption uses a fresh encryption proof nonce `r'`, including when
  seeded siblings share `r`; and
- every disclosure-share release uses fresh proof nonces, including repeated
  release for the same request, even though the resulting `W_i` is unchanged.

## 9. Core observations

1. Payload masking depends only on `(R, xR)`.
2. The zero-sharing term provides request/context binding and share isolation; it
   cancels during valid interpolation.
3. Replacing `S` changes share-authorization semantics, not the correctness of
   recovering `xR`.
4. Reusing `R` creates one underlying DH capability domain, even if the
   application declares multiple scope IDs.
5. The application defines and authenticates intended scope membership; Golden
   does not.
6. The application release authorizer enforces membership and authorization. In
   the motivating deployment, that authorizer is a TEE.
7. The cached value is participant-local `x_iR`; every released share receives a
   fresh proof.
8. After reconstruction, the capability is simply `(R, xR)`.

## 10. Blast radius

The table separates immediate failure from residual security. “Same-`R`
siblings” means wrappers under the same sealing key and underlying DH
capability. Statements in “What remains secure” assume all other requirements
in this document continue to hold, including sound DKG outputs, fresh randomness,
unknown discrete-log relations, correct authorization boundaries, and
uncompromised threshold participants. They are not unconditional guarantees.

| Event | What breaks | What remains secure |
| --- | --- | --- |
| Low-entropy seed | Public `R` permits offline candidate testing. A successful guess reveals `r`, permits computation of `rX` and the repeated mask, opens all same-seed/same-key siblings, and bypasses threshold release for them. | The guess does not itself reveal participant scalars or shares. Wrappers derived from independent high-entropy seeds or unrelated `R` values remain separate, subject to the other assumptions. |
| Seed disclosure | The holder can derive `r`, compute `rX`, recover the mask, and open every sibling using that seed and sealing key without disclosure shares. | Participant `x_i` and `z_i` values are not thereby revealed. Independently seeded capability domains remain separate unless they are compromised another way. |
| One cached `x_iR` disclosure | One participant's secret-bearing contribution for this `R` is exposed and can compose with other cached-contribution leaks. For threshold `t = 1`, it is already `xR`. | For `t > 1`, one contribution alone is not threshold `xR` and does not open payloads. Under discrete-log hardness it does not directly reveal `x_i`, does not supply `z_i`, and does not compute that participant's contribution for an unrelated `R`. |
| Threshold cached `x_iR` disclosures | Interpolating a threshold of participant contributions reconstructs `xR`. Every wrapper in the underlying same-`R` capability domain can then be opened at the cryptographic level, regardless of logical scope ID, request context, or associated data. | The leaks do not directly reveal the scalar secret `x` or individual `x_i` values under discrete-log hardness. Unrelated `R` values remain separate unless long-lived shares, seeds, authorization, or group assumptions are also compromised. |
| Reused encryption proof nonce | When the same `r'` is reused with the same seeded `r` across distinct challenges, the public responses reveal `r`; all payloads using that `r` lose confidentiality and threshold release is bypassed. | Participant threshold shares are not directly exposed. Other independently generated `r` values remain separate, assuming their proof nonces and seeds are sound. |
| Reused one or both disclosure-share proof nonces | Across distinct challenges, reuse of the decryption nonce reveals `x_i`; reuse of the context nonce reveals `z_i`; reuse of both reveals both long-lived participant shares. Both together let the attacker impersonate that participant for exact and disclosure releases, and either leak composes with other participant or cached-state compromise. | Compromising one participant still does not meet a threshold when `t > 1`. If only one of `x_i` or `z_i` is exposed, the other witness is still needed for a complete valid share proof. Uncompromised participants and independent setups remain protected subject to policy and threshold assumptions. |
| Broken hash-to-group independence or a known relation | A relation such as `S_j = s_jG` lets anyone derive `x_iR = W_i - s_jZ_i` from that participant's release. Scope/request isolation fails, and releases from enough participants can be combined into `xR` even if they were not issued for one homogeneous request. | Long-lived scalars are not automatically recovered under discrete-log hardness. Capability domains using unrelated `R` values remain separate only if the failure is confined to the affected points; a backend-wide hash-to-group failure must be treated as backend-wide. |
| Incorrect scope membership | The application may authorize release for an unintended record or treat an attacker-chosen same-`R` wrapper as a member. Once `xR` is reconstructed, scope labels cannot cryptographically contain the mistake. | Wrappers with unrelated `R` values remain outside this capability. The ordinary key API still rejects a mismatched expected associated-data value, but that is defensive policy and does not protect against raw `xR` exposure. |
| Accidentally grouping unrelated records under one `R` | The records share one DH capability and, under seeded sealing, one payload mask. Authorization or compromise concerning one logical scope can expose all same-`R` records; ciphertext XOR leaks plaintext XOR, and one known plaintext opens all siblings. | Records under unrelated `R` values remain separate. For independently uniform fixed-length keys, ciphertext XOR alone exposes no useful key structure, but known-plaintext and reconstructed-capability risks still remain. |
| Known wrapped content key | A party that knows one plaintext content key and its wrapped ciphertext recovers the repeated mask and can open every sibling sharing that mask. Threshold release is bypassed for those siblings. | This does not by itself reveal `r`, `xR`, participant shares, or keys wrapped under a different mask/`R`. Those facts may still be exposed through seed, writer, or participant compromise. |
| Compromised writer TEE | A writer that knows one content key and its wrapper can recover the common mask and all accessible sibling content keys. If it also holds or learns the seed, it can directly derive the same capability. It may also create malformed or malicious application records within its writer authority. | Writer compromise alone does not authorize threshold shares or reveal participant shares when writer and release-authorizer roles are kept logically separate. Unrelated `R` domains remain separate. Co-location of roles composes these failures. |
| Compromised share-authorizer TEE | The attacker can violate the membership or release policy enforced by that authorizer and can obtain or cause any participant release controlled by it for attacker-selected scope/request inputs. If the authorizer controls a threshold or the threshold policy itself, `xR` can be reconstructed and the whole same-`R` domain opened. | One compromised authorizer or participant still needs a threshold when `t > 1` and the remaining participants enforce independent authorization. Writer payloads and unrelated `R` domains remain protected only to the extent those separate roles and policies remain uncompromised. |

For disclosure-share proof responses

```text
decryption_response = decryption_nonce + challenge * x_i
context_response    = context_nonce    + challenge * z_i
```

reusing either nonce across different challenges exposes the corresponding
witness by subtracting the responses and dividing by the challenge difference.
This is the standard consequence of the linked representation proof form given
for EHTDH1. [`2025-boneh-bunz-nayak-rotem-shoup-context-dependent-threshold-decryption`,
PDF p. 16 (paper p. 14), equation (2)]

The events above compose. In particular:

- one cached `x_iR` is not itself threshold `xR` when `t > 1`, but a threshold of
  cached contributions is;
- one known wrapped plaintext exposes the repeated mask and sibling content keys;
- one compromised authorizer still needs a threshold unless it also compromises
  enough participants or the threshold policy;
- writer compromise and authorizer/participant compromise can jointly remove
  both the payload and threshold-release boundaries; and
- unrelated `R` values remain separate only under the stated discrete-log,
  hash-to-group, seed, randomness, DKG, storage, and authorization assumptions.
