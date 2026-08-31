# eVRF-derived Feldman coefficients in the current Golden paper

**Primary source:** Benedikt Bünz, Kevin Choi, Chelsea Komlo, *Golden: Lightweight Non-Interactive Distributed Key Generation*, Cryptology ePrint Archive 2025/1924, current revision. Citations below use document id `GOLDEN-2025-1924` and physical PDF page numbers.

## Finding

The claim is **not true of the main Golden protocol**. Section 6.1 samples a dealer secret `ω_i ←$ Z_p` and invokes randomized `Feldman.Share(ω_i,n,t)`; the eVRF is used only for pairwise receiver pads `r_{i,j}`. [`GOLDEN-2025-1924`, physical PDF pp. 28–29]

The paper derives Feldman coefficients from an eVRF only in **Appendix K, “One-Round DKG with Aborts,” specifically Figure 9’s BHL24-DKG variant**. Appendix K starts on physical page 58; Figure 9 is on physical page 59. This is a related construction, explicitly contrasted with Golden, not an optimization or subroutine of Golden itself. [`GOLDEN-2025-1924`, physical PDF pp. 58–59]

## Coefficient derivation and formulas

For every dealer `i` and every coefficient index `ℓ ∈ {0,…,t−1}`, Figure 9 computes

```text
(a_{i,ℓ}, A_{i,ℓ}, π^a_{i,ℓ})
    ← eVRF_BHL24.Evaluate(sk_i^I, sid || ℓ).
```

By the paper’s eVRF definition, `A_{i,ℓ} = g^{a_{i,ℓ}}`. [`GOLDEN-2025-1924`, physical PDF pp. 39, 59]

Thus the intended dealer polynomial and Feldman commitment are

```text
f_i(X) = Σ_{ℓ=0}^{t−1} a_{i,ℓ} X^ℓ,
\bar{x}_{i,j} = f_i(j),
\bar{C}_i = (A_{i,0}, …, A_{i,t−1}),
A_{i,ℓ} = g^{a_{i,ℓ}},
\bar{X}_{i,j} = Π_{ℓ=0}^{t−1} A_{i,ℓ}^{j^ℓ} = g^{f_i(j)}.
```

The index range includes `ℓ=0`, so **both the constant coefficient and every nonconstant coefficient are eVRF-derived**. This differs from ordinary Feldman sharing, where the caller supplies the constant `s` and `Feldman.Share` samples only `a_1,…,a_{t−1}`. [`GOLDEN-2025-1924`, physical PDF pp. 16, 59]

**Figure 9 caveat:** lines 3–4 contain apparent notation/editing errors: line 3 writes `\bar{C}_i=(a_{i,0},…,a_{i,t−1})`, although `\bar{C}` elsewhere denotes group commitments, and line 4 still prints randomized `Feldman.Share(ω_i,n,t)` without defining `ω_i`. The intended equations above follow from line 2, the eVRF definition `A=g^a`, and Round 1’s check `\bar{X}_{j,k}=Π A_{j,ℓ}^{k^ℓ}=g^{f_j(k)}` followed by the ciphertext check. Reading lines 3–4 literally would leave the eVRF coefficients unrelated to the shared polynomial and make that check fail. [`GOLDEN-2025-1924`, physical PDF pp. 39, 59]

## Security setting and attack addressed

Main Golden targets `F^B_KeyGen`: a rushing adversary may choose a limited additive bias after seeing honest public commitments. The paper invokes the one-round impossibility result and says Appendix K instead realizes the stronger **security-with-aborts** functionality `F^⊥_KeyGen`, at additional complexity. [`GOLDEN-2025-1924`, physical PDF p. 9]

In Appendix K, the session-bound eVRF fixes each dealer’s complete polynomial from `(sk_i^I, sid, ℓ)` rather than letting the dealer select coefficients after observing honest commitments. Consequently, a completed execution has the uniformly random key required by `F^⊥_KeyGen`; the adversary’s remaining power is to abort. The theorem assumes a consistent `sid`, a static adversary, and at most `t−1` corrupt parties. [`GOLDEN-2025-1924`, physical PDF pp. 58, 60]

This is distinct from the original BHLS private-channel **split-view/denial-of-service** problem discussed in related work. Publicly verifiable two-party-eVRF ciphertexts address share-encryption verifiability; deterministic coefficient generation addresses completed-key bias/security with aborts. [`GOLDEN-2025-1924`, physical PDF pp. 10–11, 59]

## Coefficient eVRF versus receiver-pad eVRF

They are **distinct evaluations and distinct protocol roles**:

- Coefficients use the **single-party** `eVRF_BHL24` on `sid || ℓ`, producing `(a_{i,ℓ}, A_{i,ℓ}, π^a_{i,ℓ})` for one polynomial coefficient and its Feldman commitment.
- Receiver pads use the **two-party** `T-eVRF-DH` on the dealer secret key, receiver public key, and the session/message input, producing `(r_{i,j}, R_{i,j}, π_{i,j})`; then `z_{i,j}=r_{i,j}+\bar{x}_{i,j}`.

The scalar/group/proof output shapes are analogous (`A=g^a`, `R=g^r`), but the primitive, key arity, message domain, domain separation (`ℓ` only appears for coefficients), and semantic output are different. Figure 9 prints `sid_i` for pad generation but later uses the undefined `msg_j` in pad verification/decryption; that is another apparent notation carry-over. It does not make the coefficient and pad calls the same evaluation. [`GOLDEN-2025-1924`, physical PDF p. 59]

## Interface implications for this worktree

- `EvrfProofBackend::derive_pad` is coupled to the receiver-pad proof relation: the concrete `SecpSecqBackend` computes the exact pad that its proof verifies, and both dealer encryption and receiver decryption must invoke the same evaluator (`crates/golden-core/src/dkg.rs`, `crates/golden-evrf/src/paper/secp_secq/dkg_backend.rs`). It therefore belongs on this backend **if the backend represents the complete eVRF relation implementation**, not merely proof encoding. If “proof backend” is intended to mean prove/verify only, the current trait name is narrower than its responsibility.
- Appendix K provides no reason to overload `derive_pad` for polynomial coefficients. Supporting BHL24-DKG would require a separate single-party, session-and-index-bound coefficient evaluator plus coefficient commitments/proofs and polynomial construction from all `t` outputs.
- The current prototype `ShareOpeningBackend` can use the trait’s default DH/hash `derive_pad` for protocol plumbing, but it only proves knowledge of independent share and pad openings and their additive ciphertext relation. It does **not** prove that a pad is the prescribed eVRF output. Its witness carries only an optional polynomial constant, not all coefficient openings. Therefore it cannot, as written, support Appendix K’s eVRF-derived Feldman coefficients or its `F^⊥_KeyGen` security claim; doing so would require a new coefficient relation/API and materially stronger proofs (`crates/golden-core/src/dkg.rs`, `crates/golden-evrf/src/lib.rs`).
