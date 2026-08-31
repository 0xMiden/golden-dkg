# 05 — Pin proof-stream interoperability and close validation gates

**What to build:** Finish the PR with deterministic proof-stream vectors, a complete malformed-stream corpus, end-to-end Golden/EHTDH regressions, and explicit validation that the change stayed within its proof-composition boundary.

**Blocked by:** 04 — Contract proof representations and migrate consumers.

**Status:** ready-for-agent

- [ ] Versioned deterministic proof bytes and challenge checkpoints are pinned for prototype, standalone paper, and batched dealer streams under fixed RNG.
- [ ] Vectors prove the proof ID, complete statement, labels, prior messages, and operation order affect challenges as intended.
- [ ] Canonical point/scalar, identity policy, every truncation point, checked length overflow, malformed child frame, wrong proof ID, and trailing-byte cases are covered.
- [ ] Proof-only dealer-message tampering leaves existing dealing roots unchanged but fails public verification.
- [ ] A complete DKG succeeds using decoded peer dealer messages under both fast prototype and real paper paths.
- [ ] Existing prototype-backed DKG-to-EHTDH tests pass.
- [ ] The ignored paper-backed DKG-to-EHTDH test is run explicitly and passes.
- [ ] Formatting, clippy, workspace tests, all-feature tests, and explicit ignored real-proof tests pass.
- [ ] There is no source diff under the Bulletproofs engine crate.
- [ ] The PR’s breaking-change note lists source, dealer-message-v2, proof-v2, challenge, persistence, migration, and interoperability impact.
- [ ] Final deletion accounting confirms no Golden-level proof representation or standalone proof codec remains.
