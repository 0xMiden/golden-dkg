# 10 — Integrate, review, and verify

**What to build:** Demonstrate that the complete signed ticket series is internally coherent, matches the production specification, and passes the repository's relevant validation matrix.

**Blocked by:** 09 — Contract legacy APIs and refresh artifacts.

**Status:** ready-for-agent

- [ ] Run focused package/feature tests and the final workspace, feature, formatting, lint, docs, WASM, and fixture checks once on the integrated result.
- [ ] Run independent Standards and Spec reviews against `a9ca230` and the production specification and fix every in-scope finding.
- [ ] Confirm the committed series excludes `.scratch`, `CONTEXT.md`, and `docs/adr/` and contains no compatibility wrapper or unrequested release claim.
- [ ] Leave rebasing, replacement signing, pushing, posting, and PR mutation to the user.
