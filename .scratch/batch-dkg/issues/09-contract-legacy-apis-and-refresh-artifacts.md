# 09 — Contract legacy APIs and refresh artifacts

**What to build:** Finish the hard compatibility cut so every repository consumer uses the one production workflow and no prototype or legacy parsing surface remains.

**Blocked by:** 06 — Prepare, reuse, and restore generators; 07 — Persist and restore DKG state; 08 — Migrate EHTDH1.

**Status:** in-progress

- [ ] Remove public parsed dealer messages, standalone verification, static proof backends, old parameter types, and standalone one-receiver APIs/vectors.
- [ ] Migrate all remaining tests, examples, and benchmarks without retaining forwarding wrappers or fallback formats.
- [ ] Regenerate hard-cut fixtures and vectors and validate cached dealer bytes through complete with matching `OwnDealing`.
- [ ] Update documentation and CI feature/command references, including the mixed-instance extension and release-review caveat.
