# 07 — Persist and restore DKG state

**What to build:** Support trusted application persistence for validated DKG configuration, retryable local dealings, and completed participant state without creating another protocol grammar.

**Blocked by:** 04 — Complete candidate sets atomically.

**Status:** complete — `1d36b2d6c6b0b6d68033d94d64125b64ad329139`

- [x] Serde and Miden representations cover the specified public/application values and remain separate from dealer-message encoding and transcripts.
- [x] Registry/config restoration validates inputs and rederives roots; output restoration rejects malformed encodings and inconsistent dimensions.
- [x] `OwnDealing` restoration remains bound to its participant and configuration and never stores an identity secret or proof-system value.
- [x] Debug output redacts all local shares and proof bytes are not exposed as diagnostics.
