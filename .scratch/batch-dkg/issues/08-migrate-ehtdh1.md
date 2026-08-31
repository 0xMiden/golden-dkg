# 08 — Migrate EHTDH1

**What to build:** Run EHTDH1 setup through the production opaque Golden workflow while preserving its application-specific Random/Zero mapping and cryptographic postconditions.

**Blocked by:** 04 — Complete candidate sets atomically; 05 — Run Secp/Secq proofs on the new seam.

**Status:** complete — `04780ab424b955b3273566b7ae9481ee5f60aa37`

- [x] The bridge requests exactly `[Random, Zero]` and maps the two ordered outputs to decryption and context shares.
- [x] It rejects identity decryption aggregate keys and nonidentity context aggregate keys while retaining configuration/completion binding.
- [x] Existing online encryption, partial decryption, combination, serialization, and failure behavior remain intact.
- [x] Bridge tests exchange only opaque dealer bytes through the new free workflow.
