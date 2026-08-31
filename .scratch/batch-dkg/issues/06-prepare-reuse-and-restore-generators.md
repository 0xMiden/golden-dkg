# 06 — Prepare, reuse, and restore generators

**What to build:** Let operators prepare and authenticate one explicit Secp/Secq generator artifact that can serve every compatible configuration up to its declared capacity.

**Blocked by:** 05 — Run Secp/Secq proofs on the new seam.

**Status:** complete — `2e76aa7b1bebd27d7c17f6590fe2c3fab3808995`

- [x] `prepare_for` computes checked exact requirements and the smallest padded capacity, including the zero-capacity single-participant shape.
- [x] Equal and smaller configurations reuse prepared state; under-capacity state fails before proof parsing or work and never grows lazily.
- [x] Persistence emits exactly the declared logical prefix and validates version, curve, capacity, dimensions, and canonical nonidentity points on restoration.
- [x] Process-wide memoization cannot enlarge a smaller serialized artifact and restoration does not rederive the prefix.
