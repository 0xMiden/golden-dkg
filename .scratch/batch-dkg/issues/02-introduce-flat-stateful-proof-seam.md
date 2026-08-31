# 02 — Introduce the flat stateful proof seam

**What to build:** Give proof implementations one immutable, flat, core-owned Main Golden statement and witness through an injected reusable `DealerProofSystem` value.

**Blocked by:** 01 — Pin Main Golden protocol semantics.

**Status:** complete

- [x] Flat statement and witness views expose canonical instance and receiver order without public mutation or duplicate beta/configuration fields.
- [x] `DealerProofSystem` provides stateful prove, verify, and optional batch verification over opaque proof bytes.
- [x] Core provides the exact native conformance checker and a narrowly scoped validated revealed-witness reconstruction seam.
- [x] `InsecureRevealedWitnessProof` checks the exact relation and is unavailable from the default production API.
