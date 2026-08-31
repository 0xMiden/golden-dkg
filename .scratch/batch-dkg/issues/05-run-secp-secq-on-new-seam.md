# 05 — Run Secp/Secq proofs on the new seam

**What to build:** Make the production Secp/Secq Bulletproof implementation prove the core-owned Main Golden relation through the new stateful flat proof seam.

**Blocked by:** 03 — Deal through opaque bytes.

**Status:** complete (`97bfcf9`)

- [x] Circuit and native evaluation consume the same full-field beta, key-bound H1/H2 inputs, logical commitments, and canonical receiver order.
- [x] `SecpSecqBulletproofs` implements opaque single and optimized cross-dealer verification without exposing paper-specific statement types.
- [x] Proof framing and batch coefficients bind the complete ordered configuration, statements, and proof bytes before challenges.
- [x] Production proofs retain all pad, share, identity, decomposition, and chord values as private witnesses.
