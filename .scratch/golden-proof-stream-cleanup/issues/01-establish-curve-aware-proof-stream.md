# 01 — Establish the curve-aware Golden proof stream

**What to build:** Introduce paired, crate-private prover and verifier proof-stream roles and exercise them end to end through the standalone one-receiver paper proof. The stream must own one correctly bound transcript, canonical curve parsing, explicit point-identity policy, checked cursor/framing, nested current R1CS composition, and exact completion. Replace the standalone Chaum–Pedersen/R1CS/DLOG proof envelope with streamed messages while preserving its mathematical equations and the existing typed R1CS implementation.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] A private curve adapter supports canonical point/scalar operations for both existing Golden-group and cycle abstractions.
- [ ] A shared `Observe` trait implements byte/point/scalar observations once for both stream roles.
- [ ] Canonical public-statement observation is written once against `Observe`, not separately for prover and verifier.
- [ ] Prover and verifier streams support send/receive, shared challenges, nested child framing, checked cursor arithmetic, and exact `finish`.
- [ ] Failed receives do not advance the cursor or transcript.
- [ ] Point operations require an explicit allow/reject identity policy.
- [ ] The one-receiver CP, nested typed R1CS, and DLOG phases use one shared transcript in that order.
- [ ] The standalone Golden envelope/container proof types used by this path are removed.
- [ ] Deterministic transcript/challenge tests cover domain, statement, message, label, and operation-order sensitivity.
- [ ] Canonical parsing, every truncation boundary, malformed nested frames, and trailing bytes are tested without panics.
- [ ] No Bulletproofs engine source is changed.
