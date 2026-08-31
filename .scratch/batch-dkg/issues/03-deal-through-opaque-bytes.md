# 03 — Deal through opaque bytes

**What to build:** Let a registered dealer create one complete, opaque, configuration-shaped broadcast plus retryable participant-local `OwnDealing` state through the free `deal` workflow.

**Blocked by:** 02 — Introduce the flat stateful proof seam.

**Status:** complete (`804bbd4`)

- [x] Registry and configuration construction enforce the final immutable fields, roots, ordering, threshold bounds, and no caller-supplied beta.
- [x] `deal` validates the dealer identity, independently builds every Random/Zero instance, and returns exactly one opaque dealer byte string plus `OwnDealing`.
- [x] Encoding is configuration-selected, non-self-describing, canonically versioned, and bounded to 16 MiB as a whole message.
- [x] Degenerate zero pads return the dedicated coarse error without proof work or partial output; `n = 1` uses a canonical empty proof.
