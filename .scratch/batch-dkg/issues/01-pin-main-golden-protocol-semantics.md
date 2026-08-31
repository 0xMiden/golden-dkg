# 01 — Pin Main Golden protocol semantics

**What to build:** Make `golden-core` the single source of truth for Main Golden's curve capabilities, protocol-wide setup coefficient, effective messages, H1/H2 inputs, receiver pads, and native relation semantics.

**Blocked by:** None — can start immediately.

**Status:** complete

- [x] `GoldenCurve` exposes only the base-field and coordinate operations required by Main Golden and replaces `GoldenEvrfCurve` for DKG execution.
- [x] Beta is sampled unbiasedly in the full base field from the specified fixed strings, accepts zero, and is pinned by an independent Secp256k1 vector.
- [x] Effective messages bind configuration, dealer, position, kind, and nonce; H1/H2 bind that message and the canonically ordered identity-key pair.
- [x] Native receiver-pad and relation evaluation fail closed on unsupported coordinates and agree across required curve adapters.
