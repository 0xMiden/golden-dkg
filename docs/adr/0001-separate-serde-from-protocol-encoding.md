# Separate serde from protocol encoding

Public application values may implement serde for external interoperability, but serde representations are not canonical Golden protocol formats and carry no protocol compatibility guarantee. Internal protocol values use only the manually defined wire parser, encoder, and transcript observation; roots, proofs, and protocol parsing never depend on serde. This keeps serde ergonomic for callers without creating a second accidental protocol grammar or allowing context-dependent dealer messages to bypass session-bound validation.
