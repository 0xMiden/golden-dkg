# 04 — Contract proof representations and migrate consumers

**What to build:** Remove the remaining obsolete Golden proof representations and standalone persistence paths, migrate all workspace callers to group-only dealer/dealing types, and make complete dealer-message serialization the sole proof transport. Preserve current DKG outputs, roots, and production EHTDH behavior.

**Blocked by:** 03 — Stream the batched paper dealer proof.

**Status:** ready-for-agent

- [ ] Remaining prototype, Chaum–Pedersen, DLOG, one-receiver envelope, batched envelope, public byte-wrapper, and fake proof container types are deleted or reduced to private algebra helpers with no storage role.
- [ ] All associated-proof generic parameters and aliases are removed from DKG helpers, maps, completion call sites, and integration tests.
- [ ] Standalone proof wire tags/contexts, Serde visitors, Miden adapters, and wrapper tests are removed.
- [ ] Dependencies used only by standalone proof serialization are removed or reduced to forwarding features where necessary.
- [ ] Dealer-message-v2 wire, Serde, and Miden round trips provide the only proof persistence coverage.
- [ ] Existing non-proof dealer tamper, completion, and transcript-root tests continue to pass without semantic changes.
- [ ] EHTDH production code is unchanged; integration tests lose only proof-type imports, aliases, and annotations.
- [ ] No default proof generic, phantom backend parameter, legacy decoder, or duplicate old/new proof path remains.
