# 02 — Make DKG proof storage opaque through the prototype path

**What to build:** Remove the backend associated proof type and make stored DKG messages carry only opaque proof-stream bytes. Migrate the prototype proof to the shared stream, change dealer-message serialization to its v2 opaque-proof format, and demonstrate a complete fast prototype-backed dealing flow through creation, wire decoding, public verification, and completion without any proof representation in caller types.

**Blocked by:** 01 — Establish the curve-aware Golden proof stream.

**Status:** ready-for-agent

- [ ] The proof backend keeps its current configurable group seam, adds a stable proof ID, returns opaque bytes, and verifies borrowed bytes.
- [ ] Stored dealer messages and dealings no longer have a proof type parameter.
- [ ] Dealer messages store raw proof bytes without a proof wrapper, backend marker, or separate proof-ID field.
- [ ] Verification rejects a proof stream whose header does not match the selected backend’s proof ID.
- [ ] The prototype proof emits and receives canonical nonce points and response scalars in statement order through the shared stream.
- [ ] Prototype receiver-indexed proof structs/maps and their public serialization surface are removed.
- [ ] Dealer-message-v2 owns the one opaque proof length/payload and has no legacy decoder.
- [ ] Generic dealer-message decoding does not parse backend proof grammar; malformed inner bytes fail during statement-aware verification.
- [ ] A fast DKG test covers create, canonical wire round trip, verify, and complete with no proof type aliases.
- [ ] Prototype proof tampering, omissions, extras, reordering, truncation, trailing bytes, and wrong proof ID fail through the DKG verification interface.
- [ ] The existing paper backend remains buildable behind the new byte seam pending ticket 03.
