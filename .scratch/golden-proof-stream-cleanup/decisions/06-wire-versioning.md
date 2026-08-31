# Let the proof stream own proof identity and framing

**Blocked by:** [Keep the backend seam but remove its proof type](02-backend-bytes.md), [Use one shared transcript for every Golden proof phase](04-shared-transcript.md), [Migrate every Golden proof path](05-migrate-proof-paths.md).

## Question

Where do proof identity/framing live, and what serialized artifacts change?

## Resolution

Every stream begins with a canonical versioned proof-ID header. The expected backend `B` supplies the ID during proving and verification; `VerifierProofStream::new` rejects mismatches.

`DealerMessage<G>` stores only opaque proof bytes. It does not carry a separate proof-ID field, proof wrapper, or backend generic.

Dealer-message wire owns one proof length and raw proof bytes. It no longer delegates to a standalone proof `WireMessage`. Bump the dealer-message codec from v1 to v2 and hard-cut over; no legacy decoder is needed. The global Golden wire magic and unrelated standalone codecs need not change.

Remove:

- standalone proof tags/contexts;
- `WireMessage` for proof wrappers;
- standalone opaque-proof `WireMessage` if it has no remaining consumer;
- proof-specific Serde visitors and Miden adapters;
- standalone proof serialization tests.

Serde/Miden dealer-message adapters, if retained, wrap the complete dealer-message-v2 bytes and therefore provide the only proof persistence route.

Proof IDs/domains for prototype, standalone paper, and batched paper streams all bump to v2. Proof bytes and Golden-level challenges are incompatible by design.

No planned changes to statement roots, dealing roots, completion roots, DKG output, or EHTDH setup roots. The stream observes the existing complete canonical statements and adds proof-protocol domain separation through `PROOF_ID`.

## Migration

All workspace callers migrate in the same PR. Old proof/dealer-message bytes are rejected. Existing DKG outputs require no migration because proof bytes are not part of the dealing/completion roots.
