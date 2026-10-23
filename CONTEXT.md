# Golden DKG

The workspace implements the fixed Main Golden relation over native Secp256k1
and Jubjub groups. The issue 71 contract is in [docs/issue-71.md](docs/issue-71.md).
All previous state, formats and APIs are retired in the 0.5 compatibility cut.

Keep the dependency boundary explicit:

* `golden-core` owns native algebra, immutable configuration, opaque broadcasts,
  public verification, atomic completion and contextual persistence. It has no
  concrete curve or Bulletproof dependency.
* `golden-curves` supplies proof-free native adapters.
* `golden-bulletproofs` owns both concrete joint circuits, typed immutable
  preparation, commitment-cycle adapters and optimized MSM implementations.
* `bulletproofs-cycle` is the generic engine with explicitly owned generators.
* `golden-ehtdh1` implements online encryption/decryption and consumes exactly one
  completed `[Random, Zero]` batch.

Keep protocol parsing and circuit gadgets private. Extend the proof interface,
not the fixed relation. Reuse native field/group operations and existing seams
before introducing wrappers or extra representations. Public identity comes from
configuration and ordered instance position, not proof implementation or capacity.

Applications own admission, broadcast agreement, authenticated approved-generator
storage, trusted completion provenance and activation. Engineering tests and
reviews do not replace the separate composition/security release approval.
