# bulletproofs-cycle

Generic Bulletproofs R1CS and inner-product proofs through the `Cycle` trait.
Concrete Golden commitment cycles live in `golden-bulletproofs`.

Generator prefixes are explicitly owned. `BulletproofGens::new` expands a prefix;
clones share immutable backing storage. There is no process-wide generator cache.
`from_prefixes` imports canonical, subgroup-checked, nonidentity bases without
regeneration. Applications must authenticate approved generation: structurally
valid points do not establish safe generator provenance. Serialization emits
exactly the declared prefixes, regardless of a larger backing allocation.

The default `cycle-pedersen` and `bulletproofs-compat` features are mutually
exclusive. The latter tests Ristretto byte parity against upstream Bulletproofs:

```sh
cargo nextest run -p bulletproofs-cycle --features ristretto,serde
cargo nextest run -p bulletproofs-cycle --no-default-features --features bulletproofs-compat
```

Optional `parallel` enables the engine's parallel arithmetic. `serde` persists
native engine prefixes; Golden's versioned typed artifacts provide the concrete
protocol/group/proof-family binding.
