# golden-curves

Proof-free native Secp256k1 and Jubjub identity/DH group adapters for Golden DKG.
No group is enabled by default.

| Feature | Adapter | Native scalar | Native point |
| --- | --- | --- | --- |
| `secp256k1` | `Secp256k1Group` | `halo2curves::secp256k1::Fq` | `halo2curves::secp256k1::Secp256k1` |
| `jubjub` | `JubjubGroup` | `jubjub::Fr` | `jubjub::SubgroupPoint` |

Both adapters implement the flat `golden_core::DkgGroup` interface: canonical
protocol codecs, native hash-to-point mappings, affine-coordinate extraction,
integer base-to-scalar reduction and fixed-base multiplication. Applications
use the native scalar and point arithmetic directly.

Scalars use canonical 32-byte little-endian integers. Secp256k1 nonidentity
points use compressed SEC1 bytes; its identity is exactly 33 zero bytes.
Jubjub uses its native 32-byte compressed encoding, including
`01 || 00*31` for identity. Decoding checks canonical representation and
prime-order subgroup membership without cofactor clearing. The Jubjub hash map
may clear the cofactor as part of hashing. Its affine x-coordinate is Edwards
`u`, with a little-endian base-field representation.

Native scalar values remain caller-owned. Secret-bearing protocol storage and
its cleanup belong to the higher-level crates.

This crate has no proof-system or BLS FFI dependency. Concrete outer proof
cycles, prepared generators and optimized proof MSM implementations belong to
`golden-bulletproofs`.
