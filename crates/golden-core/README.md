# golden-core

Core traits and protocols for Golden distributed key generation.

This crate provides the curve independent DKG types, transcript binding,
secret sharing, commitments, and canonical wire encoding used by the
[Golden DKG](https://github.com/0xMiden/golden-dkg) workspace.

`DkgConfig::new_random` and `DkgConfig::new_zero` construct single-instance
DKGs. `DkgConfig::new` accepts an arbitrary nonempty ordered
`Vec<DkgInstanceKind>` for mixed random and zero sharings. The free `deal`
function returns dealer-local `OwnDealing` state containing one bounded opaque
broadcast with all ordered instances and one proof for the complete batch. The
current `complete` function still accepts the legacy parsed-message types;
opaque-byte completion lands in the next migration slice.

That legacy `complete` path verifies and aggregates the configured batch as one
atomic unit. It returns a `DkgOutput` whose `instances()` remain in
configuration order, along with configuration and completion roots binding the
accepted batch; an error is returned instead of a partial output if any dealing
fails.
