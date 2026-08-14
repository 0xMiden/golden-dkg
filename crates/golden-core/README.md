# golden-core

Core traits and protocols for Golden distributed key generation.

This crate provides the curve independent DKG types, transcript binding,
secret sharing, commitments, and canonical wire encoding used by the
[Golden DKG](https://github.com/0xMiden/golden-dkg) workspace.

`DkgConfig::random` and `DkgConfig::zero` construct single-instance DKGs.
`DkgConfig::batch` accepts an arbitrary nonempty ordered `Vec<DkgInstanceKind>`
for mixed random and zero sharings. `create_dealing`
produces one dealer message containing all ordered dealings and one proof for
the complete batch.

`complete` verifies and aggregates the configured batch as one atomic unit. It
returns a `DkgOutput` whose `instances()` remain in configuration order, along
with configuration and completion roots binding the accepted batch; an error
is returned instead of a partial output if any dealing fails.
