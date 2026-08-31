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
free `complete` function accepts the expected dealer index plus opaque bytes for
each peer; no parsed dealer-message or standalone verification API is exposed.

Completion validates every public relation before proof verification, accepts
every proof before decryption, and aggregates the configured batch as one
atomic unit. It returns a `DkgOutput` whose `instances()` remain in
configuration order, along with configuration and derived completion roots; an
error is returned instead of a partial output if any candidate fails.

Main Golden derives one protocol-wide full-base-field beta without bias from
the fixed string `golden-dkg/main-golden-beta/v1`. Sampling admits zero, and
the value is the same for every session under this protocol version: it is not
caller input, configuration-derived state, a setup identifier, or persisted
configuration. Its H1/H2 inputs bind the effective message and the identity-key
pair ordered lexicographically by canonical compressed encoding. The
authenticated deployment process admitting a registry entry is assumed to
establish that the participant knows its identity secret. Core validates
unique, canonical, nonidentity public keys and binds proofs to them, but carries
no separate identity-key proof-of-knowledge artifact.

Arbitrary nonempty ordered Random/Zero batches are a repository extension, not
something attributed directly to Golden Theorem 3. A dedicated composition
review remains a release and production-security-claim gate.

`ParticipantRegistry`, `DkgConfig`, `OwnDealing`, and completed outputs support
direct application persistence with the `serde` and `miden-serde` features.
These forms are distinct from protocol wire bytes, rebuild cached invariants on
restore, and must be authenticated by the deployment before restoration.
