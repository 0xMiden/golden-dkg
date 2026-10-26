# golden-core

Curve-independent Golden distributed key generation using native `ff` and
`group` arithmetic, opaque broadcasts, and an explicitly injected proof system.
Concrete curves live in `golden-curves`; Bulletproof implementations and their
prepared generators live in `golden-bulletproofs`.

## Public workflow

Build a `ParticipantRegistry<G>` and an immutable
`DkgConfig::new(threshold, session_id, registry, ordered_kinds)`. Each instance is
`DkgInstanceKind::Random` or `DkgInstanceKind::Zero`. Random samples every
polynomial coefficient, including a possibly zero constant. Zero fixes the
constant to zero. Instance positions are zero-based; repeated kinds are valid.

Every registered participant contributes as a dealer. The threshold controls
reconstruction; completion requires all registered dealers.

| Operation | Input and result |
| --- | --- |
| `deal` | Borrows the proof system, configuration, identity secret and RNG; returns `OwnDealing<G>`. |
| `verify_dealer_message` | Checks opaque bytes against an expected dealer. |
| `verify_dealer_messages` | Checks a nonempty partial or full board. |
| `aggregate_public` | Checks a full board and returns `DkgPublicOutput<G>` without credentials. |
| `complete` | Borrows own state and exactly the other dealers' messages; returns `DkgOutput<G>` atomically. |

Transport input uses `DealerMessageRef { expected_dealer, bytes }` with borrowed
bytes. `OwnDealing::broadcast_bytes()` exposes the exact outgoing broadcast;
parsing stays private. Own state is cloneable and can be reused after a rejected
candidate set.

Public validation covers every candidate before proof interpretation. Invalid
public messages and invalid proofs identify all offending dealers in canonical
order. Operational errors carry no dealer blame. The whole broadcast limit is
16 MiB, exposed by `max_dealer_message_bytes()`.

`DkgPublicOutput::instance(position)` and `instances()` expose immutable public
results. `DkgOutput::public()` borrows those results and
`secret_share(position)` borrows a native local scalar. Secret-bearing outputs
and proof witnesses are not cloneable. Equal public results under one
configuration have the same completion root, independently of participant,
proof bytes, proof implementation, or generator capacity. That root does not
establish authenticated agreement or activation.

## Algebra, proof extension and storage

Public scalar-generic Shamir and Feldman utilities retain validated mathematical
constructors. They do not construct protocol outputs or override a configured
Random policy. `DealerProofSystem<G>` supplies proofs for core's fixed Main Golden
relation through immutable core-constructed inputs with read-only getters.

Byte persistence is separate from broadcast encoding. Restore own/local state
with the expected configuration and participant; restore public outputs with the
expected configuration. Explicit snapshot types provide Serde and
`miden-serde-utils` adapters. Restored outputs require authenticated storage with
trusted completion provenance; untrusted imports must replay a complete board.

Owned secret storage has redacted diagnostics and cleanup on normal drop. This
does not erase every arithmetic temporary, caller-created copy, or
application-owned serialized buffer.

The non-default `insecure-revealed-witness` feature exposes an exact native
relation checker as a transport/testing proof. Its broadcasts reveal identity
secrets, shares and pads. Use disposable identities only.

Protocol, broadcast and persistence versions make a hard compatibility cut;
legacy artifacts are not accepted. See the [workspace](https://github.com/0xMiden/golden-dkg)
for the complete design and security review requirements.
