# golden-evrf

Main Golden proof systems for distributed key generation.

`SecpSecqBulletproofs` implements the stateful `DealerProofSystem` seam over the
Secp256k1/Secq256k1 cycle. Construct it with `prepare_for` or restore an
authenticated `SecpSecqPreparedGenerators` artifact, then pass the same proof
system to `golden_core::deal` and `golden_core::complete`. Dealer messages stay
opaque; this crate exports no parsed-message or standalone verification path.

One proof covers the complete ordered configuration and canonical receiver
order. The circuit and native checker derive one protocol-wide beta without
bias in the full curve base field from the fixed string
`golden-dkg/main-golden-beta/v1`. Sampling admits zero, and the value is the
same for every session under this protocol version; it is not caller input,
configuration-derived state, a setup identifier, or persistent state. H1/H2
bind the effective message and canonically ordered identity-key pair using
lexicographic canonical compressed encoding.

Main Golden's security scope is static corruption of at most `t - 1`
participants in the ideal eVRF/ZK hybrid and random-oracle setting, with a
consistent authenticated registry/setup, authenticated broadcast semantics,
and the paper's additive-bias key-generation functionality. It does not claim
adaptive security, fully unbiased key generation, or security with aborts. The
authenticated deployment process admitting a registry entry is assumed to
have established knowledge of its identity secret.

Random and Zero instances may be composed in any nonempty order. That joint
composition is a repository extension, is not attributed directly to Golden
Theorem 3, and requires its dedicated composition review before a production
security claim or release. That review does not reopen the fixed-beta
instantiation.

The `insecure-revealed-witness` feature exposes a native-conformance proof for
tests. It reveals the witness and is not a production proof system.

Prepared-generator persistence is an application artifact, not protocol wire
format. Restoration validates its version, curve identity, canonical points,
declared capacity, and exact logical prefix length, but does not rederive the
points. Callers must authenticate the bytes before restoration.
