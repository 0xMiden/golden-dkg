# Golden

This workspace is for a minimal, paper-aligned Golden DKG implementation.

Current rule: do not build bespoke non-native arithmetic unless a working Bulletproofs-on-curve-cycle port first proves that it is unavoidable. The first target is a zkcrypto-compatible Bulletproofs variant over `halo2curves::secp256k1` / `halo2curves::secq256k1`.

Keep only code that supports one of these jobs:

* DKG message plumbing from the Golden paper.
* Test proof implementations used to exercise DKG and EHTDH1 plumbing. They are explicit test infrastructure and make no production security claim.
* A concrete Bulletproofs curve-cycle port (`bulletproofs-cycle` plus the `golden-halo2curves` Secp/Secq adapter).
* Concrete proof systems for the fixed Main Golden dealer relation, including the Secp/Secq Bulletproof implementation in `golden-evrf::paper`.

`golden-rustcrypto` supplies RustCrypto P-256/secp256k1 group and field adapters used by comparison and plumbing tests.

Release gates, measurements, fuzzing, FROST, and further curve-cycle adapters beyond Secp/Secq can come back after the first paper eVRF proof verifies end to end. The `golden-halo2curves` Secp/Secq adapter needed for the first target is already in tree and exempt from this deferral.

## Language

**DKG session**:
The execution context defined by one immutable DKG configuration. Every dealer message, own dealing, and DKG output belongs to exactly one session; the proof system that validates a dealing is not part of the session's public-result identity.
_Avoid_: Deployment ceremony, network session

**DKG configuration**:
The immutable public inputs that determine one DKG session: its session identifier, participant registry, threshold, and ordered Random/Zero instance policy. Values derived canonically from those inputs, including the Main Golden universal-hash coefficient, are not separate configuration inputs.
_Avoid_: Ceremony manifest, validator set

**Participant registry**:
The validated, canonically ordered mapping from participant indexes to Golden identity public keys. Its root identifies the participant set and is incorporated into the DKG configuration identity.
_Avoid_: Validator set, participant list

**Dealer-proof relation**:
The fixed Main Golden statement that a dealer proves for its complete contribution, including the protocol-defined receiver-pad evaluation. Polynomial coefficients are sampled according to the configured Random/Zero instance kinds; deriving coefficients through a VRF is not a supported policy.
_Avoid_: Appendix K policy, coefficient policy

**Golden curve**:
A supported prime-order curve together with the hash-to-group and field-coordinate capabilities required to instantiate the fixed Main Golden receiver-pad relation. Selecting a Golden curve does not select a different relation or proof system.
_Avoid_: Main Golden curve, eVRF curve, proof curve

**Dealer-proof system**:
A concrete proof system for the dealer-proof relation over a supported curve. Proof systems may differ without changing the identity of an otherwise identical DKG configuration or public result; test proof systems may reveal witnesses and make no production security claim.
_Avoid_: DKG policy, protocol version

**Dealer message**:
A dealer's broadcast contribution to one configured DKG session. It is protocol input whose meaning and validity depend on that session, rather than a standalone application value.
_Avoid_: Decoded dealer message, message object

**Transport envelope**:
Deployment metadata accompanying opaque protocol input for routing and admission. It is not part of the Golden statement and is not trusted as evidence of protocol validity.
_Avoid_: Protocol envelope, authenticated dealer message

**Transport identity**:
A deployment-layer identity authenticated by the transport and used for admission and abuse controls. It is distinct from a participant's Golden identity key and participant index.
_Avoid_: Dealer identity, DKG identity

**Expected dealer**:
The participant slot that a caller expects opaque dealer-message bytes to represent. Golden checks this routing claim against the dealer encoded and proven by the protocol input; the claim is not itself evidence of validity.
_Avoid_: Sender, authenticated dealer

**Own dealing**:
The participant-local state produced when acting as a dealer, pairing the outbound dealer message with the private shares needed for completion. It belongs to one participant and one configured DKG session and may be persisted and restored by the application.
_Avoid_: Local message, DKG dealing

**Random instance**:
A DKG sharing whose polynomial constant is independently sampled. The sampled constant may itself be zero.
_Avoid_: Nonzero instance

**Zero instance**:
A DKG sharing whose polynomial constant is fixed to zero while its nonconstant coefficients remain independently random. Its participant shares are generally nonzero.
_Avoid_: Zero polynomial, zero shares

**Dealer message set**:
The complete collection containing exactly one candidate dealer message for every participant in a configured DKG session. Golden accepts or rejects the collection atomically.
_Avoid_: Message batch, accepted messages

**DKG output**:
The participant-local cryptographic result of successfully completing one dealer message set. It contains that participant's secret shares and the common public results, may be persisted and restored by the application, and represents Golden completion but not deployment agreement or activation.
_Avoid_: Accepted output, finalized deployment state

**Completion root**:
The identifier of the common public DKG result under one configuration, derived from its ordered aggregate public keys and participant public-key shares. It excludes participant-local secrets, dealer messages, proofs, and proof-system identity.
_Avoid_: Dealer transcript root, board root, proof root
