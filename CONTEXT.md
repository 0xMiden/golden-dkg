# Golden

This workspace is for a minimal, paper-aligned Golden DKG implementation.

Avoid bespoke non-native arithmetic until a working Bulletproofs curve-pair port
shows that it is unavoidable. The tree supports Secp256k1/Secq256k1 and
BLS12-381 G1/Jubjub.

Keep only code that supports one of these jobs:

* DKG message plumbing from the Golden paper.
* A transcript-bound Schnorr/Chaum-Pedersen prototype that keeps plumbing tests alive.
* The concrete `bulletproofs-cycle` port. Secp/Secq support lives in
  `golden-halo2curves`, while BLS12-381/Jubjub support lives in
  `golden-bls-jubjub`.
* A Golden eVRF backend built on one of those ports (`golden-evrf::paper::secp_secq`, `golden-evrf::paper::bls_jubjub`).

`golden-rustcrypto` supplies the RustCrypto P-256/secp256k1 group and field
backends used by the prototype and plumbing tests. It remains until the paper
eVRF backends replace the prototype entirely.

Release gates and measurements can come back after the paper eVRF proofs verify
end to end. Fuzzing and FROST work are deferred too. Additional curve-pair
adapters have the same status. The existing `golden-halo2curves` and
`golden-bls-jubjub` adapters are exempt.
