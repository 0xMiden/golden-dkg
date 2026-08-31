# Golden

This workspace is for a minimal, paper-aligned Golden DKG implementation.

Current rule: do not build bespoke non-native arithmetic unless a working Bulletproofs-on-curve-cycle port first proves that it is unavoidable. Two curve cycles are in tree: `halo2curves::secp256k1` / `halo2curves::secq256k1`, and BLS12-381 G1 / Jubjub.

Keep only code that supports one of these jobs:

* DKG message plumbing from the Golden paper.
* A prototype proof backend used to keep plumbing tests alive. The prototype is a real transcript-bound Schnorr/Chaum-Pedersen backend, not a stub; it stands in for the paper eVRF proof.
* A concrete Bulletproofs curve-cycle port (`bulletproofs-cycle` plus the `golden-halo2curves` Secp/Secq adapter and the `golden-bls-jubjub` BLS12-381/Jubjub adapter).
* A Golden eVRF backend built on one of those ports (`golden-evrf::paper::secp_secq`, `golden-evrf::paper::bls_jubjub`).

`golden-rustcrypto` supplies the RustCrypto P-256/secp256k1 group and field backends the prototype and plumbing tests depend on; it is kept until the paper eVRF backends replace the prototype entirely.

Release gates, measurements, fuzzing, FROST, and further curve-cycle adapters beyond Secp/Secq and BLS12-381/Jubjub can come back after the paper eVRF proofs verify end to end. The `golden-halo2curves` Secp/Secq adapter and the `golden-bls-jubjub` BLS12-381/Jubjub adapter are already in tree and exempt from this deferral.
