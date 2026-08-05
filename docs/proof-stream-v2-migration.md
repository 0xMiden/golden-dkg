# Proof Stream v2 migration

This change replaces Golden-level proof containers with one versioned, ordered proof stream and makes complete dealer messages the only persisted proof transport. Because `golden-core` and `golden-evrf` were published at 0.1.0, their breaking proof API migration is released as 0.2.0. The migration is atomic and intentionally has no v1 compatibility decoder.

## Interoperability vectors

The v2 proof bytes are pinned as checked-in binary fixtures:

| Protocol | Proof protocol identifier | Fixed fixture | Deterministic input |
|---|---|---|---|
| Prototype share opening | `golden-evrf/prototype-share-opening/v2` | `crates/golden-evrf/tests/vectors/prototype-share-opening-v2.bin` | P-256 four-participant DKG fixture, dealer 1, `ChaCha20Rng` seed `[10; 32]` |
| Standalone paper eVRF | `golden-paper-evrf-one-receiver-v2` | `crates/golden-evrf/tests/vectors/paper-one-receiver-v2.bin` | Secp/Secq one-receiver fixture, RNG seed `0xFEED`, message seed `0xCAFEBABE`, `beta = 0xBEE` |
| Batched paper dealer | `golden-paper-evrf-batched-v2` | `crates/golden-evrf/tests/vectors/paper-batched-dealer-v2.bin` | Secp/Secq one-slot batched fixture, RNG seed `0xBA7C_0002`, message seed `0xABCD`, `beta = 7` |

The corresponding tests pin proof bytes and transcript checkpoints:

- `prototype_dkg::deterministic_prototype_proof_stream_matches_v2_vector`
- `one_receiver::evrf_one_receiver_honest_proof_verifies`
- `paper::secp_secq::dkg_unit_tests::batched_stream_pins_statement_boundary_checkpoint`
- `batched_dealer::evrf_batched_dealer_matches_v2_vector`

The checkpoint tests also establish that the proof protocol identifier, complete public statement, operation labels, prior prover messages, and operation order affect challenges. The generic parser tests in `crates/golden-evrf/src/proof_stream.rs` pin role duality, canonical point/scalar parsing, explicit identity policy, every truncation boundary, checked nested lengths, transactional failures, wrong proof identifiers, malformed child frames, and exact completion without trailing bytes.

## Breaking-change classification

| Area | Impact |
|---|---|
| Source | `EvrfProofBackend` no longer has an associated proof type. `DealerMessage<G>` and `DkgDealing<G>` no longer carry a proof generic, and callers receive or pass borrowed opaque proof bytes. |
| Dealer message v2 | The dealer-message codec owns one length-delimited opaque proof payload. The old typed-proof field grammar and legacy decoder are removed. Persisted v1 dealer messages must be regenerated. |
| Proof v2 | Prototype, standalone paper, and batched paper proofs have new versioned identifiers, message schedules, and framing. V1 proof bytes are rejected. |
| Challenges | One Golden proof-stream transcript binds the proof identifier, complete statement observations, labels, prover messages, and operation order. Fiat–Shamir challenges and deterministic proof bytes therefore change. |
| Persistence | Standalone proof wire tags, Serde visitors, Miden adapters, and wrapper round trips are removed. A complete dealer message is the sole supported persistence unit for a DKG proof. |
| Migration | Producers, verifiers, persisted dealer messages, and deterministic fixtures must move to v2 atomically. There is no compatibility alias, default proof generic, dual decoder, or proof-version negotiation. |
| Interoperability | A producer and verifier interoperate only when they use the same v2 proof identifier, complete statement schedule, canonical curve encodings, child framing, and operation order. The checked-in vectors above are the compatibility contract. |

There is no intended change to the mathematical relations, Golden DKG state transitions, dealing roots, completion roots, DKG outputs, EHTDH1 setup roots, or EHTDH1 key material. Proof bytes remain excluded from dealing and completion roots: proof-only tampering preserves the existing roots but fails statement-aware public verification.

## Final deletion accounting

The migration removes the following Golden-level proof representations and persistence paths:

- Prototype `ShareOpeningProof`, `ShareOpeningBatchedProof`, and `ShareOpeningProofBytes` containers and receiver-indexed proof maps.
- Standalone `ChaumPedersenProof`, `DlogProof`, and `EvrfProofEnvelope` containers.
- Batched `BatchedEvrfProofEnvelope`, `SecpSecqProof`, and `SecpSecqProofBytes` wrappers.
- Core `FakeProof` and `FakeBatchedProof` test containers.
- Backend associated proof types, proof generic parameters/aliases, standalone proof codecs, and their Serde/Miden wrapper tests.
- Public `encode_proof` / `decode_proof` persistence helpers and legacy proof/dealer-message decoding paths.

What remains is intentionally narrower:

- Crate-private `ProverProofStream` and `VerifierProofStream` roles own transcript composition and byte parsing.
- Backend-private typed R1CS/inner-product values remain nested implementation details; they are not Golden storage or transport representations.
- `DealerMessage<G>::proof` is the sole Golden-level proof payload and is an opaque `Vec<u8>` interpreted only by the selected statement-aware backend.

No source under `crates/bulletproofs-cycle` is changed by this migration.
