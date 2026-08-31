# Migrate every Golden proof path

**Blocked by:** [Use one shared transcript for every Golden proof phase](04-shared-transcript.md).

## Question

Which proof paths adopt streams and which Golden proof types remain?

## Resolution

Migrate all three Golden proof paths in one PR:

1. prototype share-opening batch;
2. standalone one-receiver paper proof;
3. batched dealer paper proof used by DKG.

Remove Golden-level proof representations:

- `ShareOpeningProof`;
- `ShareOpeningBatchedProof`;
- `ChaumPedersenProof`;
- `DlogProof` as an envelope/storage type;
- `EvrfProofEnvelope`;
- `BatchedEvrfProofEnvelope`;
- `SecpSecqProof`;
- test fake proof container types.

Algebraic helper functions may remain private and return ordinary points/scalars needed to send stream messages. Direct proof-type wire, Serde, and Miden implementations disappear.

Keep:

- `EvrfStatement` and `EvrfWitness`;
- the current relation-building and verification equations;
- current R1CS constraint code;
- typed `R1CSProof` only inside the paper backend;
- typed IPP proof only inside the unchanged Bulletproofs implementation.

Migrating only the batched dealer path is rejected because it would leave most Golden proof types and would barely exercise stream challenges.
