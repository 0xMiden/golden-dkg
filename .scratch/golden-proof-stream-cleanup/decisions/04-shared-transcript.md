# Use one shared transcript for every Golden proof phase

**Blocked by:** [Make the stream curve-aware](03-curve-aware-stream.md).

## Question

How are Golden proof phases composed and bound after proof envelopes disappear?

## Resolution

Each Golden proof stream owns one Merlin transcript initialized by its versioned `PROOF_ID`.

Composition rules:

1. Verify/read the proof-ID header.
2. Observe the complete canonical public statement before any prover message.
3. Execute every Golden proof phase sequentially against the same transcript.
4. `send`/`receive` serialize/parse and absorb each accepted prover message exactly once.
5. `challenge` depends on the proof ID, complete statement, and all prior accepted messages.
6. `finish` rejects unread trailing bytes.

For the standalone paper relation, Chaum–Pedersen, nested R1CS, and DLOG run sequentially in one transcript rather than separate envelope transcripts.

For the batched dealer relation, preserve the current complete ordered batch-statement observation schedule, then execute the current R1CS child against the shared transcript.

For the prototype relation, observe the canonical statement list and stream each receiver’s nonce commitments, challenge, and responses in statement order.

The nested R1CS child receives the same mutable Merlin transcript. Its typed proof payload is length-framed into the parent stream without absorbing the raw frame a second time, because the current R1CS prover/verifier already absorbs its semantic commitments/messages and challenges.

This intentionally changes Golden proof bytes and Golden-level Fiat–Shamir challenge sequencing. New proof IDs and deterministic transcript vectors are required. Mathematical equations remain unchanged.

## Evidence

- Merlin transcript framing/composition: `merlin-transcript-protocol`, p. 1.
- Multi-round Fiat–Shamir prefix ordering: `2023-ganesh-et-al-fiat-shamir-bulletproofs-nonmalleable`, PDF pp. 15–16.
- Archived paired-role idea: `589204d:crates/bulletproofs-cycle/src/proof_stream.rs`.
