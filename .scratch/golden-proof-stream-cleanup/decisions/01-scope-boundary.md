# Keep the cleanup at the Golden proof-composition seam

**Blocked by:** None.

## Question

Is this a broad DKG/protocol redesign or a focused proof-representation cleanup?

## Resolution

Limit the PR to Golden proof composition. Preserve:

- current curve configurability and `GoldenGroup` model;
- current prototype and paper mathematical relations;
- current eVRF statements/witnesses, pad derivation, beta, hash inputs, dealer public fields, and receiver records;
- current DKG creation, verification, completion, transcript-root, and EHTDH production semantics;
- current `bulletproofs-cycle` implementation and typed `R1CSProof`.

Replace only Golden-level proof containers, parsing, framing, transcript composition, and generic proof-type propagation.

Golden proof bytes and Golden-level Fiat–Shamir challenges may change. The new stream must bind complete public statements correctly. No compatibility path is required because the crates are unpublished.

## Rejected alternatives

- Paper-alignment rewrite of group roles, beta, hashes, or broadcast records.
- DKG validated-state/output redesign.
- EHTDH setup redesign.
- Restoring the archived Bulletproofs-wide Proof Stream implementation now.

## Impact

- source-interface change;
- dealer-message wire-format change;
- proof-byte change;
- Golden-level Fiat–Shamir challenge change.

No intended DKG-output, EHTDH-material, or mathematical-relation change.
