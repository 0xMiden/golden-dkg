# 04 — Complete candidate sets atomically

**What to build:** Accept exactly one opaque candidate per configured dealer, validate and prove the complete set before decryption, and return one atomic participant-local DKG output.

**Blocked by:** 03 — Deal through opaque bytes.

**Status:** complete (`4ff9230`)

- [x] Private parsing derives every dimension and kind from the supplied configuration and rejects oversized, legacy, malformed, noncanonical, or trailing input.
- [x] Completion validates the candidate set and every public relation before proof parsing, then verifies all proofs before decrypting any share.
- [x] Batch fallback reports every invalid dealer canonically, preserves unexplained batch failure, and never converts operational errors into dealer blame.
- [x] Output contains the completing participant, ordered instances, configuration root, and a derived completion root over only the common public result.
