# Issue #72: measured joint dealer proofs

Observed 2026-10-26 on Apple M5 Max (18 logical CPUs, 64 GiB), macOS/aarch64,
Rust 1.99.0, release profile, both backends with `parallel,serde` enabled. Source:
`PENDING_SOURCE_COMMIT`, based on post-#71 `f338f38`.

Each row is the median of three fresh processes. Peak RSS is the maximum of
those processes, measured with macOS `/usr/bin/time -l` (bytes converted to MiB).
These are local observations, not portable performance guarantees. Raw samples
and environment metadata are in [issue-72.json](issue-72.json).

The baseline retains the original ladder formulas and reuses each receiver's
DH/reduction across sharings, matching the premise of the issue's analytical
projections. Every case has one Random and one Zero sharing. ECIP keeps all
terminal pad checks separate. The projections are not substituted for these
actual measurements.

## Circuit size and process memory

| Curve | t/n | Engine | Slots | Padded capacity | Dealer proof bytes | Peak RSS MiB |
|---|---:|---|---:|---:|---:|---:|
| Secp/Secq | 2/3 | ladder | 14,455 | 16,384 | 1,468 | 78.3 |
| Secp/Secq | 2/3 | ecip | 6,812 | 8,192 | 1,501 | 32.3 |
| Secp/Secq | 3/3 | ladder | 14,455 | 16,384 | 1,468 | 79.9 |
| Secp/Secq | 3/3 | ecip | 6,812 | 8,192 | 1,501 | 32.6 |
| Secp/Secq | 3/5 | ladder | 27,683 | 32,768 | 1,534 | 128.1 |
| Secp/Secq | 3/5 | ecip | 12,907 | 16,384 | 1,567 | 57.8 |
| Secp/Secq | 5/10 | ladder | 60,753 | 65,536 | 1,600 | 268.8 |
| Secp/Secq | 5/10 | ecip | 28,143 | 32,768 | 1,633 | 108.8 |
| Jubjub/BLS | 2/3 | ladder | 17,279 | 32,768 | 2,110 | 111.5 |
| Jubjub/BLS | 2/3 | ecip | 6,816 | 8,192 | 2,062 | 35.0 |
| Jubjub/BLS | 3/3 | ladder | 17,279 | 32,768 | 2,110 | 110.7 |
| Jubjub/BLS | 3/3 | ecip | 6,816 | 8,192 | 2,062 | 36.5 |
| Jubjub/BLS | 3/5 | ladder | 33,146 | 65,536 | 2,206 | 195.1 |
| Jubjub/BLS | 3/5 | ecip | 12,920 | 16,384 | 2,158 | 69.9 |
| Jubjub/BLS | 5/10 | ladder | 72,813 | 131,072 | 2,302 | 352.4 |
| Jubjub/BLS | 5/10 | ecip | 28,178 | 32,768 | 2,254 | 120.0 |

ECIP reduces actual slots by 52.9–53.7% for Secp and 60.6–61.3% for Jubjub in
these shapes. Padded capacity is half and one quarter of the respective ladder
baseline. Secp proofs are 33 bytes larger; Jubjub proofs are 48 bytes smaller.
The three extra phase-two commitments offset some or all inner-product savings.
Threshold affects public Feldman work rather than this R1CS shape, so 2/3 and
3/3 have identical slot counts.

## Stage timings

All times are milliseconds. Preparation includes layout synthesis and immutable
generator-prefix generation. Witness/build includes the native dealer relation
check, public hash-base/table construction, native witness generation and phase-one
R1CS construction. Proving includes the post-commitment challenge and phase-two
witness work, Bulletproofs generation, framing and Random constant-opening proof.
Verification includes transcript reconstruction, public tables, capacity/layout
checks, R1CS equation verification and constant-opening verification. Its prepared
object already has the measured shape cache, as in normal freshly prepared use.
A restored object pays one layout calculation at first use.

“Deal + check” times production core `deal` through the profiling adapter and one
explicit proof verification. It is a complete single-dealer observation, not a
full all-dealer DKG/completion benchmark. The adapter uses the same successful
capacity, phase-parity, framing, canonical parsing and batch-seeded verification
checks as production. Individual stage medians need not sum to the total median.

| Curve | t/n | Engine | Prepare | Witness/build | Prove | Verify | Deal + check |
|---|---:|---|---:|---:|---:|---:|---:|
| Secp/Secq | 2/3 | ladder | 69.3 | 15.6 | 230.4 | 30.1 | 277.7 |
| Secp/Secq | 2/3 | ecip | 36.0 | 20.9 | 135.3 | 17.5 | 175.9 |
| Secp/Secq | 3/3 | ladder | 68.7 | 16.1 | 252.7 | 31.0 | 311.9 |
| Secp/Secq | 3/3 | ecip | 46.4 | 22.4 | 166.0 | 22.7 | 213.3 |
| Secp/Secq | 3/5 | ladder | 154.1 | 34.5 | 515.2 | 65.6 | 624.1 |
| Secp/Secq | 3/5 | ecip | 82.3 | 43.7 | 302.8 | 41.5 | 393.4 |
| Secp/Secq | 5/10 | ladder | 307.5 | 78.6 | 1029.4 | 128.0 | 1247.3 |
| Secp/Secq | 5/10 | ecip | 161.1 | 95.0 | 540.0 | 73.0 | 712.0 |
| Jubjub/BLS | 2/3 | ladder | 196.9 | 7.4 | 362.2 | 44.6 | 413.3 |
| Jubjub/BLS | 2/3 | ecip | 55.1 | 29.4 | 135.4 | 23.0 | 191.4 |
| Jubjub/BLS | 3/3 | ladder | 174.5 | 8.2 | 374.7 | 43.3 | 428.5 |
| Jubjub/BLS | 3/3 | ecip | 54.8 | 30.4 | 145.3 | 23.3 | 201.1 |
| Jubjub/BLS | 3/5 | ladder | 390.8 | 16.4 | 706.2 | 84.8 | 812.8 |
| Jubjub/BLS | 3/5 | ecip | 100.9 | 59.5 | 233.1 | 40.9 | 338.4 |
| Jubjub/BLS | 5/10 | ladder | 842.1 | 37.1 | 1411.8 | 174.6 | 1632.1 |
| Jubjub/BLS | 5/10 | ecip | 209.6 | 117.3 | 359.0 | 78.3 | 564.1 |

Native witness/build time remains higher with ECIP, while preparation, proving,
verification and total dealer time improve in every measured shape. The quadratic
chord-product witness algorithm and one hashed shift generator per public base
are material: the earlier cubic prototype-based witness path reduced slots but
regressed total latency. Those intermediate observations are not used in the
final tables.

## Reproduction

On AC power, build the ignored profiling tests:

```sh
cargo nextest run --release -p golden-bulletproofs --all-features --no-run
```

Run the resulting `golden_bulletproofs-*` unit-test binary directly so the memory
meter measures only the fresh test process. For example:

```sh
GOLDEN_PROFILE_N=3 GOLDEN_PROFILE_T=2 GOLDEN_PROFILE_ENGINE=ecip \
  /usr/bin/time -l <test-binary> --ignored --exact \
  driver::profile::profile_secp --nocapture --test-threads=1
```

Use `GOLDEN_PROFILE_ENGINE=ladder` for the baseline, `profile_jubjub` for the other
curve, and `(N,T)=(3,2),(3,3),(5,3),(10,5)` for the cases above. Repeat each
combination in three fresh processes. No other compilation/testing ran during
measurement. The macOS meter reports RSS bytes; Linux meter units differ.

Terminal folding remains disabled. No field-sum proxy, unchecked integer carry
path or unreviewed terminal-batching speedup is included. Engineering validation
does not grant the separate final composition/security release approval.
