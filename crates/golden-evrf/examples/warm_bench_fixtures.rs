//! Pre-populate (or refresh) the on-disk dealer-message fixture cache used
//! by the `golden-evrf` benches, without paying criterion's sampling
//! overhead on top of the proof-building cost.
//!
//! See `benches/support_dir/fixture_cache.rs` for the cache itself: it is
//! keyed on `(threshold, n, BENCH_SEED, FORMAT_VERSION)` and lives under
//! `target/bench-fixtures/dealer-messages/`. `evrf_verify`, `evrf_proof_size`,
//! `dkg_communication`, and `dkg_round` all read from it, so running this
//! once ahead of time means every later `cargo bench` invocation loads
//! dealer messages from disk instead of re-proving them.
//!
//! ```bash
//! cargo run --profile optimized --example warm_bench_fixtures \
//!     --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel
//! ```
//!
//! `GOLDEN_TABLE4_NE_VALUES` / `GOLDEN_TABLE5_N_VALUES` select a
//! comma-separated subset, matching the bench harness's own env vars. A
//! cache entry already on disk and valid against `verify_dealings` is left
//! alone; delete `target/bench-fixtures/` first to force a full rebuild.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "../benches/support_dir/mod.rs"]
mod support;

use std::time::Instant;

use support::{build_config, table4_ne_values, table5_n_values, TABLE4_THRESHOLD};

fn warm(table: &str, n: usize, t: usize) {
    let start = Instant::now();
    let config = build_config(n, t);
    let count = support::cached_dealer_messages(&config).len();
    println!(
        "{table}: t={t} n={n} -> {count} dealer messages ready in {:.1?}",
        start.elapsed()
    );
}

fn main() {
    println!("Warming Table 4 fixtures (threshold = {TABLE4_THRESHOLD})...");
    for n_e in table4_ne_values() {
        warm("table-4", n_e + 1, TABLE4_THRESHOLD);
    }

    println!("Warming Table 5 fixtures (n-of-n)...");
    for n in table5_n_values() {
        warm("table-5", n, n - 1);
    }

    println!("Done.");
}
