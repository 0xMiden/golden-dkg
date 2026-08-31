//! Regenerate the checked-in opaque dealer-message fixtures used by the
//! `golden-evrf` benches (see `benches/support_dir/fixture_cache.rs`),
//! without paying criterion's sampling overhead on top of the
//! proof-building cost.
//!
//! This is the only place that writes a fixture: an already-valid one is
//! left untouched, so running this after a proof-byte-changing edit
//! replaces just the fixtures that moved instead of piling up new files.
//!
//! ```bash
//! cargo run --profile optimized --example warm_bench_fixtures \
//!     --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel,golden-evrf/serde
//! ```
//!
//! `GOLDEN_TABLE4_NE_VALUES` / `GOLDEN_TABLE5_N_VALUES` select a
//! comma-separated subset, matching the bench harness's own env vars.
//! Review and commit whatever this rewrites under `benches/fixtures/`.

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "../benches/support_dir/mod.rs"]
mod support;

use std::time::Instant;

use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use support::{build_config, table4_ne_values, table5_n_values, TABLE4_THRESHOLD};

fn warm(table: &str, n: usize, t: usize) {
    let start = Instant::now();
    let config = build_config(n, t);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let rebuilt = support::regenerate_dealer_messages(&config, &proof_system);
    let status = if rebuilt { "regenerated" } else { "up to date" };
    println!(
        "{table}: t={t} n={n} -> {status} in {:.1?}",
        start.elapsed()
    );
}

fn main() {
    println!("Checking Table 4 fixtures (threshold = {TABLE4_THRESHOLD})...");
    for n_e in table4_ne_values() {
        warm("table-4", n_e + 1, TABLE4_THRESHOLD);
    }

    println!("Checking Table 5 fixtures ((n - 1)-of-n)...");
    for n in table5_n_values() {
        warm("table-5", n, n - 1);
    }

    println!("Done. If anything was regenerated, `git add` and commit benches/fixtures/.");
}
