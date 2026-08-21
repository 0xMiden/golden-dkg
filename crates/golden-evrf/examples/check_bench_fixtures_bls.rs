//! CI gate: every checked-in BLS12-381/Jubjub dealer-message fixture must
//! still verify against the current protocol.
//!
//! Read-only, like `cached_dealer_messages` itself, and always re-runs
//! `verify_dealings` instead of trusting the `.sha256` sidecar — a missing,
//! corrupt, stale, or no-longer-verifying fixture panics and fails the job
//! rather than silently re-proving or trusting a stale-but-byte-identical
//! digest. Always checks the full canonical shape set
//! (`NE_VALUES`/`N_VALUES`), ignoring the `GOLDEN_BLS_TABLE4_NE_VALUES` /
//! `GOLDEN_BLS_TABLE5_N_VALUES` env overrides, so CI covers every fixture
//! the benches rely on regardless of local dev settings.
//!
//! Regenerate anything this flags with:
//! ```bash
//! cargo run --profile optimized --example warm_bench_fixtures_bls \
//!     --features golden-evrf/bls12-381-jubjub,golden-evrf/parallel
//! ```

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "../benches/bls_support_dir/mod.rs"]
mod support;

use std::time::Instant;

use support::{build_config, NE_VALUES, N_VALUES, TABLE4_THRESHOLD};

fn check(table: &str, n: usize, t: usize) {
    let start = Instant::now();
    let config = build_config(n, t);
    let messages = support::verify_dealer_messages(&config);
    println!(
        "{table}: t={t} n={n} -> {} messages verified in {:.1?}",
        messages.len(),
        start.elapsed()
    );
}

fn main() {
    println!("Checking Table 4 fixtures (threshold = {TABLE4_THRESHOLD})...");
    for &n_e in NE_VALUES {
        check("table-4", n_e + 1, TABLE4_THRESHOLD);
    }

    println!("Checking Table 5 fixtures (n-of-n)...");
    for &n in N_VALUES {
        check("table-5", n, n - 1);
    }

    println!("All fixtures verified against the current protocol.");
}
