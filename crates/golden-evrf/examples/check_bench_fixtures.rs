//! CI gate: every checked-in opaque dealer-message fixture must still
//! complete against the current protocol.
//!
//! Read-only and always runs `complete` with a restored matching `OwnDealing`
//! instead of trusting the `.sha256` sidecar. A missing, corrupt, stale, or
//! no-longer-completing fixture panics and fails the job rather than silently
//! re-proving. Always checks the full canonical shape set
//! (`NE_VALUES`/`N_VALUES`), ignoring the `GOLDEN_TABLE4_NE_VALUES` /
//! `GOLDEN_TABLE5_N_VALUES` env overrides, so CI covers every fixture the
//! benches rely on regardless of local dev settings.
//!
//! Regenerate anything this flags with:
//! ```bash
//! cargo run --profile optimized --example warm_bench_fixtures \
//!     --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel,golden-evrf/serde
//! ```

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[path = "../benches/support_dir/mod.rs"]
mod support;

use std::time::Instant;

use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use support::{build_config, NE_VALUES, N_VALUES, TABLE4_THRESHOLD};

fn check(table: &str, n: usize, t: usize) {
    let start = Instant::now();
    let config = build_config(n, t);
    let proof_system = SecpSecqBulletproofs::prepare_for(&config).unwrap();
    let message_count = support::validate_dealer_fixture(&config, &proof_system);
    println!(
        "{table}: t={t} n={n} -> {} messages completed in {:.1?}",
        message_count,
        start.elapsed()
    );
}

fn main() {
    println!("Checking Table 4 fixtures (threshold = {TABLE4_THRESHOLD})...");
    for &n_e in NE_VALUES {
        check("table-4", n_e + 1, TABLE4_THRESHOLD);
    }

    println!("Checking Table 5 fixtures ((n - 1)-of-n)...");
    for &n in N_VALUES {
        check("table-5", n, n - 1);
    }

    println!("All fixtures completed against the current protocol.");
}
