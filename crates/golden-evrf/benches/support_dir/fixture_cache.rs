//! Checked-in dealer-message fixtures shared across benches.
//!
//! Building `n` real dealer proofs is pure benchmark-harness cost, not what
//! `evrf_verify`, `dkg_round`, `evrf_proof_size`, or `dkg_communication`
//! measure. This module reads those `n` messages for a `(threshold, n)`
//! shape from `benches/fixtures/dealer-messages/` (wire-codec encoded and
//! git-tracked), so the cost is paid once and shared via git history.
//!
//! [`cached_dealer_messages`] (used by the benches) is read-only: a missing,
//! corrupt, or stale (fails `verify_dealings` against the current config)
//! fixture is a hard error with instructions to regenerate, never a silent
//! rebuild — a bench run should not be able to paper over a real bug by
//! quietly re-proving a fixture that no longer matches the code under test.
//!
//! [`regenerate_dealer_messages`] (used by the `warm_bench_fixtures`
//! example, the only place that writes) rebuilds and overwrites a fixture
//! in place when it is missing or invalid, and leaves it untouched
//! otherwise, so a `cargo run --example warm_bench_fixtures` after a code
//! change replaces just the fixtures whose proof bytes actually moved
//! instead of piling up new files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use golden_core::wire::{from_wire_bytes, to_wire_bytes};
use golden_core::{create_dealing, verify_dealings, DealerMessage, DkgConfig, ParticipantIndex};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use super::{identity_secret, BENCH_SEED};

/// The command printed in panic/log messages so a stale or missing fixture
/// tells the reader exactly how to fix it.
const REGENERATE_HINT: &str = "cargo run --profile optimized --example warm_bench_fixtures \
    --features golden-evrf/halo2curves-secp256k1,golden-evrf/parallel";

fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures/dealer-messages")
}

fn cache_path(threshold: usize, n: usize) -> PathBuf {
    cache_dir().join(format!("t{threshold}-n{n}.bin"))
}

/// Build all `n` dealer messages for `config` from scratch, sequentially
/// consuming one seeded RNG in registry order (dealer 1, 2, ..., n).
fn build_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> Vec<DealerMessage<Secp256k1GoldenGroup>> {
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    config
        .registry
        .indexes()
        .map(|dealer| {
            create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                config,
                &mut rng,
            )
            .unwrap()
            .message
        })
        .collect()
}

fn write_cache(path: &Path, messages: &[DealerMessage<Secp256k1GoldenGroup>]) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&(messages.len() as u32).to_le_bytes());
    for message in messages {
        let encoded = to_wire_bytes(message);
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
    }
    // Write-then-rename so a crash never leaves a partially written file at
    // the tracked path (which `git status` would otherwise flag as dirty).
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &buf)?;
    fs::rename(&tmp_path, path)
}

/// Decode a cache file. Returns `None` on any structural problem (missing
/// file, truncated length prefixes, trailing bytes, bad wire encoding).
fn read_cache(path: &Path) -> Option<Vec<DealerMessage<Secp256k1GoldenGroup>>> {
    let buf = fs::read(path).ok()?;
    let count = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    let mut offset = 4;
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_le_bytes(buf.get(offset..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        let encoded = buf.get(offset..offset + len)?;
        offset += len;
        messages.push(from_wire_bytes(encoded).ok()?);
    }
    (offset == buf.len()).then_some(messages)
}

/// Load `path` and check it decodes to exactly `n` messages that verify
/// against `config`. `None` covers every way a fixture can be unusable:
/// missing, truncated, wrong count, or cryptographically invalid/stale.
fn load_valid(
    path: &Path,
    config: &DkgConfig<Secp256k1GoldenGroup>,
    n: usize,
) -> Option<BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>>> {
    let messages = read_cache(path)?;
    if messages.len() != n {
        return None;
    }
    let refs: Vec<_> = messages.iter().collect();
    verify_dealings::<Secp256k1GoldenGroup, SecpSecqBackend>(&refs, config)
        .ok()
        .map(|()| messages.into_iter().map(|m| (m.dealer, m)).collect())
}

/// Return all `n` dealer messages for `config`, loaded from the checked-in
/// fixture at `benches/fixtures/dealer-messages/t{threshold}-n{n}.bin`.
///
/// Panics if the fixture is missing, corrupt, or no longer verifies against
/// `config` (e.g. the wire format or protocol changed) — callers regenerate
/// explicitly with the `warm_bench_fixtures` example rather than have this
/// silently re-prove and potentially mask a real regression.
pub fn cached_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>> {
    let n = config.registry.indexes().count();
    let path = cache_path(config.threshold, n);
    let message = format!(
        "bench fixture missing or invalid at {}\n\
         Regenerate it with:\n  {REGENERATE_HINT}\n\
         then `git add` and commit the result.",
        path.display()
    );
    load_valid(&path, config, n).expect(&message)
}

/// (Re)build the fixture for `config` and overwrite it on disk, but only if
/// the tracked file is missing or no longer valid. Returns `true` if it was
/// rebuilt, `false` if the existing fixture was already up to date.
pub fn regenerate_dealer_messages(config: &DkgConfig<Secp256k1GoldenGroup>) -> bool {
    let n = config.registry.indexes().count();
    let path = cache_path(config.threshold, n);
    if load_valid(&path, config, n).is_some() {
        return false;
    }
    let messages = build_dealer_messages(config);
    let message = format!("failed to write bench fixture at {}", path.display());
    write_cache(&path, &messages).expect(&message);
    true
}

/// Build the setup for one participant's Round 1: its own full dealing
/// (message plus `private_share`, which cannot be cached because it is
/// never put on the wire) alongside every peer's fixture message.
///
/// Only `receiver`'s dealing is proved fresh; the other `n - 1` messages
/// come from [`cached_dealer_messages`].
pub fn cached_round1_setup(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    receiver: ParticipantIndex,
) -> (
    golden_core::DkgDealing<Secp256k1GoldenGroup>,
    BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>>,
) {
    let mut peer_messages = cached_dealer_messages(config);
    peer_messages.remove(&receiver);

    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    let own_dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
        receiver,
        &identity_secret(receiver),
        config,
        &mut rng,
    )
    .unwrap();

    (own_dealing, peer_messages)
}
