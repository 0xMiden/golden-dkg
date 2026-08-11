//! Disk cache for dealer-message fixtures shared across benches.
//!
//! Building `n` real dealer proofs is pure benchmark-harness cost, not what
//! `evrf_verify`, `dkg_round`, `evrf_proof_size`, or `dkg_communication`
//! measure, but every one of them has to pay it before it can start timing.
//! This module builds the `n` dealer messages for a `(threshold, n)` shape
//! once, serializes them with the existing wire codec
//! (`golden_core::wire::to_wire_bytes` / `from_wire_bytes`), and reloads
//! them on later runs instead of re-proving.
//!
//! The cache is keyed on `(threshold, n, BENCH_SEED, FORMAT_VERSION)` and
//! lives under `target/`, so it is local-only and never checked in. It is
//! self-healing: a missing, truncated, or otherwise invalid cache file is
//! treated as a miss and rebuilt, and a decoded-but-corrupt cache is caught
//! by running the messages through `verify_dealings` before trusting them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use golden_core::wire::{from_wire_bytes, to_wire_bytes};
use golden_core::{create_dealing, verify_dealings, DealerMessage, DkgConfig, ParticipantIndex};
use golden_evrf::paper::secp_secq::SecpSecqBackend;
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use super::{identity_secret, BENCH_SEED};

/// Bumped whenever the cache file layout below changes shape; the wire
/// codec's own `MAGIC` already guards against `DealerMessage` format drift.
const FORMAT_VERSION: u32 = 1;

fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-fixtures/dealer-messages")
}

fn cache_path(threshold: usize, n: usize) -> PathBuf {
    let seed_hex: String = BENCH_SEED[..8].iter().map(|b| format!("{b:02x}")).collect();
    cache_dir().join(format!(
        "t{threshold}-n{n}-seed{seed_hex}-v{FORMAT_VERSION}.bin"
    ))
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
    // Write-then-rename so a crash or a concurrent bench run never leaves a
    // partially written file at the real path.
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &buf)?;
    fs::rename(&tmp_path, path)
}

/// Decode a cache file. Returns `None` on any structural problem (missing
/// file, truncated length prefixes, trailing bytes, bad wire encoding) so
/// the caller can fall back to rebuilding.
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

/// Return all `n` dealer messages for `config`, loading them from the disk
/// cache when a valid entry exists and rebuilding (then caching) otherwise.
///
/// Validity is checked by running the decoded messages through
/// `verify_dealings` against `config` before returning them, so a stale or
/// corrupt cache entry is never handed back silently.
pub fn cached_dealer_messages(
    config: &DkgConfig<Secp256k1GoldenGroup>,
) -> BTreeMap<ParticipantIndex, DealerMessage<Secp256k1GoldenGroup>> {
    let n = config.registry.indexes().count();
    let path = cache_path(config.threshold, n);

    if let Some(messages) = read_cache(&path) {
        let refs: Vec<_> = messages.iter().collect();
        if messages.len() == n
            && verify_dealings::<Secp256k1GoldenGroup, SecpSecqBackend>(&refs, config).is_ok()
        {
            return messages.into_iter().map(|m| (m.dealer, m)).collect();
        }
        eprintln!(
            "bench fixture cache at {} is stale or invalid; rebuilding",
            path.display()
        );
    }

    let messages = build_dealer_messages(config);
    if let Err(err) = write_cache(&path, &messages) {
        eprintln!(
            "failed to write bench fixture cache at {}: {err}",
            path.display()
        );
    }
    messages.into_iter().map(|m| (m.dealer, m)).collect()
}

/// Build the setup for one participant's Round 1: its own full dealing
/// (message plus `private_share`, which cannot be cached because it is
/// never put on the wire) alongside every peer's cached message.
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
