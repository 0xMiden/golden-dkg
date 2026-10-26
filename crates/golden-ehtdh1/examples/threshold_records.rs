//! Production Secp/Secq threshold setup protecting large stored records.
//!
//! Three participants run one explicitly prepared Golden `[Random, Zero]` batch
//! with threshold two. A separate writer encrypts record values with
//! XChaCha20Poly1305 and wraps only each fresh 32-byte content key with EHTDH1.
//! Every pair of valid decryption shares can recover the chosen record.
//!
//! Preparation is explicit and reusable across the dealer operations. Approved
//! generator generation, authenticated setup agreement, secret custody and
//! persistence are application responsibilities. Fixed seeds and repeatable
//! identity credentials make this example reproducible; deployments use secure
//! credentials and a cryptographic RNG.
//!
//! The record ID, AEAD/EHTDH1 associated data, decryption request context, and
//! setup context have separate roles. This example deliberately uses the same
//! record ID bytes for the first three. The setup context binds the single
//! batch session/configuration/completion identity and application epoch.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use golden_bulletproofs::{SecpSecqBulletproofs, SecpSecqPrepared};
use golden_core::{
    complete, deal, DealerMessageRef, DkgConfig, DkgGroup, DkgInstanceKind, DkgOutput, OwnDealing,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_curves::Secp256k1Group;
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    material_from_dkg_output, Ciphertext, Combiner, DecryptionShare, Ehtdh1Material, SealingKey,
    UnsealingShare,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zeroize::Zeroizing;

/// Native inner group; the proof system uses its separate Secq outer group.
type G = Secp256k1Group;
type Scalar = <G as DkgGroup>::Scalar;

/// Error type used by the example helpers.
type AppResult<T> = Result<T, Box<dyn Error>>;

/// Number of bytes in each fresh record content key.
const CONTENT_KEY_BYTES: usize = 32;
/// Number of bytes in an XChaCha20Poly1305 nonce.
const NONCE_BYTES: usize = 24;
/// Size of each example value.
const RECORD_BYTES: usize = 512 * 1024;

/// Stored form of one record ID and its encrypted value.
struct StoredRecord {
    /// Public application identifier bound into both encryption layers.
    record_id: Vec<u8>,
    /// Public nonce used by the record cipher.
    nonce: [u8; NONCE_BYTES],
    /// Large value encrypted by XChaCha20Poly1305.
    encrypted_value: Vec<u8>,
    /// Canonical EHTDH1 ciphertext bytes for the content key.
    wrapped_content_key: Vec<u8>,
}

/// Runs the complete example scenario.
fn main() -> AppResult<()> {
    // Step 1. Three participants run one Golden batch. Each participant receives
    // the same public setup and its own secret share.
    let participants = [idx(1)?, idx(2)?, idx(3)?];
    // Fixed seeds keep the example repeatable. Production callers use an OS RNG.
    let mut setup_rng = ChaCha20Rng::from_seed([1u8; 32]);
    let materials = run_golden_setup(&participants, &mut setup_rng)?;
    check_shared_setup(&materials)?;

    // Step 2. The writer receives only canonical bytes for the public sealing
    // key. The writer has no participant secret.
    let first = get(&materials, participants[0], "missing first participant")?;
    let public_key_bytes = to_wire_bytes(&first.sealing_key);
    let writer_key = from_wire_bytes::<SealingKey<G>>(&public_key_bytes)?;

    // Step 3. The writer makes three key and value pairs. Each application key
    // is the record ID bound into both encryption layers.
    let inputs = [
        (b"private-record/A".as_slice(), vec![b'A'; RECORD_BYTES]),
        (b"private-record/B".as_slice(), vec![b'B'; RECORD_BYTES]),
        (b"private-record/C".as_slice(), vec![b'C'; RECORD_BYTES]),
    ];
    let mut writer_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let mut records = Vec::new();
    for (record_id, value) in inputs {
        records.push(seal_record(
            &writer_key,
            record_id,
            &value,
            &mut writer_rng,
        )?);
    }

    // Step 4. The participants choose record B. This example deliberately uses
    // its record ID for both EHTDH1 inputs.
    let chosen = &records[1];
    let other = &records[0];
    let wrapped_key = from_wire_bytes::<Ciphertext<G>>(&chosen.wrapped_content_key)?;
    let expected_associated_data = chosen.record_id.as_slice();
    let decryption_context = chosen.record_id.as_slice();
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let shares = make_shares(
        &materials,
        &wrapped_key,
        decryption_context,
        expected_associated_data,
        &mut share_rng,
    )?;
    let combiner = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())?;

    // Step 5. One share is below the threshold and cannot open the content key.
    require(
        combiner
            .combine_exact_with_associated_data(
                &wrapped_key,
                decryption_context,
                expected_associated_data,
                &shares[..1],
            )
            .is_err(),
        "one share unexpectedly opened the content key",
    )?;

    // Each possible pair meets the threshold and opens the chosen value.
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let selected = [shares[pair[0]].clone(), shares[pair[1]].clone()];
        let content_key = Zeroizing::new(combiner.combine_exact_with_associated_data(
            &wrapped_key,
            decryption_context,
            expected_associated_data,
            &selected,
        )?);
        let opened = open_record(chosen, &content_key)?;
        require(
            opened.len() == RECORD_BYTES && opened.iter().all(|byte| *byte == b'B'),
            "a valid quorum opened the wrong value",
        )?;
    }

    // A share made for the same ciphertext and associated data under another
    // decryption context cannot combine with a share for the intended context.
    let second = get(&materials, participants[1], "missing second participant")?;
    let different_decryption_context = other.record_id.as_slice();
    let mixed_context_share = UnsealingShare::new(second.secret_share.clone())
        .decrypt_share_with_associated_data(
            &mut share_rng,
            &second.setup_context,
            &wrapped_key,
            different_decryption_context,
            expected_associated_data,
        )?;
    let mixed_context_share =
        from_wire_bytes::<DecryptionShare<G>>(&to_wire_bytes(&mixed_context_share))?;
    let mixed_context_shares = [shares[0].clone(), mixed_context_share];
    require(
        combiner
            .combine_exact_with_associated_data(
                &wrapped_key,
                decryption_context,
                expected_associated_data,
                &mixed_context_shares,
            )
            .is_err(),
        "shares from different decryption contexts were combined",
    )?;

    // Shares are also bound to ciphertext B and cannot open record A.
    let other_wrapped_key = from_wire_bytes::<Ciphertext<G>>(&other.wrapped_content_key)?;
    let other_expected_associated_data = other.record_id.as_slice();
    let other_decryption_context = other.record_id.as_slice();
    require(
        combiner
            .combine_exact_with_associated_data(
                &other_wrapped_key,
                other_decryption_context,
                other_expected_associated_data,
                &shares[..2],
            )
            .is_err(),
        "shares for one record opened another record",
    )?;

    let record_bytes = records.len() * RECORD_BYTES;
    let wrapped_bytes = records.len() * CONTENT_KEY_BYTES;
    println!("Golden setup has 3 participants and a threshold of 2.");
    println!(
        "The writer stored {} records keyed by record ID.",
        records.len()
    );
    println!(
        "In the HPKE style split, AEAD encrypted {record_bytes} record bytes. EHTDH1 wrapped \
         {wrapped_bytes} bytes total."
    );
    println!("Each EHTDH1 ciphertext wraps 32 bytes, independent of record size.");
    println!("The parties chose private-record/B and exchanged canonical shares.");
    println!("All three pairs of two opened private-record/B.");
    println!("One share and shares from another context were rejected.");
    println!("Shares made under mixed decryption contexts were rejected.");

    Ok(())
}

/// Builds a checked participant index.
fn idx(value: u32) -> AppResult<ParticipantIndex> {
    Ok(ParticipantIndex::new(value)?)
}

/// Repeatable example credential; production callers supply their own secrets.
fn identity_secret(participant: ParticipantIndex) -> Scalar {
    Scalar::from(100 + u64::from(participant.get()))
}

/// Shared threshold-two settings for one ordered Random/Zero batch.
fn dkg_config(participants: &[ParticipantIndex; 3]) -> AppResult<DkgConfig<G>> {
    let entries = participants
        .iter()
        .map(|participant| {
            (
                *participant,
                G::mul_generator(&identity_secret(*participant)),
            )
        })
        .collect();
    Ok(DkgConfig::new(
        2,
        SessionId([42; 32]),
        ParticipantRegistry::new(entries)?,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )?)
}

/// Run one batch and retain one independently owned local output per participant.
fn run_dkg(
    proofs: &SecpSecqBulletproofs,
    participants: &[ParticipantIndex; 3],
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, DkgOutput<G>>> {
    let mut dealings = BTreeMap::<ParticipantIndex, OwnDealing<G>>::new();
    for dealer in participants {
        dealings.insert(
            *dealer,
            deal(proofs, config, *dealer, &identity_secret(*dealer), rng)?,
        );
    }
    let mut outputs = BTreeMap::new();
    for participant in participants {
        let own = get(&dealings, *participant, "missing own dealing")?;
        let peers: Vec<_> = dealings
            .iter()
            .filter(|(dealer, _)| **dealer != *participant)
            .map(|(dealer, own)| DealerMessageRef {
                expected_dealer: *dealer,
                bytes: own.broadcast_bytes(),
            })
            .collect();
        outputs.insert(
            *participant,
            complete(proofs, config, &identity_secret(*participant), own, &peers)?,
        );
    }
    Ok(outputs)
}

/// Prepare once, complete one mixed batch, and give each participant its material.
fn run_golden_setup(
    participants: &[ParticipantIndex; 3],
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, Ehtdh1Material<G>>> {
    let config = dkg_config(participants)?;
    let prepared = SecpSecqPrepared::prepare_for(&config)?;
    let proofs = SecpSecqBulletproofs::from_prepared(prepared);
    let outputs = run_dkg(&proofs, participants, &config, rng)?;
    let mut materials = BTreeMap::new();
    for participant in participants {
        materials.insert(
            *participant,
            material_from_dkg_output(
                &config,
                get(&outputs, *participant, "missing local output")?,
                [8; 32],
            )?,
        );
    }
    Ok(materials)
}

/// Checks that every participant received the same public setup.
fn check_shared_setup(materials: &BTreeMap<ParticipantIndex, Ehtdh1Material<G>>) -> AppResult<()> {
    let mut values = materials.values();
    let first = values
        .next()
        .ok_or_else(|| io::Error::other("setup has no participants"))?;
    for material in values {
        require(
            material.sealing_key == first.sealing_key
                && material.public_key_set == first.public_key_set
                && material.setup_context == first.setup_context,
            "participants did not agree on setup",
        )?;
    }
    Ok(())
}

/// Encrypts one large value and wraps only its fresh content key with EHTDH1.
fn seal_record(
    sealing_key: &SealingKey<G>,
    record_id: &[u8],
    value: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<StoredRecord> {
    let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut *content_key);
    rng.fill_bytes(&mut nonce);

    // The record cipher handles the large value and binds its public record ID.
    let aead_associated_data = record_id;
    let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
        .map_err(|_| io::Error::other("invalid content key"))?;
    let encrypted_value = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: value,
                aad: aead_associated_data,
            },
        )
        .map_err(|_| io::Error::other("record encryption failed"))?;
    // EHTDH1 handles only the fixed size content key and independently binds
    // its expected associated data.
    let expected_associated_data = record_id;
    let wrapped_content_key = sealing_key.seal_bytes_with_associated_data(
        rng,
        content_key.as_ref(),
        expected_associated_data,
    )?;
    require(
        wrapped_content_key.encrypted_payload.len() == CONTENT_KEY_BYTES,
        "EHTDH1 wrapped more than the content key",
    )?;

    Ok(StoredRecord {
        record_id: record_id.to_vec(),
        nonce,
        encrypted_value,
        wrapped_content_key: to_wire_bytes(&wrapped_content_key),
    })
}

/// Makes one decryption share per participant and serializes it.
fn make_shares(
    materials: &BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
    wrapped_key: &Ciphertext<G>,
    decryption_context: &[u8],
    expected_associated_data: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<Vec<DecryptionShare<G>>> {
    let mut shares = Vec::new();
    for material in materials.values() {
        let share = UnsealingShare::new(material.secret_share.clone())
            .decrypt_share_with_associated_data(
                rng,
                &material.setup_context,
                wrapped_key,
                decryption_context,
                expected_associated_data,
            )?;
        // The example serializes each share before the combiner receives it.
        shares.push(from_wire_bytes(&to_wire_bytes(&share))?);
    }
    Ok(shares)
}

/// Decrypts one stored value with a content key recovered by the combiner.
fn open_record(record: &StoredRecord, content_key: &[u8]) -> AppResult<Vec<u8>> {
    require(
        content_key.len() == CONTENT_KEY_BYTES,
        "opened content key has the wrong length",
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| io::Error::other("invalid opened content key"))?;
    // The record cipher checks the stored record ID before returning plaintext.
    let aead_associated_data = record.record_id.as_slice();
    cipher
        .decrypt(
            &XNonce::from(record.nonce),
            Payload {
                msg: &record.encrypted_value,
                aad: aead_associated_data,
            },
        )
        .map_err(|_| io::Error::other("record decryption failed").into())
}

/// Returns one required map value or a plain example error.
fn get<'a, K: Ord, V>(
    values: &'a BTreeMap<K, V>,
    key: K,
    message: &'static str,
) -> AppResult<&'a V> {
    values
        .get(&key)
        .ok_or_else(|| io::Error::other(message).into())
}

/// Returns an error when an example claim does not hold.
fn require(condition: bool, message: &'static str) -> AppResult<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
