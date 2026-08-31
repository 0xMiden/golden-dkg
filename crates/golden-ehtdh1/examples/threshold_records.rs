//! Threshold encryption for stored records with three participants.
//!
//! This example follows the node Phase 2 flow.
//!
//! 1. Three participants run one atomic `[Random, Zero]` Golden DKG batch.
//!    They agree on one public sealing key with a threshold of two. Each
//!    participant also receives its own secret share.
//! 2. A separate writer creates three `(key, value)` pairs. Each key is the
//!    record ID for its value.
//! 3. The writer encrypts each large value with XChaCha20Poly1305 under a fresh
//!    content key. EHTDH1 encrypts only that 32 byte content key.
//! 4. The participants choose one record. Each participant uses its secret
//!    share to make a decryption share for that record and ciphertext.
//! 5. A combiner checks the decryption shares. Any two valid shares recover the
//!    content key, which then decrypts the value.
//!
//! The example uses the Secp/Secq Main Golden proof system. Proof parameter
//! preparation and dealing are intentionally explicit setup steps.
//!
//! # Context policy
//!
//! Four values in this flow are easy to conflate:
//!
//! * The **record ID** identifies the stored record.
//! * **Associated data** binds that ID into the record AEAD and the EHTDH1
//!   ciphertext.
//! * The **EHTDH1 decryption context** binds each participant's approval to a
//!   decryption request.
//! * The [`SetupContext`](golden_ehtdh1::SetupContext) identifies the Golden
//!   setup that produced the keys and shares.
//!
//! The record ID, both associated-data inputs, and the decryption context
//! happen to contain the same bytes in this example, but they remain separate
//! inputs.
//!
//! # Why setup uses two ordered sharings
//!
//! The batch first shares the joint decryption secret and then shares zero. The
//! zero-sharing contributions cancel for one decryption context, but not when
//! contexts are mixed.
//!
//! # Glossary
//!
//! * A **participant** is one of the three parties in Golden setup. Each
//!   participant has an identity key and later holds one secret share.
//! * The **writer** is a separate party. It receives only the sealing key and
//!   does not take part in DKG or hold a secret share.
//! * The **threshold** is the number of decryption shares needed to open a
//!   content key. This example uses two out of three.
//! * **Golden DKG** lets the participants create a joint public key without one
//!   party choosing the final private key. EHTDH1 setup creates its decryption
//!   and context sharings atomically in one ordered DKG batch.
//! * A **dealer message** is one participant's bounded, configuration-shaped,
//!   opaque DKG broadcast. Applications forward its exact bytes; `complete`
//!   alone parses and validates its ordered sharings and joint proof.
//! * A **DKG output** is one participant's result after all dealings pass. It
//!   contains ordered instance outputs, each with public setup data and that
//!   participant's local share for the corresponding configured sharing.
//! * A **sealing key** is the joint public key. The writer can use it without
//!   learning any participant secret.
//! * A **public key set** has the threshold and joint public key. There is also
//!   one public share for each participant. The combiner reads this set when it
//!   checks shares.
//! * A **setup context** is the identity of the Golden setup. The backend and
//!   participant list are part of it. The batch session, configuration root,
//!   and completion root are also part of it. The epoch names this setup.
//! * A **secret share** is the long lived private EHTDH1 material held by one
//!   participant. There is one scalar from each batch position in it. Participants
//!   never exchange these secret shares.
//! * An **unsealing share** wraps one secret share. A participant uses it to
//!   create a decryption share without exposing the stored secret.
//! * A **record ID** is the application key for one record. It is bound to the
//!   record cipher, EHTDH1 ciphertext, and each decryption share.
//! * A **record** is the stored record ID and record cipher nonce. It also
//!   includes the encrypted value and canonical bytes for the EHTDH1
//!   ciphertext.
//! * A **content key** is a fresh 32 byte secret used to encrypt one record
//!   value with XChaCha20Poly1305.
//! * An **EHTDH1 ciphertext** is the encrypted content key and its proof. The
//!   record ID is public associated data in this ciphertext.
//! * A **decryption share** is a message made for one EHTDH1 ciphertext and one
//!   decryption context. It is safe to exchange. It is not the participant's
//!   secret share.
//! * A **combiner** checks decryption shares against the public setup. It
//!   returns the content key only after it receives enough valid shares.
//! * A **quorum** is any set of participants that meets the threshold. All
//!   three possible pairs are valid quorums in this example.
//! * Each public value has one **canonical byte** form for storage or exchange.
//!   The writer and participants decode the same bytes. The combiner does the
//!   same.
//! * With **authenticated symmetric encryption**, the large record value is
//!   hidden and any change to its ciphertext or record ID is rejected.
//! * The **HPKE style split** means symmetric encryption handles each large
//!   value while EHTDH1 handles only its small content key. Record size does
//!   not change the EHTDH1 payload size.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use golden_core::{
    complete, deal, DkgConfig, DkgInstanceKind, DkgOutput, GoldenGroup, GoldenScalar, OwnDealing,
    ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    material_from_dkg_output, Ciphertext, Combiner, DecryptionShare, Ehtdh1Material, SealingKey,
    UnsealingShare,
};
use golden_evrf::paper::secp_secq::SecpSecqBulletproofs;
use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

/// Main Golden input group used by the Secp/Secq proof system.
type G = Secp256k1GoldenGroup;

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
    // Step 1. Three participants run Golden setup. Each participant receives
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

/// Builds a small Secp256k1 scalar for repeatable example inputs.
fn scalar(value: u64) -> AppResult<Secp256k1Scalar> {
    Ok(Secp256k1Scalar::from_u64(value)?)
}

/// Returns the repeatable identity secret for one participant.
fn identity_secret(participant: ParticipantIndex) -> AppResult<Secp256k1Scalar> {
    scalar(100 + u64::from(participant.get()))
}

/// Builds shared DKG settings with a threshold of two.
fn dkg_config(
    participants: &[ParticipantIndex; 3],
    session_id: SessionId,
) -> AppResult<DkgConfig<G>> {
    let mut entries = Vec::new();
    for participant in participants {
        entries.push((
            *participant,
            G::mul_generator(&identity_secret(*participant)?),
        ));
    }
    let registry = ParticipantRegistry::new(entries)?;
    Ok(DkgConfig::new(
        2,
        session_id,
        registry,
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )?)
}

/// Runs one atomic DKG batch and returns one local output for each participant.
fn run_dkg(
    participants: &[ParticipantIndex; 3],
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, DkgOutput<G>>> {
    let proof_system = SecpSecqBulletproofs::prepare_for(config)?;
    let mut dealings = BTreeMap::<ParticipantIndex, OwnDealing<G>>::new();
    // Every participant acts as a dealer and sends one dealing to its peers.
    for dealer in participants {
        let dealing = deal(
            &proof_system,
            config,
            *dealer,
            &identity_secret(*dealer)?,
            rng,
        )?;
        dealings.insert(*dealer, dealing);
    }

    let mut outputs = BTreeMap::new();
    // Every participant checks the peer dealings and produces its DKG output.
    for receiver in participants {
        let own_dealing = get(&dealings, *receiver, "missing own dealing")?;
        let peer_dealings = dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                (*dealer != *receiver).then_some((*dealer, dealing.dealer_message_bytes().to_vec()))
            })
            .collect::<Vec<_>>();
        let output = complete(
            &proof_system,
            config,
            &identity_secret(*receiver)?,
            own_dealing,
            &peer_dealings,
        )?;
        outputs.insert(*receiver, output);
    }
    Ok(outputs)
}

/// Runs one `[Random, Zero]` batch and gives each participant its EHTDH1 setup.
fn run_golden_setup(
    participants: &[ParticipantIndex; 3],
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, Ehtdh1Material<G>>> {
    let config = dkg_config(participants, SessionId([42u8; 32]))?;
    let outputs = run_dkg(participants, &config, rng)?;

    let mut materials = BTreeMap::new();
    for participant in participants {
        materials.insert(
            *participant,
            material_from_dkg_output(
                &config,
                get(&outputs, *participant, "missing DKG output")?,
                [8u8; 32],
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
