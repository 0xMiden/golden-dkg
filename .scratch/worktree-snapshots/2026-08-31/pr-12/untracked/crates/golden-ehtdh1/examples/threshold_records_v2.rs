//! Threshold-protected storage for large records.
//!
//! A writer encrypts each record under a fresh content key. EHTDH1 protects that
//! content key, and a threshold of participants is required to recover it.
//!
//! The writer, participants, and combiner are logical roles. A deployment may
//! assign several roles to one process or operator. For example, a blockchain
//! validator's post-validation storage path can act as the writer, share-holding
//! operators as the participants, and an authorized recovery path as the
//! combiner. This example starts with a plaintext record ready to store; it does
//! not model client submission or record validation.
//!
//! # Data flow
//!
//! Setup happens once:
//!
//! 1. Three participants run the two 2-of-3 Golden DKG sessions required by
//!    EHTDH1.
//! 2. Each participant receives the same public setup and its own secret share.
//!    The writer receives only the public [`SealingKey`].
//!
//! The writer then stores each record:
//!
//! 3. Generate a fresh 32-byte content key.
//! 4. Encrypt the 512 KiB value with XChaCha20Poly1305 under that content key.
//! 5. Encrypt only the 32-byte content key with EHTDH1.
//!
//! ```text
//! value       -- XChaCha20Poly1305(content key) --> encrypted value
//! content key -- EHTDH1(sealing key) -----------> wrapped content key
//! ```
//!
//! To recover a record, participants produce [`DecryptionShare`] values and a
//! [`Combiner`] verifies them. For the selected `record/B` ciphertext:
//!
//! * two shares under decryption context `record/B` recover the content key;
//! * one share is insufficient;
//! * shares split between contexts `record/B` and `record/A` cannot be combined.
//!
//! # Context policy
//!
//! The application supplies several values that are easy to conflate:
//!
//! * A **record ID**, such as `record/B`, identifies the stored record.
//! * **Associated data** is fixed by the writer and stored in the EHTDH1
//!   ciphertext. It says which record the writer bound the wrapped key to.
//! * A **decryption context** is supplied when participants create shares and
//!   when the combiner verifies them. It says which request a share approves.
//! * [`SetupContext`](golden_ehtdh1::SetupContext) identifies the Golden setup
//!   that produced the keys and shares.
//!
//! This example uses the record ID as XChaCha20Poly1305 associated data, EHTDH1
//! associated data, and the EHTDH1 decryption context. These remain separate
//! inputs even though they contain the same bytes here.
//!
//! A production application should canonically encode every identifier needed
//! to scope a record or request. For example, it may include an application ID,
//! key epoch, record ID, related object ID, and schema version. The stored record
//! must also carry enough metadata to select the same setup and key epoch when
//! it is recovered.
//!
//! # Why setup runs DKG twice
//!
//! The first DKG shares the joint decryption secret. The second creates shares
//! that reconstruct to zero. Their contributions cancel when a threshold uses
//! one decryption context, but not when contexts are mixed.
//!
//! # Roles and values
//!
//! * The **writer** uses public setup data to encrypt records.
//! * A **participant** keeps a private
//!   [`SecretShare`](golden_ehtdh1::SecretShare) and uses an [`UnsealingShare`]
//!   to produce decryption shares.
//! * The **combiner** uses public setup data to verify decryption shares and
//!   recover a content key after the threshold is met.
//! * A **content key** is a fresh symmetric key for one record. A **wrapped
//!   content key** is the EHTDH1 ciphertext whose plaintext is that key.
//!
//! A decryption share does not expose a participant's long-lived secret, but
//! releasing enough shares authorizes recovery. The integrating application
//! decides whether each request should be approved.
//!
//! # Scope
//!
//! The example wire-round-trips the sealing key, wrapped content keys, and
//! decryption shares as storage or transport would. It does not define a network
//! protocol, authorization policy, replay protection, secret-share custody,
//! durable storage, or setup rotation.
//!
//! Fixed RNG seeds make the example repeatable; production callers must use an
//! operating-system RNG. The fast prototype proof backend keeps the example
//! practical to run while exercising the same Golden DKG and EHTDH1 interfaces
//! as the full proof backend.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use golden_core::{
    complete, create_dealing_with_secret, DealerMessage, DkgConfig, DkgDealing, DkgOutput,
    GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{
    derive_context_session_id, material_from_dkg_outputs, Ciphertext, Combiner, DecryptionShare,
    Ehtdh1Material, SealingKey, UnsealingShare,
};
use golden_evrf::prototype::{ShareOpeningBackend, ShareOpeningBatchedProof};
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zeroize::Zeroizing;

/// Concrete group used by this fast example.
type G = P256Backend;
/// Proof attached to each prototype DKG dealing.
type Proof = ShareOpeningBatchedProof<G>;
/// Error type used by the example helpers.
type AppResult<T> = Result<T, Box<dyn Error>>;

/// Number of bytes in each fresh record content key.
const CONTENT_KEY_BYTES: usize = 32;
/// Number of bytes in an XChaCha20Poly1305 nonce.
const NONCE_BYTES: usize = 24;
/// Size of each example value.
const RECORD_BYTES: usize = 512 * 1024;

/// Minimal per-record data persisted by this single-setup example.
///
/// Production storage also needs a selector for the setup and key epoch.
struct StoredRecord {
    /// Public application identifier bound into both encryption layers.
    record_id: Vec<u8>,
    /// Public nonce for the record-value cipher.
    value_nonce: [u8; NONCE_BYTES],
    /// Large value encrypted by XChaCha20Poly1305.
    encrypted_value: Vec<u8>,
    /// Canonical EHTDH1 ciphertext bytes for the content key.
    wrapped_content_key_bytes: Vec<u8>,
}

/// Runs the complete example scenario.
fn main() -> AppResult<()> {
    // Step 1. The participants run the two DKG sessions required by EHTDH1.
    // Each receives the same public setup and different private material.
    let participants = [idx(1)?, idx(2)?, idx(3)?];
    let mut setup_rng = ChaCha20Rng::from_seed([1u8; 32]);
    let participant_material = run_ehtdh1_setup(&participants, &mut setup_rng)?;
    check_shared_public_setup(&participant_material)?;

    // Step 2. Simulate distribution by serializing the public sealing key
    // before the writer receives it. No participant secret is distributed.
    let reference_material = get(
        &participant_material,
        participants[0],
        "missing first participant",
    )?;
    let sealing_key_bytes = to_wire_bytes(&reference_material.sealing_key);
    let writer_sealing_key = from_wire_bytes::<SealingKey<G>>(&sealing_key_bytes)?;

    // Step 3. The writer encrypts three records. Record IDs are public; the
    // values and fresh content keys are secret.
    let plaintext_records = [
        (b"record/A".as_slice(), vec![b'A'; RECORD_BYTES]),
        (b"record/B".as_slice(), vec![b'B'; RECORD_BYTES]),
        (b"record/C".as_slice(), vec![b'C'; RECORD_BYTES]),
    ];
    let mut writer_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let mut stored_records = Vec::new();
    for (record_id, value) in plaintext_records {
        stored_records.push(seal_record(
            &writer_sealing_key,
            record_id,
            &value,
            &mut writer_rng,
        )?);
    }

    // Step 4. Build the application inputs for a request to recover record B.
    // This example deliberately uses the record ID for both EHTDH1 inputs.
    let selected_record = &stored_records[1];
    let different_record = &stored_records[0];
    let wrapped_content_key =
        from_wire_bytes::<Ciphertext<G>>(&selected_record.wrapped_content_key_bytes)?;
    let expected_associated_data = selected_record.record_id.as_slice();
    let decryption_context = selected_record.record_id.as_slice();

    // Producing a share is authorization-sensitive. A real application checks
    // policy first; this example authorizes every participant.
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let decryption_shares = create_decryption_shares(
        &participant_material,
        &wrapped_content_key,
        decryption_context,
        expected_associated_data,
        &mut share_rng,
    )?;
    let combiner = Combiner::new(
        reference_material.public_key_set.clone(),
        reference_material.setup_context.clone(),
    )?;

    // Step 5. One valid share remains below the threshold.
    require(
        combiner
            .combine_exact_with_associated_data(
                &wrapped_content_key,
                decryption_context,
                expected_associated_data,
                &decryption_shares[..1],
            )
            .is_err(),
        "one share unexpectedly opened the content key",
    )?;

    // Every pair meets the threshold and recovers the selected record value.
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let selected_shares = [
            decryption_shares[pair[0]].clone(),
            decryption_shares[pair[1]].clone(),
        ];
        let content_key = Zeroizing::new(combiner.combine_exact_with_associated_data(
            &wrapped_content_key,
            decryption_context,
            expected_associated_data,
            &selected_shares,
        )?);
        let opened_value = decrypt_record_value(selected_record, &content_key)?;
        require(
            opened_value.len() == RECORD_BYTES && opened_value.iter().all(|byte| *byte == b'B'),
            "a valid threshold set opened the wrong value",
        )?;
    }

    // Context binding is independent of ciphertext binding. Create a response
    // for record B's ciphertext under a different decryption context, then show
    // that it cannot be mixed with a response for the intended context.
    let second_participant = get(
        &participant_material,
        participants[1],
        "missing second participant",
    )?;
    let different_context_share = UnsealingShare::new(second_participant.secret_share.clone())
        .decrypt_share_with_associated_data(
            &mut share_rng,
            &second_participant.setup_context,
            &wrapped_content_key,
            &different_record.record_id,
            expected_associated_data,
        )?;
    let mixed_context_shares = [decryption_shares[0].clone(), different_context_share];
    require(
        combiner
            .combine_exact_with_associated_data(
                &wrapped_content_key,
                decryption_context,
                expected_associated_data,
                &mixed_context_shares,
            )
            .is_err(),
        "shares from different decryption contexts were combined",
    )?;

    // Cross-record replay is rejected: valid shares for record B cannot recover
    // record A's wrapped content key.
    let different_wrapped_content_key =
        from_wire_bytes::<Ciphertext<G>>(&different_record.wrapped_content_key_bytes)?;
    require(
        combiner
            .combine_exact_with_associated_data(
                &different_wrapped_content_key,
                &different_record.record_id,
                &different_record.record_id,
                &decryption_shares[..2],
            )
            .is_err(),
        "shares for one ciphertext opened another ciphertext",
    )?;

    let plaintext_bytes = stored_records.len() * RECORD_BYTES;
    let content_key_bytes = stored_records.len() * CONTENT_KEY_BYTES;
    println!("Golden setup has 3 participants and a threshold of 2.");
    println!(
        "The writer stored {} threshold-protected records.",
        stored_records.len()
    );
    println!(
        "AEAD encrypted {plaintext_bytes} bytes of values. EHTDH1 encrypted \
         {content_key_bytes} bytes of content keys."
    );
    println!("Each EHTDH1 ciphertext wraps 32 bytes, independent of record size.");
    println!("All three pairs of participants recovered record/B.");
    println!("One share, mixed-context shares, and cross-record shares were rejected.");

    Ok(())
}

/// Builds a checked participant index.
fn idx(value: u32) -> AppResult<ParticipantIndex> {
    Ok(ParticipantIndex::new(value)?)
}

/// Builds a small P256 scalar for repeatable example inputs.
fn scalar(value: u64) -> AppResult<P256Scalar> {
    Ok(P256Scalar::from_u64(value)?)
}

/// Returns the repeatable identity secret for one participant.
fn identity_secret(participant: ParticipantIndex) -> AppResult<P256Scalar> {
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
    Ok(DkgConfig::new(2, session_id, scalar(77)?, registry)?)
}

/// Runs one DKG session and returns one local output for each participant.
fn run_dkg(
    participants: &[ParticipantIndex; 3],
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
    zero_sharing: bool,
) -> AppResult<BTreeMap<ParticipantIndex, DkgOutput<G>>> {
    let mut dealings = BTreeMap::<ParticipantIndex, DkgDealing<G, Proof>>::new();
    // Every participant acts as a dealer and sends one dealing to its peers.
    for dealer in participants {
        let secret = if zero_sharing {
            P256Scalar::zero()
        } else {
            scalar(20 + u64::from(dealer.get()))?
        };
        let dealing = create_dealing_with_secret::<G, ShareOpeningBackend>(
            *dealer,
            &identity_secret(*dealer)?,
            secret,
            config,
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
                (*dealer != *receiver).then_some((*dealer, dealing.message.clone()))
            })
            .collect::<BTreeMap<ParticipantIndex, DealerMessage<G, Proof>>>();
        let output = complete::<G, ShareOpeningBackend>(
            *receiver,
            &identity_secret(*receiver)?,
            own_dealing,
            &peer_dealings,
            config,
        )?;
        outputs.insert(*receiver, output);
    }
    Ok(outputs)
}

/// Runs both DKG sessions and derives each participant's EHTDH1 material.
fn run_ehtdh1_setup(
    participants: &[ParticipantIndex; 3],
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, Ehtdh1Material<G>>> {
    let decryption_config = dkg_config(participants, SessionId([42u8; 32]))?;
    let context_config = dkg_config(
        participants,
        derive_context_session_id(decryption_config.session_id),
    )?;
    // The first DKG creates the joint decryption key.
    let decryption_outputs = run_dkg(participants, &decryption_config, rng, false)?;
    // The second DKG shares zero so later shares can bind a decryption context.
    let context_outputs = run_dkg(participants, &context_config, rng, true)?;

    let mut participant_material = BTreeMap::new();
    for participant in participants {
        participant_material.insert(
            *participant,
            material_from_dkg_outputs(
                &decryption_config,
                get(
                    &decryption_outputs,
                    *participant,
                    "missing decryption output",
                )?,
                &context_config,
                get(&context_outputs, *participant, "missing context output")?,
                [8u8; 32],
            )?,
        );
    }
    Ok(participant_material)
}

/// Checks that every participant derived the same public setup.
fn check_shared_public_setup(
    participant_material: &BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
) -> AppResult<()> {
    let mut values = participant_material.values();
    let reference = values
        .next()
        .ok_or_else(|| io::Error::other("setup has no participants"))?;
    for material in values {
        require(
            material.sealing_key == reference.sealing_key
                && material.public_key_set == reference.public_key_set
                && material.setup_context == reference.setup_context,
            "participants did not agree on setup",
        )?;
    }
    Ok(())
}

/// Encrypts one value and wraps only its fresh content key with EHTDH1.
fn seal_record(
    sealing_key: &SealingKey<G>,
    record_id: &[u8],
    value: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<StoredRecord> {
    let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
    let mut value_nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut *content_key);
    rng.fill_bytes(&mut value_nonce);

    // The AEAD encrypts the large value and authenticates its public record ID.
    let value_cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
        .map_err(|_| io::Error::other("invalid content key"))?;
    let encrypted_value = value_cipher
        .encrypt(
            &XNonce::from(value_nonce),
            Payload {
                msg: value,
                aad: record_id,
            },
        )
        .map_err(|_| io::Error::other("record encryption failed"))?;

    // EHTDH1 encrypts only the fixed-size content key. The record ID is public
    // associated data: changing it invalidates the EHTDH1 ciphertext.
    let wrapped_content_key =
        sealing_key.seal_bytes_with_associated_data(rng, content_key.as_ref(), record_id)?;
    require(
        wrapped_content_key.encrypted_payload.len() == CONTENT_KEY_BYTES,
        "EHTDH1 wrapped more than the content key",
    )?;

    Ok(StoredRecord {
        record_id: record_id.to_vec(),
        value_nonce,
        encrypted_value,
        wrapped_content_key_bytes: to_wire_bytes(&wrapped_content_key),
    })
}

/// Creates one decryption response per participant after application authorization.
fn create_decryption_shares(
    participant_material: &BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
    wrapped_content_key: &Ciphertext<G>,
    decryption_context: &[u8],
    expected_associated_data: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<Vec<DecryptionShare<G>>> {
    let mut decryption_shares = Vec::new();
    for material in participant_material.values() {
        let share = UnsealingShare::new(material.secret_share.clone())
            .decrypt_share_with_associated_data(
                rng,
                &material.setup_context,
                wrapped_content_key,
                decryption_context,
                expected_associated_data,
            )?;

        // Serialize each response as storage or transport would before the
        // combiner receives it.
        decryption_shares.push(from_wire_bytes(&to_wire_bytes(&share))?);
    }
    Ok(decryption_shares)
}

/// Decrypts one stored value with a content key recovered by the combiner.
fn decrypt_record_value(record: &StoredRecord, content_key: &[u8]) -> AppResult<Vec<u8>> {
    require(
        content_key.len() == CONTENT_KEY_BYTES,
        "opened content key has the wrong length",
    )?;
    let value_cipher = XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| io::Error::other("invalid opened content key"))?;

    // Authentication prevents moving an encrypted value under another record ID.
    value_cipher
        .decrypt(
            &XNonce::from(record.value_nonce),
            Payload {
                msg: &record.encrypted_value,
                aad: &record.record_id,
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
