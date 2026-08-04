//! Threshold disclosure-group decryption for stored records with three participants.
//!
//! This example follows a two-of-three disclosure-group flow.
//!
//! 1. Three participants run the two Golden DKG sessions needed by EHTDH1.
//!    They agree on one public sealing key, and each receives its own secret share.
//! 2. A client supplies one private value and a uniformly random 256-bit nonce.
//!    The application derives a shared sealing seed from
//!    `client_nonce || SHA256(canonical private plaintext)` with domain-separated
//!    HKDF-SHA256.
//! 3. Three independent writers encrypt the same logical private payload. Every
//!    writer uses the same application-level associated data and seeded `r`, so
//!    the EHTDH1 ciphertexts share `R`. Each writer independently samples a fresh
//!    content key, outer XChaCha20Poly1305 nonce, and encryption-proof nonce `r'`,
//!    so the complete ciphertexts, encrypted payloads, and proof fields differ.
//! 4. Before any request-specific context or disclosure group exists, each
//!    participant precomputes its secret-bearing contribution for the common `R`.
//!    The unsealing share and opaque precomputation remain protected in TEE storage.
//! 5. Later, the application authenticates the intended record membership and
//!    creates one disclosure group from the common `R`, common associated data,
//!    one request-specific decryption context, and an opaque application group ID.
//! 6. Each participant issues a disclosure-group share with fresh proof randomness
//!    and sends its canonical wire form. One threshold set reconstructs one opaque
//!    group key, which opens all three wrapped content keys and therefore all three
//!    outer records.
//!
//! # Security warning
//!
//! A disclosure-group key opens **any valid ciphertext with the same `R` and
//! associated data**, not only ciphertexts the application intended to place in
//! the group. The application **must authenticate disclosure-group membership**
//! separately before participants release shares. This example uses a trusted
//! manifest of complete record-envelope digests.
//!
//! Seeded sealing also reuses one payload mask: a writer that knows its own
//! content key and wrapped payload can recover the mask and open every sibling.
//! Anyone learning or guessing the seed can derive `r` and do the same without a
//! threshold. Reusing encryption-proof nonce `r'` can reveal `r`, while reusing
//! disclosure-share proof nonces can reveal a participant's long-lived shares.
//! Both are confidentiality failures, not merely proof failures.
//!
//! The example uses a fast prototype proof backend so it can run as a normal
//! example. It uses the same Golden DKG and EHTDH1 public APIs as the full proof
//! backend.
//!
//! # Context policy
//!
//! * The **record ID** is storage metadata only. Distinct record IDs are not used
//!   as EHTDH1 associated data or outer AEAD associated data.
//! * The common **application associated data** describes the logical payload and
//!   is bound into every EHTDH1 ciphertext and every outer record encryption.
//! * The **request-specific decryption context** binds participant approval to one
//!   release request.
//! * The opaque **disclosure-group ID** is supplied by the application and binds
//!   the released shares to that application group.
//! * The [`SetupContext`](golden_ehtdh1::SetupContext) identifies the Golden setup
//!   that produced the keys and shares.
//!
//! # Why setup runs DKG twice
//!
//! The first DKG shares the joint decryption secret. The second shares zero so
//! its contributions cancel for one decryption context and disclosure group, but
//! not when contexts or groups are mixed.
//!
//! # Glossary
//!
//! * A **participant** is one of the three parties in Golden setup. Each holds a
//!   long-lived secret EHTDH1 share in protected participant storage.
//! * A **writer role** uses only the sealing key. In this deployment the same
//!   three TEEs also act as threshold participants, but the writer path never uses
//!   their participant secrets.
//! * The **threshold** is the number of valid disclosure-group shares needed to
//!   construct a group key. This example uses two out of three.
//! * **Golden DKG** creates the joint public key without one party choosing the
//!   final private key. EHTDH1 setup runs one decryption-key DKG and one zero-sharing
//!   DKG for context binding.
//! * A **sealing key** is the joint public key used by writers.
//! * An **unsealing share** wraps one participant's long-lived secret share.
//! * A **decryption precomputation** is the opaque, secret-bearing `x_i R` value a
//!   participant caches for a common `R`. It stays local and is never serialized.
//! * A **record ID** identifies storage but does not establish cryptographic
//!   disclosure-group membership. A trusted manifest authenticates the complete
//!   record envelope, including its ID and wrapped content key.
//! * A **content key** is a fresh 32-byte secret used to encrypt one record with
//!   XChaCha20Poly1305.
//! * An **EHTDH1 ciphertext** wraps one content key. Its proof uses fresh nonce
//!   `r'`; reuse of `r'` is a confidentiality failure.
//! * A **disclosure group** binds common `R` and associated data to a request
//!   context and opaque group ID. The application authenticates its members.
//! * A **disclosure-group decryption share** is a public, proof-bearing message
//!   issued with fresh share-proof randomness. It has canonical wire bytes.
//! * A **disclosure-group key** is reconstructed from a threshold set and opens
//!   any valid same-`R`/same-associated-data ciphertext. It is secret-bearing,
//!   remains in memory, and is never serialized.
//! * A **combiner** verifies disclosure-group shares against the public setup and
//!   constructs the group key only from a threshold set.
//! * The **HPKE-style split** means outer authenticated encryption handles each
//!   large value while EHTDH1 handles only its fixed-size content key.

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
    derive_context_session_id, material_from_dkg_outputs, Ciphertext, Combiner,
    DecryptionPrecomputation, DisclosureGroup, DisclosureGroupDecryptionShare, Ehtdh1Material,
    SealingKey, UnsealingShare,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use hkdf::Hkdf;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Concrete group used by this fast example.
type G = P256Backend;

/// Error type used by the example helpers.
type AppResult<T> = Result<T, Box<dyn Error>>;

/// Number of bytes in each fresh record content key.
const CONTENT_KEY_BYTES: usize = 32;
/// Number of bytes in an XChaCha20Poly1305 nonce.
const NONCE_BYTES: usize = 24;
/// Size of each example value.
const RECORD_BYTES: usize = 512 * 1024;

/// Stored form of one storage record ID and its encrypted value.
struct StoredRecord {
    /// Public storage identifier; deliberately not used as cryptographic AD.
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

    // Step 2. The writer role receives only canonical bytes for the public
    // sealing key. The same three TEEs later act as threshold participants, but
    // their participant secrets are not used on this writer path.
    let first = get(&materials, participants[0], "missing first participant")?;
    let public_key_bytes = to_wire_bytes(&first.sealing_key);
    let writer_key = from_wire_bytes::<SealingKey<G>>(&public_key_bytes)?;

    // Step 3. Derive the shared sealing seed and create one independently
    // randomized record per writer. Record IDs are storage metadata, while every
    // EHTDH1 ciphertext and outer AEAD uses the same application-level AD.
    let record_ids = [
        b"private-record/A".as_slice(),
        b"private-record/B".as_slice(),
        b"private-record/C".as_slice(),
    ];
    let application_associated_data = b"threshold-records/logical-private-payload/v1";
    let canonical_private_plaintext = vec![b'T'; RECORD_BYTES];
    // Fixed only to keep the example repeatable. Production clients sample a
    // uniformly random 256-bit client nonce.
    let client_nonce = Zeroizing::new([5u8; 32]);
    let transaction_sealing_seed =
        derive_transaction_sealing_seed(&client_nonce, &canonical_private_plaintext)?;
    let mut records = Vec::new();
    for (writer_index, record_id) in record_ids.iter().copied().enumerate() {
        // A separate writer RNG independently samples the content key, outer
        // XChaCha20Poly1305 nonce, and fresh EHTDH1 proof nonce r'. Reusing r'
        // across distinct proof statements would reveal seeded r and destroy
        // confidentiality for every ciphertext sharing it.
        let mut writer_rng = ChaCha20Rng::from_seed([2 + writer_index as u8; 32]);
        records.push(seal_record(
            &writer_key,
            record_id,
            application_associated_data,
            &canonical_private_plaintext,
            &transaction_sealing_seed,
            &mut writer_rng,
        )?);
    }

    // Trusted writer/storage infrastructure records a digest of each complete
    // envelope in an authenticated manifest. Production can use signed manifests
    // or authenticated storage; record IDs alone are not membership evidence.
    let authenticated_record_manifest = records
        .iter()
        .map(|record| {
            (
                record.record_id.clone(),
                authenticated_record_digest(record),
            )
        })
        .collect::<Vec<_>>();

    // Decode the three canonical ciphertexts as their eventual readers would.
    let wrapped_keys = records
        .iter()
        .map(|record| from_wire_bytes::<Ciphertext<G>>(&record.wrapped_content_key))
        .collect::<Result<Vec<_>, _>>()?;
    require(
        wrapped_keys.iter().all(|ciphertext| {
            ciphertext.ephemeral_public == wrapped_keys[0].ephemeral_public
                && ciphertext.associated_data() == application_associated_data
        }),
        "writers did not use common R and common associated data",
    )?;
    require(
        three_distinct(&wrapped_keys[0], &wrapped_keys[1], &wrapped_keys[2]),
        "complete EHTDH1 ciphertexts were not distinct",
    )?;
    require(
        three_distinct(
            &wrapped_keys[0].encrypted_payload,
            &wrapped_keys[1].encrypted_payload,
            &wrapped_keys[2].encrypted_payload,
        ),
        "wrapped content-key payloads were not distinct",
    )?;
    require(
        three_distinct(
            &wrapped_keys[0].encryption_point,
            &wrapped_keys[1].encryption_point,
            &wrapped_keys[2].encryption_point,
        ) && three_distinct(
            &wrapped_keys[0].challenge,
            &wrapped_keys[1].challenge,
            &wrapped_keys[2].challenge,
        ) && three_distinct(
            &wrapped_keys[0].response,
            &wrapped_keys[1].response,
            &wrapped_keys[2].response,
        ),
        "EHTDH1 proof fields were not distinct",
    )?;
    require(
        three_distinct(
            &records[0].encrypted_value,
            &records[1].encrypted_value,
            &records[2].encrypted_value,
        ) && three_distinct(&records[0].nonce, &records[1].nonce, &records[2].nonce),
        "outer ciphertexts or XChaCha20Poly1305 nonces were not distinct",
    )?;

    // Step 4. Ciphertexts now exist, but no request-specific context or group has
    // been formed. Each participant calls precompute exactly once for common R.
    let common_ephemeral_public = wrapped_keys[0].ephemeral_public;
    let mut local_precomputations = Vec::<(UnsealingShare<G>, DecryptionPrecomputation<G>)>::new();
    for material in materials.values() {
        let unsealing_share = UnsealingShare::new(material.secret_share.clone());
        let precomputation =
            unsealing_share.precompute_for_ephemeral_public(&common_ephemeral_public)?;
        // This secret-bearing (UnsealingShare, DecryptionPrecomputation) tuple
        // remains sealed/protected in TEE storage. It is never serialized.
        local_precomputations.push((unsealing_share, precomputation));
    }

    // Step 5. Later, the application authenticates every complete record envelope
    // against trusted storage before treating it as an intended member.
    // DisclosureGroup itself does not authenticate membership.
    require(
        records.iter().zip(&authenticated_record_manifest).all(
            |(record, (authenticated_id, authenticated_digest))| {
                record.record_id == *authenticated_id
                    && authenticated_record_digest(record) == *authenticated_digest
            },
        ),
        "application disclosure-group membership authentication failed",
    )?;
    // These values are deliberately defined only when this release is requested.
    let opaque_disclosure_group_id = b"app-group:7f49b28d6a1c";
    let request_decryption_context = b"request:2026-08-03T12:00:00Z:4e91";
    let disclosure_group = DisclosureGroup::new(
        common_ephemeral_public,
        application_associated_data,
        request_decryption_context,
        opaque_disclosure_group_id,
    )?;

    // Each participant uses fresh share-proof randomness, then exchanges only a
    // canonical DisclosureGroupDecryptionShare. Reusing the two proof nonces
    // across distinct challenges would reveal that participant's x_i and z_i.
    // Local precomputations stay in TEE storage and are not part of the wire
    // message. Fixed seeds below exist only to keep this one release repeatable.
    let mut disclosure_shares = Vec::<DisclosureGroupDecryptionShare<G>>::new();
    for (participant_offset, (unsealing_share, precomputation)) in
        local_precomputations.iter().enumerate()
    {
        let mut share_proof_rng = ChaCha20Rng::from_seed([6 + participant_offset as u8; 32]);
        let share = unsealing_share.issue_disclosure_group_share(
            &mut share_proof_rng,
            &first.setup_context,
            precomputation,
            &disclosure_group,
        )?;
        disclosure_shares.push(from_wire_bytes::<DisclosureGroupDecryptionShare<G>>(
            &to_wire_bytes(&share),
        )?);
    }

    let combiner = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())?;

    // Step 6. One disclosure-group share is below the two-of-three threshold.
    require(
        combiner
            .combine_disclosure_group_exact(&disclosure_group, &disclosure_shares[..1])
            .is_err(),
        "one disclosure-group share unexpectedly constructed a group key",
    )?;

    // One exact threshold set reconstructs one secret-bearing group key. The key
    // remains in local memory and is intentionally never serialized.
    let threshold_shares = [disclosure_shares[0].clone(), disclosure_shares[1].clone()];
    let disclosure_group_key =
        combiner.combine_disclosure_group_exact(&disclosure_group, &threshold_shares)?;

    // The same group key opens every valid same-R/same-AD EHTDH1 ciphertext.
    // Application membership authentication above is therefore mandatory.
    for (record, wrapped_key) in records.iter().zip(&wrapped_keys) {
        let content_key = Zeroizing::new(disclosure_group_key.open(wrapped_key)?);
        let opened = open_record(record, &content_key, application_associated_data)?;
        require(
            opened == canonical_private_plaintext,
            "a disclosure-group member opened to the wrong private payload",
        )?;
    }

    let record_bytes = records.len() * RECORD_BYTES;
    let wrapped_bytes = records.len() * CONTENT_KEY_BYTES;
    println!("Golden setup has 3 participants and a threshold of 2.");
    println!(
        "Three writers encrypted the same logical private payload into {} storage records.",
        records.len()
    );
    println!("All records used common application AD and common seeded r/R.");
    println!("Each writer used an independent content key, outer nonce, and fresh proof nonce r'.");
    println!(
        "All three complete EHTDH1 ciphertexts, encrypted payloads, and proof fields were distinct."
    );
    println!(
        "In the HPKE-style split, AEAD encrypted {record_bytes} record bytes and EHTDH1 wrapped \
         {wrapped_bytes} bytes total."
    );
    println!("Participants precomputed once before the request-specific group existed.");
    println!("All three disclosure shares completed canonical wire round-trips.");
    println!("One share was rejected; one exact threshold set constructed the group key.");
    println!("The same non-serialized group key opened all three records to the same payload.");
    println!("WARNING: a disclosure-group key opens ANY valid ciphertext with the same R and AD.");
    println!(
        "APPLICATION REQUIREMENT: authenticate complete record envelopes before releasing shares."
    );
    println!(
        "CONFIDENTIALITY WARNING: seed or shared-mask exposure opens every sibling without a \
         threshold."
    );
    println!(
        "CONFIDENTIALITY WARNING: reusing encryption or share-proof nonces reveals secret \
         scalars."
    );

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
    let mut dealings = BTreeMap::<ParticipantIndex, DkgDealing<G>>::new();
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
            .collect::<BTreeMap<ParticipantIndex, DealerMessage<G>>>();
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

/// Runs both DKG sessions and gives each participant its EHTDH1 setup.
fn run_golden_setup(
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

    let mut materials = BTreeMap::new();
    for participant in participants {
        materials.insert(
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

/// Derives the shared sealing seed from a client nonce and canonical plaintext.
fn derive_transaction_sealing_seed(
    client_nonce: &[u8; 32],
    canonical_private_plaintext: &[u8],
) -> AppResult<Zeroizing<[u8; 32]>> {
    let private_plaintext_digest = Sha256::digest(canonical_private_plaintext);
    let mut input_key_material = Zeroizing::new([0u8; 64]);
    input_key_material[..32].copy_from_slice(client_nonce);
    input_key_material[32..].copy_from_slice(&private_plaintext_digest);

    let hkdf = Hkdf::<Sha256>::new(
        Some(b"threshold-record-transaction-seed-v1"),
        input_key_material.as_ref(),
    );
    let mut transaction_sealing_seed = Zeroizing::new([0u8; 32]);
    hkdf.expand(
        b"transaction-sealing-seed",
        transaction_sealing_seed.as_mut(),
    )
    .map_err(|_| io::Error::other("transaction sealing seed derivation failed"))?;
    Ok(transaction_sealing_seed)
}

/// Encrypts one large value and wraps only its fresh content key with EHTDH1.
fn seal_record(
    sealing_key: &SealingKey<G>,
    record_id: &[u8],
    application_associated_data: &[u8],
    value: &[u8],
    transaction_sealing_seed: &[u8; 32],
    rng: &mut ChaCha20Rng,
) -> AppResult<StoredRecord> {
    let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut *content_key);
    rng.fill_bytes(&mut nonce);

    // The outer cipher handles the large value. All writers bind the same
    // application-level AD; the distinct storage record ID is not AEAD AD.
    let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
        .map_err(|_| io::Error::other("invalid content key"))?;
    let encrypted_value = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: value,
                aad: application_associated_data,
            },
        )
        .map_err(|_| io::Error::other("record encryption failed"))?;
    // EHTDH1 handles only the fixed-size content key and binds the same common
    // application-level AD. The seeded r fixes R; this RNG supplies fresh r'.
    let wrapped_content_key = sealing_key.seal_bytes_with_associated_data_and_seed(
        rng,
        content_key.as_ref(),
        application_associated_data,
        transaction_sealing_seed,
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

/// Decrypts one stored value with a content key opened by the disclosure-group key.
fn open_record(
    record: &StoredRecord,
    content_key: &[u8],
    application_associated_data: &[u8],
) -> AppResult<Vec<u8>> {
    require(
        content_key.len() == CONTENT_KEY_BYTES,
        "opened content key has the wrong length",
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| io::Error::other("invalid opened content key"))?;
    // The outer cipher checks the same application-level AD used by every writer.
    // The record ID remains separate storage metadata.
    cipher
        .decrypt(
            &XNonce::from(record.nonce),
            Payload {
                msg: &record.encrypted_value,
                aad: application_associated_data,
            },
        )
        .map_err(|_| io::Error::other("record decryption failed").into())
}

/// Hashes the complete stored envelope for an authenticated membership manifest.
fn authenticated_record_digest(record: &StoredRecord) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"threshold-record-envelope-v1");
    for field in [
        record.record_id.as_slice(),
        record.nonce.as_slice(),
        record.encrypted_value.as_slice(),
        record.wrapped_content_key.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

/// Reports whether three values are pairwise distinct.
fn three_distinct<T: PartialEq>(first: &T, second: &T, third: &T) -> bool {
    first != second && first != third && second != third
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
