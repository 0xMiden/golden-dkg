//! Three-party threshold encryption for stored records.
//!
//! This follows the node Phase 2 shape. A fast Golden proof backend runs the
//! two DKG sessions required by EHTDH1 setup. A writer encrypts each large
//! record with XChaCha20-Poly1305 under a fresh content key, then EHTDH1 wraps
//! only that 32-byte key. Any two of the three parties can later open the
//! content key for one chosen record context.

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

type G = P256Backend;
type Proof = ShareOpeningBatchedProof<G>;
type AppResult<T> = Result<T, Box<dyn Error>>;

const CONTENT_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const RECORD_BYTES: usize = 512 * 1024;

struct StoredRecord {
    context: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    encrypted_value: Vec<u8>,
    wrapped_content_key: Vec<u8>,
}

fn main() -> AppResult<()> {
    let participants = [idx(1)?, idx(2)?, idx(3)?];
    // Fixed seeds keep the example repeatable. Production callers use an OS RNG.
    let mut setup_rng = ChaCha20Rng::from_seed([1u8; 32]);
    let materials = run_golden_setup(&participants, &mut setup_rng)?;
    check_shared_setup(&materials)?;

    let first = get(&materials, participants[0], "missing first participant")?;
    let public_key_bytes = to_wire_bytes(&first.sealing_key);
    let writer_key = from_wire_bytes::<SealingKey<G>>(&public_key_bytes)?;

    // Each application key is the context bound into both encryption layers.
    let inputs = [
        (b"private-record/A".as_slice(), vec![b'A'; RECORD_BYTES]),
        (b"private-record/B".as_slice(), vec![b'B'; RECORD_BYTES]),
        (b"private-record/C".as_slice(), vec![b'C'; RECORD_BYTES]),
    ];
    let mut writer_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let mut records = Vec::new();
    for (context, value) in inputs {
        records.push(seal_record(&writer_key, context, &value, &mut writer_rng)?);
    }

    let chosen = &records[1];
    let wrapped_key = from_wire_bytes::<Ciphertext<G>>(&chosen.wrapped_content_key)?;
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let shares = make_shares(&materials, &wrapped_key, &chosen.context, &mut share_rng)?;
    let combiner = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())?;

    require(
        combiner
            .combine_exact_with_associated_data(
                &wrapped_key,
                &chosen.context,
                &chosen.context,
                &shares[..1],
            )
            .is_err(),
        "one share unexpectedly opened the content key",
    )?;

    for pair in [[0, 1], [0, 2], [1, 2]] {
        let selected = [shares[pair[0]].clone(), shares[pair[1]].clone()];
        let content_key = Zeroizing::new(combiner.combine_exact_with_associated_data(
            &wrapped_key,
            &chosen.context,
            &chosen.context,
            &selected,
        )?);
        let opened = open_record(chosen, &content_key)?;
        require(
            opened.len() == RECORD_BYTES && opened.iter().all(|byte| *byte == b'B'),
            "a valid quorum opened the wrong value",
        )?;
    }

    let other = &records[0];
    let other_wrapped_key = from_wire_bytes::<Ciphertext<G>>(&other.wrapped_content_key)?;
    require(
        combiner
            .combine_exact_with_associated_data(
                &other_wrapped_key,
                &other.context,
                &other.context,
                &shares[..2],
            )
            .is_err(),
        "shares for one context opened another record",
    )?;

    let record_bytes = records.len() * RECORD_BYTES;
    let wrapped_bytes = records.len() * CONTENT_KEY_BYTES;
    println!("Golden setup: 3 parties with a threshold of 2.");
    println!("Writer stored {} context-keyed records.", records.len());
    println!(
        "HPKE-style split: AEAD encrypted {record_bytes} record bytes; EHTDH1 wrapped \
         {wrapped_bytes} bytes total."
    );
    println!("Each EHTDH1 ciphertext wraps 32 bytes, independent of record size.");
    println!("The parties chose private-record/B and exchanged canonical shares.");
    println!("All three 2-of-3 pairs opened private-record/B.");
    println!("One share and shares from another context were rejected.");

    Ok(())
}

fn idx(value: u32) -> AppResult<ParticipantIndex> {
    Ok(ParticipantIndex::new(value)?)
}

fn scalar(value: u64) -> AppResult<P256Scalar> {
    Ok(P256Scalar::from_u64(value)?)
}

fn identity_secret(participant: ParticipantIndex) -> AppResult<P256Scalar> {
    scalar(100 + u64::from(participant.get()))
}

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

fn run_dkg(
    participants: &[ParticipantIndex; 3],
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
    zero_sharing: bool,
) -> AppResult<BTreeMap<ParticipantIndex, DkgOutput<G>>> {
    let mut dealings = BTreeMap::<ParticipantIndex, DkgDealing<G, Proof>>::new();
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

fn run_golden_setup(
    participants: &[ParticipantIndex; 3],
    rng: &mut ChaCha20Rng,
) -> AppResult<BTreeMap<ParticipantIndex, Ehtdh1Material<G>>> {
    let decryption_config = dkg_config(participants, SessionId([42u8; 32]))?;
    let context_config = dkg_config(
        participants,
        derive_context_session_id(decryption_config.session_id),
    )?;
    let decryption_outputs = run_dkg(participants, &decryption_config, rng, false)?;
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

fn seal_record(
    sealing_key: &SealingKey<G>,
    context: &[u8],
    value: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<StoredRecord> {
    let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_BYTES]);
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut *content_key);
    rng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(content_key.as_ref())
        .map_err(|_| io::Error::other("invalid content key"))?;
    let encrypted_value = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: value,
                aad: context,
            },
        )
        .map_err(|_| io::Error::other("record encryption failed"))?;
    let wrapped_content_key =
        sealing_key.seal_bytes_with_associated_data(rng, content_key.as_ref(), context)?;
    require(
        wrapped_content_key.encrypted_payload.len() == CONTENT_KEY_BYTES,
        "EHTDH1 wrapped more than the content key",
    )?;

    Ok(StoredRecord {
        context: context.to_vec(),
        nonce,
        encrypted_value,
        wrapped_content_key: to_wire_bytes(&wrapped_content_key),
    })
}

fn make_shares(
    materials: &BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
    wrapped_key: &Ciphertext<G>,
    context: &[u8],
    rng: &mut ChaCha20Rng,
) -> AppResult<Vec<DecryptionShare<G>>> {
    let mut shares = Vec::new();
    for material in materials.values() {
        let share = UnsealingShare::new(material.secret_share.clone())
            .decrypt_share_with_associated_data(
                rng,
                &material.setup_context,
                wrapped_key,
                context,
                context,
            )?;
        shares.push(from_wire_bytes(&to_wire_bytes(&share))?);
    }
    Ok(shares)
}

fn open_record(record: &StoredRecord, content_key: &[u8]) -> AppResult<Vec<u8>> {
    require(
        content_key.len() == CONTENT_KEY_BYTES,
        "opened content key has the wrong length",
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| io::Error::other("invalid opened content key"))?;
    cipher
        .decrypt(
            &XNonce::from(record.nonce),
            Payload {
                msg: &record.encrypted_value,
                aad: &record.context,
            },
        )
        .map_err(|_| io::Error::other("record decryption failed").into())
}

fn get<'a, K: Ord, V>(
    values: &'a BTreeMap<K, V>,
    key: K,
    message: &'static str,
) -> AppResult<&'a V> {
    values
        .get(&key)
        .ok_or_else(|| io::Error::other(message).into())
}

fn require(condition: bool, message: &'static str) -> AppResult<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
