//! Private canonical encoding for opaque dealer broadcasts.

use crate::{
    main_golden::effective_message, DkgConfig, DkgInstanceKind, Error, EvrfMessage, FieldByteOrder,
    GoldenGroup, GoldenScalar, ParticipantIndex, Result, TranscriptBuilder, TranscriptRoot,
    PROTOCOL_VERSION,
};

const DEALER_MESSAGE_MAGIC: &[u8; 17] = b"golden-dkg-dealer";
const DEALER_MESSAGE_CODEC_VERSION: u32 = 1;
const DEALER_MESSAGE_ROOT_PREFIX: &[u8] = b"golden-dkg/dealer-message-root/v1";

pub(crate) const MAX_DEALER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DealerMessageData<G: GoldenGroup> {
    pub(crate) dealer: ParticipantIndex,
    pub(crate) instances: Vec<DealerMessageInstance<G>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DealerMessageInstance<G: GoldenGroup> {
    pub(crate) nonce: crate::DealerMessageNonce,
    pub(crate) effective_message: EvrfMessage,
    pub(crate) commitment_coefficients: Vec<G::Element>,
    pub(crate) receivers: Vec<DealerMessageReceiver<G>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DealerMessageReceiver<G: GoldenGroup> {
    pub(crate) participant: ParticipantIndex,
    pub(crate) public_key: G::Element,
    pub(crate) share_commitment: G::Element,
    pub(crate) pad_commitment: G::Element,
    pub(crate) encrypted_share: G::Scalar,
}

pub(crate) fn encoded_prefix_len<G: GoldenGroup>(config: &DkgConfig<G>) -> Result<usize> {
    let curve_id_len = G::CURVE_ID.len();
    u64::try_from(curve_id_len).map_err(|_| Error::DealerMessageTooLarge)?;

    let mut len = DEALER_MESSAGE_MAGIC.len();
    len = checked_add(len, core::mem::size_of::<u64>())?;
    len = checked_add(len, core::mem::size_of::<u32>())?;
    len = checked_add(len, core::mem::size_of::<u32>())?;
    len = checked_add(len, curve_id_len)?;
    len = checked_add(len, 32)?;
    len = checked_add(len, core::mem::size_of::<u32>())?;

    let receiver_count = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::DealerMessageTooLarge)?;
    let receiver_bytes = checked_add(G::ELEMENT_REPR_BYTES, G::Scalar::REPR_BYTES)?;
    let receivers_bytes = checked_mul(receiver_count, receiver_bytes)?;

    for kind in config.instances() {
        len = checked_add(len, crate::DEALER_MESSAGE_NONCE_BYTES)?;
        let physical_coefficients = match kind {
            DkgInstanceKind::Random => config.threshold(),
            DkgInstanceKind::Zero => config
                .threshold()
                .checked_sub(1)
                .ok_or(Error::DealerMessageTooLarge)?,
        };
        len = checked_add(
            len,
            checked_mul(physical_coefficients, G::ELEMENT_REPR_BYTES)?,
        )?;
        len = checked_add(len, receivers_bytes)?;
    }

    Ok(len)
}

pub(crate) fn dealer_message_root<G: GoldenGroup>(
    config: &DkgConfig<G>,
    message: &DealerMessageData<G>,
) -> Result<TranscriptRoot> {
    validate_shape(config, message)?;

    let mut transcript =
        TranscriptBuilder::with_prefix(DEALER_MESSAGE_ROOT_PREFIX, b"public-statement");
    transcript.u32(b"protocol-version", PROTOCOL_VERSION);
    transcript.bytes(b"configuration-root", &config.root());
    transcript.participant(b"dealer", message.dealer);
    transcript.element::<G>(
        b"dealer-public-key",
        config.registry().public_key(message.dealer)?,
    );
    transcript.usize(b"instance-count", message.instances.len());

    for (position, (instance, kind)) in message.instances.iter().zip(config.instances()).enumerate()
    {
        transcript.usize(b"instance-position", position);
        transcript.u32(
            b"instance-kind",
            match kind {
                DkgInstanceKind::Random => 0,
                DkgInstanceKind::Zero => 1,
            },
        );
        transcript.bytes(b"effective-message", &instance.effective_message.0);
        transcript.usize(
            b"commitment-coefficient-count",
            instance.commitment_coefficients.len(),
        );
        for coefficient in &instance.commitment_coefficients {
            transcript.element::<G>(b"commitment-coefficient", coefficient);
        }
        transcript.usize(b"receiver-count", instance.receivers.len());
        for (receiver_position, receiver) in instance.receivers.iter().enumerate() {
            transcript.usize(b"receiver-position", receiver_position);
            transcript.participant(b"receiver", receiver.participant);
            transcript.element::<G>(b"receiver-public-key", &receiver.public_key);
            transcript.element::<G>(b"share-commitment", &receiver.share_commitment);
            transcript.element::<G>(b"pad-commitment", &receiver.pad_commitment);
            transcript_protocol_scalar::<G>(
                &mut transcript,
                b"encrypted-share",
                &receiver.encrypted_share,
            )?;
        }
    }

    Ok(transcript.root())
}

pub(crate) fn encode_dealer_message<G: GoldenGroup>(
    config: &DkgConfig<G>,
    message: &DealerMessageData<G>,
    proof: &[u8],
) -> Result<Vec<u8>> {
    validate_shape(config, message)?;
    if config.registry().len() == 1 && !proof.is_empty() {
        return Err(Error::ProofGenerationFailed);
    }

    let prefix_len = encoded_prefix_len::<G>(config)?;
    let total_len = checked_add(prefix_len, proof.len())?;
    if total_len > MAX_DEALER_MESSAGE_BYTES {
        return Err(Error::DealerMessageTooLarge);
    }

    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_len)
        .map_err(|_| Error::DealerMessageTooLarge)?;
    encoded.extend_from_slice(DEALER_MESSAGE_MAGIC);
    encoded.extend_from_slice(&DEALER_MESSAGE_CODEC_VERSION.to_be_bytes());
    encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    encoded.extend_from_slice(
        &u64::try_from(G::CURVE_ID.len())
            .map_err(|_| Error::DealerMessageTooLarge)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(G::CURVE_ID.as_bytes());
    encoded.extend_from_slice(&config.root());
    encoded.extend_from_slice(&message.dealer.get().to_be_bytes());

    for (instance, kind) in message.instances.iter().zip(config.instances()) {
        encoded.extend_from_slice(&instance.nonce.0);
        let coefficients = match kind {
            DkgInstanceKind::Random => instance.commitment_coefficients.as_slice(),
            DkgInstanceKind::Zero => &instance.commitment_coefficients[1..],
        };
        for coefficient in coefficients {
            encoded.extend_from_slice(G::encode_element(coefficient).as_ref());
        }
        for receiver in &instance.receivers {
            encoded.extend_from_slice(G::encode_element(&receiver.pad_commitment).as_ref());
            encoded.extend_from_slice(&encode_protocol_scalar(&receiver.encrypted_share)?);
        }
    }
    encoded.extend_from_slice(proof);

    if encoded.len() != total_len {
        return Err(Error::ProofGenerationFailed);
    }
    Ok(encoded)
}

/// Encode a scalar in the fixed big-endian dealer-message protocol order.
fn encode_protocol_scalar<S: GoldenScalar>(scalar: &S) -> Result<Vec<u8>> {
    let mut encoded = scalar.to_repr().as_ref().to_vec();
    if encoded.len() != S::REPR_BYTES {
        return Err(Error::InvalidEncoding);
    }
    if S::repr_byte_order() == FieldByteOrder::LittleEndian {
        encoded.reverse();
    }
    Ok(encoded)
}

fn transcript_protocol_scalar<G: GoldenGroup>(
    transcript: &mut TranscriptBuilder,
    label: &'static [u8],
    scalar: &G::Scalar,
) -> Result<()> {
    transcript.bytes(label, &encode_protocol_scalar(scalar)?);
    Ok(())
}

fn validate_shape<G: GoldenGroup>(
    config: &DkgConfig<G>,
    message: &DealerMessageData<G>,
) -> Result<()> {
    config
        .registry()
        .public_key(message.dealer)
        .map_err(|_| Error::ProofGenerationFailed)?;
    if message.instances.len() != config.instances().len() {
        return Err(Error::ProofGenerationFailed);
    }

    let receiver_count = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofGenerationFailed)?;
    for (position, (instance, configured_kind)) in
        message.instances.iter().zip(config.instances()).enumerate()
    {
        if instance.commitment_coefficients.len() != config.threshold()
            || instance.receivers.len() != receiver_count
            || instance.effective_message
                != effective_message(
                    config.root(),
                    message.dealer,
                    position,
                    *configured_kind,
                    instance.nonce,
                )
        {
            return Err(Error::ProofGenerationFailed);
        }
        if matches!(configured_kind, DkgInstanceKind::Zero)
            && !bool::from(G::is_identity(&instance.commitment_coefficients[0]))
        {
            return Err(Error::ProofGenerationFailed);
        }

        for (receiver, (participant, public_key)) in instance.receivers.iter().zip(
            config
                .registry()
                .entries()
                .filter(|(participant, _)| *participant != message.dealer),
        ) {
            if receiver.participant != participant || receiver.public_key != *public_key {
                return Err(Error::ProofGenerationFailed);
            }
        }
    }
    Ok(())
}

fn checked_add(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_add(rhs).ok_or(Error::DealerMessageTooLarge)
}

fn checked_mul(lhs: usize, rhs: usize) -> Result<usize> {
    lhs.checked_mul(rhs).ok_or(Error::DealerMessageTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::{GoldenScalar, ParticipantRegistry, SessionId};

    fn participant(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    fn config(kind: DkgInstanceKind, participants: u32) -> DkgConfig<TinyGroup> {
        let registry = ParticipantRegistry::new(
            (1..=participants)
                .map(|value| (participant(value), scalar(u64::from(value))))
                .collect(),
        )
        .unwrap();
        DkgConfig::new(1, SessionId([4; 32]), registry, vec![kind]).unwrap()
    }

    fn message(config: &DkgConfig<TinyGroup>) -> DealerMessageData<TinyGroup> {
        let dealer = participant(1);
        let nonce = crate::DealerMessageNonce([9; 32]);
        let kind = config.instance(0).unwrap();
        DealerMessageData {
            dealer,
            instances: vec![DealerMessageInstance {
                nonce,
                effective_message: effective_message(config.root(), dealer, 0, kind, nonce),
                commitment_coefficients: vec![match kind {
                    DkgInstanceKind::Random => scalar(5),
                    DkgInstanceKind::Zero => TinyScalar::zero(),
                }],
                receivers: config
                    .registry()
                    .entries()
                    .filter(|(participant, _)| *participant != dealer)
                    .map(|(participant, public_key)| DealerMessageReceiver {
                        participant,
                        public_key: *public_key,
                        share_commitment: scalar(7),
                        pad_commitment: scalar(8),
                        encrypted_share: scalar(9),
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn canonical_encoding_is_configuration_shaped() {
        for kind in [DkgInstanceKind::Random, DkgInstanceKind::Zero] {
            let config = config(kind, 2);
            let message = message(&config);
            let proof = [0xaa, 0xbb];
            let encoded = encode_dealer_message(&config, &message, &proof).unwrap();

            let mut expected = Vec::new();
            expected.extend_from_slice(DEALER_MESSAGE_MAGIC);
            expected.extend_from_slice(&DEALER_MESSAGE_CODEC_VERSION.to_be_bytes());
            expected.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            expected.extend_from_slice(&(GOLDEN_TEST_CURVE_ID.len() as u64).to_be_bytes());
            expected.extend_from_slice(GOLDEN_TEST_CURVE_ID.as_bytes());
            expected.extend_from_slice(&config.root());
            expected.extend_from_slice(&1u32.to_be_bytes());
            expected.extend_from_slice(&[9; 32]);
            if kind == DkgInstanceKind::Random {
                expected.push(5);
            }
            expected.extend_from_slice(&[8, 9]);
            expected.extend_from_slice(&proof);

            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn protocol_scalar_encoding_uses_canonical_big_endian_bytes() {
        let encoded = encode_protocol_scalar(&scalar(9)).unwrap();

        assert_eq!(encoded, [9]);
    }

    #[test]
    fn whole_message_limit_includes_the_opaque_proof_suffix() {
        let config = config(DkgInstanceKind::Random, 2);
        let message = message(&config);
        let prefix_len = encoded_prefix_len::<TinyGroup>(&config).unwrap();
        let exact_proof = vec![0u8; MAX_DEALER_MESSAGE_BYTES - prefix_len];

        assert_eq!(
            encode_dealer_message(&config, &message, &exact_proof)
                .unwrap()
                .len(),
            MAX_DEALER_MESSAGE_BYTES
        );
        assert_eq!(
            encode_dealer_message(
                &config,
                &message,
                &vec![0u8; MAX_DEALER_MESSAGE_BYTES - prefix_len + 1],
            )
            .unwrap_err(),
            Error::DealerMessageTooLarge
        );
    }

    #[test]
    fn dealer_root_binds_logical_public_values() {
        let config = config(DkgInstanceKind::Zero, 2);
        let message = message(&config);
        let root = dealer_message_root(&config, &message).unwrap();

        let mut changed = message.clone();
        changed.instances[0].receivers[0].share_commitment = scalar(6);
        assert_ne!(root, dealer_message_root(&config, &changed).unwrap());
    }

    #[test]
    fn single_participant_rejects_a_nonempty_proof_suffix() {
        let config = config(DkgInstanceKind::Zero, 1);
        let message = message(&config);

        assert_eq!(
            encode_dealer_message(&config, &message, &[1]).unwrap_err(),
            Error::ProofGenerationFailed
        );
    }

    const GOLDEN_TEST_CURVE_ID: &str = "golden-test-tiny-v1";
}
