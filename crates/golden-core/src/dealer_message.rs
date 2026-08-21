//! Private canonical encoding for opaque dealer broadcasts.

use crate::{
    main_golden::effective_message, DealerMessageError, DealerProofStatement, DkgConfig,
    DkgInstanceKind, Error, EvrfMessage, FeldmanCommitment, FieldByteOrder, GoldenGroup,
    GoldenScalar, ParticipantIndex, Result, TranscriptBuilder, TranscriptRoot, PROTOCOL_VERSION,
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

/// One privately parsed opaque dealer message and its flat proof input.
pub(crate) struct ParsedDealerMessage<G: GoldenGroup> {
    pub(crate) message: DealerMessageData<G>,
    pub(crate) statement: DealerProofStatement<G>,
    pub(crate) proof: Vec<u8>,
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

/// Parse and publicly preflight one exact configuration-shaped message.
///
/// This does not interpret the remaining proof suffix. Callers can therefore
/// validate every public relation in a candidate set before invoking any proof
/// parser through [`crate::DealerProofSystem`].
pub(crate) fn parse_dealer_message<G>(
    config: &DkgConfig<G>,
    expected_dealer: ParticipantIndex,
    encoded: &[u8],
) -> core::result::Result<ParsedDealerMessage<G>, DealerMessageError>
where
    G: GoldenGroup,
{
    if encoded.len() > MAX_DEALER_MESSAGE_BYTES {
        return Err(DealerMessageError::TooLarge {
            actual: encoded.len(),
            maximum: MAX_DEALER_MESSAGE_BYTES,
        });
    }

    let required_prefix =
        encoded_prefix_len::<G>(config).map_err(|_| DealerMessageError::TooLarge {
            actual: encoded.len(),
            maximum: MAX_DEALER_MESSAGE_BYTES,
        })?;
    if required_prefix > MAX_DEALER_MESSAGE_BYTES {
        return Err(DealerMessageError::TooLarge {
            actual: required_prefix,
            maximum: MAX_DEALER_MESSAGE_BYTES,
        });
    }

    let mut reader = DealerMessageReader::new(encoded);
    if reader.read_exact(DEALER_MESSAGE_MAGIC.len())? != DEALER_MESSAGE_MAGIC.as_slice()
        || reader.read_u32()? != DEALER_MESSAGE_CODEC_VERSION
        || reader.read_u32()? != PROTOCOL_VERSION
    {
        return Err(DealerMessageError::Malformed);
    }
    let curve_id_len = reader.read_u64_as_usize()?;
    if curve_id_len != G::CURVE_ID.len()
        || reader.read_exact(curve_id_len)? != G::CURVE_ID.as_bytes()
    {
        return Err(DealerMessageError::Malformed);
    }
    let configuration_root = config.root();
    if reader.read_exact(32)? != configuration_root.as_slice() {
        return Err(DealerMessageError::ConfigurationMismatch);
    }
    let encoded_dealer =
        ParticipantIndex::new(reader.read_u32()?).map_err(|_| DealerMessageError::Malformed)?;
    if encoded_dealer != expected_dealer {
        return Err(DealerMessageError::DealerMismatch {
            encoded: encoded_dealer,
        });
    }
    config
        .identity_public_key(encoded_dealer)
        .ok_or(DealerMessageError::InvalidPublicRelations)?;
    if encoded.len() < required_prefix {
        return Err(DealerMessageError::Malformed);
    }

    let receivers_per_instance = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(DealerMessageError::InvalidPublicRelations)?;
    let mut instances = Vec::new();
    instances
        .try_reserve_exact(config.instances().len())
        .map_err(|_| DealerMessageError::Malformed)?;

    for (position, kind) in config.instances().iter().copied().enumerate() {
        let mut nonce_bytes = [0u8; crate::DEALER_MESSAGE_NONCE_BYTES];
        nonce_bytes.copy_from_slice(reader.read_exact(crate::DEALER_MESSAGE_NONCE_BYTES)?);
        let nonce = crate::DealerMessageNonce(nonce_bytes);
        let effective_message =
            effective_message(config.root(), encoded_dealer, position, kind, nonce);

        let physical_coefficient_count = match kind {
            DkgInstanceKind::Random => config.threshold(),
            DkgInstanceKind::Zero => config
                .threshold()
                .checked_sub(1)
                .ok_or(DealerMessageError::InvalidPublicRelations)?,
        };
        let mut logical_coefficients = Vec::new();
        logical_coefficients
            .try_reserve_exact(config.threshold())
            .map_err(|_| DealerMessageError::Malformed)?;
        if matches!(kind, DkgInstanceKind::Zero) {
            logical_coefficients.push(G::identity());
        }
        for _ in 0..physical_coefficient_count {
            logical_coefficients.push(decode_protocol_element::<G>(
                reader.read_exact(G::ELEMENT_REPR_BYTES)?,
            )?);
        }
        if logical_coefficients.len() != config.threshold() {
            return Err(DealerMessageError::InvalidPublicRelations);
        }
        let commitment = match kind {
            DkgInstanceKind::Random => FeldmanCommitment::<G>::from_coefficients(
                clone_elements_fallibly(&logical_coefficients)?,
            )
            .map_err(|_| DealerMessageError::InvalidPublicRelations)?,
            DkgInstanceKind::Zero => FeldmanCommitment::<G>::from_zero_tail(
                clone_elements_fallibly(&logical_coefficients[1..])?,
            ),
        };

        let mut receivers = Vec::new();
        receivers
            .try_reserve_exact(receivers_per_instance)
            .map_err(|_| DealerMessageError::Malformed)?;
        for (participant, public_key) in config
            .registry()
            .entries()
            .filter(|(participant, _)| *participant != encoded_dealer)
        {
            let pad_commitment =
                decode_protocol_element::<G>(reader.read_exact(G::ELEMENT_REPR_BYTES)?)?;
            if bool::from(G::is_identity(&pad_commitment)) {
                return Err(DealerMessageError::InvalidPublicRelations);
            }
            let encrypted_share =
                decode_protocol_scalar::<G::Scalar>(reader.read_exact(G::Scalar::REPR_BYTES)?)?;
            let share_commitment = commitment
                .public_key_share(participant)
                .map_err(|_| DealerMessageError::InvalidPublicRelations)?;
            let encrypted_commitment = G::mul_generator(&encrypted_share);
            let expected_encrypted_commitment = G::add(&share_commitment, &pad_commitment);
            if encrypted_commitment != expected_encrypted_commitment {
                return Err(DealerMessageError::InvalidPublicRelations);
            }
            receivers.push(DealerMessageReceiver {
                participant,
                public_key: public_key.clone(),
                share_commitment,
                pad_commitment,
                encrypted_share,
            });
        }
        if receivers.len() != receivers_per_instance {
            return Err(DealerMessageError::InvalidPublicRelations);
        }
        instances.push(DealerMessageInstance {
            nonce,
            effective_message,
            commitment_coefficients: logical_coefficients,
            receivers,
        });
    }

    if reader.position != required_prefix {
        return Err(DealerMessageError::Malformed);
    }
    let proof_suffix = reader.remaining();
    if config.registry().len() == 1 && !proof_suffix.is_empty() {
        return Err(DealerMessageError::Malformed);
    }
    let mut proof = Vec::new();
    proof
        .try_reserve_exact(proof_suffix.len())
        .map_err(|_| DealerMessageError::Malformed)?;
    proof.extend_from_slice(proof_suffix);
    let message = DealerMessageData {
        dealer: encoded_dealer,
        instances,
    };
    let message_root = dealer_message_root(config, &message)
        .map_err(|_| DealerMessageError::InvalidPublicRelations)?;
    let statement = statement_from_message(config, &message, message_root)
        .map_err(|_| DealerMessageError::InvalidPublicRelations)?;

    Ok(ParsedDealerMessage {
        message,
        statement,
        proof,
    })
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

fn decode_protocol_scalar<S: GoldenScalar>(
    encoded: &[u8],
) -> core::result::Result<S, DealerMessageError> {
    if encoded.len() != S::REPR_BYTES {
        return Err(DealerMessageError::Malformed);
    }
    let mut native = clone_bytes_fallibly(encoded)?;
    if S::repr_byte_order() == FieldByteOrder::LittleEndian {
        native.reverse();
    }
    let repr = S::Repr::try_from(native).map_err(|_| DealerMessageError::Malformed)?;
    let scalar = S::from_repr(&repr).map_err(|_| DealerMessageError::Malformed)?;
    if encode_protocol_scalar(&scalar)
        .map_err(|_| DealerMessageError::Malformed)?
        .as_slice()
        != encoded
    {
        return Err(DealerMessageError::Malformed);
    }
    Ok(scalar)
}

fn decode_protocol_element<G>(
    encoded: &[u8],
) -> core::result::Result<G::Element, DealerMessageError>
where
    G: GoldenGroup,
{
    if encoded.len() != G::ELEMENT_REPR_BYTES {
        return Err(DealerMessageError::Malformed);
    }
    let repr = G::ElementRepr::try_from(clone_bytes_fallibly(encoded)?)
        .map_err(|_| DealerMessageError::Malformed)?;
    let element = G::decode_element(&repr).map_err(|_| DealerMessageError::Malformed)?;
    if G::encode_element(&element).as_ref() != encoded {
        return Err(DealerMessageError::Malformed);
    }
    Ok(element)
}

fn clone_elements_fallibly<E: Clone>(
    elements: &[E],
) -> core::result::Result<Vec<E>, DealerMessageError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(elements.len())
        .map_err(|_| DealerMessageError::Malformed)?;
    cloned.extend(elements.iter().cloned());
    Ok(cloned)
}

fn clone_bytes_fallibly(bytes: &[u8]) -> core::result::Result<Vec<u8>, DealerMessageError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| DealerMessageError::Malformed)?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

fn statement_from_message<G: GoldenGroup>(
    config: &DkgConfig<G>,
    message: &DealerMessageData<G>,
    message_root: TranscriptRoot,
) -> Result<DealerProofStatement<G>> {
    let instance_count = message.instances.len();
    let receivers_per_instance = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofVerificationFailed)?;
    let coefficient_count = instance_count
        .checked_mul(config.threshold())
        .ok_or(Error::ProofVerificationFailed)?;
    let receiver_count = instance_count
        .checked_mul(receivers_per_instance)
        .ok_or(Error::ProofVerificationFailed)?;
    let mut effective_messages = Vec::new();
    let mut commitment_coefficients = Vec::new();
    let mut share_commitments = Vec::new();
    let mut pad_commitments = Vec::new();
    let mut encrypted_shares = Vec::new();
    effective_messages
        .try_reserve_exact(instance_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    commitment_coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    share_commitments
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    pad_commitments
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    encrypted_shares
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofVerificationFailed)?;
    for instance in &message.instances {
        effective_messages.push(instance.effective_message);
        commitment_coefficients.extend(instance.commitment_coefficients.iter().cloned());
        for receiver in &instance.receivers {
            share_commitments.push(receiver.share_commitment.clone());
            pad_commitments.push(receiver.pad_commitment.clone());
            encrypted_shares.push(receiver.encrypted_share.clone());
        }
    }
    DealerProofStatement::from_public_parts(
        config,
        message.dealer,
        message_root,
        effective_messages,
        commitment_coefficients,
        share_commitments,
        pad_commitments,
        encrypted_shares,
    )
}

struct DealerMessageReader<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> DealerMessageReader<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn read_exact(&mut self, len: usize) -> core::result::Result<&'a [u8], DealerMessageError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(DealerMessageError::Malformed)?;
        let bytes = self
            .encoded
            .get(self.position..end)
            .ok_or(DealerMessageError::Malformed)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> core::result::Result<u32, DealerMessageError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| DealerMessageError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64_as_usize(&mut self) -> core::result::Result<usize, DealerMessageError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| DealerMessageError::Malformed)?;
        usize::try_from(u64::from_be_bytes(bytes)).map_err(|_| DealerMessageError::Malformed)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.encoded[self.position..]
    }
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
