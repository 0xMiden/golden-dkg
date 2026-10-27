//! Private configuration-shaped broadcast grammar and complete public validation.
use crate::dealer_proof::{DealerProofInstance, DealerProofReceiver};
use crate::wire::{count, framed, reserve, Reader};
use crate::{
    DealerMessageNonce, DealerProofStatement, DkgConfig, DkgGroup, Error, ParticipantIndex, Result,
};
use ff::PrimeField;
use group::Group;

pub(crate) const MAX_DEALER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAGIC: &[u8] = b"golden-dkg-wire-v4";

pub(crate) struct ParsedDealerMessage<'a, G: DkgGroup> {
    pub(crate) statement: DealerProofStatement<G>,
    pub(crate) proof: &'a [u8],
}

pub(crate) fn encoded_prefix_len<G: DkgGroup>(config: &DkgConfig<G>) -> Result<usize> {
    let receiver_bytes = config
        .receiver_count()
        .checked_mul(
            G::POINT_BYTES
                .checked_add(32)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    let mut size = 8usize
        .checked_add(MAGIC.len())
        .and_then(|n| n.checked_add(32 + 4 + 8))
        .ok_or(Error::ArithmeticOverflow)?;
    for kind in config.instances() {
        let coefficient_count = config.threshold() - usize::from(kind.pins_constant());
        let body_size = coefficient_count
            .checked_mul(G::POINT_BYTES)
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(receiver_bytes))
            .ok_or(Error::ArithmeticOverflow)?;
        size = size
            .checked_add(body_size)
            .ok_or(Error::ArithmeticOverflow)?;
    }
    if size > MAX_DEALER_MESSAGE_BYTES {
        return Err(Error::DealerMessageTooLarge);
    }
    Ok(size)
}

pub(crate) use crate::feldman::evaluate;

pub(crate) fn validate_instances<G: DkgGroup>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    instances: &[DealerProofInstance<G>],
) -> Result<()> {
    config.dealers().public_key(dealer)?;
    if instances.len() != config.instances().len() {
        return Err(Error::InvalidEncoding);
    }
    for (position, instance) in instances.iter().enumerate() {
        let kind = config.instances()[position];
        if instance.kind != kind
            || instance.coefficients.len() != config.threshold()
            || instance.effective_message
                != crate::main_golden::effective_message(
                    config.root(),
                    dealer,
                    position,
                    kind,
                    instance.nonce,
                )?
            || instance.receivers.len() != config.receiver_count()
            || config
                .pinned_constant(kind, dealer)?
                .is_some_and(|pinned| pinned != instance.coefficients[0])
        {
            return Err(Error::InvalidEncoding);
        }
        for (receiver, (participant, key)) in
            instance.receivers.iter().zip(config.receivers(dealer))
        {
            if receiver.participant != participant
                || receiver.public_key != *key
                || receiver.share_commitment != evaluate::<G>(&instance.coefficients, participant)
                || bool::from(receiver.pad_commitment.is_identity())
                || G::mul_generator(&receiver.encrypted_share)
                    != receiver.share_commitment + receiver.pad_commitment
            {
                return Err(Error::InvalidEncoding);
            }
        }
    }
    Ok(())
}

pub(crate) fn statement<G: DkgGroup>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    instances: Vec<DealerProofInstance<G>>,
) -> Result<DealerProofStatement<G>> {
    validate_instances(config, dealer, &instances)?;
    let key = *config.dealers().public_key(dealer)?;
    let mut logical = Vec::new();
    logical.extend_from_slice(&config.root());
    logical.extend_from_slice(&dealer.get().to_be_bytes());
    logical.extend_from_slice(&G::encode_point(&key));
    logical.extend_from_slice(crate::main_golden::beta::<G>()?.to_repr().as_ref());
    count(&mut logical, instances.len())?;
    for (position, instance) in instances.iter().enumerate() {
        count(&mut logical, position)?;
        logical.push(instance.kind.tag());
        logical.extend_from_slice(&instance.nonce.0);
        logical.extend_from_slice(&instance.effective_message.0);
        count(&mut logical, instance.coefficients.len())?;
        for coefficient in &instance.coefficients {
            logical.extend_from_slice(&G::encode_point(coefficient));
        }
        count(&mut logical, instance.receivers.len())?;
        for receiver in &instance.receivers {
            logical.extend_from_slice(&receiver.participant.get().to_be_bytes());
            logical.extend_from_slice(&G::encode_point(&receiver.public_key));
            logical.extend_from_slice(&G::encode_point(&receiver.share_commitment));
            logical.extend_from_slice(&G::encode_point(&receiver.pad_commitment));
            logical.extend_from_slice(&G::encode_scalar(&receiver.encrypted_share));
        }
    }
    let root = crate::transcript::hash_payload(b"golden-dkg/dealer-root/v3", &logical)?;
    Ok(DealerProofStatement {
        config_root: config.root(),
        dealer,
        dealer_public_key: key,
        instances,
        logical,
        root,
    })
}

pub(crate) fn encode<G: DkgGroup>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    proof: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    statement.validate_against(config)?;
    if config.receiver_count() == 0 && !proof.is_empty() {
        return Err(Error::InvalidProof);
    }
    let length = encoded_prefix_len(config)?
        .checked_add(proof.len())
        .ok_or(Error::DealerMessageTooLarge)?;
    if length > MAX_DEALER_MESSAGE_BYTES {
        return Err(Error::DealerMessageTooLarge);
    }
    let mut out = zeroize::Zeroizing::new(reserve(length)?);
    framed(&mut out, MAGIC)?;
    out.extend_from_slice(&config.root());
    out.extend_from_slice(&statement.dealer.get().to_be_bytes());
    for instance in &statement.instances {
        out.extend_from_slice(&instance.nonce.0);
        let start = usize::from(instance.kind.pins_constant());
        for coefficient in &instance.coefficients[start..] {
            out.extend_from_slice(&G::encode_point(coefficient));
        }
        for receiver in &instance.receivers {
            out.extend_from_slice(&G::encode_point(&receiver.pad_commitment));
            out.extend_from_slice(&G::encode_scalar(&receiver.encrypted_share));
        }
    }
    framed(&mut out, proof)?;
    if out.len() != length {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

pub(crate) fn parse<'a, G: DkgGroup>(
    config: &DkgConfig<G>,
    expected_dealer: ParticipantIndex,
    encoded: &'a [u8],
) -> Result<ParsedDealerMessage<'a, G>> {
    if encoded.len() > MAX_DEALER_MESSAGE_BYTES {
        return Err(Error::DealerMessageTooLarge);
    }
    let minimum = encoded_prefix_len(config)?;
    if encoded.len() < minimum {
        return Err(Error::InvalidEncoding);
    }
    let mut reader = Reader::new(encoded);
    if reader.framed()? != MAGIC
        || reader.array::<32>()? != config.root()
        || reader.u32()? != expected_dealer.get()
    {
        return Err(Error::InvalidEncoding);
    }
    config.dealers().public_key(expected_dealer)?;
    let mut instances = reserve(config.instances().len())?;
    for (position, kind) in config.instances().iter().copied().enumerate() {
        let nonce = DealerMessageNonce(reader.array()?);
        let effective_message = crate::main_golden::effective_message(
            config.root(),
            expected_dealer,
            position,
            kind,
            nonce,
        )?;
        let mut coefficients = reserve(config.threshold())?;
        if let Some(constant) = config.pinned_constant(kind, expected_dealer)? {
            coefficients.push(constant);
        }
        for _ in coefficients.len()..config.threshold() {
            coefficients.push(G::decode_point(reader.take(G::POINT_BYTES)?)?);
        }
        let mut receivers = reserve(config.receiver_count())?;
        for (participant, key) in config.receivers(expected_dealer) {
            let pad_commitment = G::decode_point(reader.take(G::POINT_BYTES)?)?;
            let encrypted_share = G::decode_scalar(reader.take(32)?)?;
            receivers.push(DealerProofReceiver {
                participant,
                public_key: *key,
                share_commitment: evaluate::<G>(&coefficients, participant),
                pad_commitment,
                encrypted_share,
            });
        }
        instances.push(DealerProofInstance {
            kind,
            nonce,
            effective_message,
            coefficients,
            receivers,
        });
    }
    let proof = reader.framed()?;
    reader.finish()?;
    if config.receiver_count() == 0 && !proof.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    Ok(ParsedDealerMessage {
        statement: statement(config, expected_dealer, instances)?,
        proof,
    })
}
