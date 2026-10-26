//! Private configuration-shaped broadcast grammar and complete public validation.
use crate::dealer_proof::{InstanceInput, ReceiverInput};
use crate::wire::{framed, reserve, Reader};
use crate::{
    DealerMessageNonce, DealerProofStatement, DkgConfig, DkgGroup, DkgInstanceKind, Error,
    ParticipantIndex, Result,
};
use group::Group;

pub(crate) const MAX_DEALER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAGIC: &[u8] = b"golden-dkg-wire-v4";

pub(crate) struct ParsedDealerMessage<'a, G: DkgGroup> {
    pub(crate) statement: DealerProofStatement<G>,
    pub(crate) proof: &'a [u8],
}

pub(crate) fn encoded_prefix_len<G: DkgGroup>(config: &DkgConfig<G>) -> Result<usize> {
    let receiver_count = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ArithmeticOverflow)?;
    let receiver_bytes = receiver_count
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
        let coefficient_count = config.threshold() - usize::from(*kind == DkgInstanceKind::Zero);
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

pub(crate) fn encode<G: DkgGroup>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    proof: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    statement.validate_against(config)?;
    if config.registry().len() == 1 && !proof.is_empty() {
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
    out.extend_from_slice(&statement.dealer().get().to_be_bytes());
    for instance in statement.instances() {
        out.extend_from_slice(&instance.nonce().0);
        let start = usize::from(instance.kind() == DkgInstanceKind::Zero);
        for coefficient in &instance.commitment_coefficients()[start..] {
            out.extend_from_slice(&G::encode_point(coefficient));
        }
        for receiver in instance.receivers() {
            out.extend_from_slice(&G::encode_point(receiver.pad_commitment()));
            out.extend_from_slice(&G::encode_scalar(receiver.encrypted_share()));
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
    config.registry().public_key(expected_dealer)?;
    let mut instances = reserve(config.instances().len())?;
    for kind in config.instances().iter().copied() {
        let nonce = DealerMessageNonce(reader.array()?);
        let mut coefficients = reserve(config.threshold())?;
        if kind == DkgInstanceKind::Zero {
            coefficients.push(G::Point::identity());
        }
        for _ in coefficients.len()..config.threshold() {
            coefficients.push(G::decode_point(reader.take(G::POINT_BYTES)?)?);
        }
        let mut receivers = reserve(config.registry().len() - 1)?;
        for _ in 0..config.registry().len() - 1 {
            let pad_commitment = G::decode_point(reader.take(G::POINT_BYTES)?)?;
            let encrypted_share = G::decode_scalar(reader.take(32)?)?;
            receivers.push(ReceiverInput {
                pad_commitment,
                encrypted_share,
            });
        }
        instances.push(InstanceInput {
            nonce,
            coefficients,
            receivers,
        });
    }
    let proof = reader.framed()?;
    reader.finish()?;
    if config.registry().len() == 1 && !proof.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    Ok(ParsedDealerMessage {
        statement: DealerProofStatement::new(config, expected_dealer, instances)?,
        proof,
    })
}
