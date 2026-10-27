//! Fixed native Main Golden relation shared with concrete proof implementations.
use crate::error::normalize_validation_error;
use crate::wire::{count, framed};
use crate::{
    DealerMessageNonce, DealerProofStatement, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind, Error, EvrfMessage, FieldByteOrder, ParticipantIndex, Result, TranscriptRoot,
};
use ff::{Field, PrimeField};
use group::Group;
use sha2::{Digest, Sha256};

/// Deterministic protocol-wide base-field beta. Canonical zero is accepted.
pub fn beta<G: DkgGroup>() -> Result<G::BaseField> {
    let length = <G::BaseField as PrimeField>::Repr::default().as_ref().len();
    let mut attempt = 0u32;
    loop {
        let mut candidate =
            crate::wire::reserve::<u8>(length.checked_add(31).ok_or(Error::ArithmeticOverflow)?)?;
        let mut block = 0u32;
        while candidate.len() < length {
            let mut hash = Sha256::new();
            hash.update(b"golden-dkg/base-field-candidate/v1");
            hash.update(
                u64::try_from(b"golden-dkg/main-golden-beta/v1".len())
                    .map_err(|_| Error::ArithmeticOverflow)?
                    .to_be_bytes(),
            );
            hash.update(b"golden-dkg/main-golden-beta/v1");
            hash.update(attempt.to_be_bytes());
            hash.update(block.to_be_bytes());
            candidate.extend_from_slice(&hash.finalize());
            if candidate.len() < length {
                block = block
                    .checked_add(1)
                    .ok_or(Error::RelationEvaluationFailed)?;
            }
        }
        candidate.truncate(length);
        let mut repr = <G::BaseField as PrimeField>::Repr::default();
        match G::base_field_byte_order() {
            FieldByteOrder::BigEndian => repr.as_mut().copy_from_slice(&candidate),
            FieldByteOrder::LittleEndian => {
                for (output, input) in repr.as_mut().iter_mut().zip(candidate.iter().rev()) {
                    *output = *input;
                }
            }
        }
        if let Some(value) = Option::<G::BaseField>::from(G::BaseField::from_repr(repr)) {
            return Ok(value);
        }
        attempt = attempt
            .checked_add(1)
            .ok_or(Error::RelationEvaluationFailed)?;
    }
}

/// Derive a configuration/dealer/position/kind-bound effective message.
pub fn effective_message(
    config_root: TranscriptRoot,
    dealer: ParticipantIndex,
    position: usize,
    kind: DkgInstanceKind,
    nonce: DealerMessageNonce,
) -> Result<EvrfMessage> {
    let mut payload = Vec::with_capacity(73);
    payload.extend_from_slice(&config_root);
    payload.extend_from_slice(&dealer.get().to_be_bytes());
    count(&mut payload, position)?;
    payload.push(kind.tag());
    payload.extend_from_slice(&nonce.0);
    Ok(EvrfMessage(crate::transcript::hash_payload(
        b"golden-dkg/effective-message/v3",
        &payload,
    )?))
}

fn hash_input<G: DkgGroup>(
    message: EvrfMessage,
    first: &G::Point,
    second: &G::Point,
) -> Result<Vec<u8>> {
    if bool::from(first.is_identity()) || bool::from(second.is_identity()) {
        return Err(Error::RelationEvaluationFailed);
    }
    let first = G::encode_point(first);
    let second = G::encode_point(second);
    let (lower, upper) = if first <= second {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let mut input = Vec::new();
    framed(&mut input, &message.0)?;
    framed(&mut input, lower)?;
    framed(&mut input, upper)?;
    Ok(input)
}
/// First Main Golden hash point, binding both canonically sorted identity keys.
pub fn h1<G: DkgGroup>(
    message: EvrfMessage,
    first: &G::Point,
    second: &G::Point,
) -> Result<G::Point> {
    G::hash_to_point(
        b"golden-dkg/main-golden-h1/v1",
        &hash_input::<G>(message, first, second)?,
    )
}
/// Second independently domain-separated hash point.
pub fn h2<G: DkgGroup>(
    message: EvrfMessage,
    first: &G::Point,
    second: &G::Point,
) -> Result<G::Point> {
    G::hash_to_point(
        b"golden-dkg/main-golden-h2/v1",
        &hash_input::<G>(message, first, second)?,
    )
}
/// Native pad evaluation. Zero reduced DH exponents/unavailable coordinates fail closed.
pub fn receiver_pad<G: DkgGroup>(
    message: EvrfMessage,
    identity_secret: &G::Scalar,
    peer_identity_key: &G::Point,
) -> Result<G::Scalar> {
    let shared = *peer_identity_key * identity_secret;
    let exponent = G::reduce_base_field(
        &G::affine_x(&shared)
            .map_err(|error| normalize_validation_error(error, Error::RelationEvaluationFailed))?,
    );
    if bool::from(exponent.is_zero()) {
        return Err(Error::RelationEvaluationFailed);
    }
    let own = G::mul_generator(identity_secret);
    let first = h1::<G>(message, &own, peer_identity_key)? * exponent;
    let second = h2::<G>(message, &own, peer_identity_key)? * exponent;
    let first_x = G::affine_x(&first)
        .map_err(|error| normalize_validation_error(error, Error::RelationEvaluationFailed))?;
    let second_x = G::affine_x(&second)
        .map_err(|error| normalize_validation_error(error, Error::RelationEvaluationFailed))?;
    Ok(G::reduce_base_field(&(beta::<G>()? * first_x + second_x)))
}

/// Check exact native public and private relations; no backend-specific semantics.
#[doc(hidden)]
pub fn check_dealer_relation<G: DkgGroup>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    witness: &DealerProofWitness<G>,
) -> Result<()> {
    check_relation(config, statement, witness)
        .map_err(|error| normalize_validation_error(error, Error::InvalidProof))
}
fn check_relation<G: DkgGroup>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    witness: &DealerProofWitness<G>,
) -> Result<()> {
    statement.validate_against(config)?;
    witness.validate_shape(config, statement)?;
    if G::mul_generator(witness.identity_secret()) != *statement.dealer_public_key() {
        return Err(Error::InvalidProof);
    }
    for position in 0..statement.instance_count() {
        let public = statement.instance(position).ok_or(Error::InvalidProof)?;
        let private = witness.instance(position).ok_or(Error::InvalidProof)?;
        match (
            config.pinned_constant(public.kind(), statement.dealer())?,
            private.polynomial_constant(),
        ) {
            (None, Some(constant))
                if G::mul_generator(constant) == public.commitment_coefficients()[0] => {}
            (Some(pinned), None) if pinned == public.commitment_coefficients()[0] => {}
            _ => return Err(Error::InvalidProof),
        }
        for receiver_position in 0..public.receiver_count() {
            let receiver = public
                .receiver(receiver_position)
                .ok_or(Error::InvalidProof)?;
            let opening = private
                .receiver(receiver_position)
                .ok_or(Error::InvalidProof)?;
            if G::mul_generator(opening.share()) != *receiver.share_commitment()
                || bool::from(opening.pad().is_zero())
                || G::mul_generator(opening.pad()) != *receiver.pad_commitment()
                || *opening.share() + opening.pad() != *receiver.encrypted_share()
                || receiver_pad::<G>(
                    public.effective_message(),
                    witness.identity_secret(),
                    receiver.public_key(),
                )? != *opening.pad()
            {
                return Err(Error::InvalidProof);
            }
        }
    }
    Ok(())
}
