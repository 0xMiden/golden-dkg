//! Fixed Main Golden relation helpers shared by native and proof implementations.

use ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::dkg::{DealerMessageNonce, DkgInstanceKind, EvrfMessage};
use crate::group::{FieldByteOrder, GoldenCurve};
use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::{Error, ParticipantIndex, Result};

const BETA_PROTOCOL_STRING: &[u8] = b"golden-dkg/main-golden-beta/v1";
const BASE_FIELD_CANDIDATE_DOMAIN: &[u8] = b"golden-dkg/base-field-candidate/v1";
const EFFECTIVE_MESSAGE_PREFIX: &[u8] = b"golden-dkg/main-golden/v1";
const H1_DOMAIN: &[u8] = b"golden-dkg/main-golden-h1/v1";
const H2_DOMAIN: &[u8] = b"golden-dkg/main-golden-h2/v1";

/// Derive the protocol-wide Main Golden setup coefficient in the full base field.
///
/// SHA-256 expansion is interpreted as one fixed big-endian candidate integer.
/// Rejected candidates advance the attempt counter; zero is a valid result.
pub fn beta<G: GoldenCurve>() -> Result<G::BaseField> {
    let repr_len = <G::BaseField as PrimeField>::Repr::default().as_ref().len();
    sample_beta(
        repr_len,
        |attempt, block| {
            let mut hasher = Sha256::new();
            hasher.update(BASE_FIELD_CANDIDATE_DOMAIN);
            hasher.update((BETA_PROTOCOL_STRING.len() as u64).to_be_bytes());
            hasher.update(BETA_PROTOCOL_STRING);
            hasher.update(attempt.to_be_bytes());
            hasher.update(block.to_be_bytes());
            Ok(hasher.finalize().into())
        },
        |candidate| {
            let mut repr = <G::BaseField as PrimeField>::Repr::default();
            match G::base_field_byte_order() {
                FieldByteOrder::BigEndian => repr.as_mut().copy_from_slice(candidate),
                FieldByteOrder::LittleEndian => {
                    for (output, input) in repr.as_mut().iter_mut().zip(candidate.iter().rev()) {
                        *output = *input;
                    }
                }
            }
            G::BaseField::from_repr_vartime(repr)
        },
    )
}

fn sample_beta<T>(
    repr_len: usize,
    mut expand_block: impl FnMut(u32, u32) -> Result<[u8; 32]>,
    mut decode_big_endian: impl FnMut(&[u8]) -> Option<T>,
) -> Result<T> {
    let mut attempt = 0u32;

    loop {
        let mut candidate = Vec::with_capacity(repr_len);
        let mut block = 0u32;
        while candidate.len() < repr_len {
            candidate.extend_from_slice(&expand_block(attempt, block)?);
            if candidate.len() < repr_len {
                block = block.checked_add(1).ok_or(Error::InvalidEncoding)?;
            }
        }
        candidate.truncate(repr_len);

        if let Some(coefficient) = decode_big_endian(&candidate) {
            return Ok(coefficient);
        }

        attempt = attempt.checked_add(1).ok_or(Error::InvalidEncoding)?;
    }
}

/// Derive the effective message for one configured dealer instance.
pub fn effective_message(
    configuration_root: TranscriptRoot,
    dealer: ParticipantIndex,
    position: usize,
    kind: DkgInstanceKind,
    nonce: DealerMessageNonce,
) -> EvrfMessage {
    let mut transcript =
        TranscriptBuilder::with_prefix(EFFECTIVE_MESSAGE_PREFIX, b"effective-message");
    transcript.bytes(b"configuration", &configuration_root);
    transcript.participant(b"dealer", dealer);
    transcript.usize(b"position", position);
    transcript.u32(
        b"kind",
        match kind {
            DkgInstanceKind::Random => 0,
            DkgInstanceKind::Zero => 1,
        },
    );
    transcript.bytes(b"nonce", &nonce.0);
    EvrfMessage(transcript.root())
}

/// Derive the first Main Golden hash-to-group point.
pub fn h1<G: GoldenCurve>(
    message: EvrfMessage,
    first_identity_key: &G::Element,
    second_identity_key: &G::Element,
) -> Result<G::Element> {
    let input = hash_input::<G>(message, first_identity_key, second_identity_key)?;
    G::hash_to_group(H1_DOMAIN, &input)
}

/// Derive the second Main Golden hash-to-group point.
pub fn h2<G: GoldenCurve>(
    message: EvrfMessage,
    first_identity_key: &G::Element,
    second_identity_key: &G::Element,
) -> Result<G::Element> {
    let input = hash_input::<G>(message, first_identity_key, second_identity_key)?;
    G::hash_to_group(H2_DOMAIN, &input)
}

/// Evaluate the fixed Main Golden receiver pad relation.
pub fn receiver_pad<G: GoldenCurve>(
    message: EvrfMessage,
    identity_secret: &G::Scalar,
    peer_identity_key: &G::Element,
) -> Result<G::Scalar> {
    let shared_identity_point = G::mul(peer_identity_key, identity_secret);
    let shared_x = G::affine_x(&shared_identity_point)?;
    let exponent = G::reduce_base_field(&shared_x);

    let own_identity_key = G::mul_generator(identity_secret);
    let t1 = G::mul(
        &h1::<G>(message, &own_identity_key, peer_identity_key)?,
        &exponent,
    );
    let t2 = G::mul(
        &h2::<G>(message, &own_identity_key, peer_identity_key)?,
        &exponent,
    );
    let t1_x = G::affine_x(&t1)?;
    let t2_x = G::affine_x(&t2)?;
    let output = beta::<G>()? * t1_x + t2_x;

    Ok(G::reduce_base_field(&output))
}

fn hash_input<G: GoldenCurve>(
    message: EvrfMessage,
    first_identity_key: &G::Element,
    second_identity_key: &G::Element,
) -> Result<Vec<u8>> {
    if bool::from(G::is_identity(first_identity_key))
        || bool::from(G::is_identity(second_identity_key))
    {
        return Err(Error::InvalidEncoding);
    }

    let first = G::encode_element(first_identity_key);
    let second = G::encode_element(second_identity_key);
    let (lower, upper) = if first.as_ref() <= second.as_ref() {
        (first.as_ref(), second.as_ref())
    } else {
        (second.as_ref(), first.as_ref())
    };
    let mut input = Vec::with_capacity(24 + message.0.len() + lower.len() + upper.len());
    append_framed(&mut input, &message.0);
    append_framed(&mut input, lower);
    append_framed(&mut input, upper);
    Ok(input)
}

fn append_framed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beta_sampler_rejects_an_attempt_resets_blocks_and_accepts_zero() {
        let mut calls = Vec::new();
        let coefficient = sample_beta(
            48,
            |attempt, block| {
                calls.push((attempt, block));
                Ok(if attempt == 0 { [0xff; 32] } else { [0; 32] })
            },
            |candidate| {
                candidate
                    .iter()
                    .all(|byte| *byte == 0)
                    .then_some(candidate.to_vec())
            },
        )
        .expect("attempt one is the all-zero canonical candidate");

        assert_eq!(coefficient, vec![0; 48]);
        assert_eq!(calls, [(0, 0), (0, 1), (1, 0), (1, 1)]);
    }
}
