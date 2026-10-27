//! INSECURE proof mode: exact Main Golden checks while publicly revealing the witness.
//!
//! Use disposable identities only. Broadcasts, their copies and persisted local
//! state reveal the dealer identity secret, shares and pads. This is not a ZK proof.
use crate::dealer_proof::{InstanceWitness, ReceiverWitness};
use crate::error::normalize_validation_error;
use crate::secret::secret;
use crate::wire::{framed, reserve, Reader};
use crate::{
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup, Error, Result,
};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

const FAMILY: &[u8] = b"golden-dkg/insecure-revealed-witness/v1";

/// Explicitly insecure exact-relation transport/testing proof. No generators or preparation.
#[derive(Clone, Copy, Debug, Default)]
pub struct InsecureRevealedWitnessProof;

impl<G: DkgGroup> DealerProofSystem<G> for InsecureRevealedWitnessProof {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        crate::main_golden::check_dealer_relation(config, statement, witness)?;
        let receiver_count = config.receiver_count();
        let constants = config
            .instances()
            .iter()
            .filter(|kind| !kind.pins_constant())
            .count();
        let scalar_count = receiver_count
            .checked_mul(config.instances().len())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(constants))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity = scalar_count
            .checked_mul(32)
            .and_then(|n| n.checked_add(8 + FAMILY.len() + 64))
            .ok_or(Error::ArithmeticOverflow)?;
        let mut out = Zeroizing::new(reserve(capacity)?);
        framed(&mut out, FAMILY)?;
        out.extend_from_slice(&config.root());
        out.extend_from_slice(&statement.dealer_message_root());
        append_scalar::<G>(&mut out, witness.identity_secret());
        for position in 0..witness.instance_count() {
            let instance = witness.instance(position).ok_or(Error::InvalidProof)?;
            if let Some(constant) = instance.polynomial_constant() {
                append_scalar::<G>(&mut out, constant);
            }
            for receiver in 0..instance.receiver_count() {
                let opening = instance.receiver(receiver).ok_or(Error::InvalidProof)?;
                append_scalar::<G>(&mut out, opening.share());
                append_scalar::<G>(&mut out, opening.pad());
            }
        }
        Ok(core::mem::take(&mut *out))
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        verify(config, statement, proof)
            .map_err(|error| normalize_validation_error(error, Error::InvalidProof))
    }
}
fn append_scalar<G: DkgGroup>(out: &mut Vec<u8>, scalar: &G::Scalar) {
    let encoded = Zeroizing::new(G::encode_scalar(scalar));
    out.extend_from_slice(&*encoded);
}
fn verify<G: DkgGroup>(
    config: &DkgConfig<G>,
    statement: &DealerProofStatement<G>,
    proof: &[u8],
) -> Result<()> {
    statement.validate_against(config)?;
    let mut reader = Reader::new(proof);
    if reader.framed()? != FAMILY
        || reader.array::<32>()? != config.root()
        || reader.array::<32>()? != statement.dealer_message_root()
    {
        return Err(Error::InvalidProof);
    }
    let identity_secret = secret(G::decode_scalar(reader.take(32)?)?);
    let mut instances = reserve(config.instances().len())?;
    for kind in config.instances() {
        let constant = if !kind.pins_constant() {
            Some(secret(G::decode_scalar(reader.take(32)?)?))
        } else {
            None
        };
        let count = config.receiver_count();
        reader.ensure_items(count, 64)?;
        let mut receivers = reserve(count)?;
        for _ in 0..count {
            let share = secret(G::decode_scalar(reader.take(32)?)?);
            let pad = secret(G::decode_scalar(reader.take(32)?)?);
            receivers.push(ReceiverWitness { share, pad });
        }
        instances.push(InstanceWitness {
            constant,
            receivers,
        });
    }
    reader.finish()?;
    let witness = DealerProofWitness {
        identity_secret,
        instances,
    };
    crate::main_golden::check_dealer_relation(config, statement, &witness)
}
