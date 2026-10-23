//! Narrow native-relation support for proof implementations; protocol constructors stay private.
pub use crate::main_golden::{
    beta, check_dealer_relation, effective_message, h1, h2, receiver_pad,
};

/// Reconstruct a revealed witness for the explicitly insecure proof grammar.
/// The caller owns the borrowed input storage; this copies secrets into guarded core storage.
#[cfg(any(test, feature = "insecure-revealed-witness"))]
pub fn reconstruct_revealed_witness<G: crate::DkgGroup>(
    config: &crate::DkgConfig<G>,
    statement: &crate::DealerProofStatement<G>,
    identity_secret: &G::Scalar,
    constants: &[Option<G::Scalar>],
    receiver_openings: &[(G::Scalar, G::Scalar)],
) -> crate::Result<crate::DealerProofWitness<G>> {
    use crate::dealer_proof::{InstanceWitness, ReceiverWitness};
    use crate::secret::secret;
    use crate::{DkgInstanceKind, Error};
    statement.validate_against(config)?;
    if constants.len() != config.instances().len() {
        return Err(Error::InvalidProof);
    }
    let receivers = config.registry().len() - 1;
    let count = receivers
        .checked_mul(config.instances().len())
        .ok_or(Error::ArithmeticOverflow)?;
    if receiver_openings.len() != count {
        return Err(Error::InvalidProof);
    }
    let mut instances = crate::wire::reserve(config.instances().len())?;
    for (position, kind) in config.instances().iter().enumerate() {
        if constants[position].is_some() != (*kind == DkgInstanceKind::Random) {
            return Err(Error::InvalidProof);
        }
        let constant = constants[position].map(secret);
        let mut openings = crate::wire::reserve(receivers)?;
        let start = position
            .checked_mul(receivers)
            .ok_or(Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(receivers)
            .ok_or(Error::ArithmeticOverflow)?;
        for (share, pad) in &receiver_openings[start..end] {
            openings.push(ReceiverWitness {
                share: secret(*share),
                pad: secret(*pad),
            });
        }
        instances.push(InstanceWitness {
            constant,
            receivers: openings,
        });
    }
    Ok(crate::DealerProofWitness {
        identity_secret: secret(*identity_secret),
        instances,
    })
}
