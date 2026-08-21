//! Bridge from completed Golden DKG runs to EHTDH1 key material.
//!
//! See crate root for the paper-to-crate symbol map.

use std::{collections::BTreeMap, fmt};

use golden_core::{DkgConfig, DkgInstanceKind, DkgOutput, GoldenGroup, GoldenHashToGroup};

use crate::context::{Error, PublicKeySet, PublicShare, SecretShare, SetupContext};
use crate::encrypt::SealingKey;

/// EHTDH1 material for one local participant.
#[derive(Clone)]
pub struct Ehtdh1Material<G: GoldenHashToGroup> {
    /// Paper `pk = X`, used by clients to seal payloads.
    pub sealing_key: SealingKey<G>,
    /// Paper `pkc = (X; [(X_i, Z_i)]_i)`, plus the threshold.
    pub public_key_set: PublicKeySet<G>,
    /// Paper `sk_i = (x_i, z_i)` for the local validator.
    pub secret_share: SecretShare<G>,
    /// Golden setup binding added to `Hdgd` and `Hdcd`.
    pub setup_context: SetupContext,
}

impl<G: GoldenHashToGroup> fmt::Debug for Ehtdh1Material<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ehtdh1Material")
            .field("sealing_key", &self.sealing_key)
            .field("public_key_set", &self.public_key_set)
            .field("secret_share", &"<redacted>")
            .field("setup_context", &self.setup_context)
            .finish()
    }
}

fn validate_aggregate_keys<G: GoldenGroup>(
    decryption_key: &G::Element,
    context_key: &G::Element,
) -> Result<(), Error> {
    if bool::from(G::is_identity(decryption_key)) {
        return Err(Error::InvalidJointPublicKey);
    }
    if !bool::from(G::is_identity(context_key)) {
        return Err(Error::InvalidPublicKeySet);
    }
    Ok(())
}

/// Convert one Golden `[Random, Zero]` DKG batch into paper `(pk, pkc, sk_1..sk_N)` material.
///
/// The paper treats key generation as centralized. This bridge checks matching
/// configuration and output identity before interpreting batch position zero as
/// the decryption sharing and position one as the context sharing.
/// It requires the decryption aggregate key to be nonidentity and the context
/// aggregate key to be identity. `PublicKeySet::new` additionally checks that
/// `X_i` interpolates to `X` and `Z_i` interpolates to identity.
pub fn material_from_dkg_output<G: GoldenHashToGroup>(
    config: &DkgConfig<G>,
    output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    if config.instances() != [DkgInstanceKind::Random, DkgInstanceKind::Zero] {
        return Err(Error::InvalidBridge("expected [Random, Zero] batch"));
    }
    if output.configuration_root() != config.root() {
        return Err(Error::InvalidBridge("configuration root mismatch"));
    }
    if output.instances().len() != 2 {
        return Err(Error::InvalidBridge("output instance count mismatch"));
    }
    let decryption_output = output
        .instance(0)
        .ok_or(Error::InvalidBridge("output instance count mismatch"))?;
    let context_output = output
        .instance(1)
        .ok_or(Error::InvalidBridge("output instance count mismatch"))?;
    validate_aggregate_keys::<G>(decryption_output.public_key(), context_output.public_key())?;

    let participants = config.registry().indexes().collect::<Vec<_>>();

    let mut public_shares = BTreeMap::new();
    for participant in &participants {
        public_shares.insert(
            *participant,
            PublicShare {
                decryption: decryption_output
                    .public_key_shares()
                    .get(participant)
                    .ok_or(Error::InvalidBridge("missing decryption public share"))?
                    .clone(),
                context: context_output
                    .public_key_shares()
                    .get(participant)
                    .ok_or(Error::InvalidBridge("missing context public share"))?
                    .clone(),
            },
        );
    }

    let public_key_set = PublicKeySet::new(
        config.threshold(),
        decryption_output.public_key().clone(),
        public_shares,
    )?;
    let secret_share = SecretShare {
        participant: output.participant(),
        decryption: decryption_output.secret_share().clone(),
        context: context_output.secret_share().clone(),
    };
    let setup_context = SetupContext {
        backend_id: G::BACKEND_ID.to_owned(),
        threshold: config.threshold(),
        registry_root: config.registry().root(),
        participants,
        session_id: config.session_id(),
        configuration_root: config.root(),
        completion_root: output.completion_root(),
        epoch,
    };
    let sealing_key = SealingKey::new(decryption_output.public_key().clone())?;

    Ok(Ehtdh1Material {
        sealing_key,
        public_key_set,
        secret_share,
        setup_context,
    })
}

#[cfg(test)]
mod tests {
    use golden_core::{GoldenGroup, GoldenScalar};
    use golden_rustcrypto::{P256Backend, P256Scalar};

    use super::*;

    type G = P256Backend;

    fn scalar(value: u64) -> P256Scalar {
        P256Scalar::from_u64(value).unwrap()
    }

    #[test]
    fn aggregate_keys_must_be_nonidentity_then_identity() {
        let identity = G::identity();
        let nonidentity = G::mul_generator(&scalar(1));

        assert_eq!(
            validate_aggregate_keys::<G>(&identity, &identity),
            Err(Error::InvalidJointPublicKey)
        );
        assert_eq!(
            validate_aggregate_keys::<G>(&nonidentity, &nonidentity),
            Err(Error::InvalidPublicKeySet)
        );
        assert_eq!(
            validate_aggregate_keys::<G>(&nonidentity, &identity),
            Ok(())
        );
    }
}
