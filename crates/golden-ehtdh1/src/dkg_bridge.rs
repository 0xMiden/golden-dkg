//! Bridge from completed Golden DKG runs to EHTDH1 key material.
//!
//! See crate root for the paper-to-crate symbol map.

use std::{collections::BTreeMap, fmt};

use golden_core::{DkgConfig, DkgInstanceKind, DkgOutput, GoldenHashToGroup};

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

/// Convert one Golden `[Random, Zero]` DKG batch into paper `(pk, pkc, sk_1..sk_N)` material.
///
/// The paper treats key generation as centralized. This bridge checks matching
/// configuration and output identity before interpreting batch position zero as
/// the decryption sharing and position one as the context sharing.
/// `PublicKeySet::new` checks that `X_i` interpolates to `X` and `Z_i`
/// interpolates to identity.
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
    let decryption_output = &output.instances()[0];
    let context_output = &output.instances()[1];

    let participants = config.registry().indexes().collect::<Vec<_>>();

    let mut public_shares = BTreeMap::new();
    for participant in &participants {
        public_shares.insert(
            *participant,
            PublicShare {
                decryption: decryption_output.public_key_shares()[participant].clone(),
                context: context_output.public_key_shares()[participant].clone(),
            },
        );
    }

    let public_key_set = PublicKeySet::new(
        config.threshold(),
        decryption_output.public_key().clone(),
        public_shares,
    )?;
    let secret_share = SecretShare {
        participant: decryption_output.secret_share().participant,
        decryption: decryption_output.secret_share().value.clone(),
        context: context_output.secret_share().value.clone(),
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
