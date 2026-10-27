//! Conversion from one completed `[Random, Zero]` or `[Reshare, Zero]` batch to EHTDH1 material.

use golden_core::{DkgConfig, DkgGroup, DkgInstanceKind, DkgOutput, ResharePredecessor};
use group::Group;
use std::{collections::BTreeMap, fmt};

use crate::{Error, PublicKeySet, PublicShare, SealingKey, SecretShare, SetupContext};

/// Encryption, decryption and context material for one participant.
#[derive(Clone)]
pub struct Ehtdh1Material<G: DkgGroup> {
    /// Client encryption key.
    pub sealing_key: SealingKey<G>,
    /// Canonical public decryption/context shares.
    pub public_key_set: PublicKeySet<G>,
    /// Participant-local guarded scalars.
    pub secret_share: SecretShare<G>,
    /// Trusted batch and application identity.
    pub setup_context: SetupContext,
}
impl<G: DkgGroup> fmt::Debug for Ehtdh1Material<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ehtdh1Material")
            .field("sealing_key", &self.sealing_key)
            .field("public_key_set", &self.public_key_set)
            .field("secret_share", &"<redacted>")
            .field("setup_context", &self.setup_context)
            .finish()
    }
}

/// Validate a completed `[Random, Zero]` or `[Reshare, Zero]` batch and construct its EHTDH1
/// material. A `[Reshare, Zero]` batch keeps its predecessor's sealing key.
///
/// Restored outputs require authenticated trusted completion provenance. These
/// algebraic and identity checks cannot establish historical proof verification.
pub fn material_from_dkg_output<G: DkgGroup>(
    config: &DkgConfig<G>,
    output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    if !matches!(
        config.instances(),
        [
            DkgInstanceKind::Random | DkgInstanceKind::Reshare,
            DkgInstanceKind::Zero
        ]
    ) || output.config_root() != config.root()
        || output.public().instance_count() != 2
    {
        return Err(Error::InvalidBridge("batch configuration mismatch"));
    }
    let decryption = output
        .public()
        .instance(0)
        .ok_or(Error::InvalidBridge("missing decryption instance"))?;
    let context = output
        .public()
        .instance(1)
        .ok_or(Error::InvalidBridge("missing context instance"))?;
    if Some(decryption.kind()) != config.instance(0)
        || context.kind() != DkgInstanceKind::Zero
        || bool::from(decryption.public_key().is_identity())
        || !bool::from(context.public_key().is_identity())
        || (decryption.kind() == DkgInstanceKind::Reshare
            && config.predecessor().map(ResharePredecessor::public_key)
                != Some(decryption.public_key()))
    {
        return Err(Error::InvalidBridge("invalid instance keys"));
    }
    let participants: Vec<_> = config.registry().indexes().collect();
    if decryption
        .public_key_shares()
        .map(|(id, _)| id)
        .ne(participants.iter().copied())
        || context
            .public_key_shares()
            .map(|(id, _)| id)
            .ne(participants.iter().copied())
        || !participants.contains(&output.participant())
    {
        return Err(Error::InvalidBridge("participant set mismatch"));
    }
    let mut public_shares = BTreeMap::new();
    for participant in &participants {
        public_shares.insert(
            *participant,
            PublicShare {
                decryption: *decryption
                    .public_key_share(*participant)
                    .ok_or(Error::InvalidBridge("missing decryption share"))?,
                context: *context
                    .public_key_share(*participant)
                    .ok_or(Error::InvalidBridge("missing context share"))?,
            },
        );
    }
    let public_key_set =
        PublicKeySet::new(config.threshold(), *decryption.public_key(), public_shares)?;
    let x = output
        .secret_share(0)
        .ok_or(Error::InvalidBridge("missing local share"))?;
    let z = output
        .secret_share(1)
        .ok_or(Error::InvalidBridge("missing local share"))?;
    let own = public_key_set
        .public_share(output.participant())
        .ok_or(Error::InvalidBridge("unknown local participant"))?;
    if G::mul_generator(x) != own.decryption || G::mul_generator(z) != own.context {
        return Err(Error::InvalidBridge("local opening mismatch"));
    }
    let setup_context = SetupContext {
        group_id: G::GROUP_ID.to_owned(),
        threshold: config.threshold(),
        participants,
        session_id: config.session_id(),
        config_root: config.root(),
        completion_root: output.completion_root(),
        epoch,
    };
    let sealing_key = SealingKey::new(*decryption.public_key())?;
    Ok(Ehtdh1Material {
        sealing_key,
        public_key_set,
        secret_share: SecretShare::new(output.participant(), x, z),
        setup_context,
    })
}
