//! Bridge from completed Golden DKG runs to EHTDH1 key material.
//!
//! See crate root for the paper-to-crate symbol map.

use std::{collections::BTreeMap, fmt};

use golden_core::{DkgConfig, DkgOutput, GoldenGroup, GoldenHashToGroup, ParticipantIndex};

use crate::context::{
    derive_context_session_id, Error, PublicKeySet, PublicShare, SecretShare, SetupContext,
};
use crate::encrypt::SealingKey;

/// EHTDH1 material for one local participant.
#[derive(Clone)]
pub struct Ehtdh1Material<G: GoldenHashToGroup> {
    /// Paper `pk = X`, used by clients to seal payloads.
    pub sealing_key: SealingKey<G>,
    /// Paper `pkc = (X; X_i; Z_i)`, plus the threshold.
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

/// Convert two Golden DKG runs into paper `(pk, pkc, sk_1..sk_N)` material.
///
/// The paper treats key generation as centralized. This bridge checks matching
/// threshold, registry, context session, participants, local share owner, zero
/// key identity, and non-identity decryption key. `PublicKeySet::new` also
/// checks that `X_i` interpolates to `X` and `Z_i` interpolates to identity.
pub fn material_from_dkg_outputs<G: GoldenHashToGroup>(
    decryption_config: &DkgConfig<G>,
    decryption_output: &DkgOutput<G>,
    context_config: &DkgConfig<G>,
    context_output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    if decryption_config.threshold != context_config.threshold {
        return Err(Error::InvalidBridge("threshold mismatch"));
    }
    if decryption_config.registry.root() != context_config.registry.root() {
        return Err(Error::InvalidBridge("registry root mismatch"));
    }
    if context_config.session_id != derive_context_session_id(decryption_config.session_id) {
        return Err(Error::InvalidBridge("context session mismatch"));
    }
    if decryption_output.secret_share.participant != context_output.secret_share.participant {
        return Err(Error::InvalidBridge("local participant mismatch"));
    }
    if decryption_output
        .public_key_shares
        .keys()
        .ne(context_output.public_key_shares.keys())
    {
        return Err(Error::InvalidBridge("public share participant mismatch"));
    }
    if !bool::from(G::is_identity(&context_output.public_key)) {
        return Err(Error::InvalidBridge(
            "zero-sharing public key is not identity",
        ));
    }
    if bool::from(G::is_identity(&decryption_output.public_key)) {
        return Err(Error::InvalidBridge("decryption public key is identity"));
    }

    let participants = collect_participants(decryption_config);
    if participants != collect_participants(context_config) {
        return Err(Error::InvalidBridge("participant set mismatch"));
    }

    let mut public_shares = BTreeMap::new();
    for participant in &participants {
        let decryption = decryption_output
            .public_key_shares
            .get(participant)
            .cloned()
            .ok_or(Error::InvalidBridge("missing decryption public share"))?;
        let context = context_output
            .public_key_shares
            .get(participant)
            .cloned()
            .ok_or(Error::InvalidBridge("missing context public share"))?;
        public_shares.insert(
            *participant,
            PublicShare {
                decryption,
                context,
            },
        );
    }

    let public_key_set = PublicKeySet::new(
        decryption_config.threshold,
        decryption_output.public_key.clone(),
        public_shares,
    )?;
    let secret_share = SecretShare {
        participant: decryption_output.secret_share.participant,
        decryption: decryption_output.secret_share.value.clone(),
        context: context_output.secret_share.value.clone(),
    };
    let setup_context = SetupContext {
        backend_id: G::BACKEND_ID,
        threshold: decryption_config.threshold,
        registry_root: decryption_config.registry.root(),
        participants,
        decryption_session_id: decryption_config.session_id,
        context_session_id: context_config.session_id,
        decryption_transcript_root: decryption_output.transcript_root,
        context_transcript_root: context_output.transcript_root,
        epoch,
    };
    let sealing_key = SealingKey::new(decryption_output.public_key.clone())?;

    Ok(Ehtdh1Material {
        sealing_key,
        public_key_set,
        secret_share,
        setup_context,
    })
}

fn collect_participants<G: GoldenGroup>(config: &DkgConfig<G>) -> Vec<ParticipantIndex> {
    config.registry.indexes().collect()
}
