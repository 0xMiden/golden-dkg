//! Bridge from completed Golden DKG runs to EHTDH1 key material.
//!
//! See crate root for the paper-to-crate symbol map.

use std::{collections::BTreeMap, fmt};

use golden_core::{
    DkgConfig, DkgOutput, GoldenGroup, GoldenHashToGroup, ParticipantRegistry, ReshareConfig,
    SessionId,
};

use crate::context::{
    derive_context_session_id, Error, PublicKeySet, PublicShare, SecretShare, SetupContext,
};
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

/// Convert two Golden DKG runs into paper `(pk, pkc, sk_1..sk_N)` material.
///
/// The paper treats key generation as centralized. This bridge checks matching
/// threshold, registry, context session, participants, local share owner, zero
/// key identity, and non-identity decryption key. `PublicKeySet::new` also
/// checks that `X_i` interpolates to `X` and `Z_i` interpolates to identity.
///
/// `decryption_output` must be the caller's own `complete` output under
/// `decryption_config`; the bridge checks only its key and index set.
pub fn material_from_dkg_outputs<G: GoldenHashToGroup>(
    decryption_config: &DkgConfig<G>,
    decryption_output: &DkgOutput<G>,
    context_config: &DkgConfig<G>,
    context_output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    material_from_runs(
        decryption_config.threshold,
        &decryption_config.registry,
        decryption_config.session_id,
        derive_context_session_id(decryption_config.session_id),
        decryption_output,
        context_config,
        context_output,
        epoch,
    )
}

/// Convert a completed reshare and a zero sharing run by its new committee
/// into paper `(pk, pkc, sk_1..sk_N)` material.
///
/// The reshare is the decryption run. Its key must be the predecessor's key
/// `X`, so the sealing key does not change. The context run is a plain zero
/// sharing DKG by the new committee over `reshare_config.receivers()` at
/// threshold `reshare_config.threshold()`, with the session id that
/// [`derive_reshare_context_session_id`] derives from the reshare
/// configuration root. That root stands in for the decryption session:
/// [`SetupContext::decryption_session_id`] holds it, so the context run is
/// bound to the declared dealers, both registries, the threshold, beta and
/// the predecessor, not only to the reshare session id. No plain DKG may use
/// a reshare configuration root as its session id, as requirement 5 of
/// [`golden_core::reshare`] states.
///
/// `reshare_output` must be the caller's own `complete_reshare` output under
/// `reshare_config`; the bridge checks only its key and index set.
///
/// The remaining checks are those of [`material_from_dkg_outputs`], read
/// against the receiver registry and the reshare threshold.
pub fn material_from_reshare_outputs<G: GoldenHashToGroup>(
    reshare_config: &ReshareConfig<G>,
    reshare_output: &DkgOutput<G>,
    context_config: &DkgConfig<G>,
    context_output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    if reshare_output.public_key != *reshare_config.predecessor().public_key() {
        return Err(Error::InvalidBridge("reshared key mismatch"));
    }
    material_from_runs(
        reshare_config.threshold(),
        reshare_config.receivers(),
        SessionId(reshare_config.root()),
        derive_reshare_context_session_id(reshare_config),
        reshare_output,
        context_config,
        context_output,
        epoch,
    )
}

/// Session id of the EHTDH1 context run that pairs with the reshare under
/// `config`: [`derive_context_session_id`] of its configuration root.
pub fn derive_reshare_context_session_id<G: GoldenGroup>(config: &ReshareConfig<G>) -> SessionId {
    derive_context_session_id(SessionId(config.root()))
}

/// Pair a decryption run over `registry` at `threshold` with its context run
/// under `context_session_id`.
#[allow(clippy::too_many_arguments)]
fn material_from_runs<G: GoldenHashToGroup>(
    threshold: usize,
    registry: &ParticipantRegistry<G>,
    decryption_session_id: SessionId,
    context_session_id: SessionId,
    decryption_output: &DkgOutput<G>,
    context_config: &DkgConfig<G>,
    context_output: &DkgOutput<G>,
    epoch: [u8; 32],
) -> Result<Ehtdh1Material<G>, Error> {
    if threshold != context_config.threshold {
        return Err(Error::InvalidBridge("threshold mismatch"));
    }
    if registry.root() != context_config.registry.root() {
        return Err(Error::InvalidBridge("registry root mismatch"));
    }
    if context_config.session_id != context_session_id {
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

    let participants = registry.indexes().collect::<Vec<_>>();
    if participants != context_config.registry.indexes().collect::<Vec<_>>() {
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
        threshold,
        decryption_output.public_key.clone(),
        public_shares,
    )?;
    let secret_share = SecretShare {
        participant: decryption_output.secret_share.participant,
        decryption: decryption_output.secret_share.value.clone(),
        context: context_output.secret_share.value.clone(),
    };
    let setup_context = SetupContext {
        backend_id: G::BACKEND_ID.to_owned(),
        threshold,
        registry_root: registry.root(),
        participants,
        decryption_session_id,
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
