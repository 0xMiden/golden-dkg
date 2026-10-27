//! Immutable public results and participant-owned guarded local outputs.
use crate::secret::SecretVec;
use crate::wire::count;
use crate::{
    DkgConfig, DkgGroup, DkgInstanceKind, Error, ParticipantIndex, Result, TranscriptRoot,
};
use core::fmt;
use ff::Field;
use group::Group;
use std::collections::BTreeMap;

/// Public result of one zero-based configured instance.
#[derive(Clone, Debug)]
pub struct DkgPublicInstance<G: DkgGroup> {
    pub(crate) kind: DkgInstanceKind,
    pub(crate) public_key: G::Point,
    pub(crate) public_key_shares: BTreeMap<ParticipantIndex, G::Point>,
}
impl<G: DkgGroup> DkgPublicInstance<G> {
    /// Instance policy.
    pub fn kind(&self) -> DkgInstanceKind {
        self.kind
    }
    /// Aggregate public key (possibly identity).
    pub fn public_key(&self) -> &G::Point {
        &self.public_key
    }
    /// One participant's public share.
    pub fn public_key_share(&self, participant: ParticipantIndex) -> Option<&G::Point> {
        self.public_key_shares.get(&participant)
    }
    /// Canonical public shares.
    pub fn public_key_shares(
        &self,
    ) -> impl ExactSizeIterator<Item = (ParticipantIndex, &G::Point)> {
        self.public_key_shares
            .iter()
            .map(|(participant, point)| (*participant, point))
    }
}

/// Complete public batch result, independent of participant/proof implementation.
#[derive(Clone, Debug)]
pub struct DkgPublicOutput<G: DkgGroup> {
    pub(crate) config_root: TranscriptRoot,
    pub(crate) instances: Vec<DkgPublicInstance<G>>,
    pub(crate) completion_root: TranscriptRoot,
}
impl<G: DkgGroup> DkgPublicOutput<G> {
    pub(crate) fn new(config: &DkgConfig<G>, instances: Vec<DkgPublicInstance<G>>) -> Result<Self> {
        if instances.len() != config.instances().len()
            || instances
                .iter()
                .zip(config.instances())
                .any(|(instance, kind)| kind_mismatch(config, instance, *kind))
        {
            return Err(Error::InvalidPersistedState);
        }
        let completion_root = public_result_root::<G>(config.root(), &instances)?;
        Ok(Self {
            config_root: config.root(),
            instances,
            completion_root,
        })
    }
    /// Configuration identity.
    pub fn config_root(&self) -> TranscriptRoot {
        self.config_root
    }
    /// Proof-independent public result identity; does not establish agreement/activation.
    pub fn completion_root(&self) -> TranscriptRoot {
        self.completion_root
    }
    /// Borrow one zero-based instance.
    pub fn instance(&self, position: usize) -> Option<&DkgPublicInstance<G>> {
        self.instances.get(position)
    }
    /// Ordered instance views; repeated kinds retain distinct positions.
    pub fn instances(&self) -> impl ExactSizeIterator<Item = &DkgPublicInstance<G>> {
        self.instances.iter()
    }
    /// Number of public instances.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }
}

/// Participant-local output. Secret-bearing output is deliberately noncloneable.
pub struct DkgOutput<G: DkgGroup> {
    pub(crate) participant: ParticipantIndex,
    pub(crate) public: DkgPublicOutput<G>,
    pub(crate) secret_shares: SecretVec<G::Scalar>,
}
impl<G: DkgGroup> DkgOutput<G> {
    /// Local share owner.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }
    /// Borrow public results without duplicating local secrets.
    pub fn public(&self) -> &DkgPublicOutput<G> {
        &self.public
    }
    /// Borrow a native scalar at a zero-based configuration position.
    pub fn secret_share(&self, position: usize) -> Option<&G::Scalar> {
        self.secret_shares.get(position).map(|value| value.expose())
    }
    /// Public completion identity.
    pub fn completion_root(&self) -> TranscriptRoot {
        self.public.completion_root()
    }
    /// Configuration identity.
    pub fn config_root(&self) -> TranscriptRoot {
        self.public.config_root()
    }
}
impl<G: DkgGroup> fmt::Debug for DkgOutput<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgOutput")
            .field("participant", &self.participant)
            .field("public", &self.public)
            .field("secret_shares", &"<redacted>")
            .finish()
    }
}

pub(crate) fn public_payload<G: DkgGroup>(
    config_root: TranscriptRoot,
    instances: &[DkgPublicInstance<G>],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&config_root);
    count(&mut payload, instances.len())?;
    for (position, instance) in instances.iter().enumerate() {
        count(&mut payload, position)?;
        payload.push(instance.kind.tag());
        payload.extend_from_slice(&G::encode_point(&instance.public_key));
        crate::config::append_entries::<G>(
            &mut payload,
            instance
                .public_key_shares
                .iter()
                .map(|(participant, point)| (*participant, point)),
        )?;
    }
    Ok(payload)
}
fn public_result_root<G: DkgGroup>(
    config_root: TranscriptRoot,
    instances: &[DkgPublicInstance<G>],
) -> Result<TranscriptRoot> {
    crate::transcript::hash_payload(
        b"golden-dkg/completion-root/v3",
        &public_payload::<G>(config_root, instances)?,
    )
}
fn kind_mismatch<G: DkgGroup>(
    config: &DkgConfig<G>,
    instance: &DkgPublicInstance<G>,
    kind: DkgInstanceKind,
) -> bool {
    instance.kind != kind
        || config.pinned_key(kind).map_or(true, |pinned| {
            pinned.is_some_and(|key| key != instance.public_key)
        })
}

/// Recompute the EHTDH1 `[Random, Zero]` public-result identity without creating an output.
///
/// This checks canonical participant order only; it does not authenticate setup provenance.
#[doc(hidden)]
pub fn ehtdh1_completion_root<G: DkgGroup>(
    config_root: TranscriptRoot,
    joint_key: &G::Point,
    shares: &[(ParticipantIndex, G::Point, G::Point)],
) -> Result<TranscriptRoot> {
    if shares.is_empty() || shares.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(Error::InvalidEncoding);
    }
    let decryption = DkgPublicInstance::<G> {
        kind: DkgInstanceKind::Random,
        public_key: *joint_key,
        public_key_shares: shares
            .iter()
            .map(|(participant, point, _)| (*participant, *point))
            .collect(),
    };
    let context = DkgPublicInstance::<G> {
        kind: DkgInstanceKind::Zero,
        public_key: G::Point::identity(),
        public_key_shares: shares
            .iter()
            .map(|(participant, _, point)| (*participant, *point))
            .collect(),
    };
    public_result_root::<G>(config_root, &[decryption, context])
}

pub(crate) fn interpolate<G: DkgGroup>(
    basis: &[(ParticipantIndex, G::Point)],
    at: G::Scalar,
) -> Result<G::Point> {
    let mut point = G::Point::identity();
    for (i, (participant, share)) in basis.iter().enumerate() {
        let x_i = G::Scalar::from(u64::from(participant.get()));
        let mut numerator = G::Scalar::ONE;
        let mut denominator = G::Scalar::ONE;
        for (j, (other, _)) in basis.iter().enumerate() {
            if i != j {
                let x_j = G::Scalar::from(u64::from(other.get()));
                numerator *= at - x_j;
                denominator *= x_i - x_j;
            }
        }
        let inverse = Option::<G::Scalar>::from(denominator.invert())
            .ok_or(Error::NonInvertibleDenominator)?;
        point += *share * (numerator * inverse);
    }
    Ok(point)
}
pub(crate) fn on_polynomial<G: DkgGroup>(
    threshold: usize,
    key: &G::Point,
    shares: &BTreeMap<ParticipantIndex, G::Point>,
) -> Result<bool> {
    let basis = shares
        .iter()
        .take(threshold)
        .map(|(participant, point)| (*participant, *point))
        .collect::<Vec<_>>();
    if interpolate::<G>(&basis, G::Scalar::ZERO)? != *key {
        return Ok(false);
    }
    for (participant, point) in shares {
        if interpolate::<G>(&basis, G::Scalar::from(u64::from(participant.get())))? != *point {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn validate_public<G: DkgGroup>(
    config: &DkgConfig<G>,
    output: &DkgPublicOutput<G>,
) -> Result<()> {
    if output.config_root != config.root() || output.instances.len() != config.instances().len() {
        return Err(Error::InvalidPersistedState);
    }
    for (instance, kind) in output.instances.iter().zip(config.instances()) {
        if kind_mismatch(config, instance, *kind)
            || instance
                .public_key_shares
                .keys()
                .copied()
                .ne(config.registry().indexes())
        {
            return Err(Error::InvalidPersistedState);
        }
        if !on_polynomial::<G>(
            config.threshold(),
            &instance.public_key,
            &instance.public_key_shares,
        )? {
            return Err(Error::InvalidPersistedState);
        }
    }
    if public_result_root::<G>(output.config_root, &output.instances)? != output.completion_root {
        return Err(Error::InvalidPersistedState);
    }
    Ok(())
}
