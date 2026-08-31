//! Batch-native DKG orchestration over a generic Golden group.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;

#[cfg(any(feature = "serde", feature = "miden-serde"))]
use crate::lagrange_coefficients_at_zero;
use crate::transcript::{TranscriptBuilder, TranscriptRoot};
use crate::{Error, GoldenGroup, ParticipantIndex, Result};

/// Protocol version used in transcript binding.
pub const PROTOCOL_VERSION: u32 = 4;

/// Byte length of a raw dealer nonce and an effective eVRF message.
pub const DEALER_MESSAGE_NONCE_BYTES: usize = 32;

/// Session identifier for replay protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create a random session ID.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Independently sampled raw nonce carried by one dealing body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerMessageNonce(pub [u8; DEALER_MESSAGE_NONCE_BYTES]);

impl DealerMessageNonce {
    /// Create a random dealer-message nonce.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; DEALER_MESSAGE_NONCE_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Domain-separated effective message used by the Main Golden relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvrfMessage(pub [u8; DEALER_MESSAGE_NONCE_BYTES]);

/// Public participant registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRegistry<G: GoldenGroup> {
    participants: BTreeMap<ParticipantIndex, G::Element>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> ParticipantRegistry<G> {
    /// Build a registry from participant identity public keys.
    pub fn new(entries: Vec<(ParticipantIndex, G::Element)>) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::EmptyParticipantRegistry);
        }

        let mut participants = BTreeMap::new();
        let mut public_keys = Vec::<(Vec<u8>, ParticipantIndex)>::new();
        for (participant, public_key) in entries {
            if participants.contains_key(&participant) {
                return Err(Error::DuplicateParticipantIndex(participant.get()));
            }
            if bool::from(G::is_identity(&public_key)) {
                return Err(Error::InvalidEncoding);
            }
            let encoded_public_key = G::encode_element(&public_key);
            if let Some((_, first)) = public_keys
                .iter()
                .find(|(known, _)| known.as_slice() == encoded_public_key.as_ref())
            {
                return Err(Error::DuplicateParticipantPublicKey {
                    first: first.get(),
                    second: participant.get(),
                });
            }
            public_keys.push((encoded_public_key.as_ref().to_vec(), participant));
            participants.insert(participant, public_key);
        }

        let root = registry_root::<G>(&participants);
        Ok(Self { participants, root })
    }

    /// Number of registered participants.
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Return the registry root.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }

    /// Return a participant public key.
    pub fn public_key(&self, participant: ParticipantIndex) -> Result<&G::Element> {
        self.participants
            .get(&participant)
            .ok_or(Error::UnknownParticipant(participant.get()))
    }

    /// Return participant indexes in canonical order.
    pub fn indexes(&self) -> impl Iterator<Item = ParticipantIndex> + '_ {
        self.participants.keys().copied()
    }

    /// Return participant entries in canonical order.
    pub fn entries(&self) -> impl Iterator<Item = (ParticipantIndex, &G::Element)> + '_ {
        self.participants
            .iter()
            .map(|(participant, public_key)| (*participant, public_key))
    }
}

/// Constant-term policy for one sharing in an ordered DKG batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DkgInstanceKind {
    /// Independently sampled random constant term.
    Random,
    /// Identity/zero constant term.
    Zero,
}

/// Immutable, validated DKG configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgConfig<G: GoldenGroup> {
    threshold: usize,
    session_id: SessionId,
    registry: ParticipantRegistry<G>,
    instances: Vec<DkgInstanceKind>,
    root: TranscriptRoot,
}

impl<G: GoldenGroup> DkgConfig<G> {
    /// Construct an arbitrary ordered, nonempty set of sharing instances.
    pub fn new(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
        instances: Vec<DkgInstanceKind>,
    ) -> Result<Self> {
        if threshold == 0 || threshold > registry.len() {
            return Err(Error::InvalidThreshold {
                threshold,
                participants: registry.len(),
            });
        }
        if instances.is_empty() {
            return Err(Error::EmptyDkgBatch);
        }
        let root = config_root::<G>(threshold, session_id, &registry, &instances);
        Ok(Self {
            threshold,
            session_id,
            registry,
            instances,
            root,
        })
    }

    /// Construct one random sharing.
    pub fn new_random(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
    ) -> Result<Self> {
        Self::new(
            threshold,
            session_id,
            registry,
            vec![DkgInstanceKind::Random],
        )
    }

    /// Construct one zero sharing.
    pub fn new_zero(
        threshold: usize,
        session_id: SessionId,
        registry: ParticipantRegistry<G>,
    ) -> Result<Self> {
        Self::new(threshold, session_id, registry, vec![DkgInstanceKind::Zero])
    }

    /// Return the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return the session identifier.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Return the participant registry.
    pub fn registry(&self) -> &ParticipantRegistry<G> {
        &self.registry
    }

    /// Return one registered participant identity public key.
    pub fn identity_public_key(&self, participant: ParticipantIndex) -> Option<&G::Element> {
        self.registry.participants.get(&participant)
    }

    /// Return configured instance kinds in protocol order.
    pub fn instances(&self) -> &[DkgInstanceKind] {
        &self.instances
    }

    /// Return one configured instance kind by protocol position.
    pub fn instance(&self, position: usize) -> Option<DkgInstanceKind> {
        self.instances.get(position).copied()
    }

    /// Return the canonical configuration root.
    pub fn root(&self) -> TranscriptRoot {
        self.root
    }
}

/// Completed participant state for one batch position.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgInstanceOutput<G: GoldenGroup> {
    public_key: G::Element,
    secret_share: G::Scalar,
    public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
}

impl<G: GoldenGroup> DkgInstanceOutput<G> {
    pub(crate) fn new(
        public_key: G::Element,
        secret_share: G::Scalar,
        public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
    ) -> Self {
        Self {
            public_key,
            secret_share,
            public_key_shares,
        }
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    pub(crate) fn from_persisted_parts(
        public_key: G::Element,
        secret_share: G::Scalar,
        public_key_shares: BTreeMap<ParticipantIndex, G::Element>,
    ) -> Result<Self> {
        let output = Self::new(public_key, secret_share, public_key_shares);
        output.validate_persisted()?;
        Ok(output)
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    fn validate_persisted(&self) -> Result<()> {
        if self.public_key_shares.is_empty() {
            return Err(Error::InvalidEncoding);
        }

        let local_public_share = G::mul_generator(&self.secret_share);
        if !self
            .public_key_shares
            .values()
            .any(|public_share| public_share == &local_public_share)
        {
            return Err(Error::InvalidEncoding);
        }

        let participant_scalars = self
            .public_key_shares
            .keys()
            .map(|participant| participant.to_scalar::<G::Scalar>())
            .collect::<Result<Vec<_>>>()
            .map_err(|_| Error::InvalidEncoding)?;
        let coefficients = lagrange_coefficients_at_zero(&participant_scalars)
            .map_err(|_| Error::InvalidEncoding)?;
        let interpolated_public_key = self
            .public_key_shares
            .values()
            .zip(coefficients.iter())
            .fold(G::identity(), |accumulator, (public_share, coefficient)| {
                G::add(&accumulator, &G::mul(public_share, coefficient))
            });
        if interpolated_public_key != self.public_key {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }

    /// Return the shared public key.
    pub fn public_key(&self) -> &G::Element {
        &self.public_key
    }

    /// Return this participant's secret share.
    pub fn secret_share(&self) -> &G::Scalar {
        &self.secret_share
    }

    /// Return public key shares in canonical participant order.
    pub fn public_key_shares(&self) -> &BTreeMap<ParticipantIndex, G::Element> {
        &self.public_key_shares
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DkgInstanceOutput<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgInstanceOutput")
            .field("public_key", &self.public_key)
            .field("secret_share", &"<redacted>")
            .field("public_key_shares", &self.public_key_shares)
            .finish()
    }
}

/// Immutable atomic output for the complete ordered DKG batch.
#[derive(Clone, Eq, PartialEq)]
pub struct DkgOutput<G: GoldenGroup> {
    participant: ParticipantIndex,
    configuration_root: TranscriptRoot,
    instances: Vec<DkgInstanceOutput<G>>,
}

impl<G: GoldenGroup> DkgOutput<G> {
    pub(crate) fn new(
        participant: ParticipantIndex,
        configuration_root: TranscriptRoot,
        instances: Vec<DkgInstanceOutput<G>>,
    ) -> Self {
        Self {
            participant,
            configuration_root,
            instances,
        }
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    pub(crate) fn from_persisted_parts(
        participant: ParticipantIndex,
        configuration_root: TranscriptRoot,
        instances: Vec<DkgInstanceOutput<G>>,
    ) -> Result<Self> {
        let first = instances.first().ok_or(Error::InvalidEncoding)?;
        for instance in &instances {
            let local_public_share = G::mul_generator(&instance.secret_share);
            if instance.public_key_shares.get(&participant) != Some(&local_public_share)
                || !instance
                    .public_key_shares
                    .keys()
                    .eq(first.public_key_shares.keys())
            {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok(Self::new(participant, configuration_root, instances))
    }

    /// Return the participant whose local secret shares this output contains.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }

    /// Return the proof-policy-independent configuration root accepted during
    /// completion.
    pub fn configuration_root(&self) -> TranscriptRoot {
        self.configuration_root
    }

    /// Return completed instances in configuration order.
    pub fn instances(&self) -> &[DkgInstanceOutput<G>] {
        &self.instances
    }

    /// Return one completed instance by configuration position.
    pub fn instance(&self, position: usize) -> Option<&DkgInstanceOutput<G>> {
        self.instances.get(position)
    }

    /// Derive the identity of the common public DKG result.
    pub fn completion_root(&self) -> TranscriptRoot {
        completion_root_from_public::<G>(self.configuration_root, &self.instances)
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DkgOutput<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgOutput")
            .field("participant", &self.participant)
            .field("configuration_root", &self.configuration_root)
            .field("instances", &self.instances)
            .field("completion_root", &self.completion_root())
            .finish()
    }
}

fn config_root<G: GoldenGroup>(
    threshold: usize,
    session_id: SessionId,
    registry: &ParticipantRegistry<G>,
    instances: &[DkgInstanceKind],
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"dkg-config");
    transcript.u32(b"version", PROTOCOL_VERSION);
    transcript.bytes(b"curve", G::CURVE_ID.as_bytes());
    transcript.bytes(b"session", &session_id.0);
    transcript.usize(b"threshold", threshold);
    transcript.bytes(b"registry", &registry.root());
    transcript.usize(b"instances-len", instances.len());
    for kind in instances {
        transcript.u32(
            b"instance-kind",
            match kind {
                DkgInstanceKind::Random => 0,
                DkgInstanceKind::Zero => 1,
            },
        );
    }
    transcript.root()
}

fn registry_root<G: GoldenGroup>(
    participants: &BTreeMap<ParticipantIndex, G::Element>,
) -> TranscriptRoot {
    let mut transcript = TranscriptBuilder::new(b"registry");
    transcript.bytes(b"curve", G::CURVE_ID.as_bytes());
    transcript.usize(b"len", participants.len());
    for (participant, public_key) in participants {
        transcript.participant(b"participant", *participant);
        transcript.element::<G>(b"public-key", public_key);
    }
    transcript.root()
}

fn completion_root_from_public<G: GoldenGroup>(
    configuration_root: TranscriptRoot,
    instances: &[DkgInstanceOutput<G>],
) -> TranscriptRoot {
    let mut transcript =
        TranscriptBuilder::with_prefix(b"golden-dkg/completion-root/v1", b"common-public-output");
    transcript.u32(b"protocol-version", PROTOCOL_VERSION);
    transcript.bytes(b"configuration-root", &configuration_root);
    transcript.usize(b"instance-count", instances.len());
    for (position, instance) in instances.iter().enumerate() {
        transcript.usize(b"instance-position", position);
        transcript.element::<G>(b"public-key", &instance.public_key);
        transcript.usize(b"public-key-share-count", instance.public_key_shares.len());
        for (participant, public_key_share) in &instance.public_key_shares {
            transcript.participant(b"participant", *participant);
            transcript.element::<G>(b"public-key-share", public_key_share);
        }
    }
    transcript.root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_golden::effective_message;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::{DealerProofStatement, GoldenScalar};

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn secret(participant: ParticipantIndex) -> TinyScalar {
        TinyScalar::from_u64(u64::from(participant.get())).unwrap()
    }

    fn registry() -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(
            [idx(1), idx(2), idx(3)]
                .into_iter()
                .map(|participant| (participant, TinyGroup::mul_generator(&secret(participant))))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn registry_and_config_expose_the_final_validated_contract() {
        assert_eq!(
            ParticipantRegistry::<TinyGroup>::new(Vec::new()).unwrap_err(),
            Error::EmptyParticipantRegistry
        );

        let registry = registry();
        let config = DkgConfig::new(
            2,
            SessionId([7; 32]),
            registry.clone(),
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap();

        assert_eq!(PROTOCOL_VERSION, 4);
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.session_id(), SessionId([7; 32]));
        assert_eq!(config.registry(), &registry);
        assert_eq!(
            config.identity_public_key(idx(2)),
            Some(registry.public_key(idx(2)).unwrap())
        );
        assert_eq!(config.identity_public_key(idx(4)), None);
        assert_eq!(config.instance(0), Some(DkgInstanceKind::Random));
        assert_eq!(config.instance(1), Some(DkgInstanceKind::Zero));
        assert_eq!(config.instance(2), None);
    }

    fn mixed_config() -> DkgConfig<TinyGroup> {
        DkgConfig::new(
            2,
            SessionId([7; 32]),
            registry(),
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap()
    }

    fn flat_statement(config: &DkgConfig<TinyGroup>) -> DealerProofStatement<TinyGroup> {
        DealerProofStatement::new(
            config,
            idx(1),
            [13; 32],
            vec![EvrfMessage([21; 32]), EvrfMessage([22; 32])],
            vec![
                TinyScalar::from_u64(5).unwrap(),
                TinyScalar::from_u64(7).unwrap(),
                TinyScalar::zero(),
                TinyScalar::from_u64(9).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(19).unwrap(),
                TinyScalar::from_u64(26).unwrap(),
                TinyScalar::from_u64(18).unwrap(),
                TinyScalar::from_u64(27).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(31).unwrap(),
                TinyScalar::from_u64(32).unwrap(),
                TinyScalar::from_u64(33).unwrap(),
                TinyScalar::from_u64(34).unwrap(),
            ],
            vec![
                TinyScalar::from_u64(50).unwrap(),
                TinyScalar::from_u64(58).unwrap(),
                TinyScalar::from_u64(51).unwrap(),
                TinyScalar::from_u64(61).unwrap(),
            ],
        )
        .unwrap()
    }

    fn revealed_openings() -> Vec<(TinyScalar, TinyScalar)> {
        [(19, 31), (26, 32), (18, 33), (27, 34)]
            .into_iter()
            .map(|(share, pad)| {
                (
                    TinyScalar::from_u64(share).unwrap(),
                    TinyScalar::from_u64(pad).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn flat_dealer_proof_views_preserve_instance_and_receiver_order() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let witness = crate::main_golden::reconstruct_revealed_witness(
            &config,
            &statement,
            secret(idx(1)),
            vec![Some(TinyScalar::from_u64(5).unwrap()), None],
            revealed_openings(),
        )
        .unwrap();

        assert_eq!(statement.dealer(), idx(1));
        assert_eq!(statement.dealer_public_key(), &secret(idx(1)));
        assert_eq!(statement.dealer_message_root(), [13; 32]);
        assert_eq!(statement.instance_count(), 2);

        let random = statement.instance(0).unwrap();
        assert_eq!(random.effective_message(), EvrfMessage([21; 32]));
        assert_eq!(
            random.commitment_coefficients(),
            &[
                TinyScalar::from_u64(5).unwrap(),
                TinyScalar::from_u64(7).unwrap(),
            ]
        );
        assert_eq!(random.receiver_count(), 2);
        let first_receiver = random.receiver(0).unwrap();
        assert_eq!(first_receiver.participant(), idx(2));
        assert_eq!(first_receiver.public_key(), &secret(idx(2)));
        assert_eq!(
            first_receiver.share_commitment(),
            &TinyScalar::from_u64(19).unwrap()
        );
        assert_eq!(
            first_receiver.pad_commitment(),
            &TinyScalar::from_u64(31).unwrap()
        );
        assert_eq!(
            first_receiver.encrypted_share(),
            &TinyScalar::from_u64(50).unwrap()
        );
        assert_eq!(random.receiver(1).unwrap().participant(), idx(3));
        assert!(random.receiver(2).is_none());
        assert!(statement.instance(2).is_none());

        assert_eq!(witness.identity_secret(), &secret(idx(1)));
        assert_eq!(witness.instance_count(), 2);
        let random_witness = witness.instance(0).unwrap();
        assert_eq!(
            random_witness.polynomial_constant(),
            Some(&TinyScalar::from_u64(5).unwrap())
        );
        assert_eq!(random_witness.receiver_count(), 2);
        let first_opening = random_witness.receiver(0).unwrap();
        assert_eq!(first_opening.share(), &TinyScalar::from_u64(19).unwrap());
        assert_eq!(first_opening.pad(), &TinyScalar::from_u64(31).unwrap());
        assert!(random_witness.receiver(2).is_none());
        assert_eq!(witness.instance(1).unwrap().polynomial_constant(), None);
        assert!(witness.instance(2).is_none());
        assert_eq!(
            format!("{witness:?}"),
            "DealerProofWitness { identity_secret: \"<redacted>\", polynomial_constants: \"<redacted>\", receiver_openings: \"<redacted>\" }"
        );
    }

    #[test]
    fn flat_statement_construction_rejects_inexact_dimensions() {
        let config = mixed_config();
        let result = DealerProofStatement::new(
            &config,
            idx(1),
            [13; 32],
            vec![EvrfMessage([21; 32]), EvrfMessage([22; 32])],
            vec![TinyScalar::zero(); 3],
            vec![TinyScalar::one(); 4],
            vec![TinyScalar::one(); 4],
            vec![TinyScalar::one(); 4],
        );

        assert_eq!(result.unwrap_err(), Error::ProofGenerationFailed);
    }

    #[test]
    fn revealed_witness_reconstruction_checks_dimensions_and_kind_grammar() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let identity_secret = secret(idx(1));
        let random = TinyScalar::from_u64(5).unwrap();

        let cases = [
            (vec![Some(random)], revealed_openings()),
            (vec![None, None], revealed_openings()),
            (
                vec![Some(random), Some(TinyScalar::zero())],
                revealed_openings(),
            ),
            (
                vec![Some(random), None],
                revealed_openings().into_iter().take(3).collect(),
            ),
        ];

        for (polynomial_constants, receiver_openings) in cases {
            assert_eq!(
                crate::main_golden::reconstruct_revealed_witness(
                    &config,
                    &statement,
                    identity_secret,
                    polynomial_constants,
                    receiver_openings,
                )
                .unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }

    fn check_flat_relation(
        config: &DkgConfig<TinyGroup>,
        statement: &DealerProofStatement<TinyGroup>,
        witness: &crate::DealerProofWitness<TinyGroup>,
        alter_pad: bool,
    ) -> Result<()> {
        crate::main_golden::check_dealer_relation_with_pad(
            config,
            statement,
            witness,
            |message, _, peer_key| {
                let pad = match (message.0, *peer_key) {
                    (value, key) if value == [21; 32] && key == secret(idx(2)) => 31,
                    (value, key) if value == [21; 32] && key == secret(idx(3)) => 32,
                    (value, key) if value == [22; 32] && key == secret(idx(2)) => 33,
                    (value, key) if value == [22; 32] && key == secret(idx(3)) => 34,
                    _ => return Err(Error::ProofVerificationFailed),
                };
                TinyScalar::from_u64(pad + u64::from(alter_pad))
            },
        )
    }

    #[test]
    fn native_relation_checks_the_complete_flat_witness() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let witness = crate::main_golden::reconstruct_revealed_witness(
            &config,
            &statement,
            secret(idx(1)),
            vec![Some(TinyScalar::from_u64(5).unwrap()), None],
            revealed_openings(),
        )
        .unwrap();

        check_flat_relation(&config, &statement, &witness, false).unwrap();
        assert_eq!(
            check_flat_relation(&config, &statement, &witness, true).unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn native_relation_rejects_altered_secret_constant_and_share() {
        let config = mixed_config();
        let statement = flat_statement(&config);
        let cases = [
            (
                secret(idx(2)),
                vec![Some(TinyScalar::from_u64(5).unwrap()), None],
                revealed_openings(),
            ),
            (
                secret(idx(1)),
                vec![Some(TinyScalar::from_u64(6).unwrap()), None],
                revealed_openings(),
            ),
            (
                secret(idx(1)),
                vec![Some(TinyScalar::from_u64(5).unwrap()), None],
                {
                    let mut openings = revealed_openings();
                    openings[0].0 = TinyScalar::from_u64(20).unwrap();
                    openings
                },
            ),
        ];

        for (identity_secret, polynomial_constants, receiver_openings) in cases {
            let witness = crate::main_golden::reconstruct_revealed_witness(
                &config,
                &statement,
                identity_secret,
                polynomial_constants,
                receiver_openings,
            )
            .unwrap();
            assert_eq!(
                check_flat_relation(&config, &statement, &witness, false).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }

    fn single_participant_config() -> DkgConfig<TinyGroup> {
        let participant = idx(1);
        let registry = ParticipantRegistry::new(vec![(
            participant,
            TinyGroup::mul_generator(&secret(participant)),
        )])
        .unwrap();
        DkgConfig::new(
            1,
            SessionId([8; 32]),
            registry,
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )
        .unwrap()
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    fn completed_outputs(config: &DkgConfig<TinyGroup>, seed: u8) -> Vec<DkgOutput<TinyGroup>> {
        config
            .registry()
            .indexes()
            .map(|participant| {
                let instances = config
                    .instances()
                    .iter()
                    .enumerate()
                    .map(|(position, kind)| {
                        let constant = match kind {
                            DkgInstanceKind::Random => u64::from(seed) + position as u64 + 1,
                            DkgInstanceKind::Zero => 0,
                        };
                        let slope = if config.threshold() > 1 {
                            u64::from(seed) + position as u64 + 3
                        } else {
                            0
                        };
                        let public_key_shares = config
                            .registry()
                            .indexes()
                            .map(|share_participant| {
                                let x = TinyScalar::from_u64(u64::from(share_participant.get()))
                                    .unwrap();
                                let value = TinyScalar::from_u64(constant)
                                    .unwrap()
                                    .add(&TinyScalar::from_u64(slope).unwrap().mul(&x));
                                (share_participant, TinyGroup::mul_generator(&value))
                            })
                            .collect::<BTreeMap<_, _>>();
                        DkgInstanceOutput::new(
                            TinyGroup::mul_generator(&TinyScalar::from_u64(constant).unwrap()),
                            public_key_shares[&participant],
                            public_key_shares,
                        )
                    })
                    .collect();
                DkgOutput::new(participant, config.root(), instances)
            })
            .collect()
    }

    fn persisted_instance(
        participant: ParticipantIndex,
        constant: u64,
        slope: u64,
    ) -> DkgInstanceOutput<TinyGroup> {
        let public_key_shares = [idx(1), idx(2), idx(3)]
            .into_iter()
            .map(|share_participant| {
                let x = TinyScalar::from_u64(u64::from(share_participant.get())).unwrap();
                let value = TinyScalar::from_u64(constant)
                    .unwrap()
                    .add(&TinyScalar::from_u64(slope).unwrap().mul(&x));
                (share_participant, TinyGroup::mul_generator(&value))
            })
            .collect::<BTreeMap<_, _>>();
        let secret_share = public_key_shares[&participant];
        DkgInstanceOutput::new(
            TinyGroup::mul_generator(&TinyScalar::from_u64(constant).unwrap()),
            secret_share,
            public_key_shares,
        )
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    #[test]
    fn persisted_instance_reconstruction_validates_its_algebra() {
        let participant = idx(2);
        let random = persisted_instance(participant, 9, 4);
        let expected = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *random.public_key(),
            *random.secret_share(),
            random.public_key_shares().clone(),
        )
        .unwrap();
        assert_eq!(expected, random);

        let cases = [
            (
                *random.public_key(),
                *random.secret_share(),
                BTreeMap::new(),
            ),
            (
                *random.public_key(),
                TinyScalar::from_u64(96).unwrap(),
                random.public_key_shares().clone(),
            ),
            (
                TinyGroup::identity(),
                *random.secret_share(),
                random.public_key_shares().clone(),
            ),
        ];
        for (public_key, secret_share, public_key_shares) in cases {
            assert_eq!(
                DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
                    public_key,
                    secret_share,
                    public_key_shares,
                )
                .unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    #[test]
    fn persisted_output_reconstruction_validates_only_batch_composition() {
        let participant = idx(2);
        let random = persisted_instance(participant, 9, 4);
        let random = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *random.public_key(),
            *random.secret_share(),
            random.public_key_shares().clone(),
        )
        .unwrap();
        let zero = persisted_instance(participant, 0, 7);
        let zero = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *zero.public_key(),
            *zero.secret_share(),
            zero.public_key_shares().clone(),
        )
        .unwrap();
        let expected = DkgOutput::from_persisted_parts(
            participant,
            mixed_config().root(),
            vec![random.clone(), zero.clone()],
        )
        .unwrap();
        assert_eq!(expected.instances(), [random.clone(), zero.clone()]);
        assert_eq!(expected.instances()[1].public_key(), &TinyGroup::identity());

        let mut missing_local_shares = random.public_key_shares().clone();
        missing_local_shares.remove(&participant);
        let missing_local = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *random.public_key(),
            missing_local_shares[&idx(1)],
            missing_local_shares,
        )
        .unwrap();
        let wrong_local = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *random.public_key(),
            random.public_key_shares()[&idx(1)],
            random.public_key_shares().clone(),
        )
        .unwrap();
        let mut different_participant_shares = zero.public_key_shares().clone();
        different_participant_shares.remove(&idx(3));
        let different_participants = DkgInstanceOutput::<TinyGroup>::from_persisted_parts(
            *zero.public_key(),
            *zero.secret_share(),
            different_participant_shares,
        )
        .unwrap();

        for instances in [
            Vec::new(),
            vec![missing_local],
            vec![wrong_local],
            vec![random, different_participants],
        ] {
            assert_eq!(
                DkgOutput::from_persisted_parts(participant, mixed_config().root(), instances,)
                    .unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_output_persistence_round_trips_every_participant_and_batch_shape() {
        let one = DkgConfig::new_random(2, SessionId([21; 32]), registry()).unwrap();
        let mut cases = completed_outputs(&one, 21);
        cases.extend(completed_outputs(&mixed_config(), 22));
        cases.extend(completed_outputs(&single_participant_config(), 23));

        for expected in cases {
            let completion_root = expected.completion_root();
            let encoded = postcard::to_allocvec(&expected).unwrap();
            let restored = postcard::from_bytes::<DkgOutput<TinyGroup>>(&encoded).unwrap();
            assert_eq!(restored, expected);
            assert_eq!(restored.configuration_root(), expected.configuration_root());
            assert_eq!(restored.completion_root(), completion_root);
        }
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn miden_output_persistence_round_trips_every_participant_and_batch_shape() {
        use miden_serde_utils::{Deserializable as _, Serializable as _};

        let one = DkgConfig::new_random(2, SessionId([24; 32]), registry()).unwrap();
        let mut cases = completed_outputs(&one, 24);
        cases.extend(completed_outputs(&mixed_config(), 25));
        cases.extend(completed_outputs(&single_participant_config(), 26));

        for expected in cases {
            let completion_root = expected.completion_root();
            let restored = DkgOutput::<TinyGroup>::read_from_bytes(&expected.to_bytes()).unwrap();
            assert_eq!(restored, expected);
            assert_eq!(restored.configuration_root(), expected.configuration_root());
            assert_eq!(restored.completion_root(), completion_root);
        }
    }

    #[test]
    fn output_debug_redacts_the_actual_local_secret_share() {
        let participant = idx(2);
        let valid = persisted_instance(participant, 9, 4);
        let instance: DkgInstanceOutput<TinyGroup> = DkgInstanceOutput::new(
            *valid.public_key(),
            TinyScalar::from_u64(96).unwrap(),
            valid.public_key_shares().clone(),
        );
        let secret_debug = format!("{:?}", instance.secret_share());
        let debug = format!("{instance:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&secret_debug));
    }

    #[test]
    fn config_constructors_validate_shape_and_bind_order() {
        for (config, expected) in [
            (
                DkgConfig::new_random(2, SessionId([7; 32]), registry()).unwrap(),
                DkgInstanceKind::Random,
            ),
            (
                DkgConfig::new_zero(2, SessionId([7; 32]), registry()).unwrap(),
                DkgInstanceKind::Zero,
            ),
        ] {
            assert_eq!(config.instances(), [expected]);
        }

        for threshold in [0, 4] {
            assert_eq!(
                DkgConfig::new_random(threshold, SessionId([7; 32]), registry(),).unwrap_err(),
                Error::InvalidThreshold {
                    threshold,
                    participants: 3,
                }
            );
        }

        assert_eq!(
            DkgConfig::new(2, SessionId([7; 32]), registry(), Vec::new(),).unwrap_err(),
            Error::EmptyDkgBatch
        );
        let config = mixed_config();
        let reversed = DkgConfig::new(
            config.threshold(),
            config.session_id(),
            config.registry().clone(),
            vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
        )
        .unwrap();
        assert_ne!(config.root(), reversed.root());
    }

    #[test]
    fn effective_message_binds_configuration_dealer_position_kind_and_nonce() {
        let configuration = mixed_config().root();
        let dealer = idx(1);
        let position = 0;
        let kind = DkgInstanceKind::Random;
        let nonce = DealerMessageNonce([3; DEALER_MESSAGE_NONCE_BYTES]);
        let message = effective_message(configuration, dealer, position, kind, nonce);
        let variants = [
            effective_message([9; 32], dealer, position, kind, nonce),
            effective_message(configuration, idx(2), position, kind, nonce),
            effective_message(configuration, dealer, 1, kind, nonce),
            effective_message(
                configuration,
                dealer,
                position,
                DkgInstanceKind::Zero,
                nonce,
            ),
            effective_message(
                configuration,
                dealer,
                position,
                kind,
                DealerMessageNonce([4; DEALER_MESSAGE_NONCE_BYTES]),
            ),
        ];
        for changed in variants {
            assert_ne!(message, changed);
        }
    }

    #[test]
    fn config_root_binds_every_configuration_dimension() {
        let base = mixed_config();
        let changed_registry = ParticipantRegistry::new(vec![
            (
                idx(1),
                TinyGroup::mul_generator(&TinyScalar::from_u64(4).unwrap()),
            ),
            (
                idx(2),
                TinyGroup::mul_generator(&TinyScalar::from_u64(5).unwrap()),
            ),
            (
                idx(3),
                TinyGroup::mul_generator(&TinyScalar::from_u64(6).unwrap()),
            ),
        ])
        .unwrap();
        let variants = [
            DkgConfig::new(
                2,
                SessionId([8; 32]),
                base.registry().clone(),
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                3,
                base.session_id(),
                base.registry().clone(),
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                2,
                base.session_id(),
                changed_registry,
                base.instances().to_vec(),
            )
            .unwrap(),
            DkgConfig::new(
                2,
                base.session_id(),
                base.registry().clone(),
                vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
            )
            .unwrap(),
        ];
        for changed in variants {
            assert_ne!(base.root(), changed.root());
        }
    }
}
