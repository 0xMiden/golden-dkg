//! Core-owned flat dealer proof inputs and the stateful proof-system seam.

use rand_core::CryptoRngCore;

use crate::{
    DkgConfig, DkgInstanceKind, Error, EvrfMessage, GoldenCurve, GoldenGroup, ParticipantIndex,
    Result, TranscriptRoot,
};

/// One borrowed statement/proof pair for ordered batch verification.
#[derive(Clone, Copy)]
pub struct DealerProofRef<'a, G: GoldenGroup> {
    /// Core-owned flat public statement.
    pub statement: &'a DealerProofStatement<G>,
    /// Opaque proof bytes interpreted by the injected proof system.
    pub proof: &'a [u8],
}

/// Stateful, reusable dealer-proof implementation.
pub trait DealerProofSystem<G: GoldenCurve>: Send + Sync {
    /// Prove one complete dealer contribution.
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>>;

    /// Verify one complete dealer contribution.
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()>;

    /// Verify ordered independent dealer contributions.
    ///
    /// Proof systems may override this with a sound combined verifier. The
    /// default preserves the input order and verifies each proof individually.
    fn verify_batch(&self, config: &DkgConfig<G>, proofs: &[DealerProofRef<'_, G>]) -> Result<()> {
        for item in proofs {
            self.verify(config, item.statement, item.proof)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DealerProofReceiver<G: GoldenGroup> {
    participant: ParticipantIndex,
    public_key: G::Element,
    share_commitment: G::Element,
    pad_commitment: G::Element,
    encrypted_share: G::Scalar,
}

/// Immutable flat public input for one dealer's complete contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealerProofStatement<G: GoldenGroup> {
    dealer: ParticipantIndex,
    dealer_public_key: G::Element,
    dealer_message_root: TranscriptRoot,
    threshold: usize,
    receivers_per_instance: usize,
    effective_messages: Vec<EvrfMessage>,
    commitment_coefficients: Vec<G::Element>,
    receivers: Vec<DealerProofReceiver<G>>,
}

impl<G: GoldenGroup> DealerProofStatement<G> {
    // Only core constructs proof inputs from validated dealer data. Keeping
    // this crate-private prevents proof systems from defining a second
    // statement-construction seam.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &DkgConfig<G>,
        dealer: ParticipantIndex,
        dealer_message_root: TranscriptRoot,
        effective_messages: Vec<EvrfMessage>,
        commitment_coefficients: Vec<G::Element>,
        share_commitments: Vec<G::Element>,
        pad_commitments: Vec<G::Element>,
        encrypted_shares: Vec<G::Scalar>,
    ) -> Result<Self> {
        Self::build(
            config,
            dealer,
            dealer_message_root,
            effective_messages,
            commitment_coefficients,
            share_commitments,
            pad_commitments,
            encrypted_shares,
        )
        .map_err(|_| Error::ProofGenerationFailed)
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    fn build(
        config: &DkgConfig<G>,
        dealer: ParticipantIndex,
        dealer_message_root: TranscriptRoot,
        effective_messages: Vec<EvrfMessage>,
        commitment_coefficients: Vec<G::Element>,
        share_commitments: Vec<G::Element>,
        pad_commitments: Vec<G::Element>,
        encrypted_shares: Vec<G::Scalar>,
    ) -> Result<Self> {
        let dealer_public_key = config.registry().public_key(dealer)?.clone();
        let instance_count = config.instances().len();
        let receivers_per_instance = config
            .registry()
            .len()
            .checked_sub(1)
            .ok_or(Error::ProofVerificationFailed)?;
        let coefficient_count = instance_count
            .checked_mul(config.threshold())
            .ok_or(Error::ProofVerificationFailed)?;
        let receiver_count = instance_count
            .checked_mul(receivers_per_instance)
            .ok_or(Error::ProofVerificationFailed)?;

        if effective_messages.len() != instance_count
            || commitment_coefficients.len() != coefficient_count
            || share_commitments.len() != receiver_count
            || pad_commitments.len() != receiver_count
            || encrypted_shares.len() != receiver_count
        {
            return Err(Error::ProofVerificationFailed);
        }

        let mut receivers = Vec::new();
        receivers
            .try_reserve_exact(receiver_count)
            .map_err(|_| Error::ProofVerificationFailed)?;
        for instance_position in 0..instance_count {
            for (receiver_position, (participant, public_key)) in config
                .registry()
                .entries()
                .filter(|(participant, _)| *participant != dealer)
                .enumerate()
            {
                if receiver_position >= receivers_per_instance {
                    return Err(Error::ProofVerificationFailed);
                }
                let offset = instance_position
                    .checked_mul(receivers_per_instance)
                    .and_then(|start| start.checked_add(receiver_position))
                    .ok_or(Error::ProofVerificationFailed)?;
                receivers.push(DealerProofReceiver {
                    participant,
                    public_key: public_key.clone(),
                    share_commitment: share_commitments
                        .get(offset)
                        .ok_or(Error::ProofVerificationFailed)?
                        .clone(),
                    pad_commitment: pad_commitments
                        .get(offset)
                        .ok_or(Error::ProofVerificationFailed)?
                        .clone(),
                    encrypted_share: encrypted_shares
                        .get(offset)
                        .ok_or(Error::ProofVerificationFailed)?
                        .clone(),
                });
            }
        }
        if receivers.len() != receiver_count {
            return Err(Error::ProofVerificationFailed);
        }

        Ok(Self {
            dealer,
            dealer_public_key,
            dealer_message_root,
            threshold: config.threshold(),
            receivers_per_instance,
            effective_messages,
            commitment_coefficients,
            receivers,
        })
    }

    pub(crate) fn validate_against(&self, config: &DkgConfig<G>) -> Result<()> {
        let expected_dealer_key = config
            .registry()
            .public_key(self.dealer)
            .map_err(|_| Error::ProofVerificationFailed)?;
        let instance_count = config.instances().len();
        let receivers_per_instance = config
            .registry()
            .len()
            .checked_sub(1)
            .ok_or(Error::ProofVerificationFailed)?;
        let coefficient_count = instance_count
            .checked_mul(config.threshold())
            .ok_or(Error::ProofVerificationFailed)?;
        let receiver_count = instance_count
            .checked_mul(receivers_per_instance)
            .ok_or(Error::ProofVerificationFailed)?;

        if expected_dealer_key != &self.dealer_public_key
            || self.threshold != config.threshold()
            || self.receivers_per_instance != receivers_per_instance
            || self.effective_messages.len() != instance_count
            || self.commitment_coefficients.len() != coefficient_count
            || self.receivers.len() != receiver_count
        {
            return Err(Error::ProofVerificationFailed);
        }

        for instance_position in 0..instance_count {
            for (receiver_position, (participant, public_key)) in config
                .registry()
                .entries()
                .filter(|(participant, _)| *participant != self.dealer)
                .enumerate()
            {
                if receiver_position >= receivers_per_instance {
                    return Err(Error::ProofVerificationFailed);
                }
                let offset = instance_position
                    .checked_mul(receivers_per_instance)
                    .and_then(|start| start.checked_add(receiver_position))
                    .ok_or(Error::ProofVerificationFailed)?;
                let receiver = self
                    .receivers
                    .get(offset)
                    .ok_or(Error::ProofVerificationFailed)?;
                if receiver.participant != participant || receiver.public_key != *public_key {
                    return Err(Error::ProofVerificationFailed);
                }
            }
        }
        Ok(())
    }

    /// Return the dealer participant.
    pub fn dealer(&self) -> ParticipantIndex {
        self.dealer
    }

    /// Return the registered dealer identity public key.
    pub fn dealer_public_key(&self) -> &G::Element {
        &self.dealer_public_key
    }

    /// Return the proof-independent canonical dealer-message root.
    pub fn dealer_message_root(&self) -> TranscriptRoot {
        self.dealer_message_root
    }

    /// Return the number of configured instances.
    pub fn instance_count(&self) -> usize {
        self.effective_messages.len()
    }

    /// Borrow one configured instance in protocol order.
    pub fn instance(&self, position: usize) -> Option<DealerProofInstanceView<'_, G>> {
        (position < self.instance_count()).then_some(DealerProofInstanceView {
            statement: self,
            position,
        })
    }
}

/// Immutable view of one flat dealer-proof instance.
#[derive(Clone, Copy)]
pub struct DealerProofInstanceView<'a, G: GoldenGroup> {
    statement: &'a DealerProofStatement<G>,
    position: usize,
}

impl<G: GoldenGroup> DealerProofInstanceView<'_, G> {
    /// Return the effective Main Golden message.
    pub fn effective_message(&self) -> EvrfMessage {
        self.statement.effective_messages[self.position]
    }

    /// Return the complete logical Feldman coefficient commitments.
    pub fn commitment_coefficients(&self) -> &[G::Element] {
        let start = self.position * self.statement.threshold;
        &self.statement.commitment_coefficients[start..start + self.statement.threshold]
    }

    /// Return the number of non-dealer receiver slots.
    pub fn receiver_count(&self) -> usize {
        self.statement.receivers_per_instance
    }

    /// Borrow one receiver slot in canonical registry order.
    pub fn receiver(&self, position: usize) -> Option<DealerProofReceiverView<'_, G>> {
        if position >= self.receiver_count() {
            return None;
        }
        let offset = self.position * self.receiver_count() + position;
        Some(DealerProofReceiverView {
            receiver: &self.statement.receivers[offset],
        })
    }
}

/// Immutable view of one public receiver relation.
#[derive(Clone, Copy)]
pub struct DealerProofReceiverView<'a, G: GoldenGroup> {
    receiver: &'a DealerProofReceiver<G>,
}

impl<G: GoldenGroup> DealerProofReceiverView<'_, G> {
    /// Return the receiver participant.
    pub fn participant(&self) -> ParticipantIndex {
        self.receiver.participant
    }

    /// Return the receiver identity public key.
    pub fn public_key(&self) -> &G::Element {
        &self.receiver.public_key
    }

    /// Return the public commitment to the receiver share.
    pub fn share_commitment(&self) -> &G::Element {
        &self.receiver.share_commitment
    }

    /// Return the public commitment to the receiver pad.
    pub fn pad_commitment(&self) -> &G::Element {
        &self.receiver.pad_commitment
    }

    /// Return the encrypted share scalar.
    pub fn encrypted_share(&self) -> &G::Scalar {
        &self.receiver.encrypted_share
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DealerProofReceiverWitness<S> {
    share: S,
    pad: S,
}

/// Immutable private input for one dealer's complete contribution.
#[derive(Clone, Eq, PartialEq)]
pub struct DealerProofWitness<G: GoldenGroup> {
    identity_secret: G::Scalar,
    polynomial_constants: Vec<Option<G::Scalar>>,
    receivers_per_instance: usize,
    receivers: Vec<DealerProofReceiverWitness<G::Scalar>>,
}

impl<G: GoldenGroup> DealerProofWitness<G> {
    pub(crate) fn new(
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        identity_secret: G::Scalar,
        polynomial_constants: Vec<Option<G::Scalar>>,
        receiver_openings: Vec<(G::Scalar, G::Scalar)>,
    ) -> Result<Self> {
        Self::from_revealed_parts(
            config,
            statement,
            identity_secret,
            polynomial_constants,
            receiver_openings,
        )
        .map_err(|_| Error::ProofGenerationFailed)
    }

    pub(crate) fn from_revealed_parts(
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        identity_secret: G::Scalar,
        polynomial_constants: Vec<Option<G::Scalar>>,
        receiver_openings: Vec<(G::Scalar, G::Scalar)>,
    ) -> Result<Self> {
        statement.validate_against(config)?;
        if polynomial_constants.len() != statement.instance_count()
            || polynomial_constants
                .iter()
                .zip(config.instances())
                .any(|(constant, kind)| {
                    constant.is_some() != matches!(kind, DkgInstanceKind::Random)
                })
        {
            return Err(Error::ProofVerificationFailed);
        }

        let receiver_count = statement
            .instance_count()
            .checked_mul(statement.receivers_per_instance)
            .ok_or(Error::ProofVerificationFailed)?;
        if receiver_openings.len() != receiver_count {
            return Err(Error::ProofVerificationFailed);
        }
        let mut receivers = Vec::new();
        receivers
            .try_reserve_exact(receiver_count)
            .map_err(|_| Error::ProofVerificationFailed)?;
        for (share, pad) in receiver_openings {
            receivers.push(DealerProofReceiverWitness { share, pad });
        }

        Ok(Self {
            identity_secret,
            polynomial_constants,
            receivers_per_instance: statement.receivers_per_instance,
            receivers,
        })
    }

    pub(crate) fn validate_shape(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
    ) -> Result<()> {
        let receiver_count = statement
            .instance_count()
            .checked_mul(statement.receivers_per_instance)
            .ok_or(Error::ProofVerificationFailed)?;
        if self.polynomial_constants.len() != statement.instance_count()
            || self.receivers_per_instance != statement.receivers_per_instance
            || self.receivers.len() != receiver_count
            || self
                .polynomial_constants
                .iter()
                .zip(config.instances())
                .any(|(constant, kind)| {
                    constant.is_some() != matches!(kind, DkgInstanceKind::Random)
                })
        {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    }

    /// Return the dealer identity secret.
    pub fn identity_secret(&self) -> &G::Scalar {
        &self.identity_secret
    }

    /// Return the number of configured witness instances.
    pub fn instance_count(&self) -> usize {
        self.polynomial_constants.len()
    }

    /// Borrow one private instance in protocol order.
    pub fn instance(&self, position: usize) -> Option<DealerProofWitnessInstanceView<'_, G>> {
        (position < self.instance_count()).then_some(DealerProofWitnessInstanceView {
            witness: self,
            position,
        })
    }
}

impl<G: GoldenGroup> core::fmt::Debug for DealerProofWitness<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DealerProofWitness")
            .field("identity_secret", &"<redacted>")
            .field("polynomial_constants", &"<redacted>")
            .field("receiver_openings", &"<redacted>")
            .finish()
    }
}

/// Immutable view of one private dealer-proof instance.
#[derive(Clone, Copy)]
pub struct DealerProofWitnessInstanceView<'a, G: GoldenGroup> {
    witness: &'a DealerProofWitness<G>,
    position: usize,
}

impl<G: GoldenGroup> DealerProofWitnessInstanceView<'_, G> {
    /// Return the Random constant opening, or `None` for a Zero instance.
    pub fn polynomial_constant(&self) -> Option<&G::Scalar> {
        self.witness.polynomial_constants[self.position].as_ref()
    }

    /// Return the number of private receiver openings.
    pub fn receiver_count(&self) -> usize {
        self.witness.receivers_per_instance
    }

    /// Borrow one private receiver opening in canonical registry order.
    pub fn receiver(&self, position: usize) -> Option<DealerProofWitnessReceiverView<'_, G>> {
        if position >= self.receiver_count() {
            return None;
        }
        let offset = self.position * self.receiver_count() + position;
        Some(DealerProofWitnessReceiverView {
            receiver: &self.witness.receivers[offset],
        })
    }
}

/// Immutable view of one private share and pad opening.
#[derive(Clone, Copy)]
pub struct DealerProofWitnessReceiverView<'a, G: GoldenGroup> {
    receiver: &'a DealerProofReceiverWitness<G::Scalar>,
}

impl<G: GoldenGroup> DealerProofWitnessReceiverView<'_, G> {
    /// Return the receiver share opening.
    pub fn share(&self) -> &G::Scalar {
        &self.receiver.share
    }

    /// Return the receiver pad opening.
    pub fn pad(&self) -> &G::Scalar {
        &self.receiver.pad
    }
}
