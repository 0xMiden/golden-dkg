//! Immutable core-constructed inputs for the fixed Main Golden proof relation.
use crate::secret::Secret;
use crate::{
    DealerMessageNonce, DkgConfig, DkgGroup, DkgInstanceKind, Error, EvrfMessage, ParticipantIndex,
    Result, TranscriptRoot,
};
use core::fmt;
use rand_core::CryptoRngCore;

/// One immutable statement and opaque proof in canonical dealer order.
#[derive(Clone, Copy)]
pub struct DealerProofRef<'a, G: DkgGroup> {
    /// Core-owned public statement.
    pub statement: &'a DealerProofStatement<G>,
    /// Injected proof-system bytes.
    pub proof: &'a [u8],
}

/// Reusable, explicitly injected proof-only implementation of core's fixed relation.
pub trait DealerProofSystem<G: DkgGroup>: Send + Sync {
    /// Prove the complete ordered dealer contribution.
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>>;
    /// Verify one contribution. Only `InvalidProof` denotes dealer invalidity.
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()>;
    /// Verify independent contributions; optimized implementations bind the entire ordered batch.
    fn verify_batch(&self, config: &DkgConfig<G>, proofs: &[DealerProofRef<'_, G>]) -> Result<()> {
        for item in proofs {
            self.verify(config, item.statement, item.proof)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DealerProofReceiver<G: DkgGroup> {
    pub(crate) participant: ParticipantIndex,
    pub(crate) public_key: G::Point,
    pub(crate) share_commitment: G::Point,
    pub(crate) pad_commitment: G::Point,
    pub(crate) encrypted_share: G::Scalar,
}
#[derive(Clone, Debug)]
pub(crate) struct DealerProofInstance<G: DkgGroup> {
    pub(crate) kind: DkgInstanceKind,
    pub(crate) nonce: DealerMessageNonce,
    pub(crate) effective_message: EvrfMessage,
    pub(crate) coefficients: Vec<G::Point>,
    pub(crate) receivers: Vec<DealerProofReceiver<G>>,
}

/// Immutable public statement. Only core constructs it after public validation.
#[derive(Clone, Debug)]
pub struct DealerProofStatement<G: DkgGroup> {
    pub(crate) config_root: TranscriptRoot,
    pub(crate) dealer: ParticipantIndex,
    pub(crate) dealer_public_key: G::Point,
    pub(crate) instances: Vec<DealerProofInstance<G>>,
    pub(crate) logical: Vec<u8>,
    pub(crate) root: TranscriptRoot,
}
impl<G: DkgGroup> DealerProofStatement<G> {
    /// Configuration identity.
    pub fn config_root(&self) -> TranscriptRoot {
        self.config_root
    }
    /// Dealer index.
    pub fn dealer(&self) -> ParticipantIndex {
        self.dealer
    }
    /// Registered dealer identity key.
    pub fn dealer_public_key(&self) -> &G::Point {
        &self.dealer_public_key
    }
    /// Proof-independent logical dealer identity.
    pub fn dealer_message_root(&self) -> TranscriptRoot {
        self.root
    }
    /// Exact logical L payload, including reconstructed Zero constants.
    pub fn logical_bytes(&self) -> &[u8] {
        &self.logical
    }
    /// Number of configured instances.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }
    /// Borrow one zero-based instance.
    pub fn instance(&self, position: usize) -> Option<DealerProofInstanceView<'_, G>> {
        self.instances
            .get(position)
            .map(|instance| DealerProofInstanceView { instance, position })
    }
    /// Ordered instance views.
    pub fn instances(&self) -> impl ExactSizeIterator<Item = DealerProofInstanceView<'_, G>> {
        self.instances
            .iter()
            .enumerate()
            .map(|(position, instance)| DealerProofInstanceView { instance, position })
    }
    pub(crate) fn validate_against(&self, config: &DkgConfig<G>) -> Result<()> {
        if self.config_root != config.root()
            || config.identity_public_key(self.dealer) != Some(&self.dealer_public_key)
        {
            return Err(Error::InvalidProof);
        }
        crate::dealer_message::validate_instances(config, self.dealer, &self.instances).map_err(
            |error| match error {
                Error::AllocationFailed | Error::ArithmeticOverflow => error,
                _ => Error::InvalidProof,
            },
        )
    }
}

/// Borrowed public inputs of one instance.
#[derive(Clone, Copy)]
pub struct DealerProofInstanceView<'a, G: DkgGroup> {
    instance: &'a DealerProofInstance<G>,
    position: usize,
}
impl<'a, G: DkgGroup> DealerProofInstanceView<'a, G> {
    /// Zero-based configuration position.
    pub fn position(&self) -> usize {
        self.position
    }
    /// Configured constant policy.
    pub fn kind(&self) -> DkgInstanceKind {
        self.instance.kind
    }
    /// Raw independently sampled nonce.
    pub fn nonce(&self) -> DealerMessageNonce {
        self.instance.nonce
    }
    /// Core-derived effective Main Golden message.
    pub fn effective_message(&self) -> EvrfMessage {
        self.instance.effective_message
    }
    /// Logical coefficients, including Zero's identity constant.
    pub fn commitment_coefficients(&self) -> &'a [G::Point] {
        &self.instance.coefficients
    }
    /// Non-self receiver count.
    pub fn receiver_count(&self) -> usize {
        self.instance.receivers.len()
    }
    /// Receiver in canonical registry order excluding the dealer.
    pub fn receiver(&self, position: usize) -> Option<DealerProofReceiverView<'a, G>> {
        self.instance
            .receivers
            .get(position)
            .map(|receiver| DealerProofReceiverView { receiver })
    }
    /// Canonical non-self receivers.
    pub fn receivers(&self) -> impl ExactSizeIterator<Item = DealerProofReceiverView<'a, G>> + 'a {
        self.instance
            .receivers
            .iter()
            .map(|receiver| DealerProofReceiverView { receiver })
    }
}

/// Borrowed public inputs of one receiver slot.
#[derive(Clone, Copy)]
pub struct DealerProofReceiverView<'a, G: DkgGroup> {
    receiver: &'a DealerProofReceiver<G>,
}
impl<'a, G: DkgGroup> DealerProofReceiverView<'a, G> {
    /// Receiver index.
    pub fn participant(&self) -> ParticipantIndex {
        self.receiver.participant
    }
    /// Receiver identity key.
    pub fn public_key(&self) -> &'a G::Point {
        &self.receiver.public_key
    }
    /// Evaluated Feldman share commitment.
    pub fn share_commitment(&self) -> &'a G::Point {
        &self.receiver.share_commitment
    }
    /// Nonidentity pad commitment.
    pub fn pad_commitment(&self) -> &'a G::Point {
        &self.receiver.pad_commitment
    }
    /// Encrypted share scalar.
    pub fn encrypted_share(&self) -> &'a G::Scalar {
        &self.receiver.encrypted_share
    }
}

pub(crate) struct ReceiverWitness<F: ff::PrimeField> {
    pub(crate) share: Secret<F>,
    pub(crate) pad: Secret<F>,
}
pub(crate) struct InstanceWitness<F: ff::PrimeField> {
    pub(crate) constant: Option<Secret<F>>,
    pub(crate) receivers: Vec<ReceiverWitness<F>>,
}

/// Private witness with guarded owned scalar storage. It is neither Clone nor Copy.
pub struct DealerProofWitness<G: DkgGroup> {
    pub(crate) identity_secret: Secret<G::Scalar>,
    pub(crate) instances: Vec<InstanceWitness<G::Scalar>>,
}
impl<G: DkgGroup> DealerProofWitness<G> {
    /// Borrow the owned dealer credential copy.
    pub fn identity_secret(&self) -> &G::Scalar {
        self.identity_secret.expose()
    }
    /// Number of witness instances.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }
    /// Borrow one private instance.
    pub fn instance(&self, position: usize) -> Option<DealerProofWitnessInstanceView<'_, G>> {
        self.instances
            .get(position)
            .map(|instance| DealerProofWitnessInstanceView { instance })
    }
    pub(crate) fn validate_shape(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
    ) -> Result<()> {
        if self.instances.len() != config.instances().len()
            || self.instances.len() != statement.instance_count()
        {
            return Err(Error::InvalidProof);
        }
        for (position, instance) in self.instances.iter().enumerate() {
            let expected = statement.instance(position).ok_or(Error::InvalidProof)?;
            if instance.constant.is_some() != matches!(expected.kind(), DkgInstanceKind::Random)
                || instance.receivers.len() != expected.receiver_count()
            {
                return Err(Error::InvalidProof);
            }
        }
        Ok(())
    }
}
impl<G: DkgGroup> fmt::Debug for DealerProofWitness<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DealerProofWitness")
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Borrowed private instance openings.
pub struct DealerProofWitnessInstanceView<'a, G: DkgGroup> {
    instance: &'a InstanceWitness<G::Scalar>,
}
impl<'a, G: DkgGroup> DealerProofWitnessInstanceView<'a, G> {
    /// Random constant opening; Zero has none.
    pub fn polynomial_constant(&self) -> Option<&'a G::Scalar> {
        self.instance.constant.as_ref().map(|value| value.expose())
    }
    /// Number of non-self receiver openings.
    pub fn receiver_count(&self) -> usize {
        self.instance.receivers.len()
    }
    /// Borrow one receiver opening.
    pub fn receiver(&self, position: usize) -> Option<DealerProofWitnessReceiverView<'a, G>> {
        self.instance
            .receivers
            .get(position)
            .map(|receiver| DealerProofWitnessReceiverView { receiver })
    }
}
/// Borrowed private share and pad.
pub struct DealerProofWitnessReceiverView<'a, G: DkgGroup> {
    receiver: &'a ReceiverWitness<G::Scalar>,
}
impl<'a, G: DkgGroup> DealerProofWitnessReceiverView<'a, G> {
    /// Share opening.
    pub fn share(&self) -> &'a G::Scalar {
        self.receiver.share.expose()
    }
    /// Pad opening.
    pub fn pad(&self) -> &'a G::Scalar {
        self.receiver.pad.expose()
    }
}
