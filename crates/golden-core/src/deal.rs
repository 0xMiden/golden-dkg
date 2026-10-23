//! Opaque broadcasts, public verification and atomic participant completion.
use crate::dealer_message::{self, ParsedDealerMessage};
use crate::dealer_proof::{
    DealerProofInstance, DealerProofReceiver, InstanceWitness, ReceiverWitness,
};
use crate::output::DkgPublicInstance;
use crate::secret::{secret, secret_vec, SecretVec, Wipeable};
use crate::wire::reserve;
use crate::{
    DealerMessageNonce, DealerProofRef, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind, DkgOutput, DkgPublicOutput, Error, FeldmanCommitment, ParticipantIndex,
    Polynomial, Result, TranscriptRoot,
};
use core::fmt;
use ff::Field;
use group::Group;
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Caller-supplied association between an expected dealer and opaque transport bytes.
#[derive(Clone, Copy)]
pub struct DealerMessageRef<'a> {
    /// Expected registered dealer; checked against the encoded/proven identity.
    pub expected_dealer: ParticipantIndex,
    /// Exact complete broadcast.
    pub bytes: &'a [u8],
}

impl fmt::Debug for DealerMessageRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DealerMessageRef")
            .field("expected_dealer", &self.expected_dealer)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

/// Participant-local exact broadcast and self shares, containing no production credential.
#[derive(Clone)]
pub struct OwnDealing<G: DkgGroup> {
    pub(crate) participant: ParticipantIndex,
    pub(crate) config_root: TranscriptRoot,
    pub(crate) broadcast: Zeroizing<Vec<u8>>,
    pub(crate) private_shares: SecretVec<G::Scalar>,
}
impl<G: DkgGroup> OwnDealing<G> {
    /// Dealer/local share owner.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }
    /// Configuration identity.
    pub fn config_root(&self) -> TranscriptRoot {
        self.config_root
    }
    /// Exact bytes to broadcast. The insecure proof feature exposes disposable secrets here.
    pub fn broadcast_bytes(&self) -> &[u8] {
        &self.broadcast
    }
}
impl<G: DkgGroup> fmt::Debug for OwnDealing<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnDealing")
            .field("participant", &self.participant)
            .field("config_root", &self.config_root)
            .field("broadcast_length", &self.broadcast.len())
            .field("broadcast", &"<redacted>")
            .field("private_shares", &"<redacted>")
            .finish()
    }
}
/// Fixed whole-broadcast admission bound.
pub const fn max_dealer_message_bytes() -> usize {
    dealer_message::MAX_DEALER_MESSAGE_BYTES
}

/// Sample every configured sharing and produce one joint proof/broadcast.
pub fn deal<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    identity_secret: &G::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<OwnDealing<G>>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    if G::mul_generator(identity_secret) != *config.registry().public_key(dealer)? {
        return Err(Error::IdentityKeyMismatch);
    }
    dealer_message::encoded_prefix_len(config)?;
    let receiver_count = config.registry().len() - 1;
    let mut instances = reserve(config.instances().len())?;
    let mut private_instances = reserve(config.instances().len())?;
    let mut private_shares = secret_vec(config.instances().len())?;
    for (position, kind) in config.instances().iter().copied().enumerate() {
        let polynomial = match kind {
            DkgInstanceKind::Random => Polynomial::<G::Scalar>::random(config.threshold(), rng)?,
            DkgInstanceKind::Zero => Polynomial::<G::Scalar>::random_with_secret(
                G::Scalar::ZERO,
                config.threshold(),
                rng,
            )?,
        };
        let commitment = FeldmanCommitment::<G>::commit(&polynomial)?;
        let coefficients = commitment.coefficients().to_vec();
        let constant = if kind == DkgInstanceKind::Random {
            Some(secret(
                *polynomial
                    .coefficient(0)
                    .ok_or(Error::ProofGenerationFailed)?,
            ))
        } else {
            None
        };
        let own_share = polynomial.evaluate(dealer)?;
        private_shares.push(Wipeable(*own_share.value()));
        let nonce = DealerMessageNonce::random(rng);
        let effective_message =
            crate::main_golden::effective_message(config.root(), dealer, position, kind, nonce)?;
        let mut receivers = reserve(receiver_count)?;
        let mut openings = reserve(receiver_count)?;
        for (participant, key) in config
            .registry()
            .entries()
            .filter(|(participant, _)| *participant != dealer)
        {
            let share = polynomial.evaluate(participant)?;
            let pad = secret(crate::main_golden::receiver_pad::<G>(
                effective_message,
                identity_secret,
                key,
            )?);
            if bool::from(pad.expose().is_zero()) {
                return Err(Error::DegenerateEvrfOutput);
            }
            receivers.push(DealerProofReceiver {
                participant,
                public_key: *key,
                share_commitment: G::mul_generator(share.value()),
                pad_commitment: G::mul_generator(pad.expose()),
                encrypted_share: *share.value() + pad.expose(),
            });
            openings.push(ReceiverWitness {
                share: secret(*share.value()),
                pad,
            });
        }
        instances.push(DealerProofInstance {
            kind,
            nonce,
            effective_message,
            coefficients,
            receivers,
        });
        private_instances.push(InstanceWitness {
            constant,
            receivers: openings,
        });
    }
    let statement = dealer_message::statement(config, dealer, instances)?;
    let witness = DealerProofWitness {
        identity_secret: secret(*identity_secret),
        instances: private_instances,
    };
    let proof = Zeroizing::new(if receiver_count == 0 {
        Vec::new()
    } else {
        proofs.prove(config, &statement, &witness, rng)?
    });
    let broadcast = dealer_message::encode(config, &statement, &proof)?;
    Ok(OwnDealing {
        participant: dealer,
        config_root: config.root(),
        broadcast,
        private_shares,
    })
}

/// Publicly validate one expected dealer's opaque broadcast.
pub fn verify_dealer_message<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    expected_dealer: ParticipantIndex,
    bytes: &[u8],
) -> Result<()>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    verify_dealer_messages(
        proofs,
        config,
        &[DealerMessageRef {
            expected_dealer,
            bytes,
        }],
    )
}
/// Public verification of a nonempty partial/full board; no credential/decryption required.
pub fn verify_dealer_messages<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    messages: &[DealerMessageRef<'_>],
) -> Result<()>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    let board = crate::config::associate(config, messages, false)?;
    let parsed = validate_public(config, &board)?;
    verify_proofs(proofs, config, &parsed)
}
/// Verify every registered dealer and compute public results without participant credentials.
pub fn aggregate_public<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    messages: &[DealerMessageRef<'_>],
) -> Result<DkgPublicOutput<G>>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    let board = crate::config::associate(config, messages, true)?;
    let parsed = validate_public(config, &board)?;
    verify_proofs(proofs, config, &parsed)?;
    aggregate_verified(config, &parsed)
}
/// Atomically recover participant shares after accepting every public relation and proof.
/// Borrowed own state remains usable after a rejected candidate set.
pub fn complete<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    identity_secret: &G::Scalar,
    own: &OwnDealing<G>,
    peers: &[DealerMessageRef<'_>],
) -> Result<DkgOutput<G>>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    let participant = own.participant;
    let key = config
        .identity_public_key(participant)
        .ok_or(Error::OwnDealingMismatch)?;
    if own.config_root != config.root() || own.private_shares.len() != config.instances().len() {
        return Err(Error::OwnDealingMismatch);
    }
    if G::mul_generator(identity_secret) != *key {
        return Err(Error::IdentityKeyMismatch);
    }
    let mut candidates = reserve(
        peers
            .len()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?,
    )?;
    candidates.extend(peers.iter().copied());
    candidates.push(DealerMessageRef {
        expected_dealer: participant,
        bytes: own.broadcast_bytes(),
    });
    let board = crate::config::associate(config, &candidates, true)?;
    let parsed = validate_public(config, &board)?;
    verify_proofs(proofs, config, &parsed)?;
    let mut secret_shares = secret_vec(config.instances().len())?;
    for position in 0..config.instances().len() {
        let mut sum = secret(G::Scalar::ZERO);
        for message in &parsed {
            let instance = &message.statement.instances[position];
            let share = if message.statement.dealer == participant {
                secret(
                    *own.private_shares
                        .get(position)
                        .ok_or(Error::OwnDealingMismatch)?
                        .expose(),
                )
            } else {
                let receiver = instance
                    .receivers
                    .iter()
                    .find(|receiver| receiver.participant == participant)
                    .ok_or(Error::ShareDecryptionFailed)?;
                let pad = secret(
                    crate::main_golden::receiver_pad::<G>(
                        instance.effective_message,
                        identity_secret,
                        message.statement.dealer_public_key(),
                    )
                    .map_err(|_| Error::ShareDecryptionFailed)?,
                );
                if bool::from(pad.expose().is_zero())
                    || G::mul_generator(pad.expose()) != receiver.pad_commitment
                {
                    return Err(Error::ShareDecryptionFailed);
                }
                secret(receiver.encrypted_share - pad.expose())
            };
            if G::mul_generator(share.expose())
                != dealer_message::evaluate::<G>(&instance.coefficients, participant)
            {
                return Err(Error::ShareDecryptionFailed);
            }
            sum.0 += share.expose();
        }
        secret_shares.push(Wipeable(*sum.expose()));
    }
    let public = aggregate_verified(config, &parsed)?;
    Ok(DkgOutput {
        participant,
        public,
        secret_shares,
    })
}

fn validate_public<'a, G: DkgGroup>(
    config: &DkgConfig<G>,
    board: &BTreeMap<ParticipantIndex, &'a [u8]>,
) -> Result<Vec<ParsedDealerMessage<'a, G>>> {
    let mut parsed = reserve(board.len())?;
    let mut invalid = reserve(board.len())?;
    for (dealer, bytes) in board {
        match dealer_message::parse(config, *dealer, bytes) {
            Ok(message) => parsed.push(message),
            Err(Error::InvalidEncoding | Error::DealerMessageTooLarge | Error::InvalidProof) => {
                invalid.push(*dealer)
            }
            Err(error) => return Err(error),
        }
    }
    if !invalid.is_empty() {
        return Err(Error::InvalidDealerMessages { dealers: invalid });
    }
    Ok(parsed)
}
fn verify_proofs<G, P>(
    proofs: &P,
    config: &DkgConfig<G>,
    messages: &[ParsedDealerMessage<'_, G>],
) -> Result<()>
where
    G: DkgGroup,
    P: DealerProofSystem<G>,
{
    if config.registry().len() == 1 {
        return Ok(());
    }
    let mut refs = reserve(messages.len())?;
    for message in messages {
        refs.push(DealerProofRef {
            statement: &message.statement,
            proof: message.proof,
        });
    }
    match proofs.verify_batch(config, &refs) {
        Ok(()) => return Ok(()),
        Err(Error::InvalidProof) => {}
        Err(error) => return Err(error),
    }
    let mut invalid = reserve(messages.len())?;
    for message in messages {
        match proofs.verify(config, &message.statement, message.proof) {
            Ok(()) => {}
            Err(Error::InvalidProof) => invalid.push(message.statement.dealer()),
            Err(error) => return Err(error),
        }
    }
    if invalid.is_empty() {
        Err(Error::BatchVerificationFailed)
    } else {
        Err(Error::InvalidDealerProofs { dealers: invalid })
    }
}
fn aggregate_verified<G: DkgGroup>(
    config: &DkgConfig<G>,
    messages: &[ParsedDealerMessage<'_, G>],
) -> Result<DkgPublicOutput<G>> {
    let mut outputs = reserve(config.instances().len())?;
    for (position, kind) in config.instances().iter().copied().enumerate() {
        let mut coefficients = reserve(config.threshold())?;
        coefficients.resize(config.threshold(), G::Point::identity());
        for message in messages {
            for (sum, coefficient) in coefficients
                .iter_mut()
                .zip(&message.statement.instances[position].coefficients)
            {
                *sum += coefficient;
            }
        }
        let public_key = coefficients[0];
        let public_key_shares = config
            .registry()
            .indexes()
            .map(|participant| {
                (
                    participant,
                    dealer_message::evaluate::<G>(&coefficients, participant),
                )
            })
            .collect();
        outputs.push(DkgPublicInstance {
            kind,
            public_key,
            public_key_shares,
        });
    }
    DkgPublicOutput::new(config, outputs)
}
