//! Dealer-local construction of one opaque, batch-shaped broadcast.

use rand_core::CryptoRngCore;

use crate::dealer_message::{
    dealer_message_root, encode_dealer_message, encoded_prefix_len, DealerMessageData,
    DealerMessageInstance, DealerMessageReceiver, MAX_DEALER_MESSAGE_BYTES,
};
use crate::main_golden::{effective_message, receiver_pad};
use crate::{
    DealerMessageNonce, DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig,
    DkgInstanceKind, Error, FeldmanCommitment, GoldenCurve, GoldenGroup, GoldenScalar,
    ParticipantIndex, Polynomial, Result, TranscriptRoot,
};

/// Dealer-local state containing the exact opaque broadcast and private shares.
#[derive(Clone, Eq, PartialEq)]
pub struct OwnDealing<G: GoldenGroup> {
    participant: ParticipantIndex,
    configuration_root: TranscriptRoot,
    dealer_message_bytes: Vec<u8>,
    private_shares: Vec<G::Scalar>,
}

impl<G: GoldenGroup> OwnDealing<G> {
    /// Return the dealer participant.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }

    /// Return the exact opaque bytes to broadcast to peers.
    pub fn dealer_message_bytes(&self) -> &[u8] {
        &self.dealer_message_bytes
    }

    #[allow(dead_code)]
    pub(crate) fn configuration_root(&self) -> TranscriptRoot {
        self.configuration_root
    }

    #[allow(dead_code)]
    pub(crate) fn private_shares(&self) -> &[G::Scalar] {
        &self.private_shares
    }
}

impl<G: GoldenGroup> core::fmt::Debug for OwnDealing<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnDealing")
            .field("participant", &self.participant)
            .field("configuration_root", &self.configuration_root)
            .field("dealer_message_len", &self.dealer_message_bytes.len())
            .field("private_shares", &"<redacted>")
            .field("dealer_message_bytes", &"<redacted>")
            .finish()
    }
}

/// Return the maximum accepted whole dealer-message length.
pub const fn max_dealer_message_bytes() -> usize {
    MAX_DEALER_MESSAGE_BYTES
}

/// Create one complete opaque dealer broadcast and its dealer-local state.
pub fn deal<G, P>(
    proof_system: &P,
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<OwnDealing<G>>
where
    G: GoldenCurve,
    P: DealerProofSystem<G>,
{
    deal_with(
        config,
        dealer,
        dealer_identity_secret,
        rng,
        |message, secret, peer_key| {
            receiver_pad::<G>(message, secret, peer_key)
                .map_err(|_| Error::RelationEvaluationFailed)
        },
        |config, statement, witness, rng| proof_system.prove(config, statement, witness, rng),
    )
}

fn deal_with<G, R, E, P>(
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    dealer_identity_secret: &G::Scalar,
    rng: &mut R,
    mut evaluate_pad: E,
    mut prove: P,
) -> Result<OwnDealing<G>>
where
    G: GoldenGroup,
    R: CryptoRngCore,
    E: FnMut(crate::EvrfMessage, &G::Scalar, &G::Element) -> Result<G::Scalar>,
    P: FnMut(
        &DkgConfig<G>,
        &DealerProofStatement<G>,
        &DealerProofWitness<G>,
        &mut R,
    ) -> Result<Vec<u8>>,
{
    let registered_dealer_key = config.registry().public_key(dealer)?;
    if G::mul_generator(dealer_identity_secret) != *registered_dealer_key {
        return Err(Error::IdentityKeyMismatch);
    }

    let prefix_len = encoded_prefix_len::<G>(config)?;
    if prefix_len > MAX_DEALER_MESSAGE_BYTES {
        return Err(Error::DealerMessageTooLarge);
    }

    let instance_count = config.instances().len();
    let receivers_per_instance = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofGenerationFailed)?;
    let receiver_count = instance_count
        .checked_mul(receivers_per_instance)
        .ok_or(Error::ProofGenerationFailed)?;

    let mut instances = Vec::new();
    instances
        .try_reserve_exact(instance_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut private_shares = Vec::new();
    private_shares
        .try_reserve_exact(instance_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut polynomial_constants = Vec::new();
    polynomial_constants
        .try_reserve_exact(instance_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut receiver_openings = Vec::new();
    receiver_openings
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofGenerationFailed)?;

    for (position, kind) in config.instances().iter().copied().enumerate() {
        let (polynomial, commitment, polynomial_constant) = match kind {
            DkgInstanceKind::Random => {
                let constant = G::Scalar::random(rng);
                let polynomial =
                    Polynomial::random_with_secret(constant.clone(), config.threshold(), rng)?;
                let commitment = FeldmanCommitment::<G>::commit(&polynomial)?;
                (polynomial, commitment, Some(constant))
            }
            DkgInstanceKind::Zero => {
                let polynomial =
                    Polynomial::random_with_secret(G::Scalar::zero(), config.threshold(), rng)?;
                let commitment = FeldmanCommitment::<G>::commit_zero(&polynomial)?;
                (polynomial, commitment, None)
            }
        };
        let nonce = DealerMessageNonce::random(rng);
        let message = effective_message(config.root(), dealer, position, kind, nonce);

        let mut receivers = Vec::new();
        receivers
            .try_reserve_exact(receivers_per_instance)
            .map_err(|_| Error::ProofGenerationFailed)?;
        let mut own_share = None;
        for (participant, public_key) in config.registry().entries() {
            let share = polynomial.evaluate(participant)?.value;
            if participant == dealer {
                own_share = Some(share);
                continue;
            }

            let pad = evaluate_pad(message, dealer_identity_secret, public_key)?;
            if bool::from(pad.is_zero()) {
                return Err(Error::DegenerateEvrfOutput);
            }
            let pad_commitment = G::mul_generator(&pad);
            if bool::from(G::is_identity(&pad_commitment)) {
                return Err(Error::DegenerateEvrfOutput);
            }
            let share_commitment = G::mul_generator(&share);
            let encrypted_share = share.add(&pad);
            receiver_openings.push((share.clone(), pad));
            receivers.push(DealerMessageReceiver {
                participant,
                public_key: public_key.clone(),
                share_commitment,
                pad_commitment,
                encrypted_share,
            });
        }
        private_shares.push(own_share.ok_or(Error::ProofGenerationFailed)?);
        polynomial_constants.push(polynomial_constant);
        instances.push(DealerMessageInstance {
            nonce,
            effective_message: message,
            commitment_coefficients: commitment.coefficients(),
            receivers,
        });
    }

    let message = DealerMessageData { dealer, instances };
    let message_root = dealer_message_root(config, &message)?;
    let coefficient_count = instance_count
        .checked_mul(config.threshold())
        .ok_or(Error::ProofGenerationFailed)?;
    let mut effective_messages = Vec::new();
    effective_messages
        .try_reserve_exact(instance_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut commitment_coefficients = Vec::new();
    commitment_coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut share_commitments = Vec::new();
    share_commitments
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut pad_commitments = Vec::new();
    pad_commitments
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    let mut encrypted_shares = Vec::new();
    encrypted_shares
        .try_reserve_exact(receiver_count)
        .map_err(|_| Error::ProofGenerationFailed)?;
    for instance in &message.instances {
        effective_messages.push(instance.effective_message);
        commitment_coefficients.extend(instance.commitment_coefficients.iter().cloned());
        for receiver in &instance.receivers {
            share_commitments.push(receiver.share_commitment.clone());
            pad_commitments.push(receiver.pad_commitment.clone());
            encrypted_shares.push(receiver.encrypted_share.clone());
        }
    }

    let statement = DealerProofStatement::new(
        config,
        dealer,
        message_root,
        effective_messages,
        commitment_coefficients,
        share_commitments,
        pad_commitments,
        encrypted_shares,
    )?;
    let witness = DealerProofWitness::new(
        config,
        &statement,
        dealer_identity_secret.clone(),
        polynomial_constants,
        receiver_openings,
    )?;
    let proof = if receiver_count == 0 {
        Vec::new()
    } else {
        prove(config, &statement, &witness, rng)?
    };
    let dealer_message_bytes = encode_dealer_message(config, &message, &proof)?;

    Ok(OwnDealing {
        participant: dealer,
        configuration_root: config.root(),
        dealer_message_bytes,
        private_shares,
    })
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};

    fn participant(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn secret(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    fn config(participant_count: u32) -> DkgConfig<TinyGroup> {
        let registry = crate::ParticipantRegistry::new(
            (1..=participant_count)
                .map(|value| {
                    let participant = participant(value);
                    (
                        participant,
                        TinyGroup::mul_generator(&secret(u64::from(value))),
                    )
                })
                .collect(),
        )
        .unwrap();
        DkgConfig::new(
            usize::try_from(participant_count).unwrap(),
            crate::SessionId([6; 32]),
            registry,
            vec![DkgInstanceKind::Random],
        )
        .unwrap()
    }

    #[test]
    fn zero_pad_is_a_coarse_retryable_failure_before_proving() {
        let config = config(2);
        let proof_calls = Cell::new(0usize);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);

        let result = deal_with(
            &config,
            participant(1),
            &secret(1),
            &mut rng,
            |_, _, _| Ok(TinyScalar::zero()),
            |_, _, _, _| {
                proof_calls.set(proof_calls.get() + 1);
                Ok(Vec::new())
            },
        );

        assert_eq!(result.unwrap_err(), Error::DegenerateEvrfOutput);
        assert_eq!(proof_calls.get(), 0);
    }

    #[test]
    fn single_participant_uses_an_empty_proof_suffix() {
        let config = config(1);
        let proof_calls = Cell::new(0usize);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);

        let own_dealing = deal_with(
            &config,
            participant(1),
            &secret(1),
            &mut rng,
            |_, _, _| Err(Error::RelationEvaluationFailed),
            |_, _, _, _| {
                proof_calls.set(proof_calls.get() + 1);
                Ok(vec![1])
            },
        )
        .unwrap();

        assert_eq!(proof_calls.get(), 0);
        assert!(!own_dealing.dealer_message_bytes().is_empty());
    }
}
