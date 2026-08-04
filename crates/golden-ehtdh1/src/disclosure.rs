//! Disclosure-group decryption for ciphertexts sharing an ephemeral public key.
//!
//! # Warning
//!
//! This extension is not the exact EHTDH1 scheme described by the paper. A
//! [`DisclosureGroupKey`] opens every valid ciphertext with the disclosure
//! group's ephemeral public key and associated data, not only ciphertexts that
//! an application considers members of the group. Applications must
//! authenticate disclosure-group membership separately.

use std::collections::BTreeSet;
use std::fmt;

use golden_core::{
    GoldenGroup, GoldenHashToGroup, GoldenScalar, ParticipantIndex, TranscriptBuilder,
};
use rand_core::{CryptoRng, RngCore};

use crate::context::{
    hash_to_nonzero_scalar, CombineError, Error, PublicShare, SetupContext, TRANSCRIPT_PREFIX,
};
use crate::decrypt::{lagrange_at_zero, Combiner, UnsealingShare};
use crate::encrypt::{apply_payload_mask, random_nonzero_scalar, verify_ciphertext, Ciphertext};

/// Errors specific to the disclosure-group extension.
///
/// The paper-compatible exact-ciphertext APIs continue to use [`Error`]. Keeping
/// extension errors separate preserves the existing exhaustive `Error` surface.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DisclosureError {
    /// An ephemeral public point was the identity element.
    #[error("invalid ephemeral public point")]
    InvalidEphemeralPublic,
    /// A ciphertext did not use the disclosure group's ephemeral public point.
    #[error("ephemeral public point mismatch")]
    EphemeralPublicMismatch,
    /// A ciphertext did not use the disclosure group's associated data.
    #[error("associated data mismatch")]
    AssociatedDataMismatch,
    /// A cached decryption contribution belongs to another participant.
    #[error("decryption precomputation participant mismatch")]
    PrecomputationParticipantMismatch,
    /// A cached contribution was made for another ephemeral public point.
    #[error("decryption precomputation ephemeral public point mismatch")]
    PrecomputationEphemeralPublicMismatch,
    /// The underlying EHTDH1 operation failed.
    #[error(transparent)]
    Ehtdh1(#[from] Error),
}

/// Public inputs identifying a disclosure group.
///
/// # Warning
///
/// Disclosure groups are an extension to, not the exact scheme from, the
/// EHTDH1 paper. The application must authenticate which ciphertexts belong to
/// a group; the cryptographic group key is constrained only by the ephemeral
/// public key and associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureGroup<G: GoldenGroup> {
    ephemeral_public: G::Element,
    associated_data: Vec<u8>,
    decryption_context: Vec<u8>,
    group_id: Vec<u8>,
}

impl<G: GoldenGroup> DisclosureGroup<G> {
    /// Construct a disclosure group, rejecting an identity ephemeral public key.
    pub fn new(
        ephemeral_public: G::Element,
        associated_data: &[u8],
        decryption_context: &[u8],
        group_id: &[u8],
    ) -> Result<Self, DisclosureError> {
        if bool::from(G::is_identity(&ephemeral_public)) {
            return Err(DisclosureError::InvalidEphemeralPublic);
        }

        Ok(Self {
            ephemeral_public,
            associated_data: associated_data.to_vec(),
            decryption_context: decryption_context.to_vec(),
            group_id: group_id.to_vec(),
        })
    }

    /// Return the ephemeral public key `R` shared by this group.
    pub fn ephemeral_public(&self) -> &G::Element {
        &self.ephemeral_public
    }

    /// Return the associated data expected on ciphertexts in this group.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// Return the context bound into this disclosure group's shares.
    pub fn decryption_context(&self) -> &[u8] {
        &self.decryption_context
    }

    /// Return the application-provided disclosure-group identifier.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }
}

/// Cached validator contribution `x_i R` for one ephemeral public key.
///
/// # Warning
///
/// This value is secret-bearing key material. Keep it validator-local, avoid
/// unnecessary copies, and never serialize or disclose it. Its `Debug`
/// implementation deliberately redacts `x_i R`.
pub struct DecryptionPrecomputation<G: GoldenGroup> {
    participant: ParticipantIndex,
    ephemeral_public: G::Element,
    decryption_contribution: G::Element,
}

impl<G: GoldenGroup> fmt::Debug for DecryptionPrecomputation<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptionPrecomputation")
            .field("participant", &self.participant)
            .field("ephemeral_public", &self.ephemeral_public)
            .field("x_iR", &"<redacted>")
            .finish()
    }
}

/// A disclosure-group decryption share and its double-Schnorr proof.
///
/// This is intentionally distinct from [`crate::decrypt::DecryptionShare`]: its
/// group point and proof use disclosure-group-specific transcripts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureGroupDecryptionShare<G: GoldenHashToGroup> {
    /// Participant index.
    pub participant: ParticipantIndex,
    /// `W_i = x_i R + z_i S_group`.
    pub share: G::Element,
    /// Double-Schnorr proof challenge.
    pub challenge: G::Scalar,
    /// Response for the participant's `x_i` share.
    pub decryption_response: G::Scalar,
    /// Response for the participant's `z_i` share.
    pub context_response: G::Scalar,
}

/// Reconstructed `xR` key for a disclosure group's `R` and associated data.
///
/// # Warning
///
/// This key opens **all** valid ciphertexts with the same ephemeral public key
/// and associated data. It does not authenticate group membership; applications
/// must enforce membership separately. The reconstructed Diffie-Hellman point
/// is secret-bearing and is redacted from `Debug` output.
pub struct DisclosureGroupKey<G: GoldenHashToGroup> {
    expected_ephemeral_public: G::Element,
    expected_associated_data: Vec<u8>,
    dh_point: G::Element,
}

impl<G: GoldenHashToGroup> fmt::Debug for DisclosureGroupKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureGroupKey")
            .field("expected_ephemeral_public", &self.expected_ephemeral_public)
            .field("expected_associated_data", &self.expected_associated_data)
            .field("dh_point", &"<redacted>")
            .finish()
    }
}

impl<G: GoldenHashToGroup> DisclosureGroupKey<G> {
    /// Verify and open a ciphertext matching this key's `R` and associated data.
    ///
    /// This does not establish application-level disclosure-group membership.
    pub fn open(&self, message: &Ciphertext<G>) -> Result<Vec<u8>, DisclosureError> {
        verify_ciphertext(message)?;
        if message.ephemeral_public != self.expected_ephemeral_public {
            return Err(DisclosureError::EphemeralPublicMismatch);
        }
        if message.associated_data() != self.expected_associated_data {
            return Err(DisclosureError::AssociatedDataMismatch);
        }

        let mut plaintext = message.encrypted_payload.clone();
        apply_payload_mask::<G>(
            &mut plaintext,
            &self.expected_ephemeral_public,
            &self.dh_point,
        )?;
        Ok(plaintext)
    }
}

impl<G: GoldenHashToGroup> UnsealingShare<G> {
    /// Cache this validator's secret-bearing `x_i R` contribution.
    ///
    /// # Warning
    ///
    /// The returned precomputation is secret-bearing key material. Keep it
    /// validator-local and do not serialize or disclose it.
    pub fn precompute_for_ephemeral_public(
        &self,
        ephemeral_public: &G::Element,
    ) -> Result<DecryptionPrecomputation<G>, DisclosureError> {
        if bool::from(G::is_identity(ephemeral_public)) {
            return Err(DisclosureError::InvalidEphemeralPublic);
        }

        Ok(DecryptionPrecomputation {
            participant: self.share.participant,
            ephemeral_public: ephemeral_public.clone(),
            decryption_contribution: G::mul(ephemeral_public, &self.share.decryption),
        })
    }

    /// Issue a fresh proof-bearing share for a disclosure group.
    ///
    /// The application must authenticate that the intended ciphertexts belong
    /// to `disclosure_group`; this extension does not prove membership.
    ///
    /// The RNG must produce a fresh pair of Schnorr proof nonces for every
    /// release. Repeating them across distinct challenges reveals the long-lived
    /// participant shares `x_i` and `z_i`; nonce reuse is a secret-share
    /// compromise, not merely a proof failure.
    pub fn issue_disclosure_group_share<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        setup_context: &SetupContext,
        precomputation: &DecryptionPrecomputation<G>,
        disclosure_group: &DisclosureGroup<G>,
    ) -> Result<DisclosureGroupDecryptionShare<G>, DisclosureError> {
        if precomputation.participant != self.share.participant {
            return Err(DisclosureError::PrecomputationParticipantMismatch);
        }
        if precomputation.ephemeral_public != disclosure_group.ephemeral_public {
            return Err(DisclosureError::PrecomputationEphemeralPublicMismatch);
        }

        let public_decryption_share = G::mul_generator(&self.share.decryption);
        let public_context_share = G::mul_generator(&self.share.context);
        let decryption_group = disclosure_group_point::<G>(setup_context, disclosure_group)?;

        // `W_i = x_i R + z_i S_group`, reusing only the cached `x_i R` term.
        let share = G::add(
            &precomputation.decryption_contribution,
            &G::mul(&decryption_group, &self.share.context),
        );

        // These proof nonces must be fresh even when the precomputation is reused.
        let decryption_nonce = random_nonzero_scalar::<G, _>(rng);
        let context_nonce = random_nonzero_scalar::<G, _>(rng);
        let public_decryption_commitment = G::mul_generator(&decryption_nonce);
        let public_context_commitment = G::mul_generator(&context_nonce);
        let share_commitment = G::add(
            &G::mul(&disclosure_group.ephemeral_public, &decryption_nonce),
            &G::mul(&decryption_group, &context_nonce),
        );

        let challenge = disclosure_group_share_challenge::<G>(ShareChallengeInputs {
            setup_context,
            decryption_group: &decryption_group,
            public_decryption_share: &public_decryption_share,
            public_context_share: &public_context_share,
            share: &share,
            public_decryption_commitment: &public_decryption_commitment,
            public_context_commitment: &public_context_commitment,
            share_commitment: &share_commitment,
        })?;
        let decryption_response = decryption_nonce.add(&challenge.mul(&self.share.decryption));
        let context_response = context_nonce.add(&challenge.mul(&self.share.context));

        Ok(DisclosureGroupDecryptionShare {
            participant: self.share.participant,
            share,
            challenge,
            decryption_response,
            context_response,
        })
    }
}

impl<G: GoldenHashToGroup> Combiner<G> {
    /// Combine exactly the configured threshold of disclosure-group shares.
    pub fn combine_disclosure_group_exact(
        &self,
        disclosure_group: &DisclosureGroup<G>,
        shares: &[DisclosureGroupDecryptionShare<G>],
    ) -> Result<DisclosureGroupKey<G>, CombineError> {
        if shares.len() != self.public_key_set.threshold {
            return Err(CombineError::InsufficientShares {
                required: self.public_key_set.threshold,
                provided: shares.len(),
            });
        }
        self.combine_disclosure_group_selected(disclosure_group, shares)
    }

    /// Search the supplied shares for a valid threshold disclosure-group set.
    pub fn combine_disclosure_group_quorum(
        &self,
        disclosure_group: &DisclosureGroup<G>,
        shares: &[DisclosureGroupDecryptionShare<G>],
    ) -> Result<DisclosureGroupKey<G>, CombineError> {
        let mut seen = BTreeSet::new();
        let mut malformed = Vec::new();
        let mut valid = Vec::new();

        for share in shares {
            if !seen.insert(share.participant) {
                malformed.push(share.participant.get());
                continue;
            }
            let Some(public_share) = self.public_key_set.public_share(share.participant) else {
                malformed.push(share.participant.get());
                continue;
            };
            match verify_disclosure_group_share(
                &self.setup_context,
                disclosure_group,
                share,
                public_share,
            ) {
                Ok(()) => valid.push(share.clone()),
                Err(_) => malformed.push(share.participant.get()),
            }
        }

        if valid.len() < self.public_key_set.threshold {
            if !malformed.is_empty() {
                return Err(CombineError::MalformedShares(malformed));
            }
            return Err(CombineError::InsufficientShares {
                required: self.public_key_set.threshold,
                provided: valid.len(),
            });
        }

        self.combine_disclosure_group_selected(
            disclosure_group,
            &valid[..self.public_key_set.threshold],
        )
    }

    fn combine_disclosure_group_selected(
        &self,
        disclosure_group: &DisclosureGroup<G>,
        shares: &[DisclosureGroupDecryptionShare<G>],
    ) -> Result<DisclosureGroupKey<G>, CombineError> {
        let mut seen = BTreeSet::new();
        let mut malformed = Vec::new();

        for share in shares {
            if !seen.insert(share.participant) {
                malformed.push(share.participant.get());
                continue;
            }
            let public_share = self
                .public_key_set
                .public_share(share.participant)
                .ok_or(Error::UnknownParticipant(share.participant.get()))
                .map_err(CombineError::Ciphertext)?;
            if verify_disclosure_group_share(
                &self.setup_context,
                disclosure_group,
                share,
                public_share,
            )
            .is_err()
            {
                malformed.push(share.participant.get());
            }
        }

        if !malformed.is_empty() {
            return Err(CombineError::MalformedShares(malformed));
        }

        let mut dh_point = G::identity();
        for share in shares {
            let lambda = lagrange_at_zero::<G>(
                share.participant,
                shares.iter().map(|entry| entry.participant),
            )
            .map_err(CombineError::Ciphertext)?;
            dh_point = G::add(&dh_point, &G::mul(&share.share, &lambda));
        }

        Ok(DisclosureGroupKey {
            expected_ephemeral_public: disclosure_group.ephemeral_public.clone(),
            expected_associated_data: disclosure_group.associated_data.clone(),
            dh_point,
        })
    }
}

fn verify_disclosure_group_share<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    disclosure_group: &DisclosureGroup<G>,
    share: &DisclosureGroupDecryptionShare<G>,
    public_share: &PublicShare<G>,
) -> Result<(), Error> {
    let decryption_group = disclosure_group_point::<G>(setup_context, disclosure_group)?;
    let public_decryption_commitment = G::sub(
        &G::mul_generator(&share.decryption_response),
        &G::mul(&public_share.decryption, &share.challenge),
    );
    let public_context_commitment = G::sub(
        &G::mul_generator(&share.context_response),
        &G::mul(&public_share.context, &share.challenge),
    );
    let share_commitment = G::sub(
        &G::add(
            &G::mul(
                &disclosure_group.ephemeral_public,
                &share.decryption_response,
            ),
            &G::mul(&decryption_group, &share.context_response),
        ),
        &G::mul(&share.share, &share.challenge),
    );

    let expected = disclosure_group_share_challenge::<G>(ShareChallengeInputs {
        setup_context,
        decryption_group: &decryption_group,
        public_decryption_share: &public_share.decryption,
        public_context_share: &public_share.context,
        share: &share.share,
        public_decryption_commitment: &public_decryption_commitment,
        public_context_commitment: &public_context_commitment,
        share_commitment: &share_commitment,
    })?;

    if expected == share.challenge {
        Ok(())
    } else {
        Err(Error::InvalidShareProof)
    }
}

/// Derive `S_group` from the disclosure-group inputs and setup root.
fn disclosure_group_point<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    disclosure_group: &DisclosureGroup<G>,
) -> Result<G::Element, Error> {
    let mut transcript =
        TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hdgd-disclosure-group");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"setup-context-root", &setup_context.root());
    transcript.bytes(b"ad", &disclosure_group.associated_data);
    transcript.bytes(b"dc", &disclosure_group.decryption_context);
    transcript.bytes(b"disclosure-group-id", &disclosure_group.group_id);
    transcript.element::<G>(b"R", &disclosure_group.ephemeral_public);
    G::hash_to_group(
        b"golden-ehtdh1-hdgd-disclosure-group-v1",
        &transcript.root(),
    )
    .map_err(|_| Error::InvalidEncoding)
}

struct ShareChallengeInputs<'a, G: GoldenGroup> {
    setup_context: &'a SetupContext,
    decryption_group: &'a G::Element,
    public_decryption_share: &'a G::Element,
    public_context_share: &'a G::Element,
    share: &'a G::Element,
    public_decryption_commitment: &'a G::Element,
    public_context_commitment: &'a G::Element,
    share_commitment: &'a G::Element,
}

fn disclosure_group_share_challenge<G: GoldenGroup>(
    inputs: ShareChallengeInputs<'_, G>,
) -> Result<G::Scalar, Error> {
    let mut transcript =
        TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hdcd-disclosure-group");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"setup-context-root", &inputs.setup_context.root());
    transcript.element::<G>(b"S", inputs.decryption_group);
    transcript.element::<G>(b"X-i", inputs.public_decryption_share);
    transcript.element::<G>(b"Z-i", inputs.public_context_share);
    transcript.element::<G>(b"W-i", inputs.share);
    transcript.element::<G>(b"X-i-prime", inputs.public_decryption_commitment);
    transcript.element::<G>(b"Z-i-prime", inputs.public_context_commitment);
    transcript.element::<G>(b"W-i-prime", inputs.share_commitment);
    hash_to_nonzero_scalar::<G>(
        b"golden-ehtdh1-hdcd-disclosure-group-v1",
        &transcript.root(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use golden_core::{GoldenGroup, GoldenScalar, ParticipantIndex, SessionId};
    use golden_rustcrypto::{P256Backend, P256Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::*;
    use crate::context::{derive_context_session_id, PublicKeySet, SecretShare};
    use crate::decrypt::DecryptionShare;
    use crate::encrypt::SealingKey;

    type G = P256Backend;

    const ASSOCIATED_DATA: &[u8] = b"shared associated data";
    const DECRYPTION_CONTEXT: &[u8] = b"disclosure request";
    const GROUP_ID: &[u8] = b"disclosure group";
    const EPHEMERAL_SEED: [u8; 32] = [42u8; 32];

    struct Fixture {
        sealing_key: SealingKey<G>,
        public_key_set: PublicKeySet<G>,
        secret_shares: Vec<SecretShare<G>>,
        setup_context: SetupContext,
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> P256Scalar {
        P256Scalar::from_u64(value).unwrap()
    }

    fn participants() -> [ParticipantIndex; 3] {
        [idx(1), idx(2), idx(3)]
    }

    fn eval_linear(secret: P256Scalar, coefficient: P256Scalar, x: ParticipantIndex) -> P256Scalar {
        secret.add(&coefficient.mul(&x.to_scalar::<P256Scalar>().unwrap()))
    }

    fn setup_context() -> SetupContext {
        SetupContext {
            backend_id: G::BACKEND_ID.to_owned(),
            threshold: 2,
            registry_root: [1u8; 32],
            participants: participants().to_vec(),
            decryption_session_id: SessionId([2u8; 32]),
            context_session_id: derive_context_session_id(SessionId([2u8; 32])),
            decryption_transcript_root: [3u8; 32],
            context_transcript_root: [4u8; 32],
            epoch: [5u8; 32],
        }
    }

    fn fixture() -> Fixture {
        let decryption_secret = scalar(11);
        let decryption_coefficient = scalar(7);
        let context_coefficient = scalar(13);
        let mut public_shares = BTreeMap::new();
        let mut secret_shares = Vec::new();

        for participant in participants() {
            let decryption = eval_linear(
                decryption_secret.clone(),
                decryption_coefficient.clone(),
                participant,
            );
            let context = eval_linear(P256Scalar::zero(), context_coefficient.clone(), participant);
            public_shares.insert(
                participant,
                PublicShare {
                    decryption: G::mul_generator(&decryption),
                    context: G::mul_generator(&context),
                },
            );
            secret_shares.push(SecretShare {
                participant,
                decryption,
                context,
            });
        }

        let joint_public_key = G::mul_generator(&decryption_secret);
        Fixture {
            sealing_key: SealingKey::new(joint_public_key).unwrap(),
            public_key_set: PublicKeySet::new(2, joint_public_key, public_shares).unwrap(),
            secret_shares,
            setup_context: setup_context(),
        }
    }

    fn seeded_ciphertext(
        sealing_key: &SealingKey<G>,
        proof_rng_seed: u8,
        plaintext: &[u8],
        associated_data: &[u8],
        ephemeral_seed: &[u8; 32],
    ) -> Ciphertext<G> {
        let mut rng = ChaCha20Rng::from_seed([proof_rng_seed; 32]);
        sealing_key
            .seal_bytes_with_associated_data_and_seed(
                &mut rng,
                plaintext,
                associated_data,
                ephemeral_seed,
            )
            .unwrap()
    }

    fn sibling_ciphertexts(sealing_key: &SealingKey<G>) -> (Ciphertext<G>, Ciphertext<G>) {
        let first = seeded_ciphertext(
            sealing_key,
            21,
            b"first content key",
            ASSOCIATED_DATA,
            &EPHEMERAL_SEED,
        );
        let second = seeded_ciphertext(
            sealing_key,
            22,
            b"second content key",
            ASSOCIATED_DATA,
            &EPHEMERAL_SEED,
        );
        (first, second)
    }

    fn group_for(
        message: &Ciphertext<G>,
        associated_data: &[u8],
        decryption_context: &[u8],
        group_id: &[u8],
    ) -> DisclosureGroup<G> {
        DisclosureGroup::new(
            message.ephemeral_public,
            associated_data,
            decryption_context,
            group_id,
        )
        .unwrap()
    }

    fn ordinary_shares(
        secret_shares: &[SecretShare<G>],
        setup_context: &SetupContext,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
    ) -> Vec<DecryptionShare<G>> {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        secret_shares
            .iter()
            .map(|share| {
                UnsealingShare::new(share.clone())
                    .decrypt_share(&mut rng, setup_context, message, decryption_context)
                    .unwrap()
            })
            .collect()
    }

    fn disclosure_shares(
        secret_shares: &[SecretShare<G>],
        setup_context: &SetupContext,
        disclosure_group: &DisclosureGroup<G>,
        rng_seed: u8,
    ) -> Vec<DisclosureGroupDecryptionShare<G>> {
        let mut rng = ChaCha20Rng::from_seed([rng_seed; 32]);
        secret_shares
            .iter()
            .map(|share| {
                let unsealing_share = UnsealingShare::new(share.clone());
                let precomputation = unsealing_share
                    .precompute_for_ephemeral_public(disclosure_group.ephemeral_public())
                    .unwrap();
                unsealing_share
                    .issue_disclosure_group_share(
                        &mut rng,
                        setup_context,
                        &precomputation,
                        disclosure_group,
                    )
                    .unwrap()
            })
            .collect()
    }

    fn assert_malformed(
        result: Result<DisclosureGroupKey<G>, CombineError>,
        expected_participants: &[u32],
    ) {
        assert!(matches!(
            result,
            Err(CombineError::MalformedShares(participants))
                if participants == expected_participants
        ));
    }

    #[test]
    fn seeded_siblings_share_r_but_not_ciphertext_or_exact_shares() {
        let fixture = fixture();
        let (first, second) = sibling_ciphertexts(&fixture.sealing_key);

        first.verify().unwrap();
        second.verify().unwrap();
        assert_eq!(first.ephemeral_public, second.ephemeral_public);
        assert_ne!(first, second);
        assert_ne!(first.encrypted_payload, second.encrypted_payload);
        assert_ne!(first.encryption_point, second.encryption_point);
        assert_ne!(first.challenge, second.challenge);
        assert_ne!(first.response, second.response);

        let shares = ordinary_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &first,
            DECRYPTION_CONTEXT,
        );
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();

        assert_eq!(
            combiner
                .combine_exact(&first, DECRYPTION_CONTEXT, &shares[..2])
                .unwrap(),
            b"first content key"
        );
        assert_eq!(
            combiner
                .combine_quorum(&first, DECRYPTION_CONTEXT, &shares)
                .unwrap(),
            b"first content key"
        );
        assert!(matches!(
            combiner.combine_exact(&second, DECRYPTION_CONTEXT, &shares[..2]),
            Err(CombineError::MalformedShares(participants))
                if participants == vec![1, 2]
        ));
        assert!(matches!(
            combiner.combine_quorum(&second, DECRYPTION_CONTEXT, &shares),
            Err(CombineError::MalformedShares(participants))
                if participants == vec![1, 2, 3]
        ));
    }

    #[test]
    fn one_disclosure_group_key_opens_multiple_same_r_same_ad_ciphertexts() {
        let fixture = fixture();
        let (first, second) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_group = group_for(&first, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &disclosure_group,
            32,
        );
        let key = Combiner::new(fixture.public_key_set, fixture.setup_context)
            .unwrap()
            .combine_disclosure_group_exact(&disclosure_group, &shares[..2])
            .unwrap();

        assert_eq!(key.open(&first).unwrap(), b"first content key");
        assert_eq!(key.open(&second).unwrap(), b"second content key");
    }

    #[test]
    fn wrong_r_and_identity_r_are_rejected() {
        let fixture = fixture();
        let (first, _) = sibling_ciphertexts(&fixture.sealing_key);
        let other_r_message = seeded_ciphertext(
            &fixture.sealing_key,
            23,
            b"other r payload",
            ASSOCIATED_DATA,
            &[43u8; 32],
        );
        let disclosure_group = group_for(&first, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let other_r_group = group_for(
            &other_r_message,
            ASSOCIATED_DATA,
            DECRYPTION_CONTEXT,
            GROUP_ID,
        );
        let unsealing_share = UnsealingShare::new(fixture.secret_shares[0].clone());
        let precomputation = unsealing_share
            .precompute_for_ephemeral_public(&first.ephemeral_public)
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);

        assert_eq!(
            unsealing_share.issue_disclosure_group_share(
                &mut rng,
                &fixture.setup_context,
                &precomputation,
                &other_r_group,
            ),
            Err(DisclosureError::PrecomputationEphemeralPublicMismatch)
        );

        let shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &disclosure_group,
            34,
        );
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();
        assert_malformed(
            combiner.combine_disclosure_group_exact(&other_r_group, &shares[..2]),
            &[1, 2],
        );
        let key = combiner
            .combine_disclosure_group_exact(&disclosure_group, &shares[..2])
            .unwrap();
        assert_eq!(
            key.open(&other_r_message),
            Err(DisclosureError::EphemeralPublicMismatch)
        );

        let wrong_ad_message = seeded_ciphertext(
            &fixture.sealing_key,
            24,
            b"wrong ad payload",
            b"wrong associated data",
            &EPHEMERAL_SEED,
        );
        assert_eq!(
            key.open(&wrong_ad_message),
            Err(DisclosureError::AssociatedDataMismatch)
        );
        assert_eq!(
            DisclosureGroup::<G>::new(G::identity(), ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID),
            Err(DisclosureError::InvalidEphemeralPublic)
        );
        assert!(matches!(
            unsealing_share.precompute_for_ephemeral_public(&G::identity()),
            Err(DisclosureError::InvalidEphemeralPublic)
        ));
    }

    #[test]
    fn every_disclosure_group_transcript_input_is_bound() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_group = group_for(&message, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &disclosure_group,
            35,
        );
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();

        let wrong_group_id = group_for(
            &message,
            ASSOCIATED_DATA,
            DECRYPTION_CONTEXT,
            b"wrong group",
        );
        assert_malformed(
            combiner.combine_disclosure_group_exact(&wrong_group_id, &shares[..2]),
            &[1, 2],
        );

        let wrong_associated_data = group_for(
            &message,
            b"wrong associated data",
            DECRYPTION_CONTEXT,
            GROUP_ID,
        );
        assert_malformed(
            combiner.combine_disclosure_group_exact(&wrong_associated_data, &shares[..2]),
            &[1, 2],
        );

        let wrong_decryption_context =
            group_for(&message, ASSOCIATED_DATA, b"wrong request", GROUP_ID);
        assert_malformed(
            combiner.combine_disclosure_group_exact(&wrong_decryption_context, &shares[..2]),
            &[1, 2],
        );

        let mut wrong_setup_context = fixture.setup_context;
        wrong_setup_context.epoch = [99u8; 32];
        let wrong_setup_combiner =
            Combiner::new(fixture.public_key_set, wrong_setup_context).unwrap();
        assert_malformed(
            wrong_setup_combiner.combine_disclosure_group_exact(&disclosure_group, &shares[..2]),
            &[1, 2],
        );
    }

    #[test]
    fn shares_from_different_groups_or_requests_cannot_be_mixed() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let group_a = group_for(&message, ASSOCIATED_DATA, b"request a", b"group a");
        let group_b = group_for(&message, ASSOCIATED_DATA, b"request a", b"group b");
        let group_a_shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &group_a, 36);
        let group_b_shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &group_b, 37);
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();
        let mixed_groups = vec![group_a_shares[0].clone(), group_b_shares[1].clone()];
        assert_malformed(
            combiner.combine_disclosure_group_exact(&group_a, &mixed_groups),
            &[2],
        );

        let request_a = group_for(&message, ASSOCIATED_DATA, b"request a", GROUP_ID);
        let request_b = group_for(&message, ASSOCIATED_DATA, b"request b", GROUP_ID);
        let request_a_shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &request_a,
            38,
        );
        let request_b_shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &request_b,
            39,
        );
        let mixed_requests = vec![request_a_shares[0].clone(), request_b_shares[1].clone()];
        assert_malformed(
            combiner.combine_disclosure_group_exact(&request_a, &mixed_requests),
            &[2],
        );
    }

    #[test]
    fn precomputation_is_bound_to_its_participant() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_group = group_for(&message, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let first = UnsealingShare::new(fixture.secret_shares[0].clone());
        let second = UnsealingShare::new(fixture.secret_shares[1].clone());
        let precomputation = first
            .precompute_for_ephemeral_public(disclosure_group.ephemeral_public())
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([40u8; 32]);

        assert_eq!(
            second.issue_disclosure_group_share(
                &mut rng,
                &fixture.setup_context,
                &precomputation,
                &disclosure_group,
            ),
            Err(DisclosureError::PrecomputationParticipantMismatch)
        );
    }

    #[test]
    fn repeated_release_reuses_w_but_refreshes_and_verifies_the_proof() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_group = group_for(&message, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let first_participant = UnsealingShare::new(fixture.secret_shares[0].clone());
        let first_precomputation = first_participant
            .precompute_for_ephemeral_public(disclosure_group.ephemeral_public())
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
        let first_release = first_participant
            .issue_disclosure_group_share(
                &mut rng,
                &fixture.setup_context,
                &first_precomputation,
                &disclosure_group,
            )
            .unwrap();
        let second_release = first_participant
            .issue_disclosure_group_share(
                &mut rng,
                &fixture.setup_context,
                &first_precomputation,
                &disclosure_group,
            )
            .unwrap();

        assert_eq!(first_release.share, second_release.share);
        assert_ne!(first_release.challenge, second_release.challenge);
        assert_ne!(
            first_release.decryption_response,
            second_release.decryption_response
        );
        assert_ne!(
            first_release.context_response,
            second_release.context_response
        );
        assert_ne!(first_release, second_release);

        let second_participant = UnsealingShare::new(fixture.secret_shares[1].clone());
        let second_precomputation = second_participant
            .precompute_for_ephemeral_public(disclosure_group.ephemeral_public())
            .unwrap();
        let other_share = second_participant
            .issue_disclosure_group_share(
                &mut rng,
                &fixture.setup_context,
                &second_precomputation,
                &disclosure_group,
            )
            .unwrap();
        let combiner = Combiner::new(fixture.public_key_set, fixture.setup_context).unwrap();

        let first_key = combiner
            .combine_disclosure_group_exact(
                &disclosure_group,
                &[first_release, other_share.clone()],
            )
            .unwrap();
        let second_key = combiner
            .combine_disclosure_group_exact(&disclosure_group, &[second_release, other_share])
            .unwrap();
        assert_eq!(first_key.open(&message).unwrap(), b"first content key");
        assert_eq!(second_key.open(&message).unwrap(), b"first content key");
    }

    #[test]
    fn disclosure_exact_count_and_quorum_selection_match_ordinary_semantics() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_group = group_for(&message, ASSOCIATED_DATA, DECRYPTION_CONTEXT, GROUP_ID);
        let shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &disclosure_group,
            42,
        );
        let combiner = Combiner::new(fixture.public_key_set, fixture.setup_context).unwrap();

        assert!(matches!(
            combiner.combine_disclosure_group_exact(&disclosure_group, &shares[..1]),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        ));
        assert!(matches!(
            combiner.combine_disclosure_group_exact(&disclosure_group, &shares),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 3
            })
        ));
        assert!(matches!(
            combiner.combine_disclosure_group_quorum(&disclosure_group, &shares[..1]),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        ));

        let duplicate = vec![shares[0].clone(), shares[0].clone()];
        assert_malformed(
            combiner.combine_disclosure_group_exact(&disclosure_group, &duplicate),
            &[1],
        );

        let mut with_surplus_malformed = shares.clone();
        with_surplus_malformed[2].share = G::add(&with_surplus_malformed[2].share, &G::generator());
        let quorum_key = combiner
            .combine_disclosure_group_quorum(&disclosure_group, &with_surplus_malformed)
            .unwrap();
        assert_eq!(quorum_key.open(&message).unwrap(), b"first content key");

        let mut malformed_before_threshold = shares[1].clone();
        malformed_before_threshold.share =
            G::add(&malformed_before_threshold.share, &G::generator());
        assert_malformed(
            combiner.combine_disclosure_group_quorum(
                &disclosure_group,
                &[shares[0].clone(), malformed_before_threshold],
            ),
            &[2],
        );
    }
}
