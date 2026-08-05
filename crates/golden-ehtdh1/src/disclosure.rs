//! Disclosure-scope decryption for ciphertexts sharing an ephemeral public key.
//!
//! # Warning
//!
//! This extension is not the exact EHTDH1 scheme described by the paper. A
//! [`DisclosureScope`] holds stable public scope inputs, while each
//! [`DisclosureRequest`] adds one request-specific decryption context. Request
//! construction only describes transcript inputs; it does not authorize release.
//! The application release authorizer must authenticate scope membership and decide
//! whether participants may issue request-bound shares.
//!
//! Released shares use `W_i = x_iR + z_iS_scope,request`, where
//! `S_scope,request` preserves the existing disclosure transcript over setup root,
//! associated data, request context, scope ID, and `R`. Each domain-separated point
//! must behave as an independent random group element with no exploitable relation
//! to the generator, `R`, or another selected point. Repeated adaptive requests are
//! an extension security assumption and review question, not a claimed consequence
//! of the original EHTDH1 proof.
//!
//! Interpolation removes the request-binding zero share and recovers only `(R,
//! xR)`. Scope ID and request context determine which shares can reconstruct `xR`;
//! they do not constrain that recovered capability. [`DisclosureKey`] therefore
//! opens every valid ciphertext with the same `R` and expected associated data,
//! including ciphertexts outside the application-declared scope. The associated-
//! data check in [`DisclosureKey::open`] is defensive API policy, not a
//! cryptographic restriction on raw `xR`.
//!
//! See the [disclosure-scope protocol and security model](https://github.com/0xMiden/golden-dkg/blob/main/crates/golden-ehtdh1/DISCLOSURE_SCOPE_SECURITY.md)
//! for the construction, extension assumptions, lifecycle, and blast-radius analysis.

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

/// Errors specific to the disclosure-scope extension.
///
/// The paper-compatible exact-ciphertext APIs continue to use [`Error`]. Keeping
/// extension errors separate preserves the existing exhaustive `Error` surface.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DisclosureError {
    /// An ephemeral public point was the identity element.
    #[error("invalid ephemeral public point")]
    InvalidEphemeralPublic,
    /// A ciphertext did not use the disclosure scope's ephemeral public point.
    #[error("ephemeral public point mismatch")]
    EphemeralPublicMismatch,
    /// A ciphertext did not use the disclosure scope's associated data.
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

/// Stable public inputs identifying an application-declared disclosure scope.
///
/// The scope can be established before a release request exists, allowing each
/// participant to precompute `x_iR` once and reuse it across permitted requests.
///
/// # Warning
///
/// Disclosure scopes are an extension to, not the exact scheme from, the EHTDH1
/// paper. A scope declares membership and share-authorization policy; it does not
/// cryptographically constrain reconstructed `xR`. The application release
/// authorizer must authenticate membership and decide whether to issue shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureScope<G: GoldenGroup> {
    ephemeral_public: G::Element,
    associated_data: Vec<u8>,
    scope_id: Vec<u8>,
}

impl<G: GoldenGroup> DisclosureScope<G> {
    /// Construct stable disclosure-scope state, rejecting an identity `R`.
    pub fn new(
        ephemeral_public: G::Element,
        associated_data: &[u8],
        scope_id: &[u8],
    ) -> Result<Self, DisclosureError> {
        if bool::from(G::is_identity(&ephemeral_public)) {
            return Err(DisclosureError::InvalidEphemeralPublic);
        }

        Ok(Self {
            ephemeral_public,
            associated_data: associated_data.to_vec(),
            scope_id: scope_id.to_vec(),
        })
    }

    /// Construct request transcript inputs for this stable scope.
    ///
    /// This does not authenticate membership or authorize share release.
    pub fn request<'a>(&'a self, decryption_context: &[u8]) -> DisclosureRequest<'a, G> {
        DisclosureRequest {
            scope: self,
            decryption_context: decryption_context.to_vec(),
        }
    }

    /// Return the ephemeral public key `R` shared by this scope.
    pub fn ephemeral_public(&self) -> &G::Element {
        &self.ephemeral_public
    }

    /// Return the associated data expected on ciphertexts in this scope.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// Return the application-provided disclosure-scope identifier.
    pub fn scope_id(&self) -> &[u8] {
        &self.scope_id
    }
}

/// Public transcript inputs for one request against a stable disclosure scope.
///
/// Constructing a request is not an authorization decision. Requests are borrowed,
/// in-memory API values with no public wire encoding and can be created only from a
/// [`DisclosureScope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureRequest<'a, G: GoldenGroup> {
    scope: &'a DisclosureScope<G>,
    decryption_context: Vec<u8>,
}

impl<'a, G: GoldenGroup> DisclosureRequest<'a, G> {
    /// Return the stable disclosure scope described by this request.
    pub fn scope(&self) -> &'a DisclosureScope<G> {
        self.scope
    }

    /// Return the request-specific context bound into released shares.
    pub fn decryption_context(&self) -> &[u8] {
        &self.decryption_context
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

/// A request-bound disclosure decryption share and its double-Schnorr proof.
///
/// This is intentionally distinct from [`crate::decrypt::DecryptionShare`]: its
/// hash-to-group point and proof use the historical disclosure transcript domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureDecryptionShare<G: GoldenHashToGroup> {
    /// Participant index.
    pub participant: ParticipantIndex,
    /// `W_i = x_i R + z_i S_scope,request`.
    pub share: G::Element,
    /// Double-Schnorr proof challenge.
    pub challenge: G::Scalar,
    /// Response for the participant's `x_i` share.
    pub decryption_response: G::Scalar,
    /// Response for the participant's `z_i` share.
    pub context_response: G::Scalar,
}

/// Reconstructed `xR` key for a scope's `R` and associated data.
///
/// # Warning
///
/// Scope ID and request context determine which shares can reconstruct `xR`; they
/// do not constrain what `xR` can open after reconstruction. This key opens
/// **all** valid ciphertexts with the same ephemeral public key and expected
/// associated data, not only application-authenticated scope members.
///
/// The associated-data equality check in [`Self::open`] is a defensive API policy,
/// not a cryptographic restriction on `xR`: disclosure or extraction of the raw
/// point would permit opening any wrapper sharing `R`, regardless of associated
/// data. The point remains private, has no wire encoding, and is redacted from
/// `Debug` output.
pub struct DisclosureKey<G: GoldenHashToGroup> {
    expected_ephemeral_public: G::Element,
    expected_associated_data: Vec<u8>,
    dh_point: G::Element,
}

impl<G: GoldenHashToGroup> fmt::Debug for DisclosureKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureKey")
            .field("expected_ephemeral_public", &self.expected_ephemeral_public)
            .field("expected_associated_data", &self.expected_associated_data)
            .field("dh_point", &"<redacted>")
            .finish()
    }
}

impl<G: GoldenHashToGroup> DisclosureKey<G> {
    /// Verify and open a ciphertext matching this key's `R` and associated data.
    ///
    /// The associated-data check is a defensive API policy, not a cryptographic
    /// restriction on the underlying `xR`. This method does not establish
    /// application-level disclosure-scope membership.
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

    /// Issue a fresh proof-bearing share for one disclosure request.
    ///
    /// The application release authorizer must authenticate that the intended
    /// ciphertexts belong to `request.scope()` and decide that release is permitted;
    /// this extension neither proves membership nor makes that decision.
    ///
    /// The RNG must produce a fresh pair of Schnorr proof nonces for every
    /// release. Repeating them across distinct challenges reveals the long-lived
    /// participant shares `x_i` and `z_i`; nonce reuse is a secret-share
    /// compromise, not merely a proof failure.
    pub fn issue_disclosure_share<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        setup_context: &SetupContext,
        precomputation: &DecryptionPrecomputation<G>,
        request: &DisclosureRequest<'_, G>,
    ) -> Result<DisclosureDecryptionShare<G>, DisclosureError> {
        if precomputation.participant != self.share.participant {
            return Err(DisclosureError::PrecomputationParticipantMismatch);
        }
        if precomputation.ephemeral_public != request.scope.ephemeral_public {
            return Err(DisclosureError::PrecomputationEphemeralPublicMismatch);
        }

        let public_decryption_share = G::mul_generator(&self.share.decryption);
        let public_context_share = G::mul_generator(&self.share.context);
        let decryption_group = disclosure_scope_point::<G>(setup_context, request)?;

        // `W_i = x_i R + z_i S_scope,request`, reusing only cached `x_i R`.
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
            &G::mul(&request.scope.ephemeral_public, &decryption_nonce),
            &G::mul(&decryption_group, &context_nonce),
        );

        let challenge = disclosure_share_challenge::<G>(ShareChallengeInputs {
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

        Ok(DisclosureDecryptionShare {
            participant: self.share.participant,
            share,
            challenge,
            decryption_response,
            context_response,
        })
    }
}

impl<G: GoldenHashToGroup> Combiner<G> {
    /// Combine exactly the configured threshold of request-homogeneous shares.
    pub fn combine_disclosure_exact(
        &self,
        request: &DisclosureRequest<'_, G>,
        shares: &[DisclosureDecryptionShare<G>],
    ) -> Result<DisclosureKey<G>, CombineError> {
        if shares.len() != self.public_key_set.threshold {
            return Err(CombineError::InsufficientShares {
                required: self.public_key_set.threshold,
                provided: shares.len(),
            });
        }
        self.combine_disclosure_selected(request, shares)
    }

    /// Search the supplied shares for a valid threshold set for this request.
    pub fn combine_disclosure_quorum(
        &self,
        request: &DisclosureRequest<'_, G>,
        shares: &[DisclosureDecryptionShare<G>],
    ) -> Result<DisclosureKey<G>, CombineError> {
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
            match verify_disclosure_share(&self.setup_context, request, share, public_share) {
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

        self.combine_disclosure_selected(request, &valid[..self.public_key_set.threshold])
    }

    fn combine_disclosure_selected(
        &self,
        request: &DisclosureRequest<'_, G>,
        shares: &[DisclosureDecryptionShare<G>],
    ) -> Result<DisclosureKey<G>, CombineError> {
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
            if verify_disclosure_share(&self.setup_context, request, share, public_share).is_err() {
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

        Ok(DisclosureKey {
            expected_ephemeral_public: request.scope.ephemeral_public.clone(),
            expected_associated_data: request.scope.associated_data.clone(),
            dh_point,
        })
    }
}

fn verify_disclosure_share<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    request: &DisclosureRequest<'_, G>,
    share: &DisclosureDecryptionShare<G>,
    public_share: &PublicShare<G>,
) -> Result<(), Error> {
    let decryption_group = disclosure_scope_point::<G>(setup_context, request)?;
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
            &G::mul(&request.scope.ephemeral_public, &share.decryption_response),
            &G::mul(&decryption_group, &share.context_response),
        ),
        &G::mul(&share.share, &share.challenge),
    );

    let expected = disclosure_share_challenge::<G>(ShareChallengeInputs {
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

/// Derive `S_scope,request` from stable scope and request inputs.
///
/// The transcript domain, labels, field order, and encoded values intentionally
/// match the original disclosure-group construction.
fn disclosure_scope_point<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    request: &DisclosureRequest<'_, G>,
) -> Result<G::Element, Error> {
    let mut transcript =
        TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hdgd-disclosure-group");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"setup-context-root", &setup_context.root());
    transcript.bytes(b"ad", &request.scope.associated_data);
    transcript.bytes(b"dc", &request.decryption_context);
    transcript.bytes(b"disclosure-group-id", &request.scope.scope_id);
    transcript.element::<G>(b"R", &request.scope.ephemeral_public);
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

fn disclosure_share_challenge<G: GoldenGroup>(
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
    const SCOPE_ID: &[u8] = b"disclosure scope";
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

    fn scope_for(
        message: &Ciphertext<G>,
        associated_data: &[u8],
        scope_id: &[u8],
    ) -> DisclosureScope<G> {
        DisclosureScope::new(message.ephemeral_public, associated_data, scope_id).unwrap()
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
        request: &DisclosureRequest<'_, G>,
        rng_seed: u8,
    ) -> Vec<DisclosureDecryptionShare<G>> {
        let mut rng = ChaCha20Rng::from_seed([rng_seed; 32]);
        secret_shares
            .iter()
            .map(|share| {
                let unsealing_share = UnsealingShare::new(share.clone());
                let precomputation = unsealing_share
                    .precompute_for_ephemeral_public(request.scope().ephemeral_public())
                    .unwrap();
                unsealing_share
                    .issue_disclosure_share(&mut rng, setup_context, &precomputation, request)
                    .unwrap()
            })
            .collect()
    }

    fn assert_malformed(
        result: Result<DisclosureKey<G>, CombineError>,
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
    fn one_disclosure_scope_key_opens_multiple_same_r_same_ad_ciphertexts() {
        let fixture = fixture();
        let (first, second) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_scope = scope_for(&first, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &request, 32);
        let key = Combiner::new(fixture.public_key_set, fixture.setup_context)
            .unwrap()
            .combine_disclosure_exact(&request, &shares[..2])
            .unwrap();

        assert_eq!(key.open(&first).unwrap(), b"first content key");
        assert_eq!(key.open(&second).unwrap(), b"second content key");
    }

    #[test]
    fn one_precomputation_is_reusable_across_requests_for_a_stable_scope() {
        let fixture = fixture();
        let (first, second) = sibling_ciphertexts(&fixture.sealing_key);
        let scope =
            DisclosureScope::new(first.ephemeral_public, ASSOCIATED_DATA, SCOPE_ID).unwrap();

        let participants = fixture
            .secret_shares
            .iter()
            .cloned()
            .map(UnsealingShare::new)
            .collect::<Vec<_>>();
        let precomputations = participants
            .iter()
            .map(|participant| {
                participant
                    .precompute_for_ephemeral_public(scope.ephemeral_public())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let request_a = scope.request(b"request a");
        let request_b = scope.request(b"request b");
        assert_eq!(request_a.scope(), &scope);
        assert_eq!(request_a.decryption_context(), b"request a");
        assert_eq!(request_b.scope(), &scope);
        assert_eq!(request_b.decryption_context(), b"request b");

        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
        let request_a_shares = participants
            .iter()
            .zip(&precomputations)
            .map(|(participant, precomputation)| {
                participant
                    .issue_disclosure_share(
                        &mut rng,
                        &fixture.setup_context,
                        precomputation,
                        &request_a,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let request_b_shares = participants
            .iter()
            .zip(&precomputations)
            .map(|(participant, precomputation)| {
                participant
                    .issue_disclosure_share(
                        &mut rng,
                        &fixture.setup_context,
                        precomputation,
                        &request_b,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let combiner = Combiner::new(fixture.public_key_set, fixture.setup_context).unwrap();
        let request_a_key = combiner
            .combine_disclosure_exact(&request_a, &request_a_shares[..2])
            .unwrap();
        let request_b_key = combiner
            .combine_disclosure_exact(&request_b, &request_b_shares[..2])
            .unwrap();

        assert_eq!(request_a_key.open(&first).unwrap(), b"first content key");
        assert_eq!(request_a_key.open(&second).unwrap(), b"second content key");
        assert_eq!(request_b_key.open(&first).unwrap(), b"first content key");
        assert_eq!(request_b_key.open(&second).unwrap(), b"second content key");

        let mixed_requests = [request_a_shares[0].clone(), request_b_shares[1].clone()];
        assert_malformed(
            combiner.combine_disclosure_exact(&request_a, &mixed_requests),
            &[2],
        );
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
        let disclosure_scope = scope_for(&first, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let other_r_scope = scope_for(&other_r_message, ASSOCIATED_DATA, SCOPE_ID);
        let other_r_request = other_r_scope.request(DECRYPTION_CONTEXT);
        let unsealing_share = UnsealingShare::new(fixture.secret_shares[0].clone());
        let precomputation = unsealing_share
            .precompute_for_ephemeral_public(&first.ephemeral_public)
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);

        assert_eq!(
            unsealing_share.issue_disclosure_share(
                &mut rng,
                &fixture.setup_context,
                &precomputation,
                &other_r_request,
            ),
            Err(DisclosureError::PrecomputationEphemeralPublicMismatch)
        );

        let shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &request, 34);
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();
        assert_malformed(
            combiner.combine_disclosure_exact(&other_r_request, &shares[..2]),
            &[1, 2],
        );
        let key = combiner
            .combine_disclosure_exact(&request, &shares[..2])
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
            DisclosureScope::<G>::new(G::identity(), ASSOCIATED_DATA, SCOPE_ID),
            Err(DisclosureError::InvalidEphemeralPublic)
        );
        assert!(matches!(
            unsealing_share.precompute_for_ephemeral_public(&G::identity()),
            Err(DisclosureError::InvalidEphemeralPublic)
        ));
    }

    #[test]
    fn every_disclosure_scope_transcript_input_is_bound() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_scope = scope_for(&message, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &request, 35);
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();

        let wrong_scope_id = scope_for(&message, ASSOCIATED_DATA, b"wrong scope");
        let wrong_scope_id_request = wrong_scope_id.request(DECRYPTION_CONTEXT);
        assert_malformed(
            combiner.combine_disclosure_exact(&wrong_scope_id_request, &shares[..2]),
            &[1, 2],
        );

        let wrong_associated_data = scope_for(&message, b"wrong associated data", SCOPE_ID);
        let wrong_associated_data_request = wrong_associated_data.request(DECRYPTION_CONTEXT);
        assert_malformed(
            combiner.combine_disclosure_exact(&wrong_associated_data_request, &shares[..2]),
            &[1, 2],
        );

        let wrong_decryption_context = disclosure_scope.request(b"wrong request");
        assert_malformed(
            combiner.combine_disclosure_exact(&wrong_decryption_context, &shares[..2]),
            &[1, 2],
        );

        let mut wrong_setup_context = fixture.setup_context;
        wrong_setup_context.epoch = [99u8; 32];
        let wrong_setup_combiner =
            Combiner::new(fixture.public_key_set, wrong_setup_context).unwrap();
        assert_malformed(
            wrong_setup_combiner.combine_disclosure_exact(&request, &shares[..2]),
            &[1, 2],
        );
    }

    #[test]
    fn shares_from_different_scopes_or_requests_cannot_be_mixed() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let scope_a = scope_for(&message, ASSOCIATED_DATA, b"scope a");
        let scope_b = scope_for(&message, ASSOCIATED_DATA, b"scope b");
        let scope_a_request = scope_a.request(b"request a");
        let scope_b_request = scope_b.request(b"request a");
        let scope_a_shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &scope_a_request,
            36,
        );
        let scope_b_shares = disclosure_shares(
            &fixture.secret_shares,
            &fixture.setup_context,
            &scope_b_request,
            37,
        );
        let combiner = Combiner::new(
            fixture.public_key_set.clone(),
            fixture.setup_context.clone(),
        )
        .unwrap();
        let mixed_scopes = vec![scope_a_shares[0].clone(), scope_b_shares[1].clone()];
        assert_malformed(
            combiner.combine_disclosure_exact(&scope_a_request, &mixed_scopes),
            &[2],
        );

        let scope = scope_for(&message, ASSOCIATED_DATA, SCOPE_ID);
        let request_a = scope.request(b"request a");
        let request_b = scope.request(b"request b");
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
            combiner.combine_disclosure_exact(&request_a, &mixed_requests),
            &[2],
        );
    }

    #[test]
    fn precomputation_is_bound_to_its_participant() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_scope = scope_for(&message, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let first = UnsealingShare::new(fixture.secret_shares[0].clone());
        let second = UnsealingShare::new(fixture.secret_shares[1].clone());
        let precomputation = first
            .precompute_for_ephemeral_public(disclosure_scope.ephemeral_public())
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([40u8; 32]);

        assert_eq!(
            second.issue_disclosure_share(
                &mut rng,
                &fixture.setup_context,
                &precomputation,
                &request,
            ),
            Err(DisclosureError::PrecomputationParticipantMismatch)
        );
    }

    #[test]
    fn repeated_release_reuses_w_but_refreshes_and_verifies_the_proof() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_scope = scope_for(&message, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let first_participant = UnsealingShare::new(fixture.secret_shares[0].clone());
        let first_precomputation = first_participant
            .precompute_for_ephemeral_public(disclosure_scope.ephemeral_public())
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
        let first_release = first_participant
            .issue_disclosure_share(
                &mut rng,
                &fixture.setup_context,
                &first_precomputation,
                &request,
            )
            .unwrap();
        let second_release = first_participant
            .issue_disclosure_share(
                &mut rng,
                &fixture.setup_context,
                &first_precomputation,
                &request,
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
            .precompute_for_ephemeral_public(disclosure_scope.ephemeral_public())
            .unwrap();
        let other_share = second_participant
            .issue_disclosure_share(
                &mut rng,
                &fixture.setup_context,
                &second_precomputation,
                &request,
            )
            .unwrap();
        let combiner = Combiner::new(fixture.public_key_set, fixture.setup_context).unwrap();

        let first_key = combiner
            .combine_disclosure_exact(&request, &[first_release, other_share.clone()])
            .unwrap();
        let second_key = combiner
            .combine_disclosure_exact(&request, &[second_release, other_share])
            .unwrap();
        assert_eq!(first_key.open(&message).unwrap(), b"first content key");
        assert_eq!(second_key.open(&message).unwrap(), b"first content key");
    }

    #[test]
    fn disclosure_exact_count_and_quorum_selection_match_ordinary_semantics() {
        let fixture = fixture();
        let (message, _) = sibling_ciphertexts(&fixture.sealing_key);
        let disclosure_scope = scope_for(&message, ASSOCIATED_DATA, SCOPE_ID);
        let request = disclosure_scope.request(DECRYPTION_CONTEXT);
        let shares =
            disclosure_shares(&fixture.secret_shares, &fixture.setup_context, &request, 42);
        let combiner = Combiner::new(fixture.public_key_set, fixture.setup_context).unwrap();

        assert!(matches!(
            combiner.combine_disclosure_exact(&request, &shares[..1]),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        ));
        assert!(matches!(
            combiner.combine_disclosure_exact(&request, &shares),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 3
            })
        ));
        assert!(matches!(
            combiner.combine_disclosure_quorum(&request, &shares[..1]),
            Err(CombineError::InsufficientShares {
                required: 2,
                provided: 1
            })
        ));

        let duplicate = vec![shares[0].clone(), shares[0].clone()];
        assert_malformed(
            combiner.combine_disclosure_exact(&request, &duplicate),
            &[1],
        );

        let mut with_surplus_malformed = shares.clone();
        with_surplus_malformed[2].share = G::add(&with_surplus_malformed[2].share, &G::generator());
        let quorum_key = combiner
            .combine_disclosure_quorum(&request, &with_surplus_malformed)
            .unwrap();
        assert_eq!(quorum_key.open(&message).unwrap(), b"first content key");

        let mut malformed_before_threshold = shares[1].clone();
        malformed_before_threshold.share =
            G::add(&malformed_before_threshold.share, &G::generator());
        assert_malformed(
            combiner.combine_disclosure_quorum(
                &request,
                &[shares[0].clone(), malformed_before_threshold],
            ),
            &[2],
        );
    }
}
