//! Validator decryption shares and combiners.
//!
//! See crate root for the paper-to-crate symbol map.

use std::collections::BTreeSet;
use std::fmt;

use golden_core::{
    GoldenGroup, GoldenHashToGroup, GoldenScalar, ParticipantIndex, TranscriptBuilder,
};
use rand_core::{CryptoRng, RngCore};

use crate::context::{
    hash_to_nonzero_scalar, CombineError, Error, PublicKeySet, PublicShare, SecretShare,
    SetupContext, TRANSCRIPT_PREFIX,
};
use crate::encrypt::{apply_payload_mask, random_nonzero_scalar, verify_ciphertext, Ciphertext};

/// Validator wrapper around `sk_i = (x_i, z_i)` from paper Section 3.
#[derive(Clone)]
pub struct UnsealingShare<G: GoldenHashToGroup> {
    share: SecretShare<G>,
}

impl<G: GoldenHashToGroup> fmt::Debug for UnsealingShare<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnsealingShare")
            .field("participant", &self.share.participant)
            .field("share", &"<redacted>")
            .finish()
    }
}

impl<G: GoldenHashToGroup> UnsealingShare<G> {
    /// Construct a validator unsealing share.
    pub fn new(share: SecretShare<G>) -> Self {
        Self { share }
    }

    /// Return this share's participant id.
    pub fn participant(&self) -> ParticipantIndex {
        self.share.participant
    }

    /// Produce a partial decryption for this context.
    pub fn decrypt_share<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        setup_context: &SetupContext,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
    ) -> Result<DecryptionShare<G>, Error> {
        self.decrypt_share_with_associated_data(
            rng,
            setup_context,
            message,
            decryption_context,
            message.associated_data(),
        )
    }

    /// Paper Section 3 Decryption, producing `(W_i, e_i, x_i'', z_i'')`.
    ///
    /// The share proof is a double Schnorr proof for `W_i = x_i R + z_i S`.
    pub fn decrypt_share_with_associated_data<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        setup_context: &SetupContext,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        expected_associated_data: &[u8],
    ) -> Result<DecryptionShare<G>, Error> {
        if message.associated_data() != expected_associated_data {
            return Err(Error::AssociatedDataMismatch);
        }
        verify_ciphertext(message)?;

        // `X_i = x_i G`, `Z_i = z_i G`, and `S = Hdgd(ad, dc, ctxt)`.
        let public_decryption_share = G::mul_generator(&self.share.decryption);
        let public_context_share = G::mul_generator(&self.share.context);
        let decryption_group = decryption_group::<G>(setup_context, message, decryption_context)?;

        // `W_i = x_i R + z_i S`.
        let share = G::add(
            &G::mul(&message.ephemeral_public, &self.share.decryption),
            &G::mul(&decryption_group, &self.share.context),
        );

        // Paper nonces `x_i', z_i' in Zq`.
        let decryption_nonce = random_nonzero_scalar::<G, _>(rng);
        let context_nonce = random_nonzero_scalar::<G, _>(rng);

        // `X_i' = x_i'G`, `Z_i' = z_i'G`, and `W_i' = x_i'R + z_i'S`.
        let public_decryption_commitment = G::mul_generator(&decryption_nonce);
        let public_context_commitment = G::mul_generator(&context_nonce);
        let share_commitment = G::add(
            &G::mul(&message.ephemeral_public, &decryption_nonce),
            &G::mul(&decryption_group, &context_nonce),
        );

        // `e_i = Hdcd(S, X_i, Z_i, W_i, X_i', Z_i', W_i')`.
        let challenge = share_challenge::<G>(ShareChallengeInputs {
            setup_context,
            decryption_group: &decryption_group,
            public_decryption_share: &public_decryption_share,
            public_context_share: &public_context_share,
            share: &share,
            public_decryption_commitment: &public_decryption_commitment,
            public_context_commitment: &public_context_commitment,
            share_commitment: &share_commitment,
        })?;

        // `x_i'' = x_i' + e_i x_i` and `z_i'' = z_i' + e_i z_i`.
        let decryption_response = decryption_nonce.add(&challenge.mul(&self.share.decryption));
        let context_response = context_nonce.add(&challenge.mul(&self.share.context));

        Ok(DecryptionShare {
            participant: self.share.participant,
            share,
            challenge,
            decryption_response,
            context_response,
        })
    }
}

/// Decryption share `(W_i, e_i, x_i'', z_i'')` from paper Section 3.
///
/// `(e_i, x_i'', z_i'')` is a double Schnorr proof for `W_i = x_i R + z_i S`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptionShare<G: GoldenHashToGroup> {
    /// Participant index.
    pub participant: ParticipantIndex,
    /// `W_i = x_i R + z_i S` (paper Section 3 Decryption).
    pub share: G::Element,
    /// `e_i = Hdcd(S, X_i, Z_i, W_i, X_i', Z_i', W_i')`.
    pub challenge: G::Scalar,
    /// `x_i'' = x_i' + e_i x_i` (paper Section 3 Decryption).
    pub decryption_response: G::Scalar,
    /// `z_i'' = z_i' + e_i z_i` (paper Section 3 Decryption).
    pub context_response: G::Scalar,
}

/// Combiner for paper `pkc`, checking shares and opening plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Combiner<G: GoldenHashToGroup> {
    public_key_set: PublicKeySet<G>,
    setup_context: SetupContext,
}

impl<G: GoldenHashToGroup> Combiner<G> {
    /// Construct a combiner and run setup consistency checks not in the paper.
    pub fn new(
        public_key_set: PublicKeySet<G>,
        setup_context: SetupContext,
    ) -> Result<Self, Error> {
        validate_combiner_setup::<G>(&public_key_set, &setup_context)?;
        Ok(Self {
            public_key_set,
            setup_context,
        })
    }

    /// Paper combiner with exactly `t` decryption shares.
    pub fn combine_exact(
        &self,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        if shares.len() != self.public_key_set.threshold {
            return Err(CombineError::InsufficientShares {
                required: self.public_key_set.threshold,
                provided: shares.len(),
            });
        }
        self.combine_selected(message, decryption_context, shares)
    }

    /// Check exactly threshold shares, require associated data, and open plaintext.
    pub fn combine_exact_with_associated_data(
        &self,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        expected_associated_data: &[u8],
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        if message.associated_data() != expected_associated_data {
            return Err(CombineError::Ciphertext(Error::AssociatedDataMismatch));
        }
        self.combine_exact(message, decryption_context, shares)
    }

    /// Crate search variant that runs the paper combiner on a valid `t`-subset.
    pub fn combine_quorum(
        &self,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        verify_ciphertext(message).map_err(CombineError::Ciphertext)?;
        let decryption_group =
            decryption_group::<G>(&self.setup_context, message, decryption_context)
                .map_err(CombineError::Ciphertext)?;
        let (valid, malformed) = self.verify_shares(message, &decryption_group, shares);

        if valid.len() < self.public_key_set.threshold {
            if !malformed.is_empty() {
                return Err(CombineError::MalformedShares(malformed));
            }
            return Err(CombineError::InsufficientShares {
                required: self.public_key_set.threshold,
                provided: valid.len(),
            });
        }

        // `valid` already passed verification, so combine directly instead
        // of re-verifying through `combine_selected`.
        self.combine_verified(message, &valid[..self.public_key_set.threshold])
    }

    /// Search for a valid threshold set, require associated data, and open plaintext.
    pub fn combine_quorum_with_associated_data(
        &self,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        expected_associated_data: &[u8],
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        if message.associated_data() != expected_associated_data {
            return Err(CombineError::Ciphertext(Error::AssociatedDataMismatch));
        }
        self.combine_quorum(message, decryption_context, shares)
    }

    /// Computes `U = sum_j lambda_j^(J) W_j = xR`, then `m = Ds(Hkd(R, U), c)`.
    ///
    /// Unlike [`Self::verify_shares`], an unknown participant fails the
    /// whole combine immediately instead of being folded into `malformed`.
    fn combine_selected(
        &self,
        message: &Ciphertext<G>,
        decryption_context: &[u8],
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        verify_ciphertext(message).map_err(CombineError::Ciphertext)?;
        let decryption_group =
            decryption_group::<G>(&self.setup_context, message, decryption_context)
                .map_err(CombineError::Ciphertext)?;
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
            if verify_decryption_share(
                &self.setup_context,
                &decryption_group,
                message,
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

        self.combine_verified(message, shares)
    }

    /// Verifies each share once, deduplicating by participant and folding
    /// unknown participants into `malformed` (used by
    /// [`Self::combine_quorum`]'s valid-subset search). Returns the valid
    /// shares and the malformed participant ids.
    fn verify_shares(
        &self,
        message: &Ciphertext<G>,
        decryption_group: &G::Element,
        shares: &[DecryptionShare<G>],
    ) -> (Vec<DecryptionShare<G>>, Vec<u32>) {
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
            match verify_decryption_share(
                &self.setup_context,
                decryption_group,
                message,
                share,
                public_share,
            ) {
                Ok(()) => valid.push(share.clone()),
                Err(_) => malformed.push(share.participant.get()),
            }
        }

        (valid, malformed)
    }

    /// Computes `U = sum_j lambda_j^(J) W_j = xR`, then `m = Ds(Hkd(R, U), c)`
    /// from shares the caller already verified via [`Self::verify_shares`].
    fn combine_verified(
        &self,
        message: &Ciphertext<G>,
        shares: &[DecryptionShare<G>],
    ) -> Result<Vec<u8>, CombineError> {
        let participants: Vec<_> = shares.iter().map(|share| share.participant).collect();
        let lambdas =
            lagrange_coefficients_at_zero::<G>(&participants).map_err(CombineError::Ciphertext)?;

        let mut dh_point = G::identity();
        for (share, lambda) in shares.iter().zip(&lambdas) {
            dh_point = G::add(&dh_point, &G::mul(&share.share, lambda));
        }

        let mut plaintext = message.encrypted_payload.clone();
        apply_payload_mask::<G>(&mut plaintext, &message.ephemeral_public, &dh_point)
            .map_err(CombineError::Ciphertext)?;
        Ok(plaintext)
    }
}

fn validate_combiner_setup<G: GoldenHashToGroup>(
    public_key_set: &PublicKeySet<G>,
    setup_context: &SetupContext,
) -> Result<(), Error> {
    if setup_context.backend_id != G::BACKEND_ID {
        return Err(Error::InvalidBridge("setup backend mismatch"));
    }
    if setup_context.threshold != public_key_set.threshold {
        return Err(Error::InvalidBridge("setup threshold mismatch"));
    }
    let public_participants = public_key_set
        .public_shares
        .keys()
        .copied()
        .collect::<Vec<_>>();
    if setup_context.participants != public_participants {
        return Err(Error::InvalidBridge("setup participant mismatch"));
    }
    if setup_context.context_session_id
        != crate::context::derive_context_session_id(setup_context.decryption_session_id)
    {
        return Err(Error::InvalidBridge("setup context session mismatch"));
    }
    Ok(())
}

/// Paper equation (2): reconstruct `X_i'`, `Z_i'`, and `W_i'`.
///
/// This verifies the double Schnorr proof for `W_i = x_i R + z_i S`.
/// `decryption_group` (`S = Hdgd(ad, dc, ctxt)`) is computed once by the
/// caller and shared across shares instead of re-derived per share.
fn verify_decryption_share<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    decryption_group: &G::Element,
    message: &Ciphertext<G>,
    share: &DecryptionShare<G>,
    public_share: &PublicShare<G>,
) -> Result<(), Error> {
    // `X_i' = x_i''G - e_i X_i`.
    let public_decryption_commitment = G::sub(
        &G::mul_generator(&share.decryption_response),
        &G::mul(&public_share.decryption, &share.challenge),
    );

    // `Z_i' = z_i''G - e_i Z_i`.
    let public_context_commitment = G::sub(
        &G::mul_generator(&share.context_response),
        &G::mul(&public_share.context, &share.challenge),
    );

    // `W_i' = x_i''R + z_i''S - e_i W_i`.
    let share_commitment = G::sub(
        &G::add(
            &G::mul(&message.ephemeral_public, &share.decryption_response),
            &G::mul(decryption_group, &share.context_response),
        ),
        &G::mul(&share.share, &share.challenge),
    );

    // Accept only when `e_i = Hdcd(S, X_i, Z_i, W_i, X_i', Z_i', W_i')`.
    let expected = share_challenge::<G>(ShareChallengeInputs {
        setup_context,
        decryption_group,
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

/// `S = Hdgd(ad, dc, ctxt)`, additionally binding `SetupContext::root`.
fn decryption_group<G: GoldenHashToGroup>(
    setup_context: &SetupContext,
    message: &Ciphertext<G>,
    decryption_context: &[u8],
) -> Result<G::Element, Error> {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hdgd");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    // The paper's `Hdgd` input is `(ad, dc, ctxt)`.
    // This crate also binds `SetupContext::root` into that transcript.
    transcript.bytes(b"setup-context-root", &setup_context.root());
    transcript.bytes(b"ad", &message.associated_data);
    transcript.bytes(b"dc", decryption_context);
    // `ctxt = (R, V, e, r'', c)`.
    transcript.element::<G>(b"R", &message.ephemeral_public);
    transcript.element::<G>(b"V", &message.encryption_point);
    transcript.scalar::<G>(b"e", &message.challenge);
    transcript.scalar::<G>(b"r-response", &message.response);
    transcript.bytes(b"ciphertext", &message.encrypted_payload);
    G::hash_to_group(b"golden-ehtdh1-hdgd-v1", &transcript.root())
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

/// `e_i = Hdcd(S, X_i, Z_i, W_i, X_i', Z_i', W_i')`.
///
/// Commitments are `X_i' = x_i'G`, `Z_i' = z_i'G`, and `W_i' = x_i'R + z_i'S`.
fn share_challenge<G: GoldenGroup>(
    inputs: ShareChallengeInputs<'_, G>,
) -> Result<G::Scalar, Error> {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hdcd");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.bytes(b"setup-context-root", &inputs.setup_context.root());
    // The paper's `Hdcd` input tuple is `(S, X_i, Z_i, W_i, X_i', Z_i', W_i')`.
    transcript.element::<G>(b"S", inputs.decryption_group);
    transcript.element::<G>(b"X-i", inputs.public_decryption_share);
    transcript.element::<G>(b"Z-i", inputs.public_context_share);
    transcript.element::<G>(b"W-i", inputs.share);
    transcript.element::<G>(b"X-i-prime", inputs.public_decryption_commitment);
    transcript.element::<G>(b"Z-i-prime", inputs.public_context_commitment);
    transcript.element::<G>(b"W-i-prime", inputs.share_commitment);
    hash_to_nonzero_scalar::<G>(b"golden-ehtdh1-hdcd-v1", &transcript.root())
}

/// Paper coefficients `lambda_j^(J)` at 0 for every participant, computed
/// with one batch field inversion via [`golden_core::batch_invert`].
fn lagrange_coefficients_at_zero<G: GoldenGroup>(
    participants: &[ParticipantIndex],
) -> Result<Vec<G::Scalar>, Error> {
    let xs: Vec<G::Scalar> = participants
        .iter()
        .map(|participant| participant.to_scalar::<G::Scalar>())
        .collect::<Result<_, _>>()?;

    golden_core::lagrange_coefficients_at_zero(&xs).map_err(|_| Error::InvalidThreshold)
}
