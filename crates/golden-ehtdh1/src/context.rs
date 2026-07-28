//! Shared EHTDH1 setup data and transcript errors.
//!
//! See crate root for the paper-to-crate symbol map. The generic `G` supplies
//! the paper group `G`, scalar field order `q`, and identity `O`.

use std::collections::BTreeMap;
use std::fmt;

use golden_core::{
    GoldenGroup, GoldenScalar, ParticipantIndex, SessionId, TranscriptBuilder, TranscriptRoot,
};

pub(crate) const TRANSCRIPT_PREFIX: &[u8] = b"golden-ehtdh1-v1";

/// Public share material for one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicShare<G: GoldenGroup> {
    /// `X_i = x_i G` (paper Section 3 Key generation).
    pub decryption: G::Element,
    /// `Z_i = z_i G` for the zero sharing (paper Section 3 Key generation).
    pub context: G::Element,
}

/// Secret share material held by one participant.
#[derive(Clone)]
pub struct SecretShare<G: GoldenGroup> {
    /// Participant that owns this share.
    pub participant: ParticipantIndex,
    /// `x_i`, one of `(x_1..x_N)` sharing `x` (paper Section 3 Key generation).
    pub decryption: G::Scalar,
    /// `z_i`, one of `(z_1..z_N)` sharing zero (paper Section 3 Key generation).
    pub context: G::Scalar,
}

impl<G: GoldenGroup> fmt::Debug for SecretShare<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretShare")
            .field("participant", &self.participant)
            .field("decryption", &"<redacted>")
            .field("context", &"<redacted>")
            .finish()
    }
}

/// Paper `pkc = (X; [(X_i, Z_i)]_i)` plus the reconstruction threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeySet<G: GoldenGroup> {
    /// Number of shares required to decrypt.
    pub threshold: usize,
    /// `X = xG`, the joint public key (paper Section 3 Key generation).
    pub joint_public_key: G::Element,
    /// Pairs `(X_i, Z_i) = (x_i G, z_i G)`, keyed by participant.
    pub public_shares: BTreeMap<ParticipantIndex, PublicShare<G>>,
}

impl<G: GoldenGroup> PublicKeySet<G> {
    /// Build and validate a public key set.
    pub fn new(
        threshold: usize,
        joint_public_key: G::Element,
        public_shares: BTreeMap<ParticipantIndex, PublicShare<G>>,
    ) -> Result<Self, Error> {
        if threshold == 0 || public_shares.len() < threshold {
            return Err(Error::InvalidThreshold);
        }
        if bool::from(G::is_identity(&joint_public_key)) {
            return Err(Error::InvalidJointPublicKey);
        }
        validate_public_shares(threshold, &joint_public_key, &public_shares)?;
        Ok(Self {
            threshold,
            joint_public_key,
            public_shares,
        })
    }

    /// Public share for a participant.
    pub fn public_share(&self, participant: ParticipantIndex) -> Option<&PublicShare<G>> {
        self.public_shares.get(&participant)
    }
}

/// Golden setup context bound into `Hdgd` and `Hdcd`.
///
/// This is the crate's addition to paper Section 3: Golden DKG transcript
/// roots, registry root, session ids, and epoch are bound through
/// [`SetupContext::root`]. The zero sharing session id is derived by
/// [`derive_context_session_id`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupContext {
    /// Stable Golden backend id.
    pub backend_id: String,
    /// Threshold.
    pub threshold: usize,
    /// Golden participant registry root.
    pub registry_root: TranscriptRoot,
    /// Participants in canonical order.
    pub participants: Vec<ParticipantIndex>,
    /// Session id for the `x` sharing.
    pub decryption_session_id: SessionId,
    /// Session id for the zero sharing run.
    pub context_session_id: SessionId,
    /// Completion transcript root from the `x` sharing.
    pub decryption_transcript_root: TranscriptRoot,
    /// Completion transcript root from the zero sharing run.
    pub context_transcript_root: TranscriptRoot,
    /// Caller provided epoch or setup label.
    pub epoch: [u8; 32],
}

impl SetupContext {
    /// Compute the root used in EHTDH1 decryption transcripts.
    pub fn root(&self) -> TranscriptRoot {
        let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"setup-context");
        transcript.bytes(b"backend", self.backend_id.as_bytes());
        transcript.usize(b"threshold", self.threshold);
        transcript.bytes(b"registry-root", &self.registry_root);
        transcript.usize(b"participants-len", self.participants.len());
        for participant in &self.participants {
            transcript.participant(b"participant", *participant);
        }
        transcript.bytes(b"decryption-session", &self.decryption_session_id.0);
        transcript.bytes(b"context-session", &self.context_session_id.0);
        transcript.bytes(
            b"decryption-transcript-root",
            &self.decryption_transcript_root,
        );
        transcript.bytes(b"context-transcript-root", &self.context_transcript_root);
        transcript.bytes(b"epoch", &self.epoch);
        transcript.root()
    }
}

/// Golden setup derivation for the zero sharing session id, not in the paper.
pub fn derive_context_session_id(decryption_session_id: SessionId) -> SessionId {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"context-session");
    transcript.bytes(b"label", b"zero-sharing");
    transcript.bytes(b"decryption-session", &decryption_session_id.0);
    SessionId(transcript.root())
}

/// Errors returned by the EHTDH1 core.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Threshold is zero or larger than the public share count.
    #[error("invalid threshold")]
    InvalidThreshold,
    /// Encoded scalar or point was rejected.
    #[error("invalid encoding")]
    InvalidEncoding,
    /// Scalar derivation failed.
    #[error("scalar derivation failed")]
    ScalarDerivationFailed,
    /// Ciphertext proof failed.
    #[error("invalid ciphertext proof")]
    InvalidCiphertextProof,
    /// Ciphertext associated data did not match the expected value.
    #[error("associated data mismatch")]
    AssociatedDataMismatch,
    /// Joint public key is the identity element.
    #[error("invalid joint public key")]
    InvalidJointPublicKey,
    /// Public shares do not match the joint key and zero key.
    #[error("invalid public key set")]
    InvalidPublicKeySet,
    /// Decryption share proof failed.
    #[error("invalid decryption share proof")]
    InvalidShareProof,
    /// Participant was not present in the key set.
    #[error("unknown participant {0}")]
    UnknownParticipant(u32),
    /// Duplicate participant share.
    #[error("duplicate participant {0}")]
    DuplicateParticipant(u32),
    /// Golden bridge inputs do not match.
    #[error("invalid Golden bridge material: {0}")]
    InvalidBridge(&'static str),
    /// Error from Golden core.
    #[error(transparent)]
    Golden(#[from] golden_core::Error),
}

/// Errors returned by the combiner.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CombineError {
    /// Ciphertext or transcript data was invalid.
    #[error(transparent)]
    Ciphertext(#[from] Error),
    /// Not enough valid shares were provided.
    #[error("insufficient shares: required {required}, provided {provided}")]
    InsufficientShares {
        /// Required threshold.
        required: usize,
        /// Valid shares provided.
        provided: usize,
    },
    /// Malformed shares, listed by participant id.
    #[error("malformed shares from participants {0:?}")]
    MalformedShares(Vec<u32>),
}

/// `Hecd`/`Hdcd` reduction to `Zq`; the paper models this as a random oracle.
pub(crate) fn hash_to_nonzero_scalar<G: GoldenGroup>(
    domain: &[u8],
    message: &[u8],
) -> Result<G::Scalar, Error> {
    G::Scalar::hash_to_scalar(domain, message).map_err(|_| Error::ScalarDerivationFailed)
}

fn validate_public_shares<G: GoldenGroup>(
    threshold: usize,
    joint_public_key: &G::Element,
    public_shares: &BTreeMap<ParticipantIndex, PublicShare<G>>,
) -> Result<(), Error> {
    let participants = public_shares.keys().copied().collect::<Vec<_>>();
    let basis = &participants[..threshold];

    // Interpolate `X_i` shares at 0 and check that they recover `X`.
    let decryption = interpolate_public_key_share::<G>(
        basis,
        G::Scalar::zero(),
        |share| &share.decryption,
        public_shares,
    )?;
    if decryption != *joint_public_key {
        return Err(Error::InvalidPublicKeySet);
    }

    // Interpolate `Z_i` shares at 0 and check that they recover the identity.
    let context = interpolate_public_key_share::<G>(
        basis,
        G::Scalar::zero(),
        |share| &share.context,
        public_shares,
    )?;
    if !bool::from(G::is_identity(&context)) {
        return Err(Error::InvalidPublicKeySet);
    }

    for participant in participants.iter().skip(threshold) {
        let x = participant.to_scalar::<G::Scalar>()?;
        // Check that each remaining `(X_i, Z_i)` lies on the same polynomials.
        let expected_decryption = interpolate_public_key_share::<G>(
            basis,
            x.clone(),
            |share| &share.decryption,
            public_shares,
        )?;
        let expected_context =
            interpolate_public_key_share::<G>(basis, x, |share| &share.context, public_shares)?;
        let public_share = public_shares
            .get(participant)
            .ok_or(Error::UnknownParticipant(participant.get()))?;
        if expected_decryption != public_share.decryption
            || expected_context != public_share.context
        {
            return Err(Error::InvalidPublicKeySet);
        }
    }

    Ok(())
}

fn interpolate_public_key_share<'a, G: GoldenGroup>(
    participants: &[ParticipantIndex],
    x: G::Scalar,
    select: impl Fn(&'a PublicShare<G>) -> &'a G::Element,
    public_shares: &'a BTreeMap<ParticipantIndex, PublicShare<G>>,
) -> Result<G::Element, Error> {
    let mut point = G::identity();
    for participant in participants {
        let lambda = lagrange_at::<G>(*participant, participants.iter().copied(), &x)?;
        let public_share = public_shares
            .get(participant)
            .ok_or(Error::UnknownParticipant(participant.get()))?;
        point = G::add(&point, &G::mul(select(public_share), &lambda));
    }
    Ok(point)
}

fn lagrange_at<G: GoldenGroup>(
    participant: ParticipantIndex,
    participants: impl IntoIterator<Item = ParticipantIndex>,
    x: &G::Scalar,
) -> Result<G::Scalar, Error> {
    let i = participant.to_scalar::<G::Scalar>()?;
    let mut numerator = G::Scalar::one();
    let mut denominator = G::Scalar::one();

    // Lagrange basis value at `x`: product_j (x - j) / product_j (i - j).
    for other in participants {
        if other == participant {
            continue;
        }
        let j = other.to_scalar::<G::Scalar>()?;
        numerator = numerator.mul(&x.sub(&j));
        denominator = denominator.mul(&i.sub(&j));
    }

    let inverse = denominator.invert().ok_or(Error::InvalidThreshold)?;
    Ok(numerator.mul(&inverse))
}
