//! Shared EHTDH1 setup data and transcript errors.
//!
//! Online equations use the native inner group and the approved batch context. The generic `G` supplies
//! the paper group `G`, scalar field order `q`, and identity `O`.

use ff::Field;
use group::Group;
use std::collections::BTreeMap;
use std::fmt;

use golden_core::{DkgGroup, ParticipantIndex, SessionId, TranscriptBuilder, TranscriptRoot};

pub(crate) const TRANSCRIPT_PREFIX: &[u8] = b"golden-ehtdh1-v2";

/// Public share material for one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicShare<G: DkgGroup> {
    /// `X_i = x_i G` (paper Section 3 Key generation).
    pub decryption: G::Point,
    /// `Z_i = z_i G` for the zero sharing (paper Section 3 Key generation).
    pub context: G::Point,
}

/// Participant-local native scalar shares with redacted, guarded storage.
#[derive(Clone)]
pub struct SecretShare<G: DkgGroup> {
    pub(crate) participant: ParticipantIndex,
    pub(crate) decryption: crate::secret::Secret<G::Scalar>,
    pub(crate) context: crate::secret::Secret<G::Scalar>,
}
impl<G: DkgGroup> SecretShare<G> {
    /// Copy caller-owned scalar values into independently guarded storage.
    pub fn new(participant: ParticipantIndex, decryption: &G::Scalar, context: &G::Scalar) -> Self {
        Self {
            participant,
            decryption: crate::secret::secret(*decryption),
            context: crate::secret::secret(*context),
        }
    }
    /// Owning participant.
    pub fn participant(&self) -> ParticipantIndex {
        self.participant
    }
    /// Borrow the native decryption scalar.
    pub fn decryption(&self) -> &G::Scalar {
        self.decryption.expose()
    }
    /// Borrow the native context scalar.
    pub fn context(&self) -> &G::Scalar {
        self.context.expose()
    }
}
impl<G: DkgGroup> fmt::Debug for SecretShare<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretShare")
            .field("participant", &self.participant)
            .field("decryption", &"<redacted>")
            .field("context", &"<redacted>")
            .finish()
    }
}

/// Paper `pkc = (X; [(X_i, Z_i)]_i)` plus the reconstruction threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeySet<G: DkgGroup> {
    /// Number of shares required to decrypt.
    pub threshold: usize,
    /// `X = xG`, the joint public key (paper Section 3 Key generation).
    pub joint_public_key: G::Point,
    /// Pairs `(X_i, Z_i) = (x_i G, z_i G)`, keyed by participant.
    pub public_shares: BTreeMap<ParticipantIndex, PublicShare<G>>,
}

impl<G: DkgGroup> PublicKeySet<G> {
    /// Build and validate a public key set.
    pub fn new(
        threshold: usize,
        joint_public_key: G::Point,
        public_shares: BTreeMap<ParticipantIndex, PublicShare<G>>,
    ) -> Result<Self, Error> {
        let key_set = Self {
            threshold,
            joint_public_key,
            public_shares,
        };
        key_set.validate()?;
        Ok(key_set)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.threshold == 0 || self.public_shares.len() < self.threshold {
            return Err(Error::InvalidThreshold);
        }
        if bool::from(self.joint_public_key.is_identity()) {
            return Err(Error::InvalidJointPublicKey);
        }
        validate_public_shares(self.threshold, &self.joint_public_key, &self.public_shares)
    }

    /// Public share for a participant.
    pub fn public_share(&self, participant: ParticipantIndex) -> Option<&PublicShare<G>> {
        self.public_shares.get(&participant)
    }
}

/// Trusted setup identity bound into decryption transcripts.
///
/// This metadata accompanies the approved `[Random, Zero]` public result.
/// Its authenticity and agreement are application responsibilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupContext {
    /// Stable protocol group identifier.
    pub group_id: String,
    /// Reconstruction threshold.
    pub threshold: usize,
    /// Canonical registered participant indexes.
    pub participants: Vec<ParticipantIndex>,
    /// Single batch session identifier.
    pub session_id: SessionId,
    /// Configuration identity.
    pub config_root: TranscriptRoot,
    /// Public result identity.
    pub completion_root: TranscriptRoot,
    /// Application epoch.
    pub epoch: [u8; 32],
}

impl SetupContext {
    /// Derive the context used by EHTDH1 decryption proofs.
    pub fn root(&self) -> TranscriptRoot {
        let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"setup-context");
        transcript.bytes(b"group", self.group_id.as_bytes());
        transcript.usize(b"threshold", self.threshold);
        transcript.usize(b"participants-len", self.participants.len());
        for participant in &self.participants {
            transcript.participant(b"participant", *participant);
        }
        transcript.bytes(b"session", &self.session_id.0);
        transcript.bytes(b"config-root", &self.config_root);
        transcript.bytes(b"completion-root", &self.completion_root);
        transcript.bytes(b"epoch", &self.epoch);
        transcript.root()
    }
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
pub(crate) fn hash_to_nonzero_scalar<G: DkgGroup>(
    domain: &[u8],
    message: &[u8],
) -> Result<G::Scalar, Error> {
    use sha2::{Digest, Sha256};
    for counter in 0..u32::MAX {
        let mut hash = Sha256::new();
        hash.update(b"golden-scalar-v1");
        hash.update(
            u64::try_from(domain.len())
                .map_err(|_| Error::ScalarDerivationFailed)?
                .to_be_bytes(),
        );
        hash.update(domain);
        hash.update(
            u64::try_from(message.len())
                .map_err(|_| Error::ScalarDerivationFailed)?
                .to_be_bytes(),
        );
        hash.update(message);
        hash.update(counter.to_be_bytes());
        hash.update(0u32.to_be_bytes());
        if let Ok(scalar) = G::decode_scalar(&hash.finalize()) {
            if !bool::from(scalar.is_zero()) {
                return Ok(scalar);
            }
        }
    }
    Err(Error::ScalarDerivationFailed)
}

fn validate_public_shares<G: DkgGroup>(
    threshold: usize,
    joint_public_key: &G::Point,
    public_shares: &BTreeMap<ParticipantIndex, PublicShare<G>>,
) -> Result<(), Error> {
    let participants = public_shares.keys().copied().collect::<Vec<_>>();
    let basis = &participants[..threshold];

    // Interpolate `X_i` shares at 0 and check that they recover `X`.
    let decryption = interpolate_public_key_share::<G>(
        basis,
        G::Scalar::ZERO,
        |share| &share.decryption,
        public_shares,
    )?;
    if decryption != *joint_public_key {
        return Err(Error::InvalidPublicKeySet);
    }

    // Interpolate `Z_i` shares at 0 and check that they recover the identity.
    let context = interpolate_public_key_share::<G>(
        basis,
        G::Scalar::ZERO,
        |share| &share.context,
        public_shares,
    )?;
    if !bool::from(context.is_identity()) {
        return Err(Error::InvalidPublicKeySet);
    }

    for participant in participants.iter().skip(threshold) {
        let x = participant.to_scalar::<G::Scalar>()?;
        // Check that each remaining `(X_i, Z_i)` lies on the same polynomials.
        let expected_decryption =
            interpolate_public_key_share::<G>(basis, x, |share| &share.decryption, public_shares)?;
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

fn interpolate_public_key_share<'a, G: DkgGroup>(
    participants: &[ParticipantIndex],
    x: G::Scalar,
    select: impl Fn(&'a PublicShare<G>) -> &'a G::Point,
    public_shares: &'a BTreeMap<ParticipantIndex, PublicShare<G>>,
) -> Result<G::Point, Error> {
    let mut point = G::Point::identity();
    for participant in participants {
        let lambda = lagrange_at::<G>(*participant, participants.iter().copied(), &x)?;
        let public_share = public_shares
            .get(participant)
            .ok_or(Error::UnknownParticipant(participant.get()))?;
        point += *select(public_share) * lambda;
    }
    Ok(point)
}

fn lagrange_at<G: DkgGroup>(
    participant: ParticipantIndex,
    participants: impl IntoIterator<Item = ParticipantIndex>,
    x: &G::Scalar,
) -> Result<G::Scalar, Error> {
    let i = participant.to_scalar::<G::Scalar>()?;
    let mut numerator = G::Scalar::ONE;
    let mut denominator = G::Scalar::ONE;

    // Lagrange basis value at `x`: product_j (x - j) / product_j (i - j).
    for other in participants {
        if other == participant {
            continue;
        }
        let j = other.to_scalar::<G::Scalar>()?;
        numerator *= *x - j;
        denominator *= i - j;
    }

    let inverse = Option::<G::Scalar>::from(denominator.invert()).ok_or(Error::InvalidThreshold)?;
    Ok(numerator * inverse)
}
