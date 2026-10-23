//! Client side EHTDH1 sealing and ciphertext proof checks.
//!
//! Online equations use the native inner group and the approved batch context.

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};
use ff::Field;
use golden_core::{DkgGroup, TranscriptBuilder};
use group::Group;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::context::{hash_to_nonzero_scalar, Error, TRANSCRIPT_PREFIX};

/// `pk = X`, the paper Section 3 encryption public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealingKey<G: DkgGroup> {
    joint_public_key: G::Point,
}

impl<G: DkgGroup> SealingKey<G> {
    /// Construct from `X`, rejecting the identity as a defensive guard.
    pub fn new(joint_public_key: G::Point) -> Result<Self, Error> {
        if bool::from(joint_public_key.is_identity()) {
            return Err(Error::InvalidJointPublicKey);
        }
        Ok(Self { joint_public_key })
    }

    /// Return the joint public key.
    pub fn joint_public_key(&self) -> &G::Point {
        &self.joint_public_key
    }

    /// Seal bytes with no associated data.
    pub fn seal_bytes<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<Ciphertext<G>, Error> {
        self.seal_bytes_with_associated_data(rng, plaintext, &[])
    }

    /// Paper Section 3 Encryption, outputting `(R, V, e, r'', c)`.
    ///
    /// `encryption_group` computes `Y`; `encryption_challenge` computes `e`.
    pub fn seal_bytes_with_associated_data<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Ciphertext<G>, Error> {
        // Paper scalars `r, r' in Zq`.
        let r = crate::secret::secret(random_nonzero_scalar::<G, _>(rng));
        let r_prime = crate::secret::secret(random_nonzero_scalar::<G, _>(rng));

        // `R = rG`, `U = rX`, `k = Hkd(R, U)`, and `c = Es(k, m)`.
        let ephemeral_public = G::mul_generator(r.expose());
        let dh_point = self.joint_public_key * *r.expose();
        let mut encrypted_payload = plaintext.to_vec();
        apply_payload_mask::<G>(&mut encrypted_payload, &ephemeral_public, &dh_point)?;

        // Schnorr proof for `V = DH(R, Y)`: `R' = r'G` and `Y = Hegd(...)`.
        let proof_commitment = G::mul_generator(r_prime.expose());
        let encryption_group = encryption_group::<G>(
            &ephemeral_public,
            &proof_commitment,
            associated_data,
            &encrypted_payload,
        )?;

        // `V = rY`, `V' = r'Y`, `e = Hecd(Y, V, V')`, and `r'' = r' + re`.
        let encryption_point = encryption_group * *r.expose();
        let encryption_commitment = encryption_group * *r_prime.expose();
        let challenge = encryption_challenge::<G>(
            &encryption_group,
            &encryption_point,
            &encryption_commitment,
        )?;
        let response = *r_prime.expose() + *r.expose() * challenge;

        Ok(Ciphertext {
            associated_data: associated_data.to_vec(),
            encrypted_payload,
            ephemeral_public,
            encryption_point,
            challenge,
            response,
        })
    }
}

/// EHTDH1 ciphertext tuple `(R, V, e, r'', c)` from paper Section 3 Encryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext<G: DkgGroup> {
    /// Associated data `ad` bound into `Hegd(R, R', ad, c)`.
    pub associated_data: Vec<u8>,
    /// `c = Es(k, m)` (paper Section 3 Encryption).
    pub encrypted_payload: Vec<u8>,
    /// `R = rG` (paper Section 3 Encryption).
    pub ephemeral_public: G::Point,
    /// `V = rY` (paper Section 3 Encryption).
    pub encryption_point: G::Point,
    /// `e = Hecd(Y, V, V')` (paper Section 3 Encryption).
    pub challenge: G::Scalar,
    /// `r'' = r' + re` (paper Section 3 Encryption).
    pub response: G::Scalar,
}

impl<G: DkgGroup> Ciphertext<G> {
    /// Verify the ciphertext proof.
    ///
    /// This checks the associated data stored in the ciphertext. If the caller
    /// expects a specific value, use [`Ciphertext::verify_with_associated_data`]
    /// or compare [`Ciphertext::associated_data`] before accepting plaintext.
    pub fn verify(&self) -> Result<(), Error> {
        verify_ciphertext(self)
    }

    /// Verify the ciphertext proof and require this associated data.
    pub fn verify_with_associated_data(
        &self,
        expected_associated_data: &[u8],
    ) -> Result<(), Error> {
        if self.associated_data != expected_associated_data {
            return Err(Error::AssociatedDataMismatch);
        }
        self.verify()
    }

    /// Return the associated data stored in this ciphertext.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
}

/// Paper equation (1): reconstruct `R' = r''G - eR`, `Y`, and `V'`.
///
/// This verifies the Schnorr proof that `V = DH(R, Y)`.
/// The identity checks are crate-side guards against degenerate inputs.
pub(crate) fn verify_ciphertext<G: DkgGroup>(message: &Ciphertext<G>) -> Result<(), Error> {
    if bool::from(message.ephemeral_public.is_identity())
        || bool::from(message.encryption_point.is_identity())
    {
        return Err(Error::InvalidCiphertextProof);
    }

    // `R' = r''G - eR`.
    let proof_commitment =
        G::mul_generator(&message.response) - message.ephemeral_public * message.challenge;
    // `Y = Hegd(R, R', ad, c)`.
    let encryption_group = encryption_group::<G>(
        &message.ephemeral_public,
        &proof_commitment,
        &message.associated_data,
        &message.encrypted_payload,
    )?;
    // `V' = r''Y - eV`.
    let encryption_commitment =
        encryption_group * message.response - message.encryption_point * message.challenge;
    // Accept only when `e = Hecd(Y, V, V')`.
    let expected = encryption_challenge::<G>(
        &encryption_group,
        &message.encryption_point,
        &encryption_commitment,
    )?;

    if expected == message.challenge {
        Ok(())
    } else {
        Err(Error::InvalidCiphertextProof)
    }
}

/// `Y = Hegd(R, R', ad, c)` (paper Section 3 Encryption).
///
/// This is the paper's derived proof point `Y`, not a new group generator.
pub(crate) fn encryption_group<G: DkgGroup>(
    ephemeral_public: &G::Point,
    proof_commitment: &G::Point,
    associated_data: &[u8],
    encrypted_payload: &[u8],
) -> Result<G::Point, Error> {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hegd");
    transcript.bytes(b"backend", G::GROUP_ID.as_bytes());
    // The paper's `Hegd` input tuple is `(R, R', ad, c)`.
    transcript.element::<G>(b"R", ephemeral_public);
    transcript.element::<G>(b"R-prime", proof_commitment);
    transcript.bytes(b"ad", associated_data);
    transcript.bytes(b"ciphertext", encrypted_payload);
    G::hash_to_point(b"golden-ehtdh1-hegd-v1", &transcript.root())
        .map_err(|_| Error::InvalidEncoding)
}

/// `e = Hecd(Y, V, V')` (paper Section 3 Encryption).
pub(crate) fn encryption_challenge<G: DkgGroup>(
    encryption_group: &G::Point,
    encryption_point: &G::Point,
    encryption_commitment: &G::Point,
) -> Result<G::Scalar, Error> {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hecd");
    transcript.bytes(b"backend", G::GROUP_ID.as_bytes());
    // The paper's `Hecd` input tuple is `(Y, V, V')`.
    transcript.element::<G>(b"Y", encryption_group);
    transcript.element::<G>(b"V", encryption_point);
    transcript.element::<G>(b"V-prime", encryption_commitment);
    hash_to_nonzero_scalar::<G>(b"golden-ehtdh1-hecd-v1", &transcript.root())
}

/// Realizes `c = Es(Hkd(R, U), m)` with HKDF-SHA256 and XChaCha20.
pub(crate) fn apply_payload_mask<G: DkgGroup>(
    target: &mut [u8],
    ephemeral_public: &G::Point,
    dh_point: &G::Point,
) -> Result<(), Error> {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 24;
    const MATERIAL_SIZE: usize = KEY_SIZE + NONCE_SIZE;

    let material = derive_payload_mask_material::<G, MATERIAL_SIZE>(ephemeral_public, dh_point)?;
    let mut cipher = XChaCha20::new_from_slices(&material[..KEY_SIZE], &material[KEY_SIZE..])
        .map_err(|_| Error::InvalidEncoding)?;
    cipher.apply_keystream(target);
    Ok(())
}

/// `Hkd(R, U) -> k`, expanded here into XChaCha20 key and nonce material.
fn derive_payload_mask_material<G: DkgGroup, const N: usize>(
    ephemeral_public: &G::Point,
    dh_point: &G::Point,
) -> Result<Zeroizing<[u8; N]>, Error> {
    let mut transcript = TranscriptBuilder::with_prefix(TRANSCRIPT_PREFIX, b"hkd-ikm");
    transcript.bytes(b"backend", G::GROUP_ID.as_bytes());
    // The paper's `Hkd` input tuple is `(R, U)`.
    transcript.element::<G>(b"R", ephemeral_public);
    transcript.element::<G>(b"U", dh_point);
    let hkdf = Hkdf::<Sha256>::new(Some(b"golden-ehtdh1-hkd-v1"), &transcript.root());
    let mut material = Zeroizing::new([0u8; N]);
    hkdf.expand(b"golden-ehtdh1-xchacha20-mask-v1", material.as_mut())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok(material)
}

/// Samples paper scalars such as `r, r' in Zq`, resampling to avoid zero.
pub(crate) fn random_nonzero_scalar<G: DkgGroup, R: RngCore + CryptoRng>(rng: &mut R) -> G::Scalar {
    loop {
        let scalar = G::Scalar::random(&mut *rng);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}
