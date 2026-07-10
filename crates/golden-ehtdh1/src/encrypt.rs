//! Client side EHTDH1 sealing and ciphertext proof checks.

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};
use golden_core::{GoldenGroup, GoldenHashToGroup, GoldenScalar};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::context::{hash_to_nonzero_scalar, Error, Transcript};

/// Public key used to seal EHTDH1 messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealingKey<G: GoldenHashToGroup> {
    joint_public_key: G::Element,
}

impl<G: GoldenHashToGroup> SealingKey<G> {
    /// Construct from the Golden DKG joint public key `X`.
    pub fn new(joint_public_key: G::Element) -> Result<Self, Error> {
        if bool::from(G::is_identity(&joint_public_key)) {
            return Err(Error::InvalidJointPublicKey);
        }
        Ok(Self { joint_public_key })
    }

    /// Return the joint public key.
    pub fn joint_public_key(&self) -> &G::Element {
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

    /// Seal bytes with associated data.
    pub fn seal_bytes_with_associated_data<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Ciphertext<G>, Error> {
        let r = random_nonzero_scalar::<G, _>(rng);
        let r_prime = random_nonzero_scalar::<G, _>(rng);
        let ephemeral_public = G::mul_generator(&r);
        let dh_point = G::mul(&self.joint_public_key, &r);
        let mut encrypted_payload = plaintext.to_vec();
        apply_payload_mask::<G>(&mut encrypted_payload, &ephemeral_public, &dh_point)?;

        let proof_commitment = G::mul_generator(&r_prime);
        let encryption_group = encryption_group::<G>(
            &ephemeral_public,
            &proof_commitment,
            associated_data,
            &encrypted_payload,
        )?;
        let encryption_point = G::mul(&encryption_group, &r);
        let encryption_commitment = G::mul(&encryption_group, &r_prime);
        let challenge = encryption_challenge::<G>(
            &encryption_group,
            &encryption_point,
            &encryption_commitment,
        )?;
        let response = r_prime.add(&r.mul(&challenge));

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

/// EHTDH1 ciphertext and proof data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext<G: GoldenHashToGroup> {
    /// Associated data `ad`.
    pub associated_data: Vec<u8>,
    /// Masked payload `c`.
    pub encrypted_payload: Vec<u8>,
    /// `R = rG`.
    pub ephemeral_public: G::Element,
    /// `V = rY`.
    pub encryption_point: G::Element,
    /// `e = Hecd(Y, V, V')`.
    pub challenge: G::Scalar,
    /// `r'' = r' + re`.
    pub response: G::Scalar,
}

impl<G: GoldenHashToGroup> Ciphertext<G> {
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

pub(crate) fn verify_ciphertext<G: GoldenHashToGroup>(
    message: &Ciphertext<G>,
) -> Result<(), Error> {
    if bool::from(G::is_identity(&message.ephemeral_public))
        || bool::from(G::is_identity(&message.encryption_point))
    {
        return Err(Error::InvalidCiphertextProof);
    }

    let proof_commitment = G::sub(
        &G::mul_generator(&message.response),
        &G::mul(&message.ephemeral_public, &message.challenge),
    );
    let encryption_group = encryption_group::<G>(
        &message.ephemeral_public,
        &proof_commitment,
        &message.associated_data,
        &message.encrypted_payload,
    )?;
    let encryption_commitment = G::sub(
        &G::mul(&encryption_group, &message.response),
        &G::mul(&message.encryption_point, &message.challenge),
    );
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

pub(crate) fn encryption_group<G: GoldenHashToGroup>(
    ephemeral_public: &G::Element,
    proof_commitment: &G::Element,
    associated_data: &[u8],
    encrypted_payload: &[u8],
) -> Result<G::Element, Error> {
    let mut transcript = Transcript::new(b"golden-ehtdh1-hegd-v1");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.element::<G>(b"R", ephemeral_public);
    transcript.element::<G>(b"R-prime", proof_commitment);
    transcript.bytes(b"ad", associated_data);
    transcript.bytes(b"ciphertext", encrypted_payload);
    G::hash_to_group(b"golden-ehtdh1-hegd-v1", &transcript.root())
        .map_err(|_| Error::InvalidEncoding)
}

pub(crate) fn encryption_challenge<G: GoldenGroup>(
    encryption_group: &G::Element,
    encryption_point: &G::Element,
    encryption_commitment: &G::Element,
) -> Result<G::Scalar, Error> {
    let mut transcript = Transcript::new(b"golden-ehtdh1-hecd-v1");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.element::<G>(b"Y", encryption_group);
    transcript.element::<G>(b"V", encryption_point);
    transcript.element::<G>(b"V-prime", encryption_commitment);
    hash_to_nonzero_scalar::<G>(b"golden-ehtdh1-hecd-v1", &transcript.root())
}

pub(crate) fn apply_payload_mask<G: GoldenGroup>(
    target: &mut [u8],
    ephemeral_public: &G::Element,
    dh_point: &G::Element,
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

fn derive_payload_mask_material<G: GoldenGroup, const N: usize>(
    ephemeral_public: &G::Element,
    dh_point: &G::Element,
) -> Result<Zeroizing<[u8; N]>, Error> {
    let mut transcript = Transcript::new(b"golden-ehtdh1-hkd-ikm-v1");
    transcript.bytes(b"backend", G::BACKEND_ID.as_bytes());
    transcript.element::<G>(b"R", ephemeral_public);
    transcript.element::<G>(b"U", dh_point);
    let hkdf = Hkdf::<Sha256>::new(Some(b"golden-ehtdh1-hkd-v1"), &transcript.root());
    let mut material = Zeroizing::new([0u8; N]);
    hkdf.expand(b"golden-ehtdh1-xchacha20-mask-v1", material.as_mut())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok(material)
}

pub(crate) fn random_nonzero_scalar<G: GoldenGroup, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G::Scalar {
    loop {
        let scalar = G::Scalar::random(rng);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}
