//! Canonical byte encoding for EHTDH1 values.
//!
//! Standalone values use the Golden wire envelope from [`golden_core::wire`].
//! Generic group values bind the Golden backend id in that envelope.
//! [`SecretShare`] is the encoded validator secret held by [`crate::UnsealingShare`].

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use core::marker::PhantomData;
use golden_core::{
    wire::{self, WireReader},
    Error as CoreError, GoldenGroup, GoldenHashToGroup, ParticipantIndex, SessionId,
    TranscriptRoot,
};
#[cfg(feature = "miden-serde")]
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Ciphertext, DecryptionShare, Error, PublicKeySet, PublicShare, SealingKey, SecretShare,
    SetupContext,
};

pub use golden_core::wire::{WireDecode, WireEncode, WireMessage};

/// Standalone tag for [`SetupContext`].
pub const TAG_SETUP_CONTEXT: u8 = 0x20;
/// Standalone tag for [`PublicKeySet`].
pub const TAG_PUBLIC_KEY_SET: u8 = 0x21;
/// Standalone tag for [`PublicShare`].
pub const TAG_PUBLIC_SHARE: u8 = 0x22;
/// Standalone tag for [`SecretShare`].
pub const TAG_SECRET_SHARE: u8 = 0x23;
/// Standalone tag for [`SealingKey`].
pub const TAG_SEALING_KEY: u8 = 0x24;
/// Standalone tag for [`Ciphertext`].
pub const TAG_CIPHERTEXT: u8 = 0x25;
/// Standalone tag for [`DecryptionShare`].
pub const TAG_DECRYPTION_SHARE: u8 = 0x26;

/// Maximum encoded backend id length.
pub const MAX_BACKEND_ID_BYTES: usize = 255;
/// Maximum participant count in an encoded setup or public key set.
pub const MAX_PARTICIPANTS: usize = 1 << 20;
/// Maximum length of either byte field in an encoded [`Ciphertext`].
pub const MAX_CIPHERTEXT_FIELD_BYTES: usize = 1 << 30;

/// Return a standalone canonical EHTDH1 wire value.
pub fn to_wire_bytes<T: WireMessage>(value: &T) -> Vec<u8> {
    wire::to_wire_bytes(value)
}

/// Decode a standalone canonical EHTDH1 wire value.
pub fn from_wire_bytes<T: WireMessage>(bytes: &[u8]) -> Result<T, Error> {
    wire::from_wire_bytes(bytes).map_err(|_| Error::InvalidEncoding)
}

impl WireEncode for SetupContext {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_len(out, self.backend_id.len());
        out.extend_from_slice(self.backend_id.as_bytes());
        wire::write_len(out, self.threshold);
        self.registry_root.write_wire(out);
        wire::write_len(out, self.participants.len());
        for participant in &self.participants {
            participant.write_wire(out);
        }
        self.decryption_session_id.write_wire(out);
        self.context_session_id.write_wire(out);
        self.decryption_transcript_root.write_wire(out);
        self.context_transcript_root.write_wire(out);
        out.extend_from_slice(&self.epoch);
    }
}

impl WireDecode for SetupContext {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        let backend_len = reader.read_len()?;
        if backend_len == 0 || backend_len > MAX_BACKEND_ID_BYTES {
            return Err(CoreError::InvalidEncoding);
        }
        let backend_id = core::str::from_utf8(reader.read_exact(backend_len)?)
            .map_err(|_| CoreError::InvalidEncoding)?
            .to_owned();
        let threshold = reader.read_len()?;
        let registry_root = TranscriptRoot::read_wire(reader)?;
        let participant_count = reader.read_len()?;
        if participant_count > MAX_PARTICIPANTS {
            return Err(CoreError::InvalidEncoding);
        }
        reader.ensure_remaining_items(participant_count, 4)?;
        let participants = read_participants(reader, participant_count)?;
        if threshold == 0 || threshold > participants.len() {
            return Err(CoreError::InvalidEncoding);
        }
        Ok(Self {
            backend_id,
            threshold,
            registry_root,
            participants,
            decryption_session_id: SessionId::read_wire(reader)?,
            context_session_id: SessionId::read_wire(reader)?,
            decryption_transcript_root: TranscriptRoot::read_wire(reader)?,
            context_transcript_root: TranscriptRoot::read_wire(reader)?,
            epoch: reader.read_array()?,
        })
    }
}

impl WireMessage for SetupContext {
    const TAG: u8 = TAG_SETUP_CONTEXT;
    const CODEC_ID: &'static str = "ehtdh1-setup-context-v1";
}

impl<G: GoldenGroup> WireEncode for PublicShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_element::<G>(out, &self.decryption);
        wire::write_element::<G>(out, &self.context);
    }
}

impl<G> WireDecode for PublicShare<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Ok(Self {
            decryption: wire::read_element::<G>(reader)?,
            context: wire::read_element::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for PublicShare<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_PUBLIC_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-public-share-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: GoldenGroup> WireEncode for SecretShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.participant.write_wire(out);
        wire::write_scalar::<G>(out, &self.decryption);
        wire::write_scalar::<G>(out, &self.context);
    }
}

impl<G: GoldenGroup> WireDecode for SecretShare<G> {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Ok(Self {
            participant: ParticipantIndex::read_wire(reader)?,
            decryption: wire::read_scalar::<G>(reader)?,
            context: wire::read_scalar::<G>(reader)?,
        })
    }
}

impl<G: GoldenGroup> WireMessage for SecretShare<G> {
    const TAG: u8 = TAG_SECRET_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-secret-share-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: GoldenGroup> WireEncode for PublicKeySet<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_len(out, self.threshold);
        wire::write_element::<G>(out, &self.joint_public_key);
        wire::write_len(out, self.public_shares.len());
        for (participant, share) in &self.public_shares {
            participant.write_wire(out);
            share.write_wire(out);
        }
    }
}

impl<G> WireDecode for PublicKeySet<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        let threshold = reader.read_len()?;
        let joint_public_key = wire::read_element::<G>(reader)?;
        let participant_count = reader.read_len()?;
        if participant_count > MAX_PARTICIPANTS {
            return Err(CoreError::InvalidEncoding);
        }
        let entry_bytes = 4 + 2 * G::ELEMENT_REPR_BYTES;
        reader.ensure_remaining_items(participant_count, entry_bytes)?;
        let mut public_shares = BTreeMap::new();
        let mut previous = None;
        for _ in 0..participant_count {
            let participant = ParticipantIndex::read_wire(reader)?;
            ensure_increasing(&mut previous, participant)?;
            public_shares.insert(participant, PublicShare::<G>::read_wire(reader)?);
        }
        PublicKeySet::new(threshold, joint_public_key, public_shares)
            .map_err(|_| CoreError::InvalidEncoding)
    }
}

impl<G> WireMessage for PublicKeySet<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_PUBLIC_KEY_SET;
    const CODEC_ID: &'static str = "ehtdh1-public-key-set-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: GoldenHashToGroup> WireEncode for SealingKey<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_element::<G>(out, self.joint_public_key());
    }
}

impl<G> WireDecode for SealingKey<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Self::new(wire::read_element::<G>(reader)?).map_err(|_| CoreError::InvalidEncoding)
    }
}

impl<G> WireMessage for SealingKey<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_SEALING_KEY;
    const CODEC_ID: &'static str = "ehtdh1-sealing-key-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: GoldenHashToGroup> WireEncode for Ciphertext<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_bytes(out, &self.associated_data);
        write_bytes(out, &self.encrypted_payload);
        wire::write_element::<G>(out, &self.ephemeral_public);
        wire::write_element::<G>(out, &self.encryption_point);
        wire::write_scalar::<G>(out, &self.challenge);
        wire::write_scalar::<G>(out, &self.response);
    }
}

impl<G> WireDecode for Ciphertext<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Ok(Self {
            associated_data: read_bytes(reader)?,
            encrypted_payload: read_bytes(reader)?,
            ephemeral_public: wire::read_element::<G>(reader)?,
            encryption_point: wire::read_element::<G>(reader)?,
            challenge: wire::read_scalar::<G>(reader)?,
            response: wire::read_scalar::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for Ciphertext<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_CIPHERTEXT;
    const CODEC_ID: &'static str = "ehtdh1-ciphertext-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: GoldenHashToGroup> WireEncode for DecryptionShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.participant.write_wire(out);
        wire::write_element::<G>(out, &self.share);
        wire::write_scalar::<G>(out, &self.challenge);
        wire::write_scalar::<G>(out, &self.decryption_response);
        wire::write_scalar::<G>(out, &self.context_response);
    }
}

impl<G> WireDecode for DecryptionShare<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Ok(Self {
            participant: ParticipantIndex::read_wire(reader)?,
            share: wire::read_element::<G>(reader)?,
            challenge: wire::read_scalar::<G>(reader)?,
            decryption_response: wire::read_scalar::<G>(reader)?,
            context_response: wire::read_scalar::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for DecryptionShare<G>
where
    G: GoldenHashToGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_DECRYPTION_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-decryption-share-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

fn write_group_context<G: GoldenGroup, T: WireMessage>(out: &mut Vec<u8>) {
    wire::write_context_field(out, T::CODEC_ID.as_bytes());
    wire::write_context_field(out, G::BACKEND_ID.as_bytes());
}

fn read_group_context<G: GoldenGroup, T: WireMessage>(
    reader: &mut WireReader<'_>,
) -> golden_core::Result<()> {
    wire::expect_context_field(reader, T::CODEC_ID.as_bytes())?;
    wire::expect_context_field(reader, G::BACKEND_ID.as_bytes())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    wire::write_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn read_bytes(reader: &mut WireReader<'_>) -> golden_core::Result<Vec<u8>> {
    let len = reader.read_len()?;
    if len > MAX_CIPHERTEXT_FIELD_BYTES {
        return Err(CoreError::InvalidEncoding);
    }
    Ok(reader.read_exact(len)?.to_vec())
}

fn read_participants(
    reader: &mut WireReader<'_>,
    len: usize,
) -> golden_core::Result<Vec<ParticipantIndex>> {
    let mut participants = Vec::with_capacity(len);
    let mut previous = None;
    for _ in 0..len {
        let participant = ParticipantIndex::read_wire(reader)?;
        ensure_increasing(&mut previous, participant)?;
        participants.push(participant);
    }
    Ok(participants)
}

fn ensure_increasing(
    previous: &mut Option<ParticipantIndex>,
    next: ParticipantIndex,
) -> golden_core::Result<()> {
    if previous.is_some_and(|value| value >= next) {
        return Err(CoreError::InvalidEncoding);
    }
    *previous = Some(next);
    Ok(())
}

#[cfg(feature = "miden-serde")]
impl Serializable for SetupContext {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        wire::write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        wire::miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for SetupContext {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        wire::read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G: GoldenGroup> Serializable for SecretShare<G> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        wire::write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        wire::miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G: GoldenGroup> Deserializable for SecretShare<G> {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        wire::read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
macro_rules! impl_miden_group_wire {
    ($type:ident, $group_trait:path) => {
        impl<G> Serializable for $type<G>
        where
            G: $group_trait,
            G::ElementRepr: TryFrom<Vec<u8>>,
        {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                wire::write_miden_wire(self, target);
            }

            fn get_size_hint(&self) -> usize {
                wire::miden_wire_size_hint(self)
            }
        }

        impl<G> Deserializable for $type<G>
        where
            G: $group_trait,
            G::ElementRepr: TryFrom<Vec<u8>>,
        {
            fn read_from<R: ByteReader>(
                source: &mut R,
            ) -> core::result::Result<Self, DeserializationError> {
                wire::read_miden_wire(source)
            }
        }
    };
}

#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(PublicShare, GoldenGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(PublicKeySet, GoldenGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(SealingKey, GoldenHashToGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(Ciphertext, GoldenHashToGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(DecryptionShare, GoldenHashToGroup);

#[cfg(feature = "serde")]
impl Serialize for SetupContext {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SetupContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for SecretShare<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for SecretShare<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
macro_rules! impl_serde_group_wire {
    ($type:ident, $group_trait:path) => {
        impl<G> Serialize for $type<G>
        where
            G: $group_trait,
            G::ElementRepr: TryFrom<Vec<u8>>,
        {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                serialize_wire(self, serializer)
            }
        }

        impl<'de, G> Deserialize<'de> for $type<G>
        where
            G: $group_trait,
            G::ElementRepr: TryFrom<Vec<u8>>,
        {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                deserialize_wire(deserializer)
            }
        }
    };
}

#[cfg(feature = "serde")]
impl_serde_group_wire!(PublicShare, GoldenGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(PublicKeySet, GoldenGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(SealingKey, GoldenHashToGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(Ciphertext, GoldenHashToGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(DecryptionShare, GoldenHashToGroup);

#[cfg(feature = "serde")]
fn serialize_wire<T, S>(value: &T, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    T: WireMessage,
    S: Serializer,
{
    serializer.serialize_bytes(&wire::to_wire_bytes(value))
}

#[cfg(feature = "serde")]
fn deserialize_wire<'de, T, D>(deserializer: D) -> core::result::Result<T, D::Error>
where
    T: WireMessage,
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(WireBytesVisitor::<T>(PhantomData))
}

#[cfg(feature = "serde")]
struct WireBytesVisitor<T>(PhantomData<T>);

#[cfg(feature = "serde")]
impl<'de, T: WireMessage> de::Visitor<'de> for WireBytesVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("canonical Golden EHTDH1 wire bytes")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> core::result::Result<Self::Value, E> {
        wire::from_wire_bytes(bytes).map_err(|error| E::custom(error.to_string()))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> core::result::Result<Self::Value, E> {
        wire::from_wire_bytes(&bytes).map_err(|error| E::custom(error.to_string()))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> core::result::Result<Self::Value, A::Error> {
        let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(byte) = sequence.next_element()? {
            bytes.push(byte);
        }
        wire::from_wire_bytes(&bytes).map_err(|error| de::Error::custom(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use golden_core::{wire::MAGIC, GoldenScalar};
    use golden_rustcrypto::{P256Backend, P256Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use crate::{derive_context_session_id, UnsealingShare};

    type G = P256Backend;

    struct Fixtures {
        setup_context: SetupContext,
        public_key_set: PublicKeySet<G>,
        public_share: PublicShare<G>,
        secret_share: SecretShare<G>,
        sealing_key: SealingKey<G>,
        ciphertext: Ciphertext<G>,
        decryption_share: DecryptionShare<G>,
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> P256Scalar {
        P256Scalar::from_u64(value).unwrap()
    }

    fn fixtures() -> Fixtures {
        let participants = [idx(1), idx(2), idx(3)];
        let decryption_secret = scalar(11);
        let decryption_coefficient = scalar(7);
        let context_coefficient = scalar(13);
        let mut public_shares = BTreeMap::new();
        let mut secret_shares = Vec::new();

        for participant in participants {
            let participant_scalar = participant.to_scalar::<P256Scalar>().unwrap();
            let decryption =
                decryption_secret.add(&decryption_coefficient.mul(&participant_scalar));
            let context = context_coefficient.mul(&participant_scalar);
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
        let public_key_set = PublicKeySet::new(2, joint_public_key, public_shares).unwrap();
        let sealing_key = SealingKey::new(joint_public_key).unwrap();
        let decryption_session_id = SessionId([2u8; 32]);
        let setup_context = SetupContext {
            backend_id: G::BACKEND_ID.to_owned(),
            threshold: 2,
            registry_root: [1u8; 32],
            participants: participants.to_vec(),
            decryption_session_id,
            context_session_id: derive_context_session_id(decryption_session_id),
            decryption_transcript_root: [3u8; 32],
            context_transcript_root: [4u8; 32],
            epoch: [5u8; 32],
        };
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let ciphertext = sealing_key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"associated")
            .unwrap();
        let secret_share = secret_shares.remove(0);
        let decryption_share = UnsealingShare::new(secret_share.clone())
            .decrypt_share(&mut rng, &setup_context, &ciphertext, b"request")
            .unwrap();
        let public_share = public_key_set
            .public_share(secret_share.participant)
            .unwrap()
            .clone();

        Fixtures {
            setup_context,
            public_key_set,
            public_share,
            secret_share,
            sealing_key,
            ciphertext,
            decryption_share,
        }
    }

    fn payload_offset<T: WireMessage>() -> usize {
        let mut prefix = MAGIC.to_vec();
        prefix.push(T::TAG);
        T::write_wire_context(&mut prefix);
        prefix.len()
    }

    #[test]
    fn scoped_values_round_trip() {
        let values = fixtures();

        assert_eq!(
            from_wire_bytes::<SetupContext>(&to_wire_bytes(&values.setup_context)).unwrap(),
            values.setup_context
        );
        assert_eq!(
            from_wire_bytes::<PublicKeySet<G>>(&to_wire_bytes(&values.public_key_set)).unwrap(),
            values.public_key_set
        );
        assert_eq!(
            from_wire_bytes::<PublicShare<G>>(&to_wire_bytes(&values.public_share)).unwrap(),
            values.public_share
        );
        let secret =
            from_wire_bytes::<SecretShare<G>>(&to_wire_bytes(&values.secret_share)).unwrap();
        assert_eq!(secret.participant, values.secret_share.participant);
        assert_eq!(secret.decryption, values.secret_share.decryption);
        assert_eq!(secret.context, values.secret_share.context);
        assert_eq!(
            from_wire_bytes::<SealingKey<G>>(&to_wire_bytes(&values.sealing_key)).unwrap(),
            values.sealing_key
        );
        assert_eq!(
            from_wire_bytes::<Ciphertext<G>>(&to_wire_bytes(&values.ciphertext)).unwrap(),
            values.ciphertext
        );
        assert_eq!(
            from_wire_bytes::<DecryptionShare<G>>(&to_wire_bytes(&values.decryption_share))
                .unwrap(),
            values.decryption_share
        );
    }

    #[test]
    fn envelope_rejects_wrong_magic_tag_trailing_and_short_bytes() {
        let setup_context = fixtures().setup_context;
        let bytes = to_wire_bytes(&setup_context);

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert!(from_wire_bytes::<SetupContext>(&wrong_magic).is_err());

        let mut wrong_tag = bytes.clone();
        wrong_tag[MAGIC.len()] = TAG_CIPHERTEXT;
        assert!(from_wire_bytes::<SetupContext>(&wrong_tag).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(from_wire_bytes::<SetupContext>(&trailing).is_err());

        assert!(from_wire_bytes::<SetupContext>(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn secret_share_rejects_invalid_scalar() {
        let secret_share = fixtures().secret_share;
        let mut bytes = to_wire_bytes(&secret_share);
        let scalar_offset = payload_offset::<SecretShare<G>>() + 4;
        bytes[scalar_offset..scalar_offset + P256Scalar::REPR_BYTES]
            .copy_from_slice(P256Scalar::modulus().as_ref());

        assert!(from_wire_bytes::<SecretShare<G>>(&bytes).is_err());
    }

    #[test]
    fn public_share_rejects_invalid_group_element() {
        let public_share = fixtures().public_share;
        let mut bytes = to_wire_bytes(&public_share);
        let element_offset = payload_offset::<PublicShare<G>>();
        bytes[element_offset..element_offset + G::ELEMENT_REPR_BYTES].fill(0xff);

        assert!(from_wire_bytes::<PublicShare<G>>(&bytes).is_err());
    }

    #[test]
    fn setup_context_rejects_noncanonical_participant_order() {
        let setup_context = fixtures().setup_context;
        let mut bytes = to_wire_bytes(&setup_context);
        let participants_offset =
            payload_offset::<SetupContext>() + 8 + setup_context.backend_id.len() + 8 + 32 + 8;
        let first: [u8; 4] = bytes[participants_offset..participants_offset + 4]
            .try_into()
            .unwrap();
        let second: [u8; 4] = bytes[participants_offset + 4..participants_offset + 8]
            .try_into()
            .unwrap();
        bytes[participants_offset..participants_offset + 4].copy_from_slice(&second);
        bytes[participants_offset + 4..participants_offset + 8].copy_from_slice(&first);

        assert!(from_wire_bytes::<SetupContext>(&bytes).is_err());
    }

    #[test]
    fn ciphertext_rejects_oversize_byte_array_before_allocation() {
        let mut bytes = to_wire_bytes(&fixtures().ciphertext);
        bytes.truncate(payload_offset::<Ciphertext<G>>());
        bytes.extend_from_slice(&((MAX_CIPHERTEXT_FIELD_BYTES as u64) + 1).to_be_bytes());

        assert!(from_wire_bytes::<Ciphertext<G>>(&bytes).is_err());
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn miden_serde_uses_canonical_wire_bytes() {
        use miden_serde_utils::{Deserializable, Serializable};

        let values = fixtures();
        let setup_bytes = values.setup_context.to_bytes();
        assert!(setup_bytes.ends_with(&to_wire_bytes(&values.setup_context)));
        assert_eq!(
            SetupContext::read_from_bytes(&setup_bytes).unwrap(),
            values.setup_context
        );

        let ciphertext_bytes = values.ciphertext.to_bytes();
        assert!(ciphertext_bytes.ends_with(&to_wire_bytes(&values.ciphertext)));
        assert_eq!(
            Ciphertext::<G>::read_from_bytes(&ciphertext_bytes).unwrap(),
            values.ciphertext
        );

        let secret_bytes = values.secret_share.to_bytes();
        let secret = SecretShare::<G>::read_from_bytes(&secret_bytes).unwrap();
        assert_eq!(secret.participant, values.secret_share.participant);
        assert_eq!(secret.decryption, values.secret_share.decryption);
        assert_eq!(secret.context, values.secret_share.context);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_canonical_wire_bytes() {
        use serde_test::{assert_tokens, Token};

        let setup_context = fixtures().setup_context;
        let bytes: &'static [u8] = Box::leak(to_wire_bytes(&setup_context).into_boxed_slice());

        assert_tokens(&setup_context, &[Token::Bytes(bytes)]);
    }
}
