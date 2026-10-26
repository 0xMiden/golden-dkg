//! Canonical byte encoding for EHTDH1 values.
//!
//! Standalone values use an independent versioned EHTDH1 envelope.
//! Generic group values bind the protocol group id in that envelope.
//! [`SecretShare`] is the encoded validator secret held by [`crate::UnsealingShare`].
//! Tags identify the supported online and setup values.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use core::marker::PhantomData;
use golden_core::{DkgGroup, Error as CoreError, ParticipantIndex, SessionId, TranscriptRoot};
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

use crate::codec::{self as wire, WireReader};
pub use crate::codec::{WireDecode, WireEncode, WireMessage};

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

/// Maximum encoded group id length.
pub const MAX_GROUP_ID_BYTES: usize = 255;
/// Maximum participant count in an encoded setup or public key set.
pub const MAX_PARTICIPANTS: usize = 1 << 20;
/// Maximum length of either byte field in an encoded [`Ciphertext`].
pub const MAX_CIPHERTEXT_FIELD_BYTES: usize = 1 << 30;

/// Return a standalone canonical EHTDH1 wire value.
pub fn to_wire_bytes<T: WireMessage>(value: &T) -> Vec<u8> {
    wire::to_wire_bytes(value)
}

/// Decode a standalone canonical EHTDH1 wire value.
///
/// All decoding failures are reported as [`Error::InvalidEncoding`].
pub fn from_wire_bytes<T: WireMessage>(bytes: &[u8]) -> Result<T, Error> {
    wire::from_wire_bytes(bytes).map_err(|_| Error::InvalidEncoding)
}

impl WireEncode for SetupContext {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_context_field(out, self.group_id.as_bytes());
        wire::write_len(out, self.threshold);
        wire::write_len(out, self.participants.len());
        for participant in &self.participants {
            participant.write_wire(out);
        }
        self.session_id.write_wire(out);
        self.config_root.write_wire(out);
        self.completion_root.write_wire(out);
        out.extend_from_slice(&self.epoch);
    }
}
impl WireDecode for SetupContext {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        let group_len = wire::read_len(reader)?;
        if group_len == 0 || group_len > MAX_GROUP_ID_BYTES {
            return Err(CoreError::InvalidEncoding);
        }
        let group_id = core::str::from_utf8(reader.take(group_len)?)
            .map_err(|_| CoreError::InvalidEncoding)?
            .to_owned();
        let threshold = wire::read_len(reader)?;
        let count = wire::read_len(reader)?;
        if count > MAX_PARTICIPANTS {
            return Err(CoreError::InvalidEncoding);
        }
        reader.ensure_items(count, 4)?;
        let participants = read_participants(reader, count)?;
        if threshold == 0 || threshold > count {
            return Err(CoreError::InvalidEncoding);
        }
        Ok(Self {
            group_id,
            threshold,
            participants,
            session_id: SessionId::read_wire(reader)?,
            config_root: TranscriptRoot::read_wire(reader)?,
            completion_root: TranscriptRoot::read_wire(reader)?,
            epoch: reader.array()?,
        })
    }
}
impl WireMessage for SetupContext {
    const TAG: u8 = TAG_SETUP_CONTEXT;
    const CODEC_ID: &'static str = "ehtdh1-setup-context-v2";
}

impl<G: DkgGroup> WireEncode for PublicShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_element::<G>(out, &self.decryption);
        wire::write_element::<G>(out, &self.context);
    }
}

impl<G: DkgGroup> WireDecode for PublicShare<G> {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Ok(Self {
            decryption: wire::read_element::<G>(reader)?,
            context: wire::read_element::<G>(reader)?,
        })
    }
}

impl<G: DkgGroup> WireMessage for PublicShare<G> {
    const TAG: u8 = TAG_PUBLIC_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-public-share-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: DkgGroup> WireEncode for SecretShare<G> {
    fn wire_size_hint(&self) -> usize {
        4 + 32 + 32
    }
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.participant.write_wire(out);
        let decryption = zeroize::Zeroizing::new(G::encode_scalar(self.decryption()));
        let context = zeroize::Zeroizing::new(G::encode_scalar(self.context()));
        out.extend_from_slice(&*decryption);
        out.extend_from_slice(&*context);
    }
}

impl<G: DkgGroup> WireDecode for SecretShare<G> {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        let participant = ParticipantIndex::read_wire(reader)?;
        let x = crate::secret::secret(wire::read_scalar::<G>(reader)?);
        let z = crate::secret::secret(wire::read_scalar::<G>(reader)?);
        Ok(Self::new(participant, x.expose(), z.expose()))
    }
}

impl<G: DkgGroup> WireMessage for SecretShare<G> {
    const TAG: u8 = TAG_SECRET_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-secret-share-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: DkgGroup> WireEncode for PublicKeySet<G> {
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

impl<G: DkgGroup> WireDecode for PublicKeySet<G> {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        let threshold = wire::read_len(reader)?;
        let joint_public_key = wire::read_element::<G>(reader)?;
        let participant_count = wire::read_len(reader)?;
        if participant_count > MAX_PARTICIPANTS {
            return Err(CoreError::InvalidEncoding);
        }
        let entry_bytes = G::POINT_BYTES
            .checked_mul(2)
            .and_then(|size| size.checked_add(4))
            .ok_or(CoreError::InvalidEncoding)?;
        reader.ensure_items(participant_count, entry_bytes)?;
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

impl<G: DkgGroup> WireMessage for PublicKeySet<G> {
    const TAG: u8 = TAG_PUBLIC_KEY_SET;
    const CODEC_ID: &'static str = "ehtdh1-public-key-set-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: DkgGroup> WireEncode for SealingKey<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        wire::write_element::<G>(out, self.joint_public_key());
    }
}

impl<G: DkgGroup> WireDecode for SealingKey<G> {
    fn read_wire(reader: &mut WireReader<'_>) -> golden_core::Result<Self> {
        Self::new(wire::read_element::<G>(reader)?).map_err(|_| CoreError::InvalidEncoding)
    }
}

impl<G: DkgGroup> WireMessage for SealingKey<G> {
    const TAG: u8 = TAG_SEALING_KEY;
    const CODEC_ID: &'static str = "ehtdh1-sealing-key-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: DkgGroup> WireEncode for Ciphertext<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_bytes(out, &self.associated_data);
        write_bytes(out, &self.encrypted_payload);
        wire::write_element::<G>(out, &self.ephemeral_public);
        wire::write_element::<G>(out, &self.encryption_point);
        wire::write_scalar::<G>(out, &self.challenge);
        wire::write_scalar::<G>(out, &self.response);
    }
}

impl<G: DkgGroup> WireDecode for Ciphertext<G> {
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

impl<G: DkgGroup> WireMessage for Ciphertext<G> {
    const TAG: u8 = TAG_CIPHERTEXT;
    const CODEC_ID: &'static str = "ehtdh1-ciphertext-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

impl<G: DkgGroup> WireEncode for DecryptionShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.participant.write_wire(out);
        wire::write_element::<G>(out, &self.share);
        wire::write_scalar::<G>(out, &self.challenge);
        wire::write_scalar::<G>(out, &self.decryption_response);
        wire::write_scalar::<G>(out, &self.context_response);
    }
}

impl<G: DkgGroup> WireDecode for DecryptionShare<G> {
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

impl<G: DkgGroup> WireMessage for DecryptionShare<G> {
    const TAG: u8 = TAG_DECRYPTION_SHARE;
    const CODEC_ID: &'static str = "ehtdh1-decryption-share-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_group_context::<G, Self>(out);
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> golden_core::Result<()> {
        read_group_context::<G, Self>(reader)
    }
}

fn write_group_context<G: DkgGroup, T: WireMessage>(out: &mut Vec<u8>) {
    wire::write_context_field(out, T::CODEC_ID.as_bytes());
    wire::write_context_field(out, G::GROUP_ID.as_bytes());
}

fn read_group_context<G: DkgGroup, T: WireMessage>(
    reader: &mut WireReader<'_>,
) -> golden_core::Result<()> {
    wire::expect_context_field(reader, T::CODEC_ID.as_bytes())?;
    wire::expect_context_field(reader, G::GROUP_ID.as_bytes())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    wire::write_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn read_bytes(reader: &mut WireReader<'_>) -> golden_core::Result<Vec<u8>> {
    let len = wire::read_len(reader)?;
    if len > MAX_CIPHERTEXT_FIELD_BYTES {
        return Err(CoreError::InvalidEncoding);
    }
    Ok(reader.take(len)?.to_vec())
}

fn read_participants(
    reader: &mut WireReader<'_>,
    len: usize,
) -> golden_core::Result<Vec<ParticipantIndex>> {
    let mut participants = golden_core::wire::reserve(len)?;
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
impl<G: DkgGroup> Serializable for SecretShare<G> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        wire::write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        wire::miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G: DkgGroup> Deserializable for SecretShare<G> {
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
impl_miden_group_wire!(PublicShare, DkgGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(PublicKeySet, DkgGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(SealingKey, DkgGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(Ciphertext, DkgGroup);
#[cfg(feature = "miden-serde")]
impl_miden_group_wire!(DecryptionShare, DkgGroup);

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
impl<G: DkgGroup> Serialize for SecretShare<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: DkgGroup> Deserialize<'de> for SecretShare<G> {
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
impl_serde_group_wire!(PublicShare, DkgGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(PublicKeySet, DkgGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(SealingKey, DkgGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(Ciphertext, DkgGroup);
#[cfg(feature = "serde")]
impl_serde_group_wire!(DecryptionShare, DkgGroup);

#[cfg(feature = "serde")]
fn serialize_wire<T, S>(value: &T, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    T: WireMessage,
    S: Serializer,
{
    let bytes = zeroize::Zeroizing::new(wire::to_wire_bytes(value));
    serializer.serialize_bytes(&bytes)
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
        let bytes = zeroize::Zeroizing::new(bytes);
        wire::from_wire_bytes(&bytes).map_err(|error| E::custom(error.to_string()))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> core::result::Result<Self::Value, A::Error> {
        let mut bytes = zeroize::Zeroizing::new(
            golden_core::wire::reserve(sequence.size_hint().unwrap_or(256))
                .map_err(de::Error::custom)?,
        );
        while let Some(byte) = sequence.next_element::<u8>()? {
            if bytes.len() == bytes.capacity() {
                let capacity = bytes
                    .capacity()
                    .max(1)
                    .checked_mul(2)
                    .ok_or_else(|| de::Error::custom("EHTDH1 wire size overflow"))?;
                let mut next = zeroize::Zeroizing::new(
                    golden_core::wire::reserve(capacity).map_err(de::Error::custom)?,
                );
                next.extend_from_slice(&bytes);
                bytes = next;
            }
            bytes.push(byte);
        }
        wire::from_wire_bytes(&bytes).map_err(|error| de::Error::custom(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnsealingShare;
    use golden_curves::{JubjubGroup, Secp256k1Group};
    use group::Group;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use zeroize::Zeroizing;

    struct Fixtures<G: DkgGroup> {
        setup: SetupContext,
        public: PublicKeySet<G>,
        public_share: PublicShare<G>,
        secret: SecretShare<G>,
        key: SealingKey<G>,
        message: Ciphertext<G>,
        share: DecryptionShare<G>,
    }
    fn fixtures<G: DkgGroup>() -> Fixtures<G> {
        let crate::tests::Material {
            key,
            public,
            secrets,
            setup,
        } = crate::tests::material::<G>();
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let message = key
            .seal_bytes_with_associated_data(&mut rng, b"payload", b"associated")
            .unwrap();
        let secret = secrets[0].clone();
        let share = UnsealingShare::new(secret.clone())
            .decrypt_share(&mut rng, &setup, &message, b"request")
            .unwrap();
        let public_share = public.public_share(secret.participant()).unwrap().clone();
        Fixtures {
            setup,
            public,
            public_share,
            secret,
            key,
            message,
            share,
        }
    }
    fn roundtrip<T: WireMessage>(value: &T) {
        let bytes = Zeroizing::new(to_wire_bytes(value));
        let restored = from_wire_bytes::<T>(&bytes).unwrap();
        let canonical = Zeroizing::new(to_wire_bytes(&restored));
        assert_eq!(*canonical, *bytes);
    }
    fn payload_offset<T: WireMessage>() -> usize {
        let mut prefix = Vec::new();
        wire::write_context_field(&mut prefix, wire::MAGIC);
        prefix.push(T::TAG);
        T::write_wire_context(&mut prefix);
        prefix.len() + 8
    }
    fn group_offset<T: WireMessage>() -> usize {
        8 + wire::MAGIC.len() + 1 + 8 + T::CODEC_ID.len() + 8
    }
    fn roundtrip_values<G: DkgGroup>() {
        let values = fixtures::<G>();
        roundtrip(&values.setup);
        roundtrip(&values.public);
        roundtrip(&values.public_share);
        roundtrip(&values.secret);
        roundtrip(&values.key);
        roundtrip(&values.message);
        roundtrip(&values.share);
        let restored = from_wire_bytes::<SecretShare<G>>(&to_wire_bytes(&values.secret)).unwrap();
        assert_eq!(restored.participant(), values.secret.participant());
        assert_eq!(restored.decryption(), values.secret.decryption());
        assert_eq!(restored.context(), values.secret.context());
        crate::Combiner::new(
            from_wire_bytes::<PublicKeySet<G>>(&to_wire_bytes(&values.public)).unwrap(),
            from_wire_bytes::<SetupContext>(&to_wire_bytes(&values.setup)).unwrap(),
        )
        .unwrap();
    }
    fn malformed_envelopes<G: DkgGroup>() {
        let values = fixtures::<G>();
        let bytes = to_wire_bytes(&values.setup);
        let mut variants = Vec::new();
        let mut changed = bytes.clone();
        changed[8] ^= 1;
        variants.push(changed);
        let mut changed = bytes.clone();
        changed[8 + wire::MAGIC.len()] = TAG_CIPHERTEXT;
        variants.push(changed);
        let mut changed = bytes.clone();
        changed.push(0);
        variants.push(changed);
        variants.push(bytes[..bytes.len() - 1].to_vec());
        for changed in variants {
            assert_eq!(
                from_wire_bytes::<SetupContext>(&changed),
                Err(Error::InvalidEncoding)
            );
        }
        let mut bytes = to_wire_bytes(&values.key);
        bytes[group_offset::<SealingKey<G>>()] ^= 1;
        assert!(from_wire_bytes::<SealingKey<G>>(&bytes).is_err());
        let mut bytes = to_wire_bytes(&values.message);
        let offset = payload_offset::<Ciphertext<G>>();
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(from_wire_bytes::<Ciphertext<G>>(&bytes).is_err());
    }
    fn malformed_values<G: DkgGroup>() {
        let values = fixtures::<G>();
        let mut bytes = Zeroizing::new(to_wire_bytes(&values.secret));
        let offset = payload_offset::<SecretShare<G>>() + 4;
        bytes[offset..offset + 32].fill(0xff);
        assert!(from_wire_bytes::<SecretShare<G>>(&bytes).is_err());
        let mut bytes = to_wire_bytes(&values.public_share);
        let offset = payload_offset::<PublicShare<G>>();
        bytes[offset..offset + G::POINT_BYTES].fill(0xff);
        assert!(from_wire_bytes::<PublicShare<G>>(&bytes).is_err());
        let mut bytes = to_wire_bytes(&values.key);
        let offset = payload_offset::<SealingKey<G>>();
        bytes[offset..offset + G::POINT_BYTES]
            .copy_from_slice(&G::encode_point(&G::Point::identity()));
        assert!(from_wire_bytes::<SealingKey<G>>(&bytes).is_err());
        let mut bytes = to_wire_bytes(&values.setup);
        let offset = payload_offset::<SetupContext>() + 8 + G::GROUP_ID.len() + 8 + 8;
        let first: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        let second: [u8; 4] = bytes[offset + 4..offset + 8].try_into().unwrap();
        bytes[offset..offset + 4].copy_from_slice(&second);
        bytes[offset + 4..offset + 8].copy_from_slice(&first);
        assert!(from_wire_bytes::<SetupContext>(&bytes).is_err());
        // Canonical point bytes can still describe an inconsistent key set.
        let mut bytes = to_wire_bytes(&values.public);
        let offset = payload_offset::<PublicKeySet<G>>()
            + 8
            + G::POINT_BYTES
            + 8
            + 2 * (4 + 2 * G::POINT_BYTES)
            + 4;
        bytes[offset..offset + G::POINT_BYTES]
            .copy_from_slice(&G::encode_point(&G::Point::generator()));
        assert!(from_wire_bytes::<PublicKeySet<G>>(&bytes).is_err());
    }
    #[cfg(feature = "miden-serde")]
    fn miden_roundtrip<
        T: WireMessage + miden_serde_utils::Serializable + miden_serde_utils::Deserializable,
    >(
        value: &T,
    ) {
        let bytes = Zeroizing::new(miden_serde_utils::Serializable::to_bytes(value));
        let canonical = Zeroizing::new(to_wire_bytes(value));
        assert!(bytes.ends_with(&canonical));
        let restored = T::read_from_bytes(&bytes).unwrap();
        assert_eq!(to_wire_bytes(&restored), *canonical);
    }
    #[cfg(feature = "miden-serde")]
    fn miden_values<G: DkgGroup>() {
        let values = fixtures::<G>();
        miden_roundtrip(&values.setup);
        miden_roundtrip(&values.public);
        miden_roundtrip(&values.public_share);
        miden_roundtrip(&values.secret);
        miden_roundtrip(&values.key);
        miden_roundtrip(&values.message);
        miden_roundtrip(&values.share);
    }
    #[cfg(feature = "serde")]
    fn serde_roundtrip<T: WireMessage + serde::Serialize + serde::de::DeserializeOwned>(value: &T) {
        let bytes = Zeroizing::new(postcard::to_allocvec(value).unwrap());
        let canonical = Zeroizing::new(to_wire_bytes(value));
        assert!(bytes.ends_with(&canonical));
        let restored: T = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(to_wire_bytes(&restored), *canonical);
    }
    #[cfg(feature = "serde")]
    fn serde_values<G: DkgGroup>() {
        let values = fixtures::<G>();
        serde_roundtrip(&values.setup);
        serde_roundtrip(&values.public);
        serde_roundtrip(&values.public_share);
        serde_roundtrip(&values.secret);
        serde_roundtrip(&values.key);
        serde_roundtrip(&values.message);
        serde_roundtrip(&values.share);
    }
    macro_rules! both {
        ($name:ident, $body:ident) => {
            #[test]
            fn $name() {
                $body::<Secp256k1Group>();
                $body::<JubjubGroup>();
            }
        };
    }
    both!(
        all_native_wire_values_roundtrip_canonically,
        roundtrip_values
    );
    both!(
        version_group_framing_and_bounds_are_checked,
        malformed_envelopes
    );
    both!(
        native_values_and_public_key_polynomials_are_validated,
        malformed_values
    );
    #[cfg(feature = "miden-serde")]
    both!(miden_adapters_preserve_the_canonical_bytes, miden_values);
    #[cfg(feature = "serde")]
    both!(serde_adapters_preserve_the_canonical_bytes, serde_values);
}
