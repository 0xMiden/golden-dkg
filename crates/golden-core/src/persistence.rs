//! Application-owned contextual state snapshots, distinct from protocol broadcasts.
//!
//! Restoring outputs requires intact authenticated bytes with trusted completion
//! provenance. Structural validity and self-consistency do not establish a DKG
//! execution, agreement or activation. Replay a complete board for untrusted imports.
use crate::error::normalize_validation_error;
use crate::output::{self, DkgPublicInstance};
use crate::secret::{secret_vec, Wipeable};
use crate::wire::{count, framed, reserve, Reader};
use crate::{
    DkgConfig, DkgGroup, DkgInstanceKind, DkgOutput, DkgPublicOutput, Error, OwnDealing,
    ParticipantIndex, ParticipantRegistry, Result, SessionId, PROTOCOL_VERSION,
};
use core::{fmt, marker::PhantomData};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"golden-dkg-state";
const VERSION: u32 = 1;

fn envelope<G: DkgGroup>(tag: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let length = 8usize
        .checked_add(MAGIC.len())
        .and_then(|n| n.checked_add(4 + 1 + 8))
        .and_then(|n| n.checked_add(G::GROUP_ID.len()))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::ArithmeticOverflow)?;
    let mut bytes = Zeroizing::new(reserve(length)?);
    framed(&mut bytes, MAGIC)?;
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(tag);
    framed(&mut bytes, G::GROUP_ID.as_bytes())?;
    framed(&mut bytes, payload)?;
    Ok(bytes)
}
fn payload<G: DkgGroup>(tag: u8, bytes: &[u8]) -> Result<&[u8]> {
    let mut reader = Reader::new(bytes);
    if reader.framed()? != MAGIC
        || reader.u32()? != VERSION
        || reader.u8()? != tag
        || reader.framed()? != G::GROUP_ID.as_bytes()
    {
        return Err(Error::InvalidPersistedState);
    }
    let value = reader.framed()?;
    reader.finish()?;
    Ok(value)
}
fn transfer(mut bytes: Zeroizing<Vec<u8>>) -> Vec<u8> {
    core::mem::take(&mut *bytes)
}

impl<G: DkgGroup> DkgConfig<G> {
    /// Encode a configuration state envelope. Applications establish configuration agreement.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(transfer(envelope::<G>(1, self.canonical_bytes())?))
    }
    /// Restore a fully validated configuration and rederive its identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        restore_config::<G>(payload::<G>(1, bytes)?)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPersistedState))
    }
    /// Construct an explicit serializable configuration snapshot.
    pub fn snapshot(&self) -> Result<DkgConfigSnapshot<G>> {
        DkgConfigSnapshot::from_bytes(&self.to_bytes()?)
    }
}
fn restore_config<G: DkgGroup>(bytes: &[u8]) -> Result<DkgConfig<G>> {
    let mut reader = Reader::new(bytes);
    if reader.u32()? != PROTOCOL_VERSION || reader.framed()? != G::GROUP_ID.as_bytes() {
        return Err(Error::InvalidEncoding);
    }
    let threshold = reader.count()?;
    let session_id = SessionId(reader.array()?);
    let participants = reader.count()?;
    reader.ensure_items(
        participants,
        4usize
            .checked_add(G::POINT_BYTES)
            .ok_or(Error::ArithmeticOverflow)?,
    )?;
    let mut entries = reserve(participants)?;
    let mut previous = None;
    for _ in 0..participants {
        let participant = ParticipantIndex::new(reader.u32()?)?;
        if previous.is_some_and(|old| old >= participant) {
            return Err(Error::InvalidEncoding);
        }
        previous = Some(participant);
        entries.push((participant, G::decode_point(reader.take(G::POINT_BYTES)?)?));
    }
    let instance_count = reader.count()?;
    reader.ensure_items(instance_count, 1)?;
    let mut kinds = reserve(instance_count)?;
    for _ in 0..instance_count {
        kinds.push(DkgInstanceKind::from_tag(reader.u8()?)?);
    }
    reader.finish()?;
    DkgConfig::new(
        threshold,
        session_id,
        ParticipantRegistry::new(entries)?,
        kinds,
    )
}

impl<G: DkgGroup> OwnDealing<G> {
    /// Encode exact local broadcast/self shares. Returned bytes are application-owned secrets.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let size = 32usize
            .checked_add(4 + 8)
            .and_then(|n| n.checked_add(self.broadcast.len()))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| {
                self.private_shares
                    .len()
                    .checked_mul(32)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Error::ArithmeticOverflow)?;
        let mut value = Zeroizing::new(reserve(size)?);
        value.extend_from_slice(&self.config_root);
        value.extend_from_slice(&self.participant.get().to_be_bytes());
        framed(&mut value, &self.broadcast)?;
        count(&mut value, self.private_shares.len())?;
        for share in self.private_shares.iter() {
            let encoded = Zeroizing::new(G::encode_scalar(share.expose()));
            value.extend_from_slice(&*encoded);
        }
        Ok(transfer(envelope::<G>(2, &value)?))
    }
    /// Restore authenticated application-owned state against an expected local identity.
    /// No proof system is required: completion verifies the complete broadcast board again.
    pub fn from_bytes(
        config: &DkgConfig<G>,
        expected_participant: ParticipantIndex,
        bytes: &[u8],
    ) -> Result<Self> {
        restore_own(config, expected_participant, payload::<G>(2, bytes)?)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPersistedState))
    }
    /// Construct an explicit secret-bearing serializable snapshot.
    pub fn snapshot(&self) -> Result<OwnDealingSnapshot<G>> {
        let bytes = Zeroizing::new(self.to_bytes()?);
        OwnDealingSnapshot::from_bytes(&bytes)
    }
}
fn restore_own<G: DkgGroup>(
    config: &DkgConfig<G>,
    expected: ParticipantIndex,
    bytes: &[u8],
) -> Result<OwnDealing<G>> {
    let mut reader = Reader::new(bytes);
    if reader.array::<32>()? != config.root() || reader.u32()? != expected.get() {
        return Err(Error::InvalidPersistedState);
    }
    config.dealers().public_key(expected)?;
    let broadcast = reader.framed()?;
    let message = crate::dealer_message::parse(config, expected, broadcast)?;
    let count = reader.count()?;
    if count != config.instances().len() {
        return Err(Error::InvalidPersistedState);
    }
    reader.ensure_items(count, 32)?;
    let mut shares = secret_vec(count)?;
    for instance in &message.statement.instances {
        let share = crate::secret::secret(G::decode_scalar(reader.take(32)?)?);
        if G::mul_generator(share.expose())
            != crate::dealer_message::evaluate::<G>(&instance.coefficients, expected)
        {
            return Err(Error::InvalidPersistedState);
        }
        shares.push(Wipeable(*share.expose()));
    }
    reader.finish()?;
    let mut owned = Zeroizing::new(reserve(broadcast.len())?);
    owned.extend_from_slice(broadcast);
    Ok(OwnDealing {
        participant: expected,
        config_root: config.root(),
        broadcast: owned,
        private_shares: shares,
    })
}

impl<G: DkgGroup> DkgPublicOutput<G> {
    /// Encode public result state; this contains no execution/provenance certificate.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(transfer(envelope::<G>(
            3,
            &output::public_payload::<G>(self.config_root, &self.instances)?,
        )?))
    }
    /// Restore from intact authenticated bytes with trusted completion provenance.
    /// Untrusted imports must replay a complete dealer board instead.
    pub fn from_bytes(config: &DkgConfig<G>, bytes: &[u8]) -> Result<Self> {
        restore_public(config, payload::<G>(3, bytes)?)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPersistedState))
    }
    /// Explicit snapshot representation for contextual restoration.
    pub fn snapshot(&self) -> Result<DkgPublicOutputSnapshot<G>> {
        DkgPublicOutputSnapshot::from_bytes(&self.to_bytes()?)
    }
}
fn restore_public<G: DkgGroup>(config: &DkgConfig<G>, bytes: &[u8]) -> Result<DkgPublicOutput<G>> {
    let mut reader = Reader::new(bytes);
    if reader.array::<32>()? != config.root() || reader.count()? != config.instances().len() {
        return Err(Error::InvalidPersistedState);
    }
    let public_share_size = 4usize
        .checked_add(G::POINT_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    let minimum_instance = 4usize
        .checked_add(1)
        .and_then(|n| n.checked_add(G::POINT_BYTES))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| {
            config
                .registry()
                .len()
                .checked_mul(public_share_size)
                .and_then(|m| n.checked_add(m))
        })
        .ok_or(Error::ArithmeticOverflow)?;
    reader.ensure_items(config.instances().len(), minimum_instance)?;
    let mut instances = reserve(config.instances().len())?;
    for (position, kind) in config.instances().iter().copied().enumerate() {
        if reader.count()? != position || reader.u8()? != kind.tag() {
            return Err(Error::InvalidPersistedState);
        }
        let public_key = G::decode_point(reader.take(G::POINT_BYTES)?)?;
        if reader.count()? != config.registry().len() {
            return Err(Error::InvalidPersistedState);
        }
        let mut public_key_shares = BTreeMap::new();
        for participant in config.registry().indexes() {
            if reader.u32()? != participant.get() {
                return Err(Error::InvalidPersistedState);
            }
            public_key_shares.insert(participant, G::decode_point(reader.take(G::POINT_BYTES)?)?);
        }
        instances.push(DkgPublicInstance {
            kind,
            public_key,
            public_key_shares,
        });
    }
    reader.finish()?;
    let output = DkgPublicOutput::new(config, instances)?;
    output::validate_public(config, &output)?;
    Ok(output)
}

impl<G: DkgGroup> DkgOutput<G> {
    /// Encode participant secrets and public results; application-owned bytes require custody.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let public = output::public_payload::<G>(self.public.config_root, &self.public.instances)?;
        let size = 4usize
            .checked_add(8)
            .and_then(|n| n.checked_add(public.len()))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| {
                self.secret_shares
                    .len()
                    .checked_mul(32)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Error::ArithmeticOverflow)?;
        let mut value = Zeroizing::new(reserve(size)?);
        value.extend_from_slice(&self.participant.get().to_be_bytes());
        framed(&mut value, &public)?;
        count(&mut value, self.secret_shares.len())?;
        for secret in self.secret_shares.iter() {
            let encoded = Zeroizing::new(G::encode_scalar(secret.expose()));
            value.extend_from_slice(&*encoded);
        }
        Ok(transfer(envelope::<G>(4, &value)?))
    }
    /// Restore authenticated trusted-completion state, checking local/public share consistency.
    /// This does not validate an untrusted historical DKG execution.
    pub fn from_bytes(
        config: &DkgConfig<G>,
        expected_participant: ParticipantIndex,
        bytes: &[u8],
    ) -> Result<Self> {
        restore_local(config, expected_participant, payload::<G>(4, bytes)?)
            .map_err(|error| normalize_validation_error(error, Error::InvalidPersistedState))
    }
    /// Construct an explicit secret-bearing serializable snapshot.
    pub fn snapshot(&self) -> Result<DkgOutputSnapshot<G>> {
        let bytes = Zeroizing::new(self.to_bytes()?);
        DkgOutputSnapshot::from_bytes(&bytes)
    }
}
fn restore_local<G: DkgGroup>(
    config: &DkgConfig<G>,
    expected: ParticipantIndex,
    bytes: &[u8],
) -> Result<DkgOutput<G>> {
    let mut reader = Reader::new(bytes);
    if reader.u32()? != expected.get() {
        return Err(Error::InvalidPersistedState);
    }
    config.registry().public_key(expected)?;
    let public = restore_public(config, reader.framed()?)?;
    let count = reader.count()?;
    if count != config.instances().len() {
        return Err(Error::InvalidPersistedState);
    }
    reader.ensure_items(count, 32)?;
    let mut secret_shares = secret_vec(count)?;
    for instance in &public.instances {
        let value = crate::secret::secret(G::decode_scalar(reader.take(32)?)?);
        if Some(&G::mul_generator(value.expose())) != instance.public_key_shares.get(&expected) {
            return Err(Error::InvalidPersistedState);
        }
        secret_shares.push(Wipeable(*value.expose()));
    }
    reader.finish()?;
    Ok(DkgOutput {
        participant: expected,
        public,
        secret_shares,
    })
}

macro_rules! snapshot {
    ($name:ident, $tag:literal) => {
        /// An opaque explicit state representation. Restore with the required caller context.
        pub struct $name<G: DkgGroup> {
            bytes: Zeroizing<Vec<u8>>,
            group: PhantomData<G>,
        }
        impl<G: DkgGroup> $name<G> {
            /// Decode only the type/group envelope; contextual restoration validates contents.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                payload::<G>($tag, bytes)?;
                let mut owned = Zeroizing::new(reserve(bytes.len())?);
                owned.extend_from_slice(bytes);
                Ok(Self {
                    bytes: owned,
                    group: PhantomData,
                })
            }
            /// Borrow application state bytes. Secret-bearing tags require secret custody.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl<G: DkgGroup> fmt::Debug for $name<G> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("bytes", &"<redacted>")
                    .finish()
            }
        }
        #[cfg(feature = "miden-serde")]
        impl<G: DkgGroup> miden_serde_utils::Serializable for $name<G> {
            fn write_into<W: miden_serde_utils::ByteWriter>(&self, target: &mut W) {
                target.write_usize(self.bytes.len());
                target.write_bytes(&self.bytes);
            }
        }
        #[cfg(feature = "miden-serde")]
        impl<G: DkgGroup> miden_serde_utils::Deserializable for $name<G> {
            fn read_from<R: miden_serde_utils::ByteReader>(
                source: &mut R,
            ) -> core::result::Result<Self, miden_serde_utils::DeserializationError> {
                use miden_serde_utils::DeserializationError;
                let length = source.read_usize()?;
                if length > source.max_alloc(1) {
                    return Err(DeserializationError::InvalidValue(
                        "Golden snapshot exceeds reader allocation budget".into(),
                    ));
                }
                source.check_eor(length)?;
                let bytes = source.read_slice(length)?;
                Self::from_bytes(bytes).map_err(|_| {
                    DeserializationError::InvalidValue("invalid Golden snapshot".into())
                })
            }
        }
        #[cfg(feature = "serde")]
        impl<G: DkgGroup> serde::Serialize for $name<G> {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.bytes)
            }
        }
        #[cfg(feature = "serde")]
        impl<'de, G: DkgGroup> serde::Deserialize<'de> for $name<G> {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                let bytes = deserialize_guarded_bytes(deserializer)?;
                Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}
snapshot!(DkgConfigSnapshot, 1);
snapshot!(OwnDealingSnapshot, 2);
snapshot!(DkgPublicOutputSnapshot, 3);
snapshot!(DkgOutputSnapshot, 4);
impl<G: DkgGroup> DkgConfigSnapshot<G> {
    /// Validate configuration contents and rederive the configuration root.
    pub fn restore(&self) -> Result<DkgConfig<G>> {
        DkgConfig::from_bytes(&self.bytes)
    }
}
impl<G: DkgGroup> OwnDealingSnapshot<G> {
    /// Restore authenticated local state with explicit expected ownership.
    pub fn restore(
        &self,
        config: &DkgConfig<G>,
        expected: ParticipantIndex,
    ) -> Result<OwnDealing<G>> {
        OwnDealing::from_bytes(config, expected, &self.bytes)
    }
}
impl<G: DkgGroup> DkgPublicOutputSnapshot<G> {
    /// Restore only authenticated bytes with trusted completion provenance.
    pub fn restore(&self, config: &DkgConfig<G>) -> Result<DkgPublicOutput<G>> {
        DkgPublicOutput::from_bytes(config, &self.bytes)
    }
}
impl<G: DkgGroup> DkgOutputSnapshot<G> {
    /// Restore only authenticated bytes with trusted completion provenance and expected ownership.
    pub fn restore(
        &self,
        config: &DkgConfig<G>,
        expected: ParticipantIndex,
    ) -> Result<DkgOutput<G>> {
        DkgOutput::from_bytes(config, expected, &self.bytes)
    }
}

#[cfg(feature = "serde")]
fn deserialize_guarded_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Zeroizing<Vec<u8>>, D::Error> {
    use serde::de::{Error as _, SeqAccess, Visitor};
    struct Bytes;
    impl<'de> Visitor<'de> for Bytes {
        type Value = Zeroizing<Vec<u8>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an encoded Golden state snapshot")
        }
        fn visit_bytes<E: serde::de::Error>(
            self,
            bytes: &[u8],
        ) -> core::result::Result<Self::Value, E> {
            let mut out = Zeroizing::new(reserve(bytes.len()).map_err(E::custom)?);
            out.extend_from_slice(bytes);
            Ok(out)
        }
        fn visit_byte_buf<E: serde::de::Error>(
            self,
            bytes: Vec<u8>,
        ) -> core::result::Result<Self::Value, E> {
            Ok(Zeroizing::new(bytes))
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let initial = sequence.size_hint().unwrap_or(256);
            let mut out = Zeroizing::new(reserve(initial).map_err(A::Error::custom)?);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if out.len() == out.capacity() {
                    let capacity = out
                        .capacity()
                        .max(1)
                        .checked_mul(2)
                        .ok_or_else(|| A::Error::custom("snapshot size overflow"))?;
                    let mut next = Zeroizing::new(reserve(capacity).map_err(A::Error::custom)?);
                    next.extend_from_slice(&out);
                    out = next;
                }
                out.push(byte);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_bytes(Bytes)
}
