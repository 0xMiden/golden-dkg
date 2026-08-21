//! Canonical byte encoding for Golden DKG wire values.
//!
//! Standalone wire values start with [`MAGIC`], a one-byte type tag, and a
//! codec context. Nested fields omit that envelope and are encoded in the order
//! documented by each type's [`WireEncode`] implementation.
//!
//! In the DKG protocol, [`DealerMessage`] is the broadcast message. The other
//! tagged values are standalone encodings for setup artifacts, nested fields,
//! tests, or persistence.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use core::marker::PhantomData;
#[cfg(feature = "miden-serde")]
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "serde")]
use serde::{
    de,
    ser::{SerializeSeq, SerializeTuple},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    DealerMessage, DealerMessageNonce, DealingBody, DkgConfig, DkgInstanceKind, EncryptedShare,
    Error, FeldmanCommitment, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry,
    Result, SessionId, TranscriptRoot,
};
#[cfg(any(feature = "serde", feature = "miden-serde"))]
use crate::{DkgInstanceOutput, DkgOutput, OwnDealing};

/// Magic prefix for every standalone DKG wire value.
pub const MAGIC: &[u8; 18] = b"golden-dkg-wire-v4";

/// Standalone tag for [`SessionId`].
pub const TAG_SESSION_ID: u8 = 0x01;
/// Standalone tag for [`DealerMessageNonce`].
pub const TAG_DEALER_MESSAGE_NONCE: u8 = 0x02;
/// Standalone tag for [`EncryptedShare`].
pub const TAG_ENCRYPTED_SHARE: u8 = 0x03;
/// Standalone tag for [`FeldmanCommitment`].
pub const TAG_FELDMAN_COMMITMENT: u8 = 0x04;
/// Standalone tag for [`ParticipantRegistry`].
pub const TAG_PARTICIPANT_REGISTRY: u8 = 0x05;
/// Standalone tag for [`DkgConfig`].
pub const TAG_DKG_CONFIG: u8 = 0x06;
/// Protocol broadcast tag for [`DealerMessage`].
pub const TAG_DEALER_MESSAGE: u8 = 0x07;

/// Maximum accepted byte length of a dealer's proof.
pub const MAX_DEALER_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// Coarse allocation ceiling for one trusted-persistence collection.
#[cfg(any(feature = "serde", feature = "miden-serde"))]
const MAX_PERSISTED_COLLECTION_BYTES: usize = 16 * 1024 * 1024;

/// Encode a value into its nested canonical wire representation.
pub trait WireEncode {
    /// Write this value without a top-level magic or tag prefix.
    fn write_wire(&self, out: &mut Vec<u8>);

    /// Byte length `write_wire` will append, used to pre-size the output
    /// buffer; the default `0` falls back to `Vec`'s own growth.
    fn wire_size_hint(&self) -> usize {
        0
    }

    /// Return this value's nested wire bytes.
    fn to_nested_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_size_hint());
        self.write_wire(&mut out);
        out
    }
}

/// Decode a value from its nested canonical wire representation.
pub trait WireDecode: Sized {
    /// Read this value without a top-level magic or tag prefix.
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self>;
}

/// A standalone wire value with a stable tag.
pub trait WireMessage: WireEncode + WireDecode {
    /// Standalone type tag.
    const TAG: u8;

    /// Stable codec identifier inside the standalone envelope.
    const CODEC_ID: &'static str;

    /// Write codec context after the top-level tag.
    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
    }

    /// Read and validate codec context after the top-level tag.
    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())
    }
}

/// Return a standalone canonical wire value.
pub fn to_wire_bytes<T: WireMessage>(value: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + value.wire_size_hint());
    out.extend_from_slice(MAGIC);
    out.push(T::TAG);
    T::write_wire_context(&mut out);
    value.write_wire(&mut out);
    out
}

/// Decode a standalone canonical wire value and reject trailing bytes.
pub fn from_wire_bytes<T: WireMessage>(bytes: &[u8]) -> Result<T> {
    let mut reader = WireReader::new(bytes);
    reader.expect_magic()?;
    let tag = reader.read_u8()?;
    if tag != T::TAG {
        return Err(Error::InvalidEncoding);
    }
    T::read_wire_context(&mut reader)?;
    let value = T::read_wire(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Reader for canonical wire bytes.
#[derive(Clone, Debug)]
pub struct WireReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> WireReader<'a> {
    /// Build a reader over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let byte = self.read_exact(1)?[0];
        Ok(byte)
    }

    /// Read a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    /// Read a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    /// Read a length prefix as a `usize`.
    pub fn read_len(&mut self) -> Result<usize> {
        usize::try_from(self.read_u64()?).map_err(|_| Error::InvalidEncoding)
    }

    /// Return the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    /// Validate that at least `count * min_item_size` bytes remain.
    pub fn ensure_remaining_items(&self, count: usize, min_item_size: usize) -> Result<()> {
        let required = count
            .checked_mul(min_item_size)
            .ok_or(Error::InvalidEncoding)?;
        if required <= self.remaining() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// Read `N` bytes into an array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.read_exact(N)?);
        Ok(out)
    }

    /// Read `len` bytes.
    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.cursor.checked_add(len).ok_or(Error::InvalidEncoding)?;
        if end > self.bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        let slice = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    /// Read and validate the standalone magic prefix.
    pub fn expect_magic(&mut self) -> Result<()> {
        if self.read_exact(MAGIC.len())? == MAGIC.as_slice() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// Reject unread trailing bytes.
    pub fn finish(&self) -> Result<()> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

impl WireEncode for SessionId {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl WireDecode for SessionId {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self(reader.read_array()?))
    }
}

impl WireMessage for SessionId {
    const TAG: u8 = TAG_SESSION_ID;
    const CODEC_ID: &'static str = "session-id-v1";
}

impl WireEncode for DealerMessageNonce {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl WireDecode for DealerMessageNonce {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self(reader.read_array()?))
    }
}

impl WireMessage for DealerMessageNonce {
    const TAG: u8 = TAG_DEALER_MESSAGE_NONCE;
    const CODEC_ID: &'static str = "dealer-message-nonce-v1";
}

impl WireEncode for ParticipantIndex {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_u32(out, self.get());
    }
}

impl WireDecode for ParticipantIndex {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Self::new(reader.read_u32()?)
    }
}

impl WireEncode for TranscriptRoot {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl WireDecode for TranscriptRoot {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        reader.read_array()
    }
}

impl<G: GoldenGroup> WireEncode for EncryptedShare<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_element::<G>(out, &self.pad_commitment);
        write_scalar::<G>(out, &self.encrypted_share);
    }
}

impl<G> WireDecode for EncryptedShare<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self {
            pad_commitment: read_element::<G>(reader)?,
            encrypted_share: read_scalar::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for EncryptedShare<G>
where
    G: GoldenGroup,
{
    const TAG: u8 = TAG_ENCRYPTED_SHARE;
    const CODEC_ID: &'static str = "encrypted-share-v2";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
        write_context_field(out, G::BACKEND_ID.as_bytes());
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())?;
        expect_context_field(reader, G::BACKEND_ID.as_bytes())
    }
}

impl WireEncode for DkgInstanceKind {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Self::Random => 0,
            Self::Zero => 1,
        });
    }
}

impl WireDecode for DkgInstanceKind {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        match reader.read_u8()? {
            0 => Ok(Self::Random),
            1 => Ok(Self::Zero),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

impl<G: GoldenGroup> WireEncode for DealingBody<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.nonce.write_wire(out);
        self.commitment.write_wire(out);
        write_len(out, self.encrypted_shares.len());
        for (receiver, encrypted_share) in &self.encrypted_shares {
            receiver.write_wire(out);
            encrypted_share.write_wire(out);
        }
    }

    fn wire_size_hint(&self) -> usize {
        let commitment_points =
            self.commitment.threshold() - 1 + usize::from(self.commitment.constant().is_some());
        let commitment_len = 1 + 8 + commitment_points * G::ELEMENT_REPR_BYTES;
        let encrypted_share_len = 4 + G::ELEMENT_REPR_BYTES + G::Scalar::REPR_BYTES;
        32 + commitment_len + 8 + self.encrypted_shares.len() * encrypted_share_len
    }
}

impl<G> WireDecode for DealingBody<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let nonce = DealerMessageNonce::read_wire(reader)?;
        let commitment = FeldmanCommitment::<G>::read_wire(reader)?;
        let len = reader.read_len()?;
        let encrypted_share_len = 4 + G::ELEMENT_REPR_BYTES + G::Scalar::REPR_BYTES;
        reader.ensure_remaining_items(len, encrypted_share_len)?;
        let mut encrypted_shares = BTreeMap::new();
        let mut last = None;
        for _ in 0..len {
            let receiver = ParticipantIndex::read_wire(reader)?;
            ensure_increasing(&mut last, receiver)?;
            encrypted_shares.insert(receiver, EncryptedShare::<G>::read_wire(reader)?);
        }
        Ok(Self {
            nonce,
            commitment,
            encrypted_shares,
        })
    }
}

impl<G: GoldenGroup> WireEncode for FeldmanCommitment<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        let coefficients = self.coefficients();
        out.push(u8::from(self.constant().is_some()));
        write_len(out, coefficients.len() - 1);
        if let Some(constant) = self.constant() {
            write_element::<G>(out, constant);
        }
        for coefficient in &coefficients[1..] {
            write_element::<G>(out, coefficient);
        }
    }
}

impl<G> WireDecode for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let has_constant = match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidEncoding),
        };
        let tail_len = reader.read_len()?;
        let point_count = tail_len
            .checked_add(usize::from(has_constant))
            .ok_or(Error::InvalidEncoding)?;
        reader.ensure_remaining_items(point_count, G::ELEMENT_REPR_BYTES)?;
        let constant = has_constant
            .then(|| read_element::<G>(reader))
            .transpose()?;
        let mut tail = Vec::with_capacity(tail_len);
        for _ in 0..tail_len {
            tail.push(read_element::<G>(reader)?);
        }
        match constant {
            Some(constant) => {
                Self::from_coefficients(core::iter::once(constant).chain(tail).collect())
            }
            None => Ok(Self::from_zero_tail(tail)),
        }
    }
}

impl<G> WireMessage for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    const TAG: u8 = TAG_FELDMAN_COMMITMENT;
    const CODEC_ID: &'static str = "feldman-commitment-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
        write_context_field(out, G::BACKEND_ID.as_bytes());
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())?;
        expect_context_field(reader, G::BACKEND_ID.as_bytes())
    }
}

impl<G: GoldenGroup> WireEncode for ParticipantRegistry<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.len());
        for (participant, public_key) in self.entries() {
            participant.write_wire(out);
            write_element::<G>(out, public_key);
        }
    }
}

impl<G> WireDecode for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let len = reader.read_len()?;
        let entry_len = 4 + G::ELEMENT_REPR_BYTES;
        reader.ensure_remaining_items(len, entry_len)?;
        let mut entries = Vec::with_capacity(len);
        let mut last = None;
        for _ in 0..len {
            let participant = ParticipantIndex::read_wire(reader)?;
            ensure_increasing(&mut last, participant)?;
            entries.push((participant, read_element::<G>(reader)?));
        }
        Self::new(entries)
    }
}

impl<G> WireMessage for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    const TAG: u8 = TAG_PARTICIPANT_REGISTRY;
    const CODEC_ID: &'static str = "participant-registry-v1";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
        write_context_field(out, G::BACKEND_ID.as_bytes());
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())?;
        expect_context_field(reader, G::BACKEND_ID.as_bytes())
    }
}

impl<G: GoldenGroup> WireEncode for DkgConfig<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.threshold());
        self.session_id().write_wire(out);
        self.registry().write_wire(out);
        write_len(out, self.instances().len());
        for kind in self.instances() {
            kind.write_wire(out);
        }
    }
}

impl<G> WireDecode for DkgConfig<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let threshold = reader.read_len()?;
        let session_id = SessionId::read_wire(reader)?;
        let registry = ParticipantRegistry::read_wire(reader)?;
        let instance_count = reader.read_len()?;
        reader.ensure_remaining_items(instance_count, 1)?;
        let mut instances = Vec::with_capacity(instance_count);
        for _ in 0..instance_count {
            instances.push(DkgInstanceKind::read_wire(reader)?);
        }
        Self::new(threshold, session_id, registry, instances)
    }
}

impl<G> WireMessage for DkgConfig<G>
where
    G: GoldenGroup,
{
    const TAG: u8 = TAG_DKG_CONFIG;
    const CODEC_ID: &'static str = "dkg-config-v3";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
        write_context_field(out, G::BACKEND_ID.as_bytes());
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())?;
        expect_context_field(reader, G::BACKEND_ID.as_bytes())
    }
}

impl<G: GoldenGroup> WireEncode for DealerMessage<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.configuration_root.write_wire(out);
        self.dealer.write_wire(out);
        write_len(out, self.dealings.len());
        for dealing in &self.dealings {
            dealing.write_wire(out);
        }
        write_len(out, self.proof.len());
        out.extend_from_slice(&self.proof);
    }

    fn wire_size_hint(&self) -> usize {
        32 // configuration_root
            + 4 // dealer
            + 8 // dealings length
            + self
                .dealings
                .iter()
                .map(WireEncode::wire_size_hint)
                .sum::<usize>()
            + 8 + self.proof.len() // proof
    }
}

impl<G> WireDecode for DealerMessage<G>
where
    G: GoldenGroup,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let configuration_root = TranscriptRoot::read_wire(reader)?;
        let dealer = ParticipantIndex::read_wire(reader)?;
        let len = reader.read_len()?;
        if len == 0 {
            return Err(Error::InvalidEncoding);
        }
        let minimum_dealing_len = 32 + 1 + 8 + 8;
        reader.ensure_remaining_items(len, minimum_dealing_len)?;
        let mut dealings = Vec::with_capacity(len);
        for _ in 0..len {
            dealings.push(DealingBody::<G>::read_wire(reader)?);
        }
        let proof_len = reader.read_len()?;
        if proof_len > MAX_DEALER_PROOF_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let proof = reader.read_exact(proof_len)?.to_vec();
        Ok(Self {
            configuration_root,
            dealer,
            dealings,
            proof,
        })
    }
}

impl<G> WireMessage for DealerMessage<G>
where
    G: GoldenGroup,
{
    const TAG: u8 = TAG_DEALER_MESSAGE;
    const CODEC_ID: &'static str = "dealer-message-v4";

    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
        write_context_field(out, G::BACKEND_ID.as_bytes());
    }

    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())?;
        expect_context_field(reader, G::BACKEND_ID.as_bytes())
    }
}

#[cfg(feature = "miden-serde")]
impl Serializable for SessionId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }

    fn get_size_hint(&self) -> usize {
        32
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for SessionId {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }

    fn min_serialized_size() -> usize {
        32
    }
}

#[cfg(feature = "miden-serde")]
impl Serializable for ParticipantIndex {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.get());
    }

    fn get_size_hint(&self) -> usize {
        4
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for ParticipantIndex {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        Self::new(source.read_u32()?).map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        4
    }
}

#[cfg(feature = "miden-serde")]
impl Serializable for DkgInstanceKind {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(match self {
            Self::Random => 0,
            Self::Zero => 1,
        });
    }

    fn get_size_hint(&self) -> usize {
        1
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for DkgInstanceKind {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::Random),
            1 => Ok(Self::Zero),
            value => Err(DeserializationError::InvalidValue(format!(
                "invalid DKG instance kind {value}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        1
    }
}

#[cfg(feature = "miden-serde")]
impl Serializable for DealerMessageNonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for DealerMessageNonce {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for EncryptedShare<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for EncryptedShare<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        for (participant, public_key) in self.entries() {
            participant.write_into(target);
            write_miden_element::<G, _>(public_key, target);
        }
    }

    fn get_size_hint(&self) -> usize {
        miden_usize_size(self.len()) + self.len() * (4 + G::ELEMENT_REPR_BYTES)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        let len = read_miden_persisted_len(source, 4 + G::ELEMENT_REPR_BYTES)?;
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            entries.push((
                ParticipantIndex::read_from(source)?,
                read_miden_element::<G, _>(source)?,
            ));
        }
        ParticipantRegistry::new(entries).map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        1 + 4 + G::ELEMENT_REPR_BYTES
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for DkgConfig<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.threshold());
        self.session_id().write_into(target);
        self.registry().write_into(target);
        target.write_usize(self.instances().len());
        for kind in self.instances() {
            kind.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        miden_usize_size(self.threshold())
            + self.session_id().get_size_hint()
            + self.registry().get_size_hint()
            + miden_usize_size(self.instances().len())
            + self.instances().len()
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for DkgConfig<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        let threshold = source.read_usize()?;
        let session_id = SessionId::read_from(source)?;
        let registry = ParticipantRegistry::<G>::read_from(source)?;
        let instance_count = read_miden_persisted_len(source, 1)?;
        let mut instances = Vec::with_capacity(instance_count);
        for _ in 0..instance_count {
            instances.push(DkgInstanceKind::read_from(source)?);
        }
        DkgConfig::new(threshold, session_id, registry, instances).map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        1 + 32 + <ParticipantRegistry<G> as Deserializable>::min_serialized_size() + 1 + 1
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for OwnDealing<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.participant().get());
        target.write_bytes(&self.configuration_root());
        target.write_usize(self.dealer_message_bytes().len());
        target.write_bytes(self.dealer_message_bytes());
        target.write_usize(self.private_shares().len());
        for share in self.private_shares() {
            target.write_bytes(share.to_repr().as_ref());
        }
    }

    fn get_size_hint(&self) -> usize {
        4 + 32
            + miden_usize_size(self.dealer_message_bytes().len())
            + self.dealer_message_bytes().len()
            + miden_usize_size(self.private_shares().len())
            + self.private_shares().len() * G::Scalar::REPR_BYTES
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for OwnDealing<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        let participant =
            ParticipantIndex::new(source.read_u32()?).map_err(miden_persistence_error)?;
        let configuration_root = source.read_array()?;
        let dealer_message_len = read_miden_persisted_len(source, 1)?;
        let dealer_message_bytes = source.read_vec(dealer_message_len)?;
        let private_share_count = read_miden_persisted_len(source, G::Scalar::REPR_BYTES)?;
        let mut private_shares = Vec::with_capacity(private_share_count);
        for _ in 0..private_share_count {
            private_shares.push(read_miden_scalar::<G, _>(source)?);
        }
        OwnDealing::from_persisted_parts(
            participant,
            configuration_root,
            dealer_message_bytes,
            private_shares,
        )
        .map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        4 + 32 + 1 + 1 + G::Scalar::REPR_BYTES
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for DkgInstanceOutput<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_element::<G, _>(self.public_key(), target);
        target.write_bytes(self.secret_share().to_repr().as_ref());
        target.write_usize(self.public_key_shares().len());
        for (participant, public_share) in self.public_key_shares() {
            participant.write_into(target);
            write_miden_element::<G, _>(public_share, target);
        }
    }

    fn get_size_hint(&self) -> usize {
        G::ELEMENT_REPR_BYTES
            + G::Scalar::REPR_BYTES
            + miden_usize_size(self.public_key_shares().len())
            + self.public_key_shares().len() * (4 + G::ELEMENT_REPR_BYTES)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for DkgInstanceOutput<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        let public_key = read_miden_element::<G, _>(source)?;
        let secret_share = read_miden_scalar::<G, _>(source)?;
        let public_share_count = read_miden_persisted_len(source, 4 + G::ELEMENT_REPR_BYTES)?;
        let mut public_key_shares = BTreeMap::new();
        for _ in 0..public_share_count {
            let participant = ParticipantIndex::read_from(source)?;
            let public_share = read_miden_element::<G, _>(source)?;
            if public_key_shares
                .insert(participant, public_share)
                .is_some()
            {
                return Err(DeserializationError::InvalidValue(
                    "duplicate participant in public-key-share map".into(),
                ));
            }
        }
        DkgInstanceOutput::from_persisted_parts(public_key, secret_share, public_key_shares)
            .map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        G::ELEMENT_REPR_BYTES + G::Scalar::REPR_BYTES + 1 + 4 + G::ELEMENT_REPR_BYTES
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for DkgOutput<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.participant().write_into(target);
        target.write_bytes(&self.configuration_root());
        target.write_usize(self.instances().len());
        for instance in self.instances() {
            instance.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        4 + 32
            + miden_usize_size(self.instances().len())
            + self
                .instances()
                .iter()
                .map(|instance| instance.get_size_hint())
                .sum::<usize>()
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for DkgOutput<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        let participant = ParticipantIndex::read_from(source)?;
        let configuration_root = source.read_array()?;
        let instance_count = read_miden_persisted_len(
            source,
            <DkgInstanceOutput<G> as Deserializable>::min_serialized_size(),
        )?;
        let mut instances = Vec::with_capacity(instance_count);
        for _ in 0..instance_count {
            instances.push(DkgInstanceOutput::<G>::read_from(source)?);
        }
        DkgOutput::from_persisted_parts(participant, configuration_root, instances)
            .map_err(miden_persistence_error)
    }

    fn min_serialized_size() -> usize {
        4 + 32 + 1 + <DkgInstanceOutput<G> as Deserializable>::min_serialized_size()
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for DealerMessage<G>
where
    G: GoldenGroup,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for DealerMessage<G>
where
    G: GoldenGroup,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
/// Write a length-delimited standalone wire value into a Miden byte writer.
pub fn write_miden_wire<T, W>(value: &T, target: &mut W)
where
    T: WireMessage,
    W: ByteWriter,
{
    let bytes = to_wire_bytes(value);
    target.write_usize(bytes.len());
    target.write_bytes(&bytes);
}

#[cfg(feature = "miden-serde")]
/// Read a length-delimited standalone wire value from a Miden byte reader.
pub fn read_miden_wire<T, R>(source: &mut R) -> core::result::Result<T, DeserializationError>
where
    T: WireMessage,
    R: ByteReader,
{
    let len = source.read_usize()?;
    if len > source.max_alloc(1) {
        return Err(DeserializationError::InvalidValue(format!(
            "wire payload length {len} exceeds reader allocation budget"
        )));
    }
    source.check_eor(len)?;
    let bytes = source.read_vec(len)?;
    from_wire_bytes(&bytes).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
}

#[cfg(feature = "miden-serde")]
/// Return the serialized size hint for a length-delimited Miden wire value.
pub fn miden_wire_size_hint<T: WireMessage>(value: &T) -> usize {
    // Miden asks for a size hint, not a no-allocation bound. Reuse the
    // canonical encoder here so the hint cannot drift from the written bytes.
    let len = to_wire_bytes(value).len();
    miden_usize_size(len) + len
}

#[cfg(feature = "miden-serde")]
fn miden_usize_size(value: usize) -> usize {
    let zeros = (value as u64).leading_zeros() as usize;
    let len = zeros.saturating_sub(1) / 7;
    9 - core::cmp::min(len, 8)
}

#[cfg(feature = "miden-serde")]
fn read_miden_persisted_len<R: ByteReader>(
    source: &mut R,
    minimum_item_bytes: usize,
) -> core::result::Result<usize, DeserializationError> {
    let minimum_item_bytes = minimum_item_bytes.max(1);
    let len = source.read_usize()?;
    let maximum = MAX_PERSISTED_COLLECTION_BYTES / minimum_item_bytes;
    if len > maximum || len > source.max_alloc(minimum_item_bytes) {
        return Err(DeserializationError::InvalidValue(format!(
            "persistence collection length {len} exceeds allocation bound {maximum}"
        )));
    }
    source.check_eor(len.checked_mul(minimum_item_bytes).ok_or_else(|| {
        DeserializationError::InvalidValue("persistence length overflow".into())
    })?)?;
    Ok(len)
}

#[cfg(feature = "miden-serde")]
fn read_miden_scalar<G, R>(source: &mut R) -> core::result::Result<G::Scalar, DeserializationError>
where
    G: GoldenGroup,
    R: ByteReader,
{
    let bytes = source.read_vec(G::Scalar::REPR_BYTES)?;
    let repr = <G::Scalar as GoldenScalar>::Repr::try_from(bytes.clone())
        .map_err(|_| DeserializationError::InvalidValue("invalid scalar width".into()))?;
    let scalar = G::Scalar::from_repr(&repr).map_err(miden_persistence_error)?;
    if scalar.to_repr().as_ref() != bytes {
        return Err(DeserializationError::InvalidValue(
            "noncanonical scalar encoding".into(),
        ));
    }
    Ok(scalar)
}

#[cfg(feature = "miden-serde")]
fn write_miden_element<G, W>(element: &G::Element, target: &mut W)
where
    G: GoldenGroup,
    W: ByteWriter,
{
    target.write_bytes(G::encode_element(element).as_ref());
}

#[cfg(feature = "miden-serde")]
fn read_miden_element<G, R>(
    source: &mut R,
) -> core::result::Result<G::Element, DeserializationError>
where
    G: GoldenGroup,
    R: ByteReader,
{
    let bytes = source.read_vec(G::ELEMENT_REPR_BYTES)?;
    let repr = G::ElementRepr::try_from(bytes.clone())
        .map_err(|_| DeserializationError::InvalidValue("invalid group element width".into()))?;
    let element = G::decode_element(&repr).map_err(miden_persistence_error)?;
    if G::encode_element(&element).as_ref() != bytes {
        return Err(DeserializationError::InvalidValue(
            "noncanonical group element encoding".into(),
        ));
    }
    Ok(element)
}

#[cfg(feature = "miden-serde")]
fn miden_persistence_error(error: Error) -> DeserializationError {
    DeserializationError::InvalidValue(error.to_string())
}

#[cfg(feature = "serde")]
struct PersistenceBytes<'a>(&'a [u8]);

#[cfg(feature = "serde")]
impl Serialize for PersistenceBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

#[cfg(feature = "serde")]
struct DecodedPersistenceBytes(Vec<u8>);

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for DecodedPersistenceBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_bytes(PersistenceBytesVisitor)
    }
}

#[cfg(feature = "serde")]
struct PersistenceBytesVisitor;

#[cfg(feature = "serde")]
impl<'de> de::Visitor<'de> for PersistenceBytesVisitor {
    type Value = DecodedPersistenceBytes;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded byte string used for trusted application persistence")
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> core::result::Result<Self::Value, E> {
        if value.len() > MAX_PERSISTED_COLLECTION_BYTES {
            return Err(E::custom(
                "persistence byte string exceeds allocation bound",
            ));
        }
        Ok(DecodedPersistenceBytes(value.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> core::result::Result<Self::Value, E> {
        if value.len() > MAX_PERSISTED_COLLECTION_BYTES {
            return Err(E::custom(
                "persistence byte string exceeds allocation bound",
            ));
        }
        Ok(DecodedPersistenceBytes(value))
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        if seq
            .size_hint()
            .is_some_and(|hint| hint > MAX_PERSISTED_COLLECTION_BYTES)
        {
            return Err(de::Error::custom(
                "persistence byte sequence exceeds allocation bound",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            if bytes.len() == MAX_PERSISTED_COLLECTION_BYTES {
                return Err(de::Error::custom(
                    "persistence byte sequence exceeds allocation bound",
                ));
            }
            bytes.push(byte);
        }
        Ok(DecodedPersistenceBytes(bytes))
    }
}

#[cfg(feature = "serde")]
struct ScalarSlice<'a, G: GoldenGroup>(&'a [G::Scalar]);

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for ScalarSlice<'_, G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for scalar in self.0 {
            let repr = scalar.to_repr();
            sequence.serialize_element(&PersistenceBytes(repr.as_ref()))?;
        }
        sequence.end()
    }
}

#[cfg(feature = "serde")]
struct ScalarVec<G: GoldenGroup>(Vec<G::Scalar>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for ScalarVec<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(ScalarVecVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
struct ScalarVecVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for ScalarVecVisitor<G> {
    type Value = ScalarVec<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded sequence of canonical Golden scalars")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let maximum = MAX_PERSISTED_COLLECTION_BYTES / G::Scalar::REPR_BYTES.max(1);
        if seq.size_hint().is_some_and(|hint| hint > maximum) {
            return Err(de::Error::custom(
                "persistence scalar sequence exceeds allocation bound",
            ));
        }
        let mut scalars = Vec::new();
        while let Some(DecodedPersistenceBytes(bytes)) = seq.next_element()? {
            if scalars.len() == maximum || bytes.len() != G::Scalar::REPR_BYTES {
                return Err(de::Error::custom(
                    "invalid persistence scalar sequence or scalar width",
                ));
            }
            let repr = <G::Scalar as GoldenScalar>::Repr::try_from(bytes.clone())
                .map_err(|_| de::Error::custom("invalid scalar width"))?;
            let scalar = G::Scalar::from_repr(&repr).map_err(de::Error::custom)?;
            if scalar.to_repr().as_ref() != bytes {
                return Err(de::Error::custom("noncanonical scalar encoding"));
            }
            scalars.push(scalar);
        }
        Ok(ScalarVec(scalars))
    }
}

#[cfg(feature = "serde")]
struct ScalarRef<'a, G: GoldenGroup>(&'a G::Scalar);

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for ScalarRef<'_, G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let repr = self.0.to_repr();
        serializer.serialize_bytes(repr.as_ref())
    }
}

#[cfg(feature = "serde")]
struct ScalarValue<G: GoldenGroup>(G::Scalar);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for ScalarValue<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let DecodedPersistenceBytes(bytes) = DecodedPersistenceBytes::deserialize(deserializer)?;
        if bytes.len() != G::Scalar::REPR_BYTES {
            return Err(de::Error::custom("invalid scalar width"));
        }
        let repr = <G::Scalar as GoldenScalar>::Repr::try_from(bytes.clone())
            .map_err(|_| de::Error::custom("invalid scalar width"))?;
        let scalar = G::Scalar::from_repr(&repr).map_err(de::Error::custom)?;
        if scalar.to_repr().as_ref() != bytes.as_slice() {
            return Err(de::Error::custom("noncanonical scalar encoding"));
        }
        Ok(Self(scalar))
    }
}

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for OwnDealing<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let configuration_root = self.configuration_root();
        let mut tuple = serializer.serialize_tuple(4)?;
        tuple.serialize_element(&self.participant().get())?;
        tuple.serialize_element(&PersistenceBytes(&configuration_root))?;
        tuple.serialize_element(&PersistenceBytes(self.dealer_message_bytes()))?;
        tuple.serialize_element(&ScalarSlice::<G>(self.private_shares()))?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for OwnDealing<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_tuple(4, OwnDealingVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
struct OwnDealingVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for OwnDealingVisitor<G> {
    type Value = OwnDealing<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a validated Golden own-dealing persistence tuple")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let participant = seq
            .next_element::<u32>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))
            .and_then(|value| ParticipantIndex::new(value).map_err(de::Error::custom))?;
        let DecodedPersistenceBytes(configuration_root) = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let configuration_root: TranscriptRoot = configuration_root
            .try_into()
            .map_err(|_| de::Error::custom("configuration root must contain 32 bytes"))?;
        let DecodedPersistenceBytes(dealer_message_bytes) = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let ScalarVec(private_shares): ScalarVec<G> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(5, &self));
        }
        OwnDealing::from_persisted_parts(
            participant,
            configuration_root,
            dealer_message_bytes,
            private_shares,
        )
        .map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
struct ElementRef<'a, G: GoldenGroup>(&'a G::Element);

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for ElementRef<'_, G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let repr = G::encode_element(self.0);
        serializer.serialize_bytes(repr.as_ref())
    }
}

#[cfg(feature = "serde")]
struct ElementValue<G: GoldenGroup>(G::Element);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for ElementValue<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let DecodedPersistenceBytes(bytes) = DecodedPersistenceBytes::deserialize(deserializer)?;
        if bytes.len() != G::ELEMENT_REPR_BYTES {
            return Err(de::Error::custom("invalid group element width"));
        }
        let repr = G::ElementRepr::try_from(bytes.clone())
            .map_err(|_| de::Error::custom("invalid group element width"))?;
        let element = G::decode_element(&repr).map_err(de::Error::custom)?;
        if G::encode_element(&element).as_ref() != bytes {
            return Err(de::Error::custom("noncanonical group element encoding"));
        }
        Ok(Self(element))
    }
}

#[cfg(feature = "serde")]
struct ParticipantElementRef<'a, G: GoldenGroup> {
    participant: ParticipantIndex,
    element: &'a G::Element,
}

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for ParticipantElementRef<'_, G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.participant)?;
        tuple.serialize_element(&ElementRef::<G>(self.element))?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
struct ParticipantElement<G: GoldenGroup> {
    participant: ParticipantIndex,
    element: G::Element,
}

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for ParticipantElement<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_tuple(2, ParticipantElementVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
struct ParticipantElementVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for ParticipantElementVisitor<G> {
    type Value = ParticipantElement<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a participant and canonical Golden group element")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let participant = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let ElementValue(element): ElementValue<G> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(3, &self));
        }
        Ok(ParticipantElement {
            participant,
            element,
        })
    }
}

#[cfg(feature = "serde")]
struct PublicShareMapRef<'a, G: GoldenGroup>(&'a BTreeMap<ParticipantIndex, G::Element>);

#[cfg(feature = "serde")]
impl<G: GoldenGroup> Serialize for PublicShareMapRef<'_, G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (participant, public_share) in self.0 {
            sequence.serialize_element(&ParticipantElementRef::<G> {
                participant: *participant,
                element: public_share,
            })?;
        }
        sequence.end()
    }
}

#[cfg(feature = "serde")]
struct PublicShareMap<G: GoldenGroup>(BTreeMap<ParticipantIndex, G::Element>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for PublicShareMap<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(PublicShareMapVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
struct PublicShareMapVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for PublicShareMapVisitor<G> {
    type Value = PublicShareMap<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded canonical participant/public-key-share sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let minimum_item_bytes = 4usize.saturating_add(G::ELEMENT_REPR_BYTES).max(1);
        let maximum = MAX_PERSISTED_COLLECTION_BYTES / minimum_item_bytes;
        if seq.size_hint().is_some_and(|hint| hint > maximum) {
            return Err(de::Error::custom(
                "public-key-share map exceeds persistence allocation bound",
            ));
        }
        let mut shares = BTreeMap::new();
        while let Some(ParticipantElement {
            participant,
            element,
        }) = seq.next_element::<ParticipantElement<G>>()?
        {
            if shares.len() == maximum {
                return Err(de::Error::custom(
                    "public-key-share map exceeds persistence allocation bound",
                ));
            }
            if shares.insert(participant, element).is_some() {
                return Err(de::Error::custom(
                    "duplicate participant in public-key-share map",
                ));
            }
        }
        Ok(PublicShareMap(shares))
    }
}

#[cfg(feature = "serde")]
struct DkgInstanceOutputVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for DkgInstanceOutputVisitor<G> {
    type Value = DkgInstanceOutput<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a validated Golden DKG instance-output persistence tuple")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let ElementValue(public_key): ElementValue<G> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let ScalarValue(secret_share): ScalarValue<G> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let PublicShareMap(public_key_shares): PublicShareMap<G> = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(4, &self));
        }
        DkgInstanceOutput::from_persisted_parts(public_key, secret_share, public_key_shares)
            .map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
struct InstanceVec<G: GoldenGroup>(Vec<DkgInstanceOutput<G>>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> Deserialize<'de> for InstanceVec<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(InstanceVecVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
struct InstanceVecVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for InstanceVecVisitor<G> {
    type Value = InstanceVec<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded sequence of validated Golden DKG instance outputs")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let minimum_item_bytes = G::ELEMENT_REPR_BYTES
            .saturating_add(G::Scalar::REPR_BYTES)
            .saturating_add(1)
            .max(1);
        let maximum = MAX_PERSISTED_COLLECTION_BYTES / minimum_item_bytes;
        if seq.size_hint().is_some_and(|hint| hint > maximum) {
            return Err(de::Error::custom(
                "DKG output instance sequence exceeds persistence allocation bound",
            ));
        }
        let mut instances = Vec::new();
        while let Some(instance) = seq.next_element()? {
            if instances.len() == maximum {
                return Err(de::Error::custom(
                    "DKG output instance sequence exceeds persistence allocation bound",
                ));
            }
            instances.push(instance);
        }
        Ok(InstanceVec(instances))
    }
}

#[cfg(feature = "serde")]
struct DkgOutputVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for DkgOutputVisitor<G> {
    type Value = DkgOutput<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a validated Golden DKG output persistence tuple")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let participant = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let DecodedPersistenceBytes(configuration_root) = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let configuration_root = configuration_root
            .try_into()
            .map_err(|_| de::Error::custom("configuration root must contain 32 bytes"))?;
        let InstanceVec(instances) = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(4, &self));
        }
        DkgOutput::from_persisted_parts(participant, configuration_root, instances)
            .map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
struct ParticipantRegistryVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for ParticipantRegistryVisitor<G> {
    type Value = ParticipantRegistry<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded participant registry persistence sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let minimum_item_bytes = 4usize.saturating_add(G::ELEMENT_REPR_BYTES).max(1);
        let maximum = MAX_PERSISTED_COLLECTION_BYTES / minimum_item_bytes;
        if seq.size_hint().is_some_and(|hint| hint > maximum) {
            return Err(de::Error::custom(
                "participant registry exceeds persistence allocation bound",
            ));
        }
        let mut entries = Vec::new();
        while let Some(ParticipantElement {
            participant,
            element,
        }) = seq.next_element::<ParticipantElement<G>>()?
        {
            if entries.len() == maximum {
                return Err(de::Error::custom(
                    "participant registry exceeds persistence allocation bound",
                ));
            }
            if entries.iter().any(|(known, _)| *known == participant) {
                return Err(de::Error::custom("duplicate participant in registry"));
            }
            entries.push((participant, element));
        }
        ParticipantRegistry::new(entries).map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
struct KindVec(Vec<DkgInstanceKind>);

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for KindVec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(KindVecVisitor)
    }
}

#[cfg(feature = "serde")]
struct KindVecVisitor;

#[cfg(feature = "serde")]
impl<'de> de::Visitor<'de> for KindVecVisitor {
    type Value = KindVec;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded sequence of DKG instance kinds")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        if seq
            .size_hint()
            .is_some_and(|hint| hint > MAX_PERSISTED_COLLECTION_BYTES)
        {
            return Err(de::Error::custom(
                "DKG instance sequence exceeds persistence allocation bound",
            ));
        }
        let mut instances = Vec::new();
        while let Some(kind) = seq.next_element()? {
            if instances.len() == MAX_PERSISTED_COLLECTION_BYTES {
                return Err(de::Error::custom(
                    "DKG instance sequence exceeds persistence allocation bound",
                ));
            }
            instances.push(kind);
        }
        Ok(KindVec(instances))
    }
}

#[cfg(feature = "serde")]
struct DkgConfigVisitor<G: GoldenGroup>(PhantomData<G>);

#[cfg(feature = "serde")]
impl<'de, G: GoldenGroup> de::Visitor<'de> for DkgConfigVisitor<G> {
    type Value = DkgConfig<G>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a validated Golden DKG configuration persistence tuple")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let threshold = seq
            .next_element::<u64>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))
            .and_then(|value| {
                usize::try_from(value)
                    .map_err(|_| de::Error::custom("threshold does not fit usize"))
            })?;
        let session_id = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let registry = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let KindVec(instances) = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(5, &self));
        }
        DkgConfig::new(threshold, session_id, registry, instances).map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let DecodedPersistenceBytes(bytes) = DecodedPersistenceBytes::deserialize(deserializer)?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| de::Error::custom("session identifier must contain 32 bytes"))
    }
}

#[cfg(feature = "serde")]
impl Serialize for ParticipantIndex {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ParticipantIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        Self::new(u32::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl Serialize for DkgInstanceKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::Random => 0,
            Self::Zero => 1,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for DkgInstanceKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Random),
            1 => Ok(Self::Zero),
            value => Err(de::Error::custom(format!(
                "invalid DKG instance kind {value}"
            ))),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for DealerMessageNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for DealerMessageNonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for EncryptedShare<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for EncryptedShare<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for FeldmanCommitment<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for (participant, public_key) in self.entries() {
            sequence.serialize_element(&ParticipantElementRef::<G> {
                participant,
                element: public_key,
            })?;
        }
        sequence.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for ParticipantRegistry<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_seq(ParticipantRegistryVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for DkgConfig<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let threshold = u64::try_from(self.threshold())
            .map_err(|_| serde::ser::Error::custom("DKG threshold does not fit u64"))?;
        let mut tuple = serializer.serialize_tuple(4)?;
        tuple.serialize_element(&threshold)?;
        tuple.serialize_element(&self.session_id())?;
        tuple.serialize_element(self.registry())?;
        tuple.serialize_element(self.instances())?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DkgConfig<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_tuple(4, DkgConfigVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for DkgInstanceOutput<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&ElementRef::<G>(self.public_key()))?;
        tuple.serialize_element(&ScalarRef::<G>(self.secret_share()))?;
        tuple.serialize_element(&PublicShareMapRef::<G>(self.public_key_shares()))?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DkgInstanceOutput<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_tuple(3, DkgInstanceOutputVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for DkgOutput<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let configuration_root = self.configuration_root();
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&self.participant())?;
        tuple.serialize_element(&PersistenceBytes(&configuration_root))?;
        tuple.serialize_element(self.instances())?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DkgOutput<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_tuple(3, DkgOutputVisitor::<G>(PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for DealerMessage<G>
where
    G: GoldenGroup,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DealerMessage<G>
where
    G: GoldenGroup,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
fn serialize_wire<T, S>(value: &T, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    T: WireMessage,
    S: Serializer,
{
    serializer.serialize_bytes(&to_wire_bytes(value))
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
impl<'de, T> de::Visitor<'de> for WireBytesVisitor<T>
where
    T: WireMessage,
{
    type Value = T;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("canonical Golden DKG wire bytes")
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> core::result::Result<Self::Value, E> {
        from_wire_bytes(value).map_err(|err| E::custom(err.to_string()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> core::result::Result<Self::Value, E> {
        from_wire_bytes(&value).map_err(|err| E::custom(err.to_string()))
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        from_wire_bytes(&bytes).map_err(|err| de::Error::custom(err.to_string()))
    }
}

/// Write a big-endian `u32`.
pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Write a collection length as a big-endian `u64`.
pub fn write_len(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_be_bytes());
}

/// Write one length-delimited codec context field.
pub fn write_context_field(out: &mut Vec<u8>, bytes: &[u8]) {
    write_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Read one length-delimited codec context field and compare it to `expected`.
pub fn expect_context_field(reader: &mut WireReader<'_>, expected: &[u8]) -> Result<()> {
    let len = reader.read_len()?;
    if reader.read_exact(len)? == expected {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// Write a scalar using its canonical Golden representation.
pub fn write_scalar<G: GoldenGroup>(out: &mut Vec<u8>, scalar: &G::Scalar) {
    out.extend_from_slice(scalar.to_repr().as_ref());
}

/// Read a scalar using its canonical Golden representation.
pub fn read_scalar<G: GoldenGroup>(reader: &mut WireReader<'_>) -> Result<G::Scalar> {
    let repr = <G::Scalar as GoldenScalar>::Repr::try_from(
        reader.read_exact(G::Scalar::REPR_BYTES)?.to_vec(),
    )
    .map_err(|_| Error::InvalidEncoding)?;
    G::Scalar::from_repr(&repr)
}

/// Write a group element using its canonical Golden representation.
pub fn write_element<G: GoldenGroup>(out: &mut Vec<u8>, element: &G::Element) {
    out.extend_from_slice(G::encode_element(element).as_ref());
}

/// Read a group element using its canonical Golden representation.
pub fn read_element<G>(reader: &mut WireReader<'_>) -> Result<G::Element>
where
    G: GoldenGroup,
{
    let repr = G::ElementRepr::try_from(reader.read_exact(G::ELEMENT_REPR_BYTES)?.to_vec())
        .map_err(|_| Error::InvalidEncoding)?;
    G::decode_element(&repr)
}

fn ensure_increasing(last: &mut Option<ParticipantIndex>, next: ParticipantIndex) -> Result<()> {
    if last.is_some_and(|previous| previous >= next) {
        return Err(Error::DuplicateParticipantIndex(next.get()));
    }
    *last = Some(next);
    Ok(())
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};

    #[cfg(feature = "serde")]
    struct HostileSizeHintSeq {
        bytes: std::vec::IntoIter<u8>,
    }

    #[cfg(feature = "serde")]
    impl<'de> de::SeqAccess<'de> for HostileSizeHintSeq {
        type Error = de::value::Error;

        fn next_element_seed<T>(
            &mut self,
            seed: T,
        ) -> core::result::Result<Option<T::Value>, Self::Error>
        where
            T: de::DeserializeSeed<'de>,
        {
            self.bytes
                .next()
                .map(|byte| seed.deserialize(de::value::U8Deserializer::<Self::Error>::new(byte)))
                .transpose()
        }

        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    fn element(value: u64) -> TinyScalar {
        TinyGroup::mul_generator(&scalar(value))
    }

    fn registry() -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(vec![
            (idx(3), element(3)),
            (idx(1), element(1)),
            (idx(2), element(2)),
        ])
        .unwrap()
    }

    fn config(kinds: Vec<DkgInstanceKind>) -> DkgConfig<TinyGroup> {
        DkgConfig::new(2, SessionId([7; 32]), registry(), kinds).unwrap()
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    fn instance_output(
        participant: ParticipantIndex,
        constant: u64,
        slope: u64,
    ) -> DkgInstanceOutput<TinyGroup> {
        let public_key_shares = [idx(1), idx(2), idx(3)]
            .into_iter()
            .map(|share_participant| {
                let x = scalar(u64::from(share_participant.get()));
                let value = scalar(constant).add(&scalar(slope).mul(&x));
                (share_participant, TinyGroup::mul_generator(&value))
            })
            .collect::<BTreeMap<_, _>>();
        DkgInstanceOutput::new(
            element(constant),
            public_key_shares[&participant],
            public_key_shares,
        )
    }

    #[cfg(any(feature = "serde", feature = "miden-serde"))]
    fn output() -> DkgOutput<TinyGroup> {
        let participant = idx(2);
        DkgOutput::from_persisted_parts(
            participant,
            [19; 32],
            vec![
                instance_output(participant, 9, 4),
                instance_output(participant, 0, 7),
            ],
        )
        .unwrap()
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_application_values_use_logical_persistence_and_rederive_roots() {
        let participant = idx(3);
        let kind = DkgInstanceKind::Zero;
        let expected = config(vec![DkgInstanceKind::Random, kind]);

        let participant_bytes = postcard::to_allocvec(&participant).unwrap();
        let kind_bytes = postcard::to_allocvec(&kind).unwrap();
        let encoded = postcard::to_allocvec(&expected).unwrap();
        assert!(!encoded.windows(MAGIC.len()).any(|window| window == MAGIC));

        assert_eq!(
            postcard::from_bytes::<ParticipantIndex>(&participant_bytes).unwrap(),
            participant
        );
        assert_eq!(
            postcard::from_bytes::<DkgInstanceKind>(&kind_bytes).unwrap(),
            kind
        );
        let decoded = postcard::from_bytes::<DkgConfig<TinyGroup>>(&encoded).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.registry().root(), expected.registry().root());
        assert_eq!(decoded.root(), expected.root());
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn miden_application_values_use_logical_persistence_and_rederive_roots() {
        use miden_serde_utils::{Deserializable as _, Serializable as _};

        let participant = idx(3);
        let kind = DkgInstanceKind::Zero;
        let expected = config(vec![DkgInstanceKind::Random, kind]);

        let participant_bytes = participant.to_bytes();
        let kind_bytes = kind.to_bytes();
        let encoded = expected.to_bytes();
        assert!(!encoded.windows(MAGIC.len()).any(|window| window == MAGIC));

        assert_eq!(
            ParticipantIndex::read_from_bytes(&participant_bytes).unwrap(),
            participant
        );
        assert_eq!(DkgInstanceKind::read_from_bytes(&kind_bytes).unwrap(), kind);
        let decoded = DkgConfig::<TinyGroup>::read_from_bytes(&encoded).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.registry().root(), expected.registry().root());
        assert_eq!(decoded.root(), expected.root());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_output_values_are_direct_logical_persistence() {
        let expected = output();
        let encoded_instance = postcard::to_allocvec(&expected.instances()[0]).unwrap();
        let encoded_output = postcard::to_allocvec(&expected).unwrap();
        assert!(!encoded_output
            .windows(MAGIC.len())
            .any(|window| window == MAGIC));

        assert_eq!(
            postcard::from_bytes::<DkgInstanceOutput<TinyGroup>>(&encoded_instance).unwrap(),
            expected.instances()[0]
        );
        let decoded = postcard::from_bytes::<DkgOutput<TinyGroup>>(&encoded_output).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.completion_root(), expected.completion_root());
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn miden_output_restoration_rejects_noncanonical_and_inconsistent_state() {
        use miden_serde_utils::{Deserializable as _, Serializable as _};

        let expected = output();
        let mut invalid_point = expected.instances()[0].to_bytes();
        invalid_point[0] = 97;
        assert!(DkgInstanceOutput::<TinyGroup>::read_from_bytes(&invalid_point).is_err());

        let mut invalid_scalar = expected.instances()[0].to_bytes();
        invalid_scalar[1] = 97;
        assert!(DkgInstanceOutput::<TinyGroup>::read_from_bytes(&invalid_scalar).is_err());

        let mut duplicate_participant = expected.instances()[0].to_bytes();
        let first_participant = duplicate_participant[3..7].to_vec();
        duplicate_participant[8..12].copy_from_slice(&first_participant);
        assert!(DkgInstanceOutput::<TinyGroup>::read_from_bytes(&duplicate_participant).is_err());

        let one_instance = DkgOutput::new(
            expected.participant(),
            expected.configuration_root(),
            vec![expected.instances()[0].clone()],
        );
        let mut wrong_local_binding = one_instance.to_bytes();
        wrong_local_binding[38] = wrong_local_binding[44];
        assert!(DkgOutput::<TinyGroup>::read_from_bytes(&wrong_local_binding).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_persistence_rejects_hostile_collection_size_hints_before_allocation() {
        use serde::de::Visitor as _;

        assert!(PersistenceBytesVisitor
            .visit_seq(HostileSizeHintSeq {
                bytes: Vec::new().into_iter(),
            })
            .is_err());
        assert!(KindVecVisitor
            .visit_seq(HostileSizeHintSeq {
                bytes: Vec::new().into_iter(),
            })
            .is_err());
    }

    fn encrypted_share(pad: u64, encrypted: u64) -> EncryptedShare<TinyGroup> {
        EncryptedShare {
            pad_commitment: element(pad),
            encrypted_share: scalar(encrypted),
        }
    }

    fn body(nonce: u8, constant: Option<u64>, receiver_offset: u64) -> DealingBody<TinyGroup> {
        let commitment = match constant {
            Some(constant) => {
                FeldmanCommitment::from_coefficients(vec![element(constant), element(constant + 1)])
                    .unwrap()
            }
            None => FeldmanCommitment::from_zero_tail(Vec::new()),
        };
        DealingBody {
            nonce: DealerMessageNonce([nonce; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([
                (
                    idx(2),
                    encrypted_share(receiver_offset, receiver_offset + 10),
                ),
                (
                    idx(3),
                    encrypted_share(receiver_offset + 1, receiver_offset + 11),
                ),
            ]),
        }
    }

    fn dealer_message() -> DealerMessage<TinyGroup> {
        DealerMessage {
            configuration_root: config(vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]).root(),
            dealer: idx(1),
            dealings: vec![body(0x11, Some(4), 20), body(0x22, None, 40)],
            proof: vec![0, 0xff, 7, 0, 9],
        }
    }

    fn standalone_prefix<T: WireMessage>() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(T::TAG);
        T::write_wire_context(&mut bytes);
        bytes
    }

    fn wrap<T: WireMessage>(nested: &[u8]) -> Vec<u8> {
        let mut bytes = standalone_prefix::<T>();
        bytes.extend_from_slice(nested);
        bytes
    }

    #[test]
    fn wrong_top_level_tag_is_rejected() {
        let nonce = DealerMessageNonce([9u8; 32]);
        let bytes = to_wire_bytes(&nonce);

        assert_eq!(
            from_wire_bytes::<SessionId>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn wrong_top_level_context_is_rejected() {
        let session_id = SessionId([7u8; 32]);
        let mut bytes = to_wire_bytes(&session_id);
        bytes[MAGIC.len() + 1 + 8] ^= 1;

        assert_eq!(
            from_wire_bytes::<SessionId>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn encrypted_share_round_trips() {
        let share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };

        let decoded = from_wire_bytes::<EncryptedShare<TinyGroup>>(&to_wire_bytes(&share)).unwrap();

        assert_eq!(decoded, share);
    }

    #[test]
    fn encrypted_share_rejects_noncanonical_scalar() {
        let share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let mut bytes = to_wire_bytes(&share);
        let last = bytes.len() - 1;
        bytes[last] = 97;

        assert_eq!(
            from_wire_bytes::<EncryptedShare<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn fixed_zero_commitment_round_trips_without_encoding_the_constant() {
        let full =
            FeldmanCommitment::<TinyGroup>::from_coefficients(vec![TinyGroup::identity()]).unwrap();
        let fixed_zero = FeldmanCommitment::<TinyGroup>::from_zero_tail(Vec::new());

        let full_bytes = to_wire_bytes(&full);
        let fixed_zero_bytes = to_wire_bytes(&fixed_zero);
        let decoded = from_wire_bytes::<FeldmanCommitment<TinyGroup>>(&fixed_zero_bytes).unwrap();

        assert_eq!(decoded, fixed_zero);
        assert_eq!(
            full_bytes.len() - fixed_zero_bytes.len(),
            TinyGroup::ELEMENT_REPR_BYTES
        );
    }

    #[test]
    fn registry_round_trips_and_rejects_non_increasing_participants() {
        let registry = ParticipantRegistry::<TinyGroup>::new(vec![
            (idx(1), TinyScalar::from_u64(11).unwrap()),
            (idx(2), TinyScalar::from_u64(12).unwrap()),
        ])
        .unwrap();
        let bytes = to_wire_bytes(&registry);

        assert_eq!(
            from_wire_bytes::<ParticipantRegistry<TinyGroup>>(&bytes).unwrap(),
            registry
        );

        let mut nested = registry.to_nested_wire_bytes();
        nested[11] = 2;
        nested[16] = 1;
        let mut top_level = Vec::new();
        top_level.extend_from_slice(MAGIC);
        top_level.push(TAG_PARTICIPANT_REGISTRY);
        <ParticipantRegistry<TinyGroup> as WireMessage>::write_wire_context(&mut top_level);
        top_level.extend_from_slice(&nested);

        assert_eq!(
            from_wire_bytes::<ParticipantRegistry<TinyGroup>>(&top_level).unwrap_err(),
            Error::DuplicateParticipantIndex(1)
        );
    }

    fn assert_all_truncations_rejected<T: WireMessage>(bytes: &[u8]) {
        for end in 0..bytes.len() {
            assert!(
                from_wire_bytes::<T>(&bytes[..end]).is_err(),
                "accepted truncation at byte {end}"
            );
        }
    }

    #[test]
    fn random_zero_and_mixed_configs_round_trip() {
        assert_eq!(MAGIC, b"golden-dkg-wire-v4");
        assert_eq!(
            <DkgConfig<TinyGroup> as WireMessage>::CODEC_ID,
            "dkg-config-v3"
        );
        assert_eq!(
            <DealerMessage<TinyGroup> as WireMessage>::CODEC_ID,
            "dealer-message-v4"
        );

        for kinds in [
            vec![DkgInstanceKind::Random],
            vec![DkgInstanceKind::Zero],
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
            vec![DkgInstanceKind::Zero, DkgInstanceKind::Random],
        ] {
            let expected = config(kinds.clone());
            let decoded =
                from_wire_bytes::<DkgConfig<TinyGroup>>(&to_wire_bytes(&expected)).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.instances(), kinds);
            assert_eq!(decoded.root(), expected.root());
        }
    }

    #[test]
    fn config_wire_grammar_contains_only_final_configuration_fields() {
        let expected = config(vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
        let encoded = to_wire_bytes(&expected);
        let mut expected_nested = Vec::new();
        write_len(&mut expected_nested, expected.threshold());
        expected.session_id().write_wire(&mut expected_nested);
        expected.registry().write_wire(&mut expected_nested);
        write_len(&mut expected_nested, expected.instances().len());
        for kind in expected.instances() {
            kind.write_wire(&mut expected_nested);
        }

        assert_eq!(encoded, wrap::<DkgConfig<TinyGroup>>(&expected_nested));
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn dealer_message_preserves_body_order_proof_bytes_and_derived_root() {
        let message = dealer_message();
        let encoded = to_wire_bytes(&message);
        let decoded = from_wire_bytes::<DealerMessage<TinyGroup>>(&encoded).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.dealings[0].nonce, DealerMessageNonce([0x11; 32]));
        assert_eq!(decoded.dealings[1].nonce, DealerMessageNonce([0x22; 32]));
        assert_eq!(decoded.proof, [0, 0xff, 7, 0, 9]);
        assert_eq!(decoded.root(), message.root());

        // The nested encoding contains exactly the canonical fields. There is
        // no serialized claimed dealer-message root between body data and proof.
        let mut expected_nested = Vec::new();
        message.configuration_root.write_wire(&mut expected_nested);
        message.dealer.write_wire(&mut expected_nested);
        write_len(&mut expected_nested, message.dealings.len());
        for dealing in &message.dealings {
            dealing.write_wire(&mut expected_nested);
        }
        write_len(&mut expected_nested, message.proof.len());
        expected_nested.extend_from_slice(&message.proof);
        assert_eq!(encoded, wrap::<DealerMessage<TinyGroup>>(&expected_nested));
    }

    #[test]
    fn configuration_order_is_canonical_and_root_sensitive() {
        let random_zero = config(vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
        let zero_random = config(vec![DkgInstanceKind::Zero, DkgInstanceKind::Random]);
        assert_ne!(to_wire_bytes(&random_zero), to_wire_bytes(&zero_random));
        assert_ne!(random_zero.root(), zero_random.root());

        let decoded =
            from_wire_bytes::<DkgConfig<TinyGroup>>(&to_wire_bytes(&random_zero)).unwrap();
        assert_eq!(
            decoded.registry().indexes().collect::<Vec<_>>(),
            vec![idx(1), idx(2), idx(3)]
        );
    }

    #[test]
    fn config_rejects_empty_invalid_kind_and_malformed_instance_lengths() {
        let expected = config(vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
        let mut bytes = to_wire_bytes(&expected);
        let kind_count_offset = bytes.len() - expected.instances().len() - 8;

        let mut empty = bytes[..kind_count_offset + 8].to_vec();
        empty[kind_count_offset..kind_count_offset + 8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&empty).unwrap_err(),
            Error::EmptyDkgBatch
        );

        let last = bytes.len() - 1;
        bytes[last] = 0xff;
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );

        let mut oversized = to_wire_bytes(&expected);
        oversized[kind_count_offset..kind_count_offset + 8].copy_from_slice(&3u64.to_be_bytes());
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&oversized).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn wrong_magic_codec_tag_and_trailing_bytes_are_rejected() {
        let expected = config(vec![DkgInstanceKind::Random]);
        let bytes = to_wire_bytes(&expected);

        let mut wrong_magic = bytes.clone();
        wrong_magic[MAGIC.len() - 1] = b'3';
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&wrong_magic).unwrap_err(),
            Error::InvalidEncoding
        );

        let mut wrong_tag = bytes.clone();
        wrong_tag[MAGIC.len()] = TAG_DEALER_MESSAGE;
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&wrong_tag).unwrap_err(),
            Error::InvalidEncoding
        );

        let mut wrong_codec = bytes.clone();
        let codec_first_byte = MAGIC.len() + 1 + 8;
        wrong_codec[codec_first_byte] ^= 1;
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&wrong_codec).unwrap_err(),
            Error::InvalidEncoding
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&trailing).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn noncanonical_config_registry_element_is_rejected() {
        let expected = config(vec![DkgInstanceKind::Random]);
        let payload = standalone_prefix::<DkgConfig<TinyGroup>>().len();
        let mut bytes = to_wire_bytes(&expected);
        let first_registry_element = payload + 8 + 32 + 8 + 4;
        bytes[first_registry_element] = 97;
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn invalid_threshold_and_hostile_collection_lengths_are_rejected() {
        let expected = config(vec![DkgInstanceKind::Random]);
        let payload = standalone_prefix::<DkgConfig<TinyGroup>>().len();
        let mut zero_threshold = to_wire_bytes(&expected);
        zero_threshold[payload..payload + 8].copy_from_slice(&0u64.to_be_bytes());
        assert!(matches!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&zero_threshold),
            Err(Error::InvalidThreshold { .. })
        ));

        let mut empty_registry = to_wire_bytes(&expected);
        let registry_len = payload + 8 + 32;
        empty_registry[registry_len..registry_len + 8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&empty_registry).unwrap_err(),
            Error::EmptyParticipantRegistry
        );

        let mut hostile = to_wire_bytes(&expected);
        let kind_count_offset = hostile.len() - expected.instances().len() - 8;
        hostile[kind_count_offset..kind_count_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&hostile).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn dealer_message_rejects_zero_or_impossible_dealing_dimensions() {
        let message = dealer_message();
        let payload = standalone_prefix::<DealerMessage<TinyGroup>>().len();
        let dealing_count_offset = payload + 32 + 4;

        let mut zero = Vec::new();
        message.configuration_root.write_wire(&mut zero);
        message.dealer.write_wire(&mut zero);
        write_len(&mut zero, 0);
        write_len(&mut zero, 0);
        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&wrap::<DealerMessage<TinyGroup>>(&zero))
                .unwrap_err(),
            Error::InvalidEncoding
        );

        let mut hostile = to_wire_bytes(&message);
        hostile[dealing_count_offset..dealing_count_offset + 8]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&hostile).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn dealer_message_rejects_oversized_proof_before_reading_it() {
        let message = dealer_message();
        let mut nested = Vec::new();
        message.configuration_root.write_wire(&mut nested);
        message.dealer.write_wire(&mut nested);
        write_len(&mut nested, message.dealings.len());
        for dealing in &message.dealings {
            dealing.write_wire(&mut nested);
        }
        write_len(&mut nested, MAX_DEALER_PROOF_BYTES + 1);

        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&wrap::<DealerMessage<TinyGroup>>(&nested))
                .unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_byte_sequence_ignores_hostile_size_hint() {
        use serde::de::Visitor as _;

        let expected = SessionId([42; 32]);
        let decoded = WireBytesVisitor::<SessionId>(PhantomData)
            .visit_seq(HostileSizeHintSeq {
                bytes: to_wire_bytes(&expected).into_iter(),
            })
            .unwrap();
        assert_eq!(decoded, expected);

        let empty = WireBytesVisitor::<SessionId>(PhantomData).visit_seq(HostileSizeHintSeq {
            bytes: Vec::new().into_iter(),
        });
        assert!(empty.is_err());
    }

    #[test]
    fn malformed_nested_body_dimensions_and_receiver_order_are_rejected() {
        let message = dealer_message();
        let mut nested = Vec::new();
        message.configuration_root.write_wire(&mut nested);
        message.dealer.write_wire(&mut nested);
        write_len(&mut nested, 1);
        DealerMessageNonce([1; 32]).write_wire(&mut nested);
        nested.push(2);
        write_len(&mut nested, 0);
        write_len(&mut nested, 0);
        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&wrap::<DealerMessage<TinyGroup>>(&nested))
                .unwrap_err(),
            Error::InvalidEncoding
        );

        let mut nested = Vec::new();
        message.configuration_root.write_wire(&mut nested);
        message.dealer.write_wire(&mut nested);
        write_len(&mut nested, 1);
        DealerMessageNonce([1; 32]).write_wire(&mut nested);
        FeldmanCommitment::<TinyGroup>::from_coefficients(vec![element(4)])
            .unwrap()
            .write_wire(&mut nested);
        write_len(&mut nested, 2);
        idx(3).write_wire(&mut nested);
        encrypted_share(1, 2).write_wire(&mut nested);
        idx(2).write_wire(&mut nested);
        encrypted_share(2, 3).write_wire(&mut nested);
        write_len(&mut nested, 0);
        assert!(matches!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&wrap::<DealerMessage<TinyGroup>>(&nested)),
            Err(Error::DuplicateParticipantIndex(2))
        ));
    }

    #[test]
    fn aggregate_wire_values_reject_every_truncation() {
        assert_all_truncations_rejected::<DkgConfig<TinyGroup>>(&to_wire_bytes(&config(vec![
            DkgInstanceKind::Random,
            DkgInstanceKind::Zero,
        ])));
        assert_all_truncations_rejected::<DealerMessage<TinyGroup>>(&to_wire_bytes(
            &dealer_message(),
        ));
    }
}
