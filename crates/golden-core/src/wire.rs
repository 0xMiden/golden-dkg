//! Canonical byte encoding for Golden DKG wire messages.
//!
//! Top-level wire messages start with [`MAGIC`] followed by a one-byte type
//! tag. Nested fields omit that prefix and are encoded in the order documented
//! by each type's [`WireEncode`] implementation.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use core::marker::PhantomData;
#[cfg(feature = "miden-serde")]
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    DealerMessage, DealerMessageNonce, DkgConfig, EncryptedShare, Error, FeldmanCommitment,
    GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, Result, SessionId,
    TranscriptRoot,
};

/// Magic prefix for every top-level DKG wire message.
pub const MAGIC: &[u8; 18] = b"golden-dkg-wire-v1";

/// Top-level tag for [`SessionId`].
pub const TAG_SESSION_ID: u8 = 0x01;
/// Top-level tag for [`DealerMessageNonce`].
pub const TAG_DEALER_MESSAGE_NONCE: u8 = 0x02;
/// Top-level tag for [`EncryptedShare`].
pub const TAG_ENCRYPTED_SHARE: u8 = 0x03;
/// Top-level tag for [`FeldmanCommitment`].
pub const TAG_FELDMAN_COMMITMENT: u8 = 0x04;
/// Top-level tag for [`ParticipantRegistry`].
pub const TAG_PARTICIPANT_REGISTRY: u8 = 0x05;
/// Top-level tag for [`DkgConfig`].
pub const TAG_DKG_CONFIG: u8 = 0x06;
/// Top-level tag for [`DealerMessage`].
pub const TAG_DEALER_MESSAGE: u8 = 0x07;
/// Top-level tag for opaque proof bytes.
pub const TAG_PROOF_BYTES: u8 = 0x08;
/// Top-level tag for prototype share-opening batch proofs.
pub const TAG_SHARE_OPENING_BATCHED_PROOF: u8 = 0x09;

/// Encode a value into its nested canonical wire representation.
pub trait WireEncode {
    /// Write this value without a top-level magic or tag prefix.
    fn write_wire(&self, out: &mut Vec<u8>);

    /// Return this value's nested wire bytes.
    fn to_nested_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_wire(&mut out);
        out
    }
}

/// Decode a value from its nested canonical wire representation.
pub trait WireDecode: Sized {
    /// Read this value without a top-level magic or tag prefix.
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self>;
}

/// A top-level wire message with a stable tag.
pub trait WireMessage: WireEncode + WireDecode {
    /// Top-level type tag.
    const TAG: u8;
}

/// Return a top-level canonical wire message.
pub fn to_wire_bytes<T: WireMessage>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(T::TAG);
    value.write_wire(&mut out);
    out
}

/// Decode a top-level canonical wire message and reject trailing bytes.
pub fn from_wire_bytes<T: WireMessage>(bytes: &[u8]) -> Result<T> {
    let mut reader = WireReader::new(bytes);
    reader.expect_magic()?;
    let tag = reader.read_u8()?;
    if tag != T::TAG {
        return Err(Error::InvalidEncoding);
    }
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

    /// Read and validate the top-level magic prefix.
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
        write_element::<G>(out, &self.dh_commitment);
        write_scalar::<G>(out, &self.encrypted_share);
    }
}

impl<G> WireDecode for EncryptedShare<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self {
            pad_commitment: read_element::<G>(reader)?,
            dh_commitment: read_element::<G>(reader)?,
            encrypted_share: read_scalar::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for EncryptedShare<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_ENCRYPTED_SHARE;
}

impl<G: GoldenGroup> WireEncode for FeldmanCommitment<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.coefficients().len());
        for coefficient in self.coefficients() {
            write_element::<G>(out, coefficient);
        }
    }
}

impl<G> WireDecode for FeldmanCommitment<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let len = reader.read_len()?;
        reader.ensure_remaining_items(len, G::encode_element(&G::identity()).as_ref().len())?;
        let mut coefficients = Vec::with_capacity(len);
        for _ in 0..len {
            coefficients.push(read_element::<G>(reader)?);
        }
        Self::from_coefficients(coefficients)
    }
}

impl<G> WireMessage for FeldmanCommitment<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_FELDMAN_COMMITMENT;
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let len = reader.read_len()?;
        let entry_len = 4 + G::encode_element(&G::identity()).as_ref().len();
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_PARTICIPANT_REGISTRY;
}

impl<G: GoldenGroup> WireEncode for DkgConfig<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.threshold);
        self.session_id.write_wire(out);
        write_scalar::<G>(out, &self.beta);
        self.registry.write_wire(out);
    }
}

impl<G> WireDecode for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let threshold = reader.read_len()?;
        let session_id = SessionId::read_wire(reader)?;
        let beta = read_scalar::<G>(reader)?;
        let registry = ParticipantRegistry::read_wire(reader)?;
        Self::new(threshold, session_id, beta, registry)
    }
}

impl<G> WireMessage for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_DKG_CONFIG;
}

impl<G, P> WireEncode for DealerMessage<G, P>
where
    G: GoldenGroup,
    P: WireEncode,
{
    fn write_wire(&self, out: &mut Vec<u8>) {
        self.session_id.write_wire(out);
        self.registry_root.write_wire(out);
        self.dealer.write_wire(out);
        self.msg_i.write_wire(out);
        self.commitment.write_wire(out);
        write_len(out, self.encrypted_shares.len());
        for (receiver, encrypted_share) in &self.encrypted_shares {
            receiver.write_wire(out);
            encrypted_share.write_wire(out);
        }
        self.proof.write_wire(out);
        self.transcript_root.write_wire(out);
    }
}

impl<G, P> WireDecode for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireDecode,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let session_id = SessionId::read_wire(reader)?;
        let registry_root = TranscriptRoot::read_wire(reader)?;
        let dealer = ParticipantIndex::read_wire(reader)?;
        let msg_i = DealerMessageNonce::read_wire(reader)?;
        let commitment = FeldmanCommitment::<G>::read_wire(reader)?;
        let len = reader.read_len()?;
        let encrypted_share_len = 4
            + 2 * G::encode_element(&G::identity()).as_ref().len()
            + G::Scalar::zero().to_repr().as_ref().len();
        reader.ensure_remaining_items(len, encrypted_share_len)?;
        let mut encrypted_shares = BTreeMap::new();
        let mut last = None;
        for _ in 0..len {
            let receiver = ParticipantIndex::read_wire(reader)?;
            ensure_increasing(&mut last, receiver)?;
            encrypted_shares.insert(receiver, EncryptedShare::<G>::read_wire(reader)?);
        }
        let proof = P::read_wire(reader)?;
        let transcript_root = TranscriptRoot::read_wire(reader)?;
        Ok(Self {
            session_id,
            registry_root,
            dealer,
            msg_i,
            commitment,
            encrypted_shares,
            proof,
            transcript_root,
        })
    }
}

impl<G, P> WireMessage for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireEncode + WireDecode,
{
    const TAG: u8 = TAG_DEALER_MESSAGE;
}

impl WireEncode for Vec<u8> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.len());
        out.extend_from_slice(self);
    }
}

impl WireDecode for Vec<u8> {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let len = reader.read_len()?;
        Ok(reader.read_exact(len)?.to_vec())
    }
}

impl WireMessage for Vec<u8> {
    const TAG: u8 = TAG_PROOF_BYTES;
}

#[cfg(feature = "miden-serde")]
impl Serializable for SessionId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl Deserializable for SessionId {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for ParticipantRegistry<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Serializable for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G> Deserializable for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
impl<G, P> Serializable for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireEncode + WireDecode,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_miden_wire(self, target);
    }

    fn get_size_hint(&self) -> usize {
        miden_wire_size_hint(self)
    }
}

#[cfg(feature = "miden-serde")]
impl<G, P> Deserializable for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireEncode + WireDecode,
{
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> core::result::Result<Self, DeserializationError> {
        read_miden_wire(source)
    }
}

#[cfg(feature = "miden-serde")]
/// Write a length-delimited top-level wire message into a Miden byte writer.
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
/// Read a length-delimited top-level wire message from a Miden byte reader.
pub fn read_miden_wire<T, R>(source: &mut R) -> core::result::Result<T, DeserializationError>
where
    T: WireMessage,
    R: ByteReader,
{
    let len = source.read_usize()?;
    let bytes = source.read_vec(len)?;
    from_wire_bytes(&bytes).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
}

#[cfg(feature = "miden-serde")]
/// Return the serialized size hint for a length-delimited Miden wire message.
pub fn miden_wire_size_hint<T: WireMessage>(value: &T) -> usize {
    let len = to_wire_bytes(value).len();
    miden_usize_size(len) + len
}

#[cfg(feature = "miden-serde")]
fn miden_usize_size(value: usize) -> usize {
    let zeros = (value as u64).leading_zeros() as usize;
    let len = zeros.saturating_sub(1) / 7;
    9 - core::cmp::min(len, 8)
}

#[cfg(feature = "serde")]
impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for EncryptedShare<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for FeldmanCommitment<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for FeldmanCommitment<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for ParticipantRegistry<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for ParticipantRegistry<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G> Serialize for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserialize_wire(deserializer)
    }
}

#[cfg(feature = "serde")]
impl<G, P> Serialize for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireEncode + WireDecode,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G, P> Deserialize<'de> for DealerMessage<G, P>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
    P: WireEncode + WireDecode,
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
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
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

/// Write a scalar using its canonical Golden representation.
pub fn write_scalar<G: GoldenGroup>(out: &mut Vec<u8>, scalar: &G::Scalar) {
    out.extend_from_slice(scalar.to_repr().as_ref());
}

/// Read a scalar using its canonical Golden representation.
pub fn read_scalar<G: GoldenGroup>(reader: &mut WireReader<'_>) -> Result<G::Scalar> {
    let repr_len = G::Scalar::zero().to_repr().as_ref().len();
    let repr = <G::Scalar as GoldenScalar>::Repr::try_from(reader.read_exact(repr_len)?.to_vec())
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    let repr_len = G::encode_element(&G::identity()).as_ref().len();
    let repr = G::ElementRepr::try_from(reader.read_exact(repr_len)?.to_vec())
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
mod tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::GoldenScalar;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    #[test]
    fn session_id_top_level_round_trips_and_rejects_trailing_bytes() {
        let session_id = SessionId([7u8; 32]);
        let bytes = to_wire_bytes(&session_id);

        assert_eq!(from_wire_bytes::<SessionId>(&bytes).unwrap(), session_id);

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            from_wire_bytes::<SessionId>(&trailing).unwrap_err(),
            Error::InvalidEncoding
        );
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
    fn encrypted_share_round_trips() {
        let share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            dh_commitment: TinyScalar::from_u64(3).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };

        let decoded = from_wire_bytes::<EncryptedShare<TinyGroup>>(&to_wire_bytes(&share)).unwrap();

        assert_eq!(decoded, share);
    }

    #[test]
    fn encrypted_share_rejects_noncanonical_scalar() {
        let share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            dh_commitment: TinyScalar::from_u64(3).unwrap(),
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
        top_level.extend_from_slice(&nested);

        assert_eq!(
            from_wire_bytes::<ParticipantRegistry<TinyGroup>>(&top_level).unwrap_err(),
            Error::DuplicateParticipantIndex(1)
        );
    }

    #[test]
    fn dealer_message_preserves_transcript_root() {
        let commitment = FeldmanCommitment::<TinyGroup>::from_coefficients(vec![
            TinyScalar::from_u64(10).unwrap(),
            TinyScalar::from_u64(20).unwrap(),
        ])
        .unwrap();
        let encrypted_share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            dh_commitment: TinyScalar::from_u64(3).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let message = DealerMessage::<TinyGroup, Vec<u8>> {
            session_id: SessionId([1u8; 32]),
            registry_root: [2u8; 32],
            dealer: idx(1),
            msg_i: DealerMessageNonce([3u8; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([(idx(2), encrypted_share)]),
            proof: vec![4, 5, 6],
            transcript_root: [7u8; 32],
        };

        let decoded =
            from_wire_bytes::<DealerMessage<TinyGroup, Vec<u8>>>(&to_wire_bytes(&message)).unwrap();

        assert_eq!(decoded, message);
        assert_eq!(decoded.transcript_root, [7u8; 32]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_canonical_wire_bytes() {
        use serde_test::{assert_de_tokens, assert_tokens, Token};

        let session_id = SessionId([11u8; 32]);
        let bytes: &'static [u8] = Box::leak(to_wire_bytes(&session_id).into_boxed_slice());

        assert_tokens(&session_id, &[Token::Bytes(bytes)]);

        let mut seq = Vec::with_capacity(bytes.len() + 2);
        seq.push(Token::Seq {
            len: Some(bytes.len()),
        });
        seq.extend(bytes.iter().copied().map(Token::U8));
        seq.push(Token::SeqEnd);

        assert_de_tokens(&session_id, &seq);
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn miden_serde_uses_canonical_wire_bytes() {
        use miden_serde_utils::{Deserializable, Serializable, SliceReader};

        let session_id = SessionId([12u8; 32]);
        let bytes = session_id.to_bytes();
        let wire_bytes = to_wire_bytes(&session_id);

        assert!(bytes.ends_with(&wire_bytes));
        assert_eq!(SessionId::read_from_bytes(&bytes).unwrap(), session_id);

        let other = SessionId([13u8; 32]);
        let mut adjacent = Vec::new();
        session_id.write_into(&mut adjacent);
        other.write_into(&mut adjacent);
        let mut reader = SliceReader::new(&adjacent);

        assert_eq!(SessionId::read_from(&mut reader).unwrap(), session_id);
        assert_eq!(SessionId::read_from(&mut reader).unwrap(), other);
    }
}
