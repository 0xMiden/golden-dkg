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
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    DealerMessage, DealerMessageNonce, DealingBody, DkgConfig, DkgInstanceKind, EncryptedShare,
    Error, FeldmanCommitment, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry,
    Result, SessionId, TranscriptRoot,
};

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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
        write_scalar::<G>(out, self.beta());
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
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let threshold = reader.read_len()?;
        let session_id = SessionId::read_wire(reader)?;
        let beta = read_scalar::<G>(reader)?;
        let registry = ParticipantRegistry::read_wire(reader)?;
        let instance_count = reader.read_len()?;
        reader.ensure_remaining_items(instance_count, 1)?;
        let mut instances = Vec::with_capacity(instance_count);
        for _ in 0..instance_count {
            instances.push(DkgInstanceKind::read_wire(reader)?);
        }
        Self::batch(threshold, session_id, beta, registry, instances)
    }
}

impl<G> WireMessage for DkgConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_DKG_CONFIG;
    const CODEC_ID: &'static str = "dkg-config-v2";

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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
impl<G> Serializable for DealerMessage<G>
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
impl<G> Deserializable for DealerMessage<G>
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
impl<G> Serialize for DealerMessage<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for DealerMessage<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
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
    G::ElementRepr: TryFrom<Vec<u8>>,
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
        DkgConfig::batch(2, SessionId([7; 32]), scalar(9), registry(), kinds).unwrap()
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
            "dkg-config-v2"
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
    fn noncanonical_config_scalar_and_registry_element_are_rejected() {
        let expected = config(vec![DkgInstanceKind::Random]);
        let mut bytes = to_wire_bytes(&expected);
        let payload = standalone_prefix::<DkgConfig<TinyGroup>>().len();
        let beta_offset = payload + 8 + 32;
        bytes[beta_offset] = 97;
        assert_eq!(
            from_wire_bytes::<DkgConfig<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );

        let mut bytes = to_wire_bytes(&expected);
        let first_registry_element = payload + 8 + 32 + TinyScalar::REPR_BYTES + 8 + 4;
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
