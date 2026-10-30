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
    DealerMessage, DealerMessageNonce, DkgConfig, EncryptedShare, Error, FeldmanCommitment,
    GoldenGroup, GoldenScalar, IdentityKeyProof, ParticipantIndex, ParticipantRegistry,
    ReshareConfig, ResharePredecessor, Result, SessionId, TranscriptRoot,
};

/// Magic prefix for every standalone DKG wire value.
pub const MAGIC: &[u8; 18] = b"golden-dkg-wire-v3";

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
/// Standalone tag for [`IdentityKeyProof`].
pub const TAG_IDENTITY_KEY_PROOF: u8 = 0x08;
/// Standalone tag for [`ReshareConfig`].
pub const TAG_RESHARE_CONFIG: u8 = 0x09;

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
        reader.ensure_remaining_items(len, G::ELEMENT_REPR_BYTES)?;
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

impl<G: GoldenGroup> WireEncode for IdentityKeyProof<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_element::<G>(out, &self.nonce_point);
        write_scalar::<G>(out, &self.response);
    }
}

impl<G> WireDecode for IdentityKeyProof<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self {
            nonce_point: read_element::<G>(reader)?,
            response: read_scalar::<G>(reader)?,
        })
    }
}

impl<G> WireMessage for IdentityKeyProof<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_IDENTITY_KEY_PROOF;
    const CODEC_ID: &'static str = "identity-key-proof-v1";

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
        for (participant, public_key, proof) in self.entries_with_proofs() {
            participant.write_wire(out);
            write_element::<G>(out, public_key);
            proof.write_wire(out);
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
        let entry_len = 4 + 2 * G::ELEMENT_REPR_BYTES + G::Scalar::REPR_BYTES;
        reader.ensure_remaining_items(len, entry_len)?;
        let mut entries = Vec::with_capacity(len);
        let mut last = None;
        for _ in 0..len {
            let participant = ParticipantIndex::read_wire(reader)?;
            ensure_increasing(&mut last, participant)?;
            let public_key = read_element::<G>(reader)?;
            let proof = IdentityKeyProof::<G>::read_wire(reader)?;
            entries.push((participant, public_key, proof));
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
    const CODEC_ID: &'static str = "participant-registry-v2";

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

/// Write the predecessor field of a reshare configuration.
fn write_predecessor<G: GoldenGroup>(out: &mut Vec<u8>, predecessor: &ResharePredecessor<G>) {
    write_len(out, predecessor.threshold());
    write_element::<G>(out, predecessor.public_key());
    write_len(out, predecessor.public_key_shares().len());
    for (participant, share) in predecessor.public_key_shares() {
        participant.write_wire(out);
        write_element::<G>(out, share);
    }
    predecessor.completion_root().write_wire(out);
}

/// Read and validate the predecessor field of a reshare configuration.
fn read_predecessor<G>(reader: &mut WireReader<'_>) -> Result<ResharePredecessor<G>>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    let threshold = reader.read_len()?;
    let public_key = read_element::<G>(reader)?;
    let len = reader.read_len()?;
    reader.ensure_remaining_items(len, 4 + G::ELEMENT_REPR_BYTES)?;
    let mut public_key_shares = BTreeMap::new();
    let mut last = None;
    for _ in 0..len {
        let participant = ParticipantIndex::read_wire(reader)?;
        ensure_increasing(&mut last, participant)?;
        public_key_shares.insert(participant, read_element::<G>(reader)?);
    }
    let completion_root = TranscriptRoot::read_wire(reader)?;
    ResharePredecessor::new(threshold, public_key, public_key_shares, completion_root)
}

impl<G: GoldenGroup> WireEncode for ReshareConfig<G> {
    fn write_wire(&self, out: &mut Vec<u8>) {
        write_len(out, self.threshold());
        write_len(out, self.max_corrupt_receivers());
        self.session_id().write_wire(out);
        write_scalar::<G>(out, self.beta());
        self.dealers().write_wire(out);
        self.receivers().write_wire(out);
        write_predecessor::<G>(out, self.predecessor());
    }
}

impl<G> WireDecode for ReshareConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let threshold = reader.read_len()?;
        let max_corrupt_receivers = reader.read_len()?;
        let session_id = SessionId::read_wire(reader)?;
        let beta = read_scalar::<G>(reader)?;
        let dealers = ParticipantRegistry::read_wire(reader)?;
        let receivers = ParticipantRegistry::read_wire(reader)?;
        let predecessor = read_predecessor::<G>(reader)?;
        Self::new(
            threshold,
            max_corrupt_receivers,
            session_id,
            beta,
            dealers,
            receivers,
            predecessor,
        )
    }
}

impl<G> WireMessage for ReshareConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_RESHARE_CONFIG;
    const CODEC_ID: &'static str = "reshare-config-v1";

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
        write_len(out, self.proof.len());
        out.extend_from_slice(&self.proof);
    }

    fn wire_size_hint(&self) -> usize {
        let encrypted_share_len = 4 + G::ELEMENT_REPR_BYTES + G::Scalar::REPR_BYTES;
        32 // session_id
            + 32 // registry_root
            + 4 // dealer
            + 32 // msg_i
            + 8 + self.commitment.coefficients().len() * G::ELEMENT_REPR_BYTES // commitment
            + 8 + self.encrypted_shares.len() * encrypted_share_len // encrypted_shares
            + 8 + self.proof.len() // proof
    }
}

impl<G> WireDecode for DealerMessage<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        let session_id = SessionId::read_wire(reader)?;
        let registry_root = TranscriptRoot::read_wire(reader)?;
        let dealer = ParticipantIndex::read_wire(reader)?;
        let msg_i = DealerMessageNonce::read_wire(reader)?;
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
        let proof_len = reader.read_len()?;
        let proof = reader.read_exact(proof_len)?.to_vec();
        let mut message = Self {
            session_id,
            registry_root,
            dealer,
            msg_i,
            commitment,
            encrypted_shares,
            proof,
            transcript_root: [0u8; 32],
        };
        message.transcript_root = message.recompute_transcript_root();
        Ok(message)
    }
}

impl<G> WireMessage for DealerMessage<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    const TAG: u8 = TAG_DEALER_MESSAGE;
    const CODEC_ID: &'static str = "dealer-message-v3";

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
impl<G> Serializable for IdentityKeyProof<G>
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
impl<G> Deserializable for IdentityKeyProof<G>
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
impl<G> Serializable for ReshareConfig<G>
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
impl<G> Deserializable for ReshareConfig<G>
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
impl<G> Serialize for IdentityKeyProof<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for IdentityKeyProof<G>
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
impl<G> Serialize for ReshareConfig<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serialize_wire(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G> Deserialize<'de> for ReshareConfig<G>
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
mod tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};
    use crate::GoldenScalar;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn dealer_message() -> DealerMessage<TinyGroup> {
        let commitment = FeldmanCommitment::<TinyGroup>::from_coefficients(vec![
            TinyScalar::from_u64(10).unwrap(),
            TinyScalar::from_u64(20).unwrap(),
        ])
        .unwrap();
        let encrypted_share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let mut message = DealerMessage::<TinyGroup> {
            session_id: SessionId([1u8; 32]),
            registry_root: [2u8; 32],
            dealer: idx(1),
            msg_i: DealerMessageNonce([3u8; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([(idx(2), encrypted_share)]),
            proof: vec![4, 5, 6],
            transcript_root: [0u8; 32],
        };
        message.transcript_root = message.recompute_transcript_root();
        message
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
    fn old_wire_magic_is_rejected() {
        let session_id = SessionId([7u8; 32]);
        let mut bytes = to_wire_bytes(&session_id);
        bytes[MAGIC.len() - 1] = b'1';

        assert_eq!(
            from_wire_bytes::<SessionId>(&bytes).unwrap_err(),
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

    fn registry_entry(
        participant: ParticipantIndex,
        identity_secret: u64,
    ) -> (ParticipantIndex, TinyScalar, IdentityKeyProof<TinyGroup>) {
        let identity_secret = TinyScalar::from_u64(identity_secret).unwrap();
        (
            participant,
            TinyGroup::mul_generator(&identity_secret),
            IdentityKeyProof::prove(&identity_secret).unwrap(),
        )
    }

    // Fixed fields, including valid proofs for identity secrets 11 and 12.
    // Do not regenerate these with the prover or wire encoder: these fixtures
    // must catch matching changes to the encoder and decoder.
    fn fixed_registry() -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(
            [(1, 11, 9, 25), (0x0102_0304, 12, 62, 95)]
                .into_iter()
                .map(|(participant, public_key, nonce_point, response)| {
                    (
                        idx(participant),
                        TinyScalar::from_u64(public_key).unwrap(),
                        IdentityKeyProof {
                            nonce_point: TinyScalar::from_u64(nonce_point).unwrap(),
                            response: TinyScalar::from_u64(response).unwrap(),
                        },
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn participant_registry_v2_fixed_wire_vector() {
        let bytes = concat!(
            "golden-dkg-wire-v3\x05", // Magic and registry tag.
            "\x00\x00\x00\x00\x00\x00\x00\x17participant-registry-v2",
            "\x00\x00\x00\x00\x00\x00\x00\x13golden-test-tiny-v1",
            "\x00\x00\x00\x00\x00\x00\x00\x02", // Entry count.
            "\x00\x00\x00\x01\x0b\x09\x19",     // Index, key, nonce point, response.
            "\x01\x02\x03\x04\x0c\x3e\x5f",
        )
        .as_bytes();
        let expected = fixed_registry();

        let decoded = from_wire_bytes::<ParticipantRegistry<TinyGroup>>(bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(to_wire_bytes(&expected), bytes);
    }

    #[test]
    fn dkg_config_v2_fixed_wire_vector() {
        let bytes = concat!(
            "golden-dkg-wire-v3\x06", // Magic and config tag.
            "\x00\x00\x00\x00\x00\x00\x00\x0ddkg-config-v2",
            "\x00\x00\x00\x00\x00\x00\x00\x13golden-test-tiny-v1",
            "\x00\x00\x00\x00\x00\x00\x00\x01", // Threshold.
            "0123456789abcdef0123456789abcdef", // Session ID.
            "\x07",                             // Beta.
            "\x00\x00\x00\x00\x00\x00\x00\x02", // Nested registry entry count.
            "\x00\x00\x00\x01\x0b\x09\x19",     // Index, key, nonce point, response.
            "\x01\x02\x03\x04\x0c\x3e\x5f",
        )
        .as_bytes();
        let expected = DkgConfig::new(
            1,
            SessionId(*b"0123456789abcdef0123456789abcdef"),
            TinyScalar::from_u64(7).unwrap(),
            fixed_registry(),
        )
        .unwrap();

        let decoded = from_wire_bytes::<DkgConfig<TinyGroup>>(bytes).unwrap();
        assert_eq!(decoded.threshold, expected.threshold);
        assert_eq!(decoded.session_id, expected.session_id);
        assert_eq!(decoded.beta, expected.beta);
        assert_eq!(decoded.registry, expected.registry);
        assert_eq!(to_wire_bytes(&expected), bytes);
    }

    #[test]
    fn reshare_config_v1_fixed_wire_vector() {
        let bytes = concat!(
            "golden-dkg-wire-v3\x09", // Magic and reshare config tag.
            "\x00\x00\x00\x00\x00\x00\x00\x11reshare-config-v1",
            "\x00\x00\x00\x00\x00\x00\x00\x13golden-test-tiny-v1",
            "\x00\x00\x00\x00\x00\x00\x00\x02", // Threshold.
            "\x00\x00\x00\x00\x00\x00\x00\x01", // Max corrupt receivers.
            "0123456789abcdef0123456789abcdef", // Session ID.
            "\x07",                             // Beta.
            "\x00\x00\x00\x00\x00\x00\x00\x02", // Dealer registry entry count.
            "\x00\x00\x00\x01\x0b\x09\x19",     // Index, key, nonce point, response.
            "\x01\x02\x03\x04\x0c\x3e\x5f",
            "\x00\x00\x00\x00\x00\x00\x00\x03", // Receiver registry entry count.
            "\x00\x00\x00\x01\x15\x2c\x03",
            "\x00\x00\x00\x02\x16\x1e\x18",
            "\x00\x00\x00\x03\x17\x5a\x5e",
            "\x00\x00\x00\x00\x00\x00\x00\x02", // Predecessor threshold.
            "\x03",                             // Predecessor key.
            "\x00\x00\x00\x00\x00\x00\x00\x03", // Predecessor share count.
            "\x00\x00\x00\x01\x0a",             // Index, public share.
            "\x00\x00\x00\x02\x11",
            "\x01\x02\x03\x04\x2e",
            "fedcba9876543210fedcba9876543210", // Predecessor completion root.
        )
        .as_bytes();
        // Fixed fields, including valid proofs for identity secrets 21, 22
        // and 23 and the column of 3 + 7x. Do not regenerate these with the
        // prover or wire encoder.
        let receivers = ParticipantRegistry::new(
            [(1, 21, 44, 3), (2, 22, 30, 24), (3, 23, 90, 94)]
                .into_iter()
                .map(|(participant, public_key, nonce_point, response)| {
                    (
                        idx(participant),
                        TinyScalar::from_u64(public_key).unwrap(),
                        IdentityKeyProof {
                            nonce_point: TinyScalar::from_u64(nonce_point).unwrap(),
                            response: TinyScalar::from_u64(response).unwrap(),
                        },
                    )
                })
                .collect(),
        )
        .unwrap();
        let predecessor = ResharePredecessor::new(
            2,
            TinyScalar::from_u64(3).unwrap(),
            [(1, 10), (2, 17), (0x0102_0304, 46)]
                .map(|(participant, share)| {
                    (idx(participant), TinyScalar::from_u64(share).unwrap())
                })
                .into(),
            *b"fedcba9876543210fedcba9876543210",
        )
        .unwrap();
        let expected = ReshareConfig::new(
            2,
            1,
            SessionId(*b"0123456789abcdef0123456789abcdef"),
            TinyScalar::from_u64(7).unwrap(),
            fixed_registry(),
            receivers,
            predecessor,
        )
        .unwrap();

        assert_eq!(
            from_wire_bytes::<ReshareConfig<TinyGroup>>(bytes).unwrap(),
            expected
        );
        assert_eq!(to_wire_bytes(&expected), bytes);
    }

    /// Reshare config fields, written by [`Self::to_bytes`] without
    /// validation.
    #[derive(Clone, Copy)]
    struct ReshareConfigFields {
        threshold: usize,
        max_corrupt_receivers: usize,
        dealers: &'static [(u32, u64)],
        receivers: &'static [(u32, u64)],
        predecessor_threshold: usize,
        public_key: u64,
        column: &'static [(u32, u64)],
    }

    // A valid configuration over the column of 1 − x, whose share at 1 is the
    // identity.
    const VALID_RESHARE: ReshareConfigFields = ReshareConfigFields {
        threshold: 2,
        max_corrupt_receivers: 1,
        dealers: &[(1, 11), (2, 12), (3, 13)],
        receivers: &[(1, 21), (2, 22), (3, 23)],
        predecessor_threshold: 2,
        public_key: 1,
        column: &[(1, 0), (2, 96), (3, 95)],
    };

    fn tiny(value: u64) -> TinyScalar {
        TinyScalar::from_u64(value).unwrap()
    }

    fn registry(entries: &[(u32, u64)]) -> ParticipantRegistry<TinyGroup> {
        ParticipantRegistry::new(
            entries
                .iter()
                .map(|(participant, secret)| registry_entry(idx(*participant), *secret))
                .collect(),
        )
        .unwrap()
    }

    impl ReshareConfigFields {
        fn to_bytes(self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(MAGIC);
            bytes.push(TAG_RESHARE_CONFIG);
            <ReshareConfig<TinyGroup> as WireMessage>::write_wire_context(&mut bytes);
            write_len(&mut bytes, self.threshold);
            write_len(&mut bytes, self.max_corrupt_receivers);
            SessionId([1u8; 32]).write_wire(&mut bytes);
            write_scalar::<TinyGroup>(&mut bytes, &tiny(7));
            registry(self.dealers).write_wire(&mut bytes);
            registry(self.receivers).write_wire(&mut bytes);
            write_len(&mut bytes, self.predecessor_threshold);
            write_element::<TinyGroup>(&mut bytes, &tiny(self.public_key));
            write_len(&mut bytes, self.column.len());
            for (participant, share) in self.column {
                write_u32(&mut bytes, *participant);
                write_element::<TinyGroup>(&mut bytes, &tiny(*share));
            }
            bytes.extend_from_slice(&[2u8; 32]);
            bytes
        }

        fn decode(self) -> Result<ReshareConfig<TinyGroup>> {
            from_wire_bytes(&self.to_bytes())
        }
    }

    fn reshare_config() -> ReshareConfig<TinyGroup> {
        let fields = VALID_RESHARE;
        ReshareConfig::new(
            fields.threshold,
            fields.max_corrupt_receivers,
            SessionId([1u8; 32]),
            tiny(7),
            registry(fields.dealers),
            registry(fields.receivers),
            ResharePredecessor::new(
                fields.predecessor_threshold,
                tiny(fields.public_key),
                fields
                    .column
                    .iter()
                    .map(|(participant, share)| (idx(*participant), tiny(*share)))
                    .collect(),
                [2u8; 32],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn reshare_config_round_trips() {
        let config = reshare_config();
        let bytes = to_wire_bytes(&config);

        assert_eq!(VALID_RESHARE.to_bytes(), bytes);
        let decoded = from_wire_bytes::<ReshareConfig<TinyGroup>>(&bytes).unwrap();
        assert_eq!(decoded, config);
        assert_eq!(decoded.root(), config.root());
        assert_eq!(
            decoded.predecessor().public_key_share(idx(1)),
            Some(&TinyGroup::identity())
        );
    }

    #[test]
    fn reshare_config_decode_reruns_validation() {
        for (fields, expected) in [
            (
                ReshareConfigFields {
                    column: &[(1, 0), (2, 96), (3, 94)],
                    ..VALID_RESHARE
                },
                Error::InvalidPredecessor,
            ),
            (
                ReshareConfigFields {
                    public_key: 2,
                    ..VALID_RESHARE
                },
                Error::InvalidPredecessor,
            ),
            (
                ReshareConfigFields {
                    predecessor_threshold: 4,
                    ..VALID_RESHARE
                },
                Error::InvalidPredecessor,
            ),
            (
                ReshareConfigFields {
                    threshold: 4,
                    ..VALID_RESHARE
                },
                Error::InvalidThreshold {
                    threshold: 4,
                    participants: 3,
                },
            ),
            (
                ReshareConfigFields {
                    max_corrupt_receivers: 2,
                    ..VALID_RESHARE
                },
                Error::InsecureReshareThreshold {
                    threshold: 2,
                    max_corrupt_receivers: 2,
                },
            ),
            (
                ReshareConfigFields {
                    threshold: 3,
                    ..VALID_RESHARE
                },
                Error::InsufficientHonestReceivers {
                    threshold: 3,
                    receivers: 3,
                    max_corrupt_receivers: 1,
                },
            ),
            (
                ReshareConfigFields {
                    dealers: &[(1, 11), (4, 14)],
                    ..VALID_RESHARE
                },
                Error::InvalidReshareConfiguration,
            ),
            (
                ReshareConfigFields {
                    receivers: VALID_RESHARE.dealers,
                    ..VALID_RESHARE
                },
                Error::ReshareKeyCollision {
                    dealer: 1,
                    receiver: 1,
                },
            ),
        ] {
            assert_eq!(fields.decode().unwrap_err(), expected);
        }

        // The receiver registry ends with the proof response of receiver 3,
        // just before the predecessor field.
        let mut predecessor = Vec::new();
        write_predecessor::<TinyGroup>(&mut predecessor, reshare_config().predecessor());
        let mut tampered = VALID_RESHARE.to_bytes();
        let response = tampered.len() - predecessor.len() - 1;
        tampered[response] = (tampered[response] + 1) % 97;
        assert_eq!(
            from_wire_bytes::<ReshareConfig<TinyGroup>>(&tampered).unwrap_err(),
            Error::InvalidIdentityKeyProof(3)
        );

        // Swapped registries are valid here, under a different root.
        let swapped = ReshareConfigFields {
            dealers: VALID_RESHARE.receivers,
            receivers: VALID_RESHARE.dealers,
            ..VALID_RESHARE
        }
        .decode()
        .unwrap();
        assert_eq!(swapped.dealers(), reshare_config().receivers());
        assert_ne!(swapped.root(), reshare_config().root());
    }

    #[test]
    fn reshare_config_rejects_non_increasing_columns() {
        for (column, duplicate) in [
            (&[(1, 0), (3, 95), (2, 96)][..], 2),
            (&[(1, 0), (1, 0), (2, 96)][..], 1),
        ] {
            let fields = ReshareConfigFields {
                column,
                ..VALID_RESHARE
            };
            assert_eq!(
                fields.decode().unwrap_err(),
                Error::DuplicateParticipantIndex(duplicate)
            );
        }
    }

    #[test]
    fn reshare_config_rejects_trailing_and_truncated_bytes() {
        let bytes = to_wire_bytes(&reshare_config());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            from_wire_bytes::<ReshareConfig<TinyGroup>>(&trailing).unwrap_err(),
            Error::InvalidEncoding
        );
        for len in 0..bytes.len() {
            assert_eq!(
                from_wire_bytes::<ReshareConfig<TinyGroup>>(&bytes[..len]).unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }

    #[test]
    fn identity_key_proof_round_trips() {
        let (_, _, proof) = registry_entry(idx(1), 11);

        assert_eq!(
            from_wire_bytes::<IdentityKeyProof<TinyGroup>>(&to_wire_bytes(&proof)).unwrap(),
            proof
        );
    }

    #[test]
    fn registry_decode_rejects_invalid_identity_key_proof() {
        let registry = ParticipantRegistry::<TinyGroup>::new(vec![
            registry_entry(idx(1), 11),
            registry_entry(idx(2), 12),
        ])
        .unwrap();
        let mut bytes = to_wire_bytes(&registry);
        let last = bytes.len() - 1;
        bytes[last] = (bytes[last] + 1) % 97;

        assert_eq!(
            from_wire_bytes::<ParticipantRegistry<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidIdentityKeyProof(2)
        );
    }

    #[test]
    fn registry_round_trips_and_rejects_non_increasing_participants() {
        let registry = ParticipantRegistry::<TinyGroup>::new(vec![
            registry_entry(idx(1), 11),
            registry_entry(idx(2), 12),
        ])
        .unwrap();
        let bytes = to_wire_bytes(&registry);

        assert_eq!(
            from_wire_bytes::<ParticipantRegistry<TinyGroup>>(&bytes).unwrap(),
            registry
        );

        let mut nested = registry.to_nested_wire_bytes();
        nested[11] = 2;
        nested[18] = 1;
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

    #[test]
    fn dealer_message_derives_transcript_root_on_decode() {
        let commitment = FeldmanCommitment::<TinyGroup>::from_coefficients(vec![
            TinyScalar::from_u64(10).unwrap(),
            TinyScalar::from_u64(20).unwrap(),
        ])
        .unwrap();
        let encrypted_share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let message = DealerMessage::<TinyGroup> {
            session_id: SessionId([1u8; 32]),
            registry_root: [2u8; 32],
            dealer: idx(1),
            msg_i: DealerMessageNonce([3u8; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([(idx(2), encrypted_share)]),
            proof: vec![4, 5, 6],
            transcript_root: [7u8; 32],
        };
        let expected_root = message.recompute_transcript_root();

        let decoded =
            from_wire_bytes::<DealerMessage<TinyGroup>>(&to_wire_bytes(&message)).unwrap();

        assert_eq!(decoded.session_id, message.session_id);
        assert_eq!(decoded.registry_root, message.registry_root);
        assert_eq!(decoded.dealer, message.dealer);
        assert_eq!(decoded.msg_i, message.msg_i);
        assert_eq!(decoded.commitment, message.commitment);
        assert_eq!(decoded.encrypted_shares, message.encrypted_shares);
        assert_eq!(decoded.proof, message.proof);
        assert_ne!(decoded.transcript_root, message.transcript_root);
        assert_eq!(decoded.transcript_root, expected_root);
        assert_eq!(decoded.transcript_root, decoded.recompute_transcript_root());
    }

    #[test]
    fn dealer_message_wire_has_no_nested_proof_marker() {
        let commitment = FeldmanCommitment::<TinyGroup>::from_coefficients(vec![
            TinyScalar::from_u64(10).unwrap(),
            TinyScalar::from_u64(20).unwrap(),
        ])
        .unwrap();
        let encrypted_share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let message = DealerMessage::<TinyGroup> {
            session_id: SessionId([1u8; 32]),
            registry_root: [2u8; 32],
            dealer: idx(1),
            msg_i: DealerMessageNonce([3u8; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([(idx(2), encrypted_share)]),
            proof: vec![4, 5, 6],
            transcript_root: [7u8; 32],
        };
        let bytes = to_wire_bytes(&message);
        let mut prefix = Vec::new();
        prefix.extend_from_slice(MAGIC);
        prefix.push(TAG_DEALER_MESSAGE);
        <DealerMessage<TinyGroup> as WireMessage>::write_wire_context(&mut prefix);
        let mut expected = {
            let mut without_proof = message.clone();
            without_proof.proof.clear();
            let mut bytes = to_wire_bytes(&without_proof);
            bytes.truncate(bytes.len() - 8);
            bytes
        };
        write_len(&mut expected, message.proof.len());
        expected.extend_from_slice(&message.proof);

        assert_eq!(
            <DealerMessage<TinyGroup> as WireMessage>::CODEC_ID,
            "dealer-message-v3"
        );
        assert_eq!(bytes, expected);
        assert_eq!(bytes[prefix.len()], message.session_id.0[0]);
        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&bytes)
                .unwrap()
                .proof,
            message.proof
        );
    }

    #[test]
    fn dealer_message_rejects_malformed_outer_proof_length() {
        let message = dealer_message();
        let mut without_proof = message.clone();
        without_proof.proof.clear();
        let proof_len_offset = to_wire_bytes(&without_proof).len() - 8;

        for declared_len in [4u64, u64::MAX] {
            let mut bytes = to_wire_bytes(&message);
            bytes[proof_len_offset..proof_len_offset + 8]
                .copy_from_slice(&declared_len.to_be_bytes());
            assert_eq!(
                from_wire_bytes::<DealerMessage<TinyGroup>>(&bytes).unwrap_err(),
                Error::InvalidEncoding
            );
        }
    }

    #[test]
    fn dealer_message_rejects_trailing_transcript_root() {
        let commitment = FeldmanCommitment::<TinyGroup>::from_coefficients(vec![
            TinyScalar::from_u64(10).unwrap(),
            TinyScalar::from_u64(20).unwrap(),
        ])
        .unwrap();
        let encrypted_share = EncryptedShare::<TinyGroup> {
            pad_commitment: TinyScalar::from_u64(2).unwrap(),
            encrypted_share: TinyScalar::from_u64(4).unwrap(),
        };
        let message = DealerMessage::<TinyGroup> {
            session_id: SessionId([1u8; 32]),
            registry_root: [2u8; 32],
            dealer: idx(1),
            msg_i: DealerMessageNonce([3u8; 32]),
            commitment,
            encrypted_shares: BTreeMap::from([(idx(2), encrypted_share)]),
            proof: vec![4, 5, 6],
            transcript_root: [7u8; 32],
        };
        let mut bytes = to_wire_bytes(&message);
        bytes.extend_from_slice(&message.transcript_root);

        assert_eq!(
            from_wire_bytes::<DealerMessage<TinyGroup>>(&bytes).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn dealer_message_serde_uses_canonical_wire_bytes() {
        use serde_test::{assert_de_tokens, assert_tokens, Token};

        let message = dealer_message();
        let bytes: &'static [u8] = Box::leak(to_wire_bytes(&message).into_boxed_slice());

        assert_tokens(&message, &[Token::Bytes(bytes)]);

        let mut seq = Vec::with_capacity(bytes.len() + 2);
        seq.push(Token::Seq {
            len: Some(bytes.len()),
        });
        seq.extend(bytes.iter().copied().map(Token::U8));
        seq.push(Token::SeqEnd);

        assert_de_tokens(&message, &seq);
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn dealer_message_miden_serde_uses_canonical_wire_bytes() {
        use miden_serde_utils::{BudgetedReader, Deserializable, Serializable, SliceReader};

        let message = dealer_message();
        let bytes = message.to_bytes();
        let wire_bytes = to_wire_bytes(&message);

        assert!(bytes.ends_with(&wire_bytes));
        assert_eq!(
            DealerMessage::<TinyGroup>::read_from_bytes(&bytes).unwrap(),
            message
        );

        let mut other = dealer_message();
        other.proof = vec![7, 8, 9];
        let mut adjacent = Vec::new();
        message.write_into(&mut adjacent);
        other.write_into(&mut adjacent);
        let mut reader = SliceReader::new(&adjacent);

        assert_eq!(
            DealerMessage::<TinyGroup>::read_from(&mut reader).unwrap(),
            message
        );
        assert_eq!(
            DealerMessage::<TinyGroup>::read_from(&mut reader).unwrap(),
            other
        );

        let mut oversized = usize::MAX.to_bytes();
        oversized.push(0);
        assert!(DealerMessage::<TinyGroup>::read_from_bytes(&oversized).is_err());

        let mut budgeted = SliceReader::new(&bytes);
        let declared_len = budgeted.read_usize().unwrap();
        assert!(declared_len > 8);
        let mut budgeted = BudgetedReader::new(SliceReader::new(&bytes), 8);
        assert!(read_miden_wire::<DealerMessage<TinyGroup>, _>(&mut budgeted).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn reshare_config_serde_uses_canonical_wire_bytes() {
        use serde_test::{assert_tokens, Token};

        let config = reshare_config();
        let bytes: &'static [u8] = Box::leak(to_wire_bytes(&config).into_boxed_slice());

        assert_tokens(&config, &[Token::Bytes(bytes)]);
    }

    #[cfg(feature = "miden-serde")]
    #[test]
    fn reshare_config_miden_serde_uses_canonical_wire_bytes() {
        use miden_serde_utils::{Deserializable, Serializable};

        let config = reshare_config();
        let bytes = config.to_bytes();

        assert!(bytes.ends_with(&to_wire_bytes(&config)));
        assert_eq!(bytes.len(), config.get_size_hint());
        assert_eq!(
            ReshareConfig::<TinyGroup>::read_from_bytes(&bytes).unwrap(),
            config
        );
    }
}
