//! EHTDH1 value envelopes, sharing the core's checked reader primitives.
pub use golden_core::wire::Reader as WireReader;
use golden_core::{DkgGroup, Error, ParticipantIndex, Result, SessionId, TranscriptRoot};
#[cfg(feature = "miden-serde")]
use miden_serde_utils::{ByteReader, ByteWriter, DeserializationError};

pub(crate) const MAGIC: &[u8] = b"golden-ehtdh1-wire-v2";

/// Encode a nested EHTDH1 value.
pub trait WireEncode {
    /// Append the canonical payload.
    fn write_wire(&self, out: &mut Vec<u8>);
    /// Payload allocation hint.
    fn wire_size_hint(&self) -> usize {
        0
    }
    /// Encode without the standalone envelope.
    fn to_nested_wire_bytes(&self) -> Vec<u8> {
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(self.wire_size_hint()));
        self.write_wire(&mut out);
        core::mem::take(&mut *out)
    }
}
/// Decode a nested EHTDH1 value.
pub trait WireDecode: Sized {
    /// Decode with the shared checked reader.
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self>;
}
/// A versioned standalone EHTDH1 value.
pub trait WireMessage: WireEncode + WireDecode {
    /// Value kind.
    const TAG: u8;
    /// Canonical payload grammar identifier.
    const CODEC_ID: &'static str;
    /// Append the type/group context.
    fn write_wire_context(out: &mut Vec<u8>) {
        write_context_field(out, Self::CODEC_ID.as_bytes());
    }
    /// Check the type/group context.
    fn read_wire_context(reader: &mut WireReader<'_>) -> Result<()> {
        expect_context_field(reader, Self::CODEC_ID.as_bytes())
    }
}

pub(crate) fn to_wire_bytes<T: WireMessage>(value: &T) -> Vec<u8> {
    let mut out = zeroize::Zeroizing::new(Vec::new());
    write_context_field(&mut out, MAGIC);
    out.push(T::TAG);
    T::write_wire_context(&mut out);
    let frame = out.len();
    out.extend_from_slice(&[0u8; 8]);
    let start = out.len();
    out.reserve_exact(value.wire_size_hint());
    value.write_wire(&mut out);
    let len = length_bytes(out.len() - start);
    out[frame..start].copy_from_slice(&len);
    core::mem::take(&mut *out)
}
pub(crate) fn from_wire_bytes<T: WireMessage>(bytes: &[u8]) -> Result<T> {
    let mut reader = WireReader::new(bytes);
    expect_context_field(&mut reader, MAGIC)?;
    if reader.u8()? != T::TAG {
        return Err(Error::InvalidEncoding);
    }
    T::read_wire_context(&mut reader)?;
    let payload = reader.framed()?;
    reader.finish()?;
    let mut nested = WireReader::new(payload);
    let value = T::read_wire(&mut nested)?;
    nested.finish()?;
    Ok(value)
}
pub(crate) fn write_len(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&length_bytes(value));
}
// All supported Rust targets have pointers of at most 64 bits. The constant
// subtraction also rejects an unsupported wider target at compilation.
fn length_bytes(value: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[8 - core::mem::size_of::<usize>()..].copy_from_slice(&value.to_be_bytes());
    bytes
}
pub(crate) fn read_len(reader: &mut WireReader<'_>) -> Result<usize> {
    usize::try_from(u64::from_be_bytes(reader.array()?)).map_err(|_| Error::InvalidEncoding)
}
pub(crate) fn write_context_field(out: &mut Vec<u8>, value: &[u8]) {
    write_len(out, value.len());
    out.extend_from_slice(value);
}
pub(crate) fn expect_context_field(reader: &mut WireReader<'_>, value: &[u8]) -> Result<()> {
    if reader.framed()? == value {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}
pub(crate) fn write_element<G: DkgGroup>(out: &mut Vec<u8>, value: &G::Point) {
    out.extend_from_slice(&G::encode_point(value));
}
pub(crate) fn read_element<G: DkgGroup>(reader: &mut WireReader<'_>) -> Result<G::Point> {
    G::decode_point(reader.take(G::POINT_BYTES)?)
}
pub(crate) fn write_scalar<G: DkgGroup>(out: &mut Vec<u8>, value: &G::Scalar) {
    let encoded = zeroize::Zeroizing::new(G::encode_scalar(value));
    out.extend_from_slice(encoded.as_ref());
}
pub(crate) fn read_scalar<G: DkgGroup>(reader: &mut WireReader<'_>) -> Result<G::Scalar> {
    G::decode_scalar(reader.take(32)?)
}
impl WireEncode for ParticipantIndex {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.get().to_be_bytes());
    }
}
impl WireDecode for ParticipantIndex {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Self::new(reader.u32()?)
    }
}
impl WireEncode for SessionId {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}
impl WireDecode for SessionId {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        Ok(Self(reader.array()?))
    }
}
impl WireEncode for TranscriptRoot {
    fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl WireDecode for TranscriptRoot {
    fn read_wire(reader: &mut WireReader<'_>) -> Result<Self> {
        reader.array()
    }
}
#[cfg(feature = "miden-serde")]
pub(crate) fn write_miden_wire<T: WireMessage, W: ByteWriter>(value: &T, target: &mut W) {
    let bytes = zeroize::Zeroizing::new(to_wire_bytes(value));
    target.write_usize(bytes.len());
    target.write_bytes(&bytes);
}
#[cfg(feature = "miden-serde")]
pub(crate) fn read_miden_wire<T: WireMessage, R: ByteReader>(
    source: &mut R,
) -> core::result::Result<T, DeserializationError> {
    let len = source.read_usize()?;
    if len > source.max_alloc(1) {
        return Err(DeserializationError::InvalidValue(
            "EHTDH1 allocation budget exceeded".into(),
        ));
    }
    source.check_eor(len)?;
    let bytes = source.read_slice(len)?;
    from_wire_bytes(bytes).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
}
#[cfg(feature = "miden-serde")]
pub(crate) fn miden_wire_size_hint<T: WireMessage>(value: &T) -> usize {
    let bytes = zeroize::Zeroizing::new(to_wire_bytes(value));
    let len = bytes.len();
    let zeros = u64::from_be_bytes(length_bytes(len)).leading_zeros() as usize;
    9 - core::cmp::min(zeros.saturating_sub(1) / 7, 8) + len
}
