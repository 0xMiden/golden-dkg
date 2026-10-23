//! Deterministic transcript helpers and the protocol's framed SHA-256 hash.
use crate::{DkgGroup, Error, ParticipantIndex, Result};
use sha2::{Digest, Sha256};

/// SHA-256 protocol identity.
pub type TranscriptRoot = [u8; 32];

/// Hash `U64_BE(domain.len()) || domain || payload`.
pub fn hash_payload(domain: &[u8], payload: &[u8]) -> Result<TranscriptRoot> {
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

/// Labelled transcript utility for applications; DKG C/L/P use their exact schemas.
pub struct TranscriptBuilder {
    hasher: Sha256,
}
impl TranscriptBuilder {
    /// Start a domain-separated labelled transcript.
    pub fn with_prefix(prefix: &'static [u8], label: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(prefix);
        hasher.update(size_bytes(label.len()));
        hasher.update(label);
        Self { hasher }
    }
    /// Append a labelled length-framed value.
    pub fn bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.hasher.update(size_bytes(label.len()));
        self.hasher.update(label);
        self.hasher.update(size_bytes(bytes.len()));
        self.hasher.update(bytes);
    }
    /// Append a fixed-width integer.
    pub fn u32(&mut self, label: &'static [u8], value: u32) {
        self.bytes(label, &value.to_be_bytes());
    }
    /// Append a platform size as U64.
    pub fn usize(&mut self, label: &'static [u8], value: usize) {
        self.bytes(label, &size_bytes(value));
    }
    /// Append a participant index.
    pub fn participant(&mut self, label: &'static [u8], value: ParticipantIndex) {
        self.u32(label, value.get());
    }
    /// Append the canonical protocol scalar bytes.
    pub fn scalar<G: DkgGroup>(&mut self, label: &'static [u8], value: &G::Scalar) {
        self.bytes(label, &G::encode_scalar(value));
    }
    /// Append the canonical protocol point bytes.
    pub fn element<G: DkgGroup>(&mut self, label: &'static [u8], value: &G::Point) {
        self.bytes(label, &G::encode_point(value));
    }
    /// Finish this transcript.
    pub fn root(self) -> TranscriptRoot {
        self.hasher.finalize().into()
    }
}

// Supported Rust/WASM targets have at most 64-bit address spaces. Enforce that
// fact at compile time, then zero-extend native sizes without truncation or a
// saturating fallback in this infallible application transcript utility.
const _: () = assert!(usize::BITS <= u64::BITS);
fn size_bytes(value: usize) -> [u8; 8] {
    let mut output = [0; 8];
    for (destination, source) in output
        .iter_mut()
        .rev()
        .zip(value.to_be_bytes().iter().rev())
    {
        *destination = *source;
    }
    output
}
