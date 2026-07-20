//! Deterministic transcript helpers for message binding.

use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::{Error, Result};
use crate::{GoldenGroup, GoldenScalar, ParticipantIndex};

/// SHA-256 digest used as the shared root for every Golden-core transcript
/// (dealing, completion, registry, evrf-statement, pad).
pub type TranscriptRoot = [u8; 32];

/// Decode a transcript root from its canonical 32-byte representation.
#[cfg(test)]
pub(crate) fn transcript_root_from_slice(bytes: &[u8]) -> Result<TranscriptRoot> {
    if bytes.len() != 32 {
        return Err(Error::InvalidEncoding);
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(bytes);
    Ok(root)
}

/// Deterministic SHA-256 transcript builder for Golden protocol roots.
pub struct TranscriptBuilder {
    hasher: Sha256,
}

impl TranscriptBuilder {
    pub(crate) fn new(label: &'static [u8]) -> Self {
        Self::with_prefix(b"golden-core-v1", label)
    }

    /// Build a transcript with an explicit protocol prefix.
    pub fn with_prefix(prefix: &'static [u8], label: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        // Domain separator: a fixed ASCII tag that scopes one protocol away
        // from any other SHA-256 use of the same labels. Unlike labels and
        // payloads below, it is not length-prefixed because callers supply
        // compile-time constants, not attacker-controlled strings.
        hasher.update(prefix);
        hasher.update((label.len() as u64).to_be_bytes());
        hasher.update(label);
        Self { hasher }
    }

    /// Append a byte slice under a fixed label.
    pub fn bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.hasher.update((label.len() as u64).to_be_bytes());
        self.hasher.update(label);
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Append a `u32` under a fixed label.
    pub fn u32(&mut self, label: &'static [u8], value: u32) {
        self.bytes(label, &value.to_be_bytes());
    }

    /// Append a `usize` as a fixed-width `u64` under a fixed label.
    pub fn usize(&mut self, label: &'static [u8], value: usize) {
        self.bytes(label, &(value as u64).to_be_bytes());
    }

    /// Append a participant index under a fixed label.
    pub fn participant(&mut self, label: &'static [u8], value: ParticipantIndex) {
        self.u32(label, value.get());
    }

    /// Append a scalar's canonical representation under a fixed label.
    pub fn scalar<G: GoldenGroup>(&mut self, label: &'static [u8], value: &G::Scalar) {
        self.bytes(label, value.to_repr().as_ref());
    }

    /// Append a group element's canonical representation under a fixed label.
    pub fn element<G: GoldenGroup>(&mut self, label: &'static [u8], value: &G::Element) {
        self.bytes(label, G::encode_element(value).as_ref());
    }

    /// Finish the transcript and return its root.
    pub fn root(self) -> TranscriptRoot {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TinyGroup, TinyScalar};

    #[test]
    fn transcript_root_decoding_requires_exact_length() {
        let root = [7u8; 32];

        assert_eq!(transcript_root_from_slice(&root).unwrap(), root);
        assert_eq!(
            transcript_root_from_slice(&root[..31]).unwrap_err(),
            Error::InvalidEncoding
        );
        assert_eq!(
            transcript_root_from_slice(&[0u8; 33]).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    // Golden vectors pin the exact SHA-256 output of TranscriptBuilder for
    // fixed input sequences. Any change to the domain separator, length
    // prefix width, or label/payload order breaks these and is caught here
    // rather than silently shifting every transcript root in the crate.

    #[test]
    fn transcript_builder_pins_u32_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.u32(b"version", 1);
        assert_eq!(
            t.root(),
            [
                0x96, 0x51, 0x45, 0x00, 0xe6, 0x6a, 0xe1, 0x90, 0xa7, 0xbf, 0x11, 0xcf, 0xfe, 0x99,
                0xa8, 0x72, 0xe4, 0xcf, 0x8f, 0x40, 0xa0, 0x18, 0x5f, 0x2a, 0x96, 0x78, 0x25, 0x3d,
                0xdc, 0xa9, 0x7c, 0x04
            ]
        );
    }

    #[test]
    fn transcript_builder_pins_usize_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.usize(b"size", 0xdead_beef);
        assert_eq!(
            t.root(),
            [
                0x27, 0x82, 0x74, 0xa7, 0x88, 0x80, 0x9c, 0x7a, 0x10, 0x5f, 0xc7, 0x90, 0x1e, 0xa2,
                0x24, 0x98, 0x7c, 0xa0, 0x58, 0xa7, 0xc4, 0x89, 0x6d, 0x23, 0x2f, 0x53, 0x62, 0x58,
                0xd3, 0x6f, 0x79, 0xe5
            ]
        );
    }

    #[test]
    fn transcript_builder_pins_bytes_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.bytes(b"bytes", b"abc");
        assert_eq!(
            t.root(),
            [
                0x13, 0x3a, 0xd0, 0xe6, 0x1c, 0x48, 0x53, 0xb8, 0x86, 0x60, 0x98, 0xc4, 0xec, 0x92,
                0x0c, 0xfa, 0xc7, 0x43, 0x86, 0x80, 0xdd, 0x87, 0xd4, 0x47, 0x2e, 0x04, 0xb8, 0x3b,
                0x07, 0xb9, 0x69, 0x09
            ]
        );
    }

    #[test]
    fn transcript_builder_pins_participant_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.participant(b"p", ParticipantIndex::new(5).unwrap());
        assert_eq!(
            t.root(),
            [
                0xd9, 0x0b, 0xfb, 0xcc, 0x25, 0xb5, 0x99, 0x0b, 0x9f, 0x6f, 0xda, 0x6e, 0xc5, 0x22,
                0xf4, 0xde, 0xce, 0xbe, 0x32, 0x64, 0xef, 0x6b, 0x56, 0xa2, 0xcf, 0x5b, 0xb3, 0x84,
                0xa1, 0x4b, 0x46, 0x9b
            ]
        );
    }

    #[test]
    fn transcript_builder_pins_scalar_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.scalar::<TinyGroup>(b"scalar", &TinyScalar::from_u64(7).unwrap());
        assert_eq!(
            t.root(),
            [
                0x34, 0xf4, 0xa6, 0x89, 0xdc, 0x51, 0xac, 0xff, 0xfc, 0x23, 0x55, 0xda, 0xab, 0x51,
                0xe3, 0x73, 0x6e, 0x7b, 0x3c, 0x28, 0xdf, 0x08, 0x1e, 0xf1, 0x32, 0x8c, 0x4b, 0xa5,
                0x96, 0x78, 0x27, 0x4e
            ]
        );
    }

    #[test]
    fn transcript_builder_pins_element_encoding() {
        let mut t = TranscriptBuilder::new(b"dealing");
        t.element::<TinyGroup>(b"elem", &TinyScalar::from_u64(7).unwrap());
        assert_eq!(
            t.root(),
            [
                0x3e, 0xf8, 0x56, 0x85, 0x94, 0x1a, 0xa3, 0x2f, 0x7c, 0x0d, 0xee, 0xcf, 0xd4, 0xe4,
                0xe7, 0x91, 0x82, 0xc4, 0x15, 0xa6, 0x7e, 0xbc, 0x07, 0xf3, 0xe3, 0x59, 0x9f, 0x76,
                0x31, 0x51, 0xa6, 0x30
            ]
        );
    }

    #[test]
    fn transcript_builder_custom_prefix_changes_root() {
        let mut core = TranscriptBuilder::new(b"setup");
        core.bytes(b"value", b"abc");
        let mut ehtdh1 = TranscriptBuilder::with_prefix(b"golden-ehtdh1-v1", b"setup");
        ehtdh1.bytes(b"value", b"abc");
        assert_ne!(core.root(), ehtdh1.root());
    }

    #[test]
    fn transcript_builder_distinguishes_label_swaps() {
        // Same payload, different label -> different root. Guards against
        // collisions where (label_a, payload) and (label_b, payload) share
        // an encoding because the length prefixes were dropped.
        let mut a = TranscriptBuilder::new(b"dealing");
        a.u32(b"version", 1);
        let mut b = TranscriptBuilder::new(b"dealing");
        b.u32(b"nonce", 1);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn transcript_builder_distinguishes_payload_swaps() {
        // Same label, different payload -> different root. Guards against
        // length-prefix bugs that would make (label, a) and (label, b)
        // collide when a is a prefix of b.
        let mut a = TranscriptBuilder::new(b"dealing");
        a.u32(b"version", 1);
        let mut b = TranscriptBuilder::new(b"dealing");
        b.u32(b"version", 2);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn transcript_builder_distinguishes_prefix_payloads() {
        // bytes(b"x", b"abc") must not collide with bytes(b"x", b"abcd").
        // The length prefix is what separates them.
        let mut a = TranscriptBuilder::new(b"dealing");
        a.bytes(b"bytes", b"abc");
        let mut b = TranscriptBuilder::new(b"dealing");
        b.bytes(b"bytes", b"abcd");
        assert_ne!(a.root(), b.root());
    }
}
