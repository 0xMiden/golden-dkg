//! Paired prover and verifier roles for Golden proof streams.

use core::marker::PhantomData;

use golden_core::{max_dealer_message_bytes, Error, Result};
#[cfg(test)]
use golden_core::{GoldenGroup, GoldenScalar};
use merlin::Transcript;

const PROOF_ID_LEN_BYTES: usize = 4;
const MAX_PROOF_STREAM_BYTES: usize = max_dealer_message_bytes();
#[cfg(any(test, feature = "halo2curves-secp256k1"))]
const NESTED_LEN_BYTES: usize = 8;

/// Whether a point operation permits the group identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityPolicy {
    /// Permit the identity.
    #[cfg(any(test, feature = "halo2curves-secp256k1"))]
    Allow,
    /// Reject the identity.
    Reject,
}

/// Fixed-width canonical point and scalar operations used by a proof stream.
pub(crate) trait ProofStreamCurve {
    /// Point type for this adapter.
    type Point;
    /// Scalar type for this adapter.
    type Scalar;

    /// Canonical point width.
    const POINT_BYTES: usize;
    /// Canonical scalar width.
    const SCALAR_BYTES: usize;

    /// Encodes a point canonically.
    fn encode_point(point: &Self::Point) -> Vec<u8>;
    /// Decodes an exact-width canonical point.
    fn decode_point(bytes: &[u8]) -> Result<Self::Point>;
    /// Returns whether `point` is the identity.
    fn is_identity(point: &Self::Point) -> bool;

    /// Encodes a scalar canonically.
    fn encode_scalar(scalar: &Self::Scalar) -> Vec<u8>;
    /// Decodes an exact-width canonical scalar.
    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar>;
}

/// Proof-stream adapter for a [`GoldenGroup`].
#[cfg(test)]
pub(crate) struct GoldenCurve<G: GoldenGroup>(PhantomData<G>);

#[cfg(test)]
impl<G> ProofStreamCurve for GoldenCurve<G>
where
    G: GoldenGroup,
    G::ElementRepr: TryFrom<Vec<u8>>,
{
    type Point = G::Element;
    type Scalar = G::Scalar;

    const POINT_BYTES: usize = G::ELEMENT_REPR_BYTES;
    const SCALAR_BYTES: usize = G::Scalar::REPR_BYTES;

    fn encode_point(point: &Self::Point) -> Vec<u8> {
        G::encode_element(point).as_ref().to_vec()
    }

    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        if bytes.len() != Self::POINT_BYTES {
            return Err(stream_error());
        }
        let repr = G::ElementRepr::try_from(bytes.to_vec()).map_err(|_| stream_error())?;
        let point = G::decode_element(&repr).map_err(|_| stream_error())?;
        if G::encode_element(&point).as_ref() != bytes {
            return Err(stream_error());
        }
        Ok(point)
    }

    fn is_identity(point: &Self::Point) -> bool {
        bool::from(G::is_identity(point))
    }

    fn encode_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
    }

    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        if bytes.len() != Self::SCALAR_BYTES {
            return Err(stream_error());
        }
        let repr = <G::Scalar as GoldenScalar>::Repr::try_from(bytes.to_vec())
            .map_err(|_| stream_error())?;
        let scalar = G::Scalar::from_repr(&repr).map_err(|_| stream_error())?;
        if scalar.to_repr().as_ref() != bytes {
            return Err(stream_error());
        }
        Ok(scalar)
    }
}

/// Proof-stream adapter for a [`bulletproofs_cycle::Cycle`].
#[cfg(feature = "halo2curves-secp256k1")]
pub(crate) struct CycleCurve<C: bulletproofs_cycle::Cycle>(PhantomData<C>);

#[cfg(feature = "halo2curves-secp256k1")]
impl<C: bulletproofs_cycle::Cycle> ProofStreamCurve for CycleCurve<C> {
    type Point = C::Point;
    type Scalar = C::Scalar;

    const POINT_BYTES: usize = C::COMPRESSED_BYTES;
    const SCALAR_BYTES: usize = 32;

    fn encode_point(point: &Self::Point) -> Vec<u8> {
        let compressed = C::point_compress(point);
        C::compressed_as_bytes(&compressed).to_vec()
    }

    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        if bytes.len() != Self::POINT_BYTES {
            return Err(stream_error());
        }
        let compressed = C::compressed_from_bytes(bytes);
        let point = C::compressed_decompress(&compressed).ok_or_else(stream_error)?;
        let canonical = C::point_compress(&point);
        let canonical_bytes = C::compressed_as_bytes(&canonical);
        if canonical_bytes.len() != Self::POINT_BYTES || canonical_bytes != bytes {
            return Err(stream_error());
        }
        Ok(point)
    }

    fn is_identity(point: &Self::Point) -> bool {
        C::compressed_is_identity(&C::point_compress(point))
    }

    fn encode_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        C::scalar_to_canonical(scalar).to_vec()
    }

    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| stream_error())?;
        let scalar = C::scalar_from_canonical(&bytes).ok_or_else(stream_error)?;
        if C::scalar_to_canonical(&scalar) != bytes {
            return Err(stream_error());
        }
        Ok(scalar)
    }
}

/// Shared transcript operations for prover and verifier proof-stream roles.
pub(crate) trait Observe {
    /// Borrows the stream's single transcript.
    fn transcript_mut(&mut self) -> &mut Transcript;

    /// Observes public bytes that are not included in proof bytes.
    fn observe_bytes(&mut self, label: &'static [u8], value: &[u8]) {
        self.transcript_mut().append_message(label, value);
    }

    /// Validates and observes a public point without including it in proof bytes.
    #[cfg(any(test, feature = "halo2curves-secp256k1"))]
    fn observe_point<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
        point: &C::Point,
        identity: IdentityPolicy,
    ) -> Result<()> {
        let encoded = checked_point_encoding::<C>(point, identity)?;
        self.observe_bytes(label, &encoded);
        Ok(())
    }

    /// Validates and observes a public scalar without including it in proof bytes.
    #[cfg(any(test, feature = "halo2curves-secp256k1"))]
    fn observe_scalar<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
        scalar: &C::Scalar,
    ) -> Result<()> {
        let encoded = checked_scalar_encoding::<C>(scalar)?;
        self.observe_bytes(label, &encoded);
        Ok(())
    }

    /// Derives challenge bytes from all preceding transcript operations.
    fn challenge(&mut self, label: &'static [u8], output: &mut [u8]) {
        self.transcript_mut().challenge_bytes(label, output);
    }
}

impl Observe for Transcript {
    fn transcript_mut(&mut self) -> &mut Transcript {
        self
    }
}

/// Prover-side proof stream backed by one transcript and an output buffer.
pub(crate) struct ProverProofStream {
    transcript: Transcript,
    proof: Vec<u8>,
}

impl ProverProofStream {
    /// Starts a proof stream for a statically identified proof protocol.
    pub(crate) fn new(proof_id: &'static [u8]) -> Result<Self> {
        let proof_id_len =
            u32::try_from(proof_id.len()).map_err(|_| Error::ProofVerificationFailed)?;
        let capacity = PROOF_ID_LEN_BYTES
            .checked_add(proof_id.len())
            .ok_or_else(stream_error)?;
        let mut proof = Vec::with_capacity(capacity);
        proof.extend_from_slice(&proof_id_len.to_be_bytes());
        proof.extend_from_slice(proof_id);
        Ok(Self {
            transcript: Transcript::new(proof_id),
            proof,
        })
    }

    /// Sends bytes and observes them exactly once.
    pub(crate) fn send_bytes(&mut self, label: &'static [u8], value: &[u8]) {
        self.proof.extend_from_slice(value);
        self.observe_bytes(label, value);
    }

    /// Validates, sends, and observes a canonical point exactly once.
    pub(crate) fn send_point<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
        point: &C::Point,
        identity: IdentityPolicy,
    ) -> Result<()> {
        let encoded = checked_point_encoding::<C>(point, identity)?;
        self.send_bytes(label, &encoded);
        Ok(())
    }

    /// Validates, sends, and observes a canonical scalar exactly once.
    pub(crate) fn send_scalar<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
        scalar: &C::Scalar,
    ) -> Result<()> {
        let encoded = checked_scalar_encoding::<C>(scalar)?;
        self.send_bytes(label, &encoded);
        Ok(())
    }

    /// Runs a nested child protocol against the shared transcript and frames its bytes.
    #[cfg(any(test, feature = "halo2curves-secp256k1"))]
    pub(crate) fn send_nested(
        &mut self,
        build: impl FnOnce(&mut Transcript) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let transcript_before = self.transcript.clone();
        let payload = match build(&mut self.transcript) {
            Ok(payload) => payload,
            Err(err) => {
                self.transcript = transcript_before;
                return Err(err);
            }
        };
        let payload_len = match u64::try_from(payload.len()) {
            Ok(payload_len) => payload_len,
            Err(_) => {
                self.transcript = transcript_before;
                return Err(stream_error());
            }
        };
        self.proof.extend_from_slice(&payload_len.to_be_bytes());
        self.proof.extend_from_slice(&payload);
        Ok(())
    }

    /// Finishes proving and returns the complete proof bytes.
    #[cfg(test)]
    pub(crate) fn finish(self) -> Vec<u8> {
        self.proof
    }

    /// Finishes proving after enforcing the protocol's dealer-proof byte limit.
    pub(crate) fn finish_checked(self) -> Result<Vec<u8>> {
        if self.proof.len() > MAX_PROOF_STREAM_BYTES {
            return Err(stream_error());
        }
        Ok(self.proof)
    }
}

impl Observe for ProverProofStream {
    fn transcript_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
}

/// Verifier-side proof stream backed by one transcript and a checked proof cursor.
pub(crate) struct VerifierProofStream<'proof> {
    transcript: Transcript,
    proof: &'proof [u8],
    cursor: usize,
}

impl<'proof> VerifierProofStream<'proof> {
    /// Starts a verifier stream after validating the exact proof-ID header.
    pub(crate) fn new(proof_id: &'static [u8], proof: &'proof [u8]) -> Result<Self> {
        if proof.len() > MAX_PROOF_STREAM_BYTES {
            return Err(stream_error());
        }
        let length_bytes: [u8; PROOF_ID_LEN_BYTES] = proof
            .get(..PROOF_ID_LEN_BYTES)
            .ok_or_else(stream_error)?
            .try_into()
            .map_err(|_| stream_error())?;
        let encoded_len =
            usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| stream_error())?;
        if encoded_len != proof_id.len() {
            return Err(stream_error());
        }
        let cursor = PROOF_ID_LEN_BYTES
            .checked_add(encoded_len)
            .ok_or_else(stream_error)?;
        let encoded_id = proof
            .get(PROOF_ID_LEN_BYTES..cursor)
            .ok_or_else(stream_error)?;
        if encoded_id != proof_id {
            return Err(stream_error());
        }
        Ok(Self {
            transcript: Transcript::new(proof_id),
            proof,
            cursor,
        })
    }

    /// Receives fixed-width bytes and observes them exactly once.
    #[cfg(test)]
    pub(crate) fn receive_bytes(
        &mut self,
        label: &'static [u8],
        len: usize,
    ) -> Result<&'proof [u8]> {
        let start = self.cursor;
        let end = self.checked_end(start, len)?;
        let value = self.proof.get(start..end).ok_or_else(stream_error)?;
        self.transcript.append_message(label, value);
        self.cursor = end;
        Ok(value)
    }

    /// Receives and canonically validates a point before observing it once.
    pub(crate) fn receive_point<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
        identity: IdentityPolicy,
    ) -> Result<C::Point> {
        let start = self.cursor;
        let end = self.checked_end(start, C::POINT_BYTES)?;
        let encoded = self.proof.get(start..end).ok_or_else(stream_error)?;
        let point = decode_point::<C>(encoded, identity)?;
        self.transcript.append_message(label, encoded);
        self.cursor = end;
        Ok(point)
    }

    /// Receives and canonically validates a scalar before observing it once.
    pub(crate) fn receive_scalar<C: ProofStreamCurve>(
        &mut self,
        label: &'static [u8],
    ) -> Result<C::Scalar> {
        let start = self.cursor;
        let end = self.checked_end(start, C::SCALAR_BYTES)?;
        let encoded = self.proof.get(start..end).ok_or_else(stream_error)?;
        let scalar = C::decode_scalar(encoded)?;
        self.transcript.append_message(label, encoded);
        self.cursor = end;
        Ok(scalar)
    }

    /// Borrows a checked nested payload and runs its child protocol on the shared transcript.
    #[cfg(any(test, feature = "halo2curves-secp256k1"))]
    pub(crate) fn receive_nested<T>(
        &mut self,
        consume: impl FnOnce(&mut Transcript, &'proof [u8]) -> Result<T>,
    ) -> Result<T> {
        let length_start = self.cursor;
        let payload_start = self.checked_end(length_start, NESTED_LEN_BYTES)?;
        let length_bytes: [u8; NESTED_LEN_BYTES] = self
            .proof
            .get(length_start..payload_start)
            .ok_or_else(stream_error)?
            .try_into()
            .map_err(|_| stream_error())?;
        let payload_len =
            usize::try_from(u64::from_be_bytes(length_bytes)).map_err(|_| stream_error())?;
        let frame_end = self.checked_end(payload_start, payload_len)?;
        let payload = self
            .proof
            .get(payload_start..frame_end)
            .ok_or_else(stream_error)?;

        let transcript_before = self.transcript.clone();
        match consume(&mut self.transcript, payload) {
            Ok(value) => {
                self.cursor = frame_end;
                Ok(value)
            }
            Err(err) => {
                self.transcript = transcript_before;
                Err(err)
            }
        }
    }

    /// Finishes verification, rejecting any trailing proof bytes.
    pub(crate) fn finish(self) -> Result<()> {
        if self.cursor == self.proof.len() {
            Ok(())
        } else {
            Err(stream_error())
        }
    }

    fn checked_end(&self, start: usize, len: usize) -> Result<usize> {
        start.checked_add(len).ok_or_else(stream_error)
    }
}

impl Observe for VerifierProofStream<'_> {
    fn transcript_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
}

fn checked_point_encoding<C: ProofStreamCurve>(
    point: &C::Point,
    identity: IdentityPolicy,
) -> Result<Vec<u8>> {
    // `point` is already a valid, typed group element, so re-decoding its
    // fresh encoding would only re-check encode/decode are inverses on a
    // value already known valid — not an untrusted-data validation.
    enforce_identity::<C>(point, identity)?;
    let encoded = C::encode_point(point);
    if encoded.len() != C::POINT_BYTES {
        return Err(stream_error());
    }
    Ok(encoded)
}

/// Decodes a canonical point under an explicit relation-specific identity policy.
pub(crate) fn decode_point<C: ProofStreamCurve>(
    encoded: &[u8],
    identity: IdentityPolicy,
) -> Result<C::Point> {
    let point = C::decode_point(encoded)?;
    enforce_identity::<C>(&point, identity)?;
    Ok(point)
}

fn checked_scalar_encoding<C: ProofStreamCurve>(scalar: &C::Scalar) -> Result<Vec<u8>> {
    let encoded = C::encode_scalar(scalar);
    if encoded.len() != C::SCALAR_BYTES {
        return Err(stream_error());
    }
    C::decode_scalar(&encoded)?;
    Ok(encoded)
}

fn enforce_identity<C: ProofStreamCurve>(point: &C::Point, identity: IdentityPolicy) -> Result<()> {
    if identity == IdentityPolicy::Reject && C::is_identity(point) {
        Err(stream_error())
    } else {
        Ok(())
    }
}

fn stream_error() -> Error {
    Error::ProofVerificationFailed
}

#[cfg(test)]
mod tests {
    use golden_core::{GoldenGroup, GoldenScalar};
    use golden_rustcrypto::P256Backend;

    use super::*;

    const PROOF_ID: &[u8] = b"golden-evrf/proof-stream-tests/v1";
    type P256Curve = GoldenCurve<P256Backend>;

    #[test]
    fn prover_writes_canonical_proof_id_header() {
        let proof = ProverProofStream::new(PROOF_ID).unwrap().finish();
        let mut expected = u32::try_from(PROOF_ID.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        expected.extend_from_slice(PROOF_ID);
        assert_eq!(proof, expected);
    }

    #[test]
    fn prover_and_verifier_apply_dual_stream_operations() {
        let point = P256Backend::generator();
        let scalar = <P256Backend as GoldenGroup>::Scalar::from_u64(42).unwrap();

        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover.observe_bytes(b"public-bytes", b"known to both roles");
        prover
            .observe_point::<P256Curve>(b"public-point", &point, IdentityPolicy::Reject)
            .unwrap();
        prover
            .observe_scalar::<P256Curve>(b"public-scalar", &scalar)
            .unwrap();
        prover.send_bytes(b"bytes", b"message");
        prover
            .send_point::<P256Curve>(b"point", &point, IdentityPolicy::Reject)
            .unwrap();
        let mut prover_challenge = [0u8; 32];
        prover.challenge(b"challenge", &mut prover_challenge);
        prover.send_scalar::<P256Curve>(b"scalar", &scalar).unwrap();
        let proof = prover.finish();

        let mut expected_proof = u32::try_from(PROOF_ID.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        expected_proof.extend_from_slice(PROOF_ID);
        expected_proof.extend_from_slice(b"message");
        expected_proof.extend_from_slice(&P256Backend::encode_element(&point));
        expected_proof.extend_from_slice(&scalar.to_repr());
        assert_eq!(proof, expected_proof);

        let mut verifier = VerifierProofStream::new(PROOF_ID, &proof).unwrap();
        verifier.observe_bytes(b"public-bytes", b"known to both roles");
        verifier
            .observe_point::<P256Curve>(b"public-point", &point, IdentityPolicy::Reject)
            .unwrap();
        verifier
            .observe_scalar::<P256Curve>(b"public-scalar", &scalar)
            .unwrap();
        assert_eq!(verifier.receive_bytes(b"bytes", 7).unwrap(), b"message");
        assert_eq!(
            verifier
                .receive_point::<P256Curve>(b"point", IdentityPolicy::Reject)
                .unwrap(),
            point
        );
        let mut verifier_challenge = [0u8; 32];
        verifier.challenge(b"challenge", &mut verifier_challenge);
        assert_eq!(
            verifier.receive_scalar::<P256Curve>(b"scalar").unwrap(),
            scalar
        );
        verifier.finish().unwrap();

        assert_eq!(verifier_challenge, prover_challenge);
    }

    #[test]
    fn challenges_bind_domain_observation_message_label_and_order() {
        const OTHER_PROOF_ID: &[u8] = b"golden-evrf/proof-stream-tests/v2";

        let challenge_after =
            |proof_id: &'static [u8], public: &[u8], message: &[u8], label, reverse| {
                let mut stream = ProverProofStream::new(proof_id).unwrap();
                if reverse {
                    stream.send_bytes(b"second", b"two");
                    stream.observe_bytes(b"public", public);
                    stream.send_bytes(label, message);
                } else {
                    stream.observe_bytes(b"public", public);
                    stream.send_bytes(label, message);
                    stream.send_bytes(b"second", b"two");
                }
                let mut challenge = [0u8; 32];
                stream.challenge(b"challenge", &mut challenge);
                challenge
            };

        let baseline = challenge_after(PROOF_ID, b"statement-a", b"one", b"first", false);
        assert_eq!(
            baseline,
            [
                227, 145, 65, 64, 148, 204, 195, 253, 102, 169, 3, 98, 109, 9, 215, 68, 114, 161,
                88, 89, 253, 125, 76, 98, 32, 220, 11, 198, 133, 144, 245, 108,
            ]
        );
        let variants = [
            challenge_after(OTHER_PROOF_ID, b"statement-a", b"one", b"first", false),
            challenge_after(PROOF_ID, b"statement-b", b"one", b"first", false),
            challenge_after(PROOF_ID, b"statement-a", b"changed", b"first", false),
            challenge_after(PROOF_ID, b"statement-a", b"one", b"renamed", false),
            challenge_after(PROOF_ID, b"statement-a", b"one", b"first", true),
        ];
        for variant in variants {
            assert_ne!(variant, baseline);
        }
    }

    #[test]
    fn golden_curve_accepts_only_exact_canonical_encodings() {
        let point = P256Backend::generator();
        let point_bytes = <P256Curve as ProofStreamCurve>::encode_point(&point);
        assert_eq!(point_bytes.len(), P256Curve::POINT_BYTES);
        assert_eq!(
            <P256Curve as ProofStreamCurve>::decode_point(&point_bytes).unwrap(),
            point
        );
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_point(
            &point_bytes[..point_bytes.len() - 1],
        ));
        let mut long_point = point_bytes.clone();
        long_point.push(0);
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_point(&long_point));
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_point(&[1u8; 33]));
        let mut noncanonical_coordinate = [0xffu8; 33];
        noncanonical_coordinate[0] = 2;
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_point(
            &noncanonical_coordinate,
        ));

        let scalar = <P256Backend as GoldenGroup>::Scalar::from_u64(42).unwrap();
        let scalar_bytes = <P256Curve as ProofStreamCurve>::encode_scalar(&scalar);
        assert_eq!(scalar_bytes.len(), P256Curve::SCALAR_BYTES);
        assert_eq!(
            <P256Curve as ProofStreamCurve>::decode_scalar(&scalar_bytes).unwrap(),
            scalar
        );
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_scalar(
            &scalar_bytes[..scalar_bytes.len() - 1],
        ));
        let mut long_scalar = scalar_bytes;
        long_scalar.push(0);
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_scalar(&long_scalar));
        assert_rejected(<P256Curve as ProofStreamCurve>::decode_scalar(
            &<P256Backend as GoldenGroup>::Scalar::modulus(),
        ));
    }

    #[test]
    fn every_point_operation_enforces_its_identity_policy() {
        let identity = P256Backend::identity();

        let mut observing = ProverProofStream::new(PROOF_ID).unwrap();
        observing
            .observe_point::<P256Curve>(b"identity", &identity, IdentityPolicy::Allow)
            .unwrap();
        assert_rejected(observing.observe_point::<P256Curve>(
            b"rejected",
            &identity,
            IdentityPolicy::Reject,
        ));

        let mut rejected_observation = ProverProofStream::new(PROOF_ID).unwrap();
        assert_rejected(rejected_observation.observe_point::<P256Curve>(
            b"identity",
            &identity,
            IdentityPolicy::Reject,
        ));
        let mut rejected_challenge = [0u8; 32];
        rejected_observation.challenge(b"after-rejection", &mut rejected_challenge);
        let mut untouched = ProverProofStream::new(PROOF_ID).unwrap();
        let mut untouched_challenge = [0u8; 32];
        untouched.challenge(b"after-rejection", &mut untouched_challenge);
        assert_eq!(rejected_challenge, untouched_challenge);

        let mut rejected_send = ProverProofStream::new(PROOF_ID).unwrap();
        assert_rejected(rejected_send.send_point::<P256Curve>(
            b"identity",
            &identity,
            IdentityPolicy::Reject,
        ));
        assert_eq!(
            rejected_send.finish(),
            ProverProofStream::new(PROOF_ID).unwrap().finish()
        );

        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover
            .send_point::<P256Curve>(b"identity", &identity, IdentityPolicy::Allow)
            .unwrap();
        let mut expected_challenge = [0u8; 32];
        prover.challenge(b"after-identity", &mut expected_challenge);
        let proof = prover.finish();

        let mut verifier = VerifierProofStream::new(PROOF_ID, &proof).unwrap();
        assert_rejected(verifier.receive_point::<P256Curve>(b"identity", IdentityPolicy::Reject));
        assert_eq!(
            verifier
                .receive_point::<P256Curve>(b"identity", IdentityPolicy::Allow)
                .unwrap(),
            identity
        );
        let mut actual_challenge = [0u8; 32];
        verifier.challenge(b"after-identity", &mut actual_challenge);
        verifier.finish().unwrap();
        assert_eq!(actual_challenge, expected_challenge);
    }

    #[test]
    fn failed_curve_receives_leave_cursor_and_transcript_unchanged() {
        let malformed_point = [1u8; 33];
        let point_proof = proof_with_body(&malformed_point);
        let mut attempted_point = VerifierProofStream::new(PROOF_ID, &point_proof).unwrap();
        assert_rejected(
            attempted_point.receive_point::<P256Curve>(b"point", IdentityPolicy::Reject),
        );
        assert_eq!(
            attempted_point
                .receive_bytes(b"raw-point", malformed_point.len())
                .unwrap(),
            malformed_point
        );
        let mut after_point_failure = [0u8; 32];
        attempted_point.challenge(b"challenge", &mut after_point_failure);
        attempted_point.finish().unwrap();

        let mut direct_point = VerifierProofStream::new(PROOF_ID, &point_proof).unwrap();
        direct_point
            .receive_bytes(b"raw-point", malformed_point.len())
            .unwrap();
        let mut without_point_failure = [0u8; 32];
        direct_point.challenge(b"challenge", &mut without_point_failure);
        direct_point.finish().unwrap();
        assert_eq!(after_point_failure, without_point_failure);

        let noncanonical_scalar = <P256Backend as GoldenGroup>::Scalar::modulus();
        let scalar_proof = proof_with_body(&noncanonical_scalar);
        let mut attempted_scalar = VerifierProofStream::new(PROOF_ID, &scalar_proof).unwrap();
        assert_rejected(attempted_scalar.receive_scalar::<P256Curve>(b"scalar"));
        assert_eq!(
            attempted_scalar
                .receive_bytes(b"raw-scalar", noncanonical_scalar.len())
                .unwrap(),
            noncanonical_scalar
        );
        let mut after_scalar_failure = [0u8; 32];
        attempted_scalar.challenge(b"challenge", &mut after_scalar_failure);
        attempted_scalar.finish().unwrap();

        let mut direct_scalar = VerifierProofStream::new(PROOF_ID, &scalar_proof).unwrap();
        direct_scalar
            .receive_bytes(b"raw-scalar", noncanonical_scalar.len())
            .unwrap();
        let mut without_scalar_failure = [0u8; 32];
        direct_scalar.challenge(b"challenge", &mut without_scalar_failure);
        direct_scalar.finish().unwrap();
        assert_eq!(after_scalar_failure, without_scalar_failure);
    }

    #[test]
    fn every_truncation_of_a_mixed_stream_is_rejected() {
        let point = P256Backend::generator();
        let scalar = <P256Backend as GoldenGroup>::Scalar::from_u64(17).unwrap();
        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover.observe_bytes(b"public", b"statement");
        prover.send_bytes(b"prefix", b"abc");
        prover
            .send_point::<P256Curve>(b"point", &point, IdentityPolicy::Reject)
            .unwrap();
        let mut ignored_challenge = [0u8; 16];
        prover.challenge(b"midstream", &mut ignored_challenge);
        prover.send_scalar::<P256Curve>(b"scalar", &scalar).unwrap();
        prover
            .send_nested(|transcript| {
                transcript.append_message(b"child", b"semantic-message");
                Ok(b"child-payload".to_vec())
            })
            .unwrap();
        prover.send_bytes(b"suffix", b"xy");
        let proof = prover.finish();

        verify_mixed_stream(&proof).unwrap();
        for cut in 0..proof.len() {
            assert_rejected(verify_mixed_stream(&proof[..cut]));
        }
    }

    #[test]
    fn verifier_rejects_wrong_or_incomplete_proof_id_headers() {
        let proof = ProverProofStream::new(PROOF_ID).unwrap().finish();
        for cut in 0..PROOF_ID_LEN_BYTES {
            assert_rejected(VerifierProofStream::new(PROOF_ID, &proof[..cut]));
        }

        let mut wrong_length = proof.clone();
        wrong_length[..PROOF_ID_LEN_BYTES]
            .copy_from_slice(&(u32::try_from(PROOF_ID.len()).unwrap() - 1).to_be_bytes());
        assert_rejected(VerifierProofStream::new(PROOF_ID, &wrong_length));

        let mut wrong_id = proof.clone();
        wrong_id[PROOF_ID_LEN_BYTES] ^= 1;
        assert_rejected(VerifierProofStream::new(PROOF_ID, &wrong_id));

        let mut oversized = u32::MAX.to_be_bytes().to_vec();
        oversized.extend_from_slice(PROOF_ID);
        assert_rejected(VerifierProofStream::new(PROOF_ID, &oversized));
    }

    #[test]
    fn proof_stream_enforces_dealer_proof_byte_limit() {
        let oversized = vec![0u8; MAX_PROOF_STREAM_BYTES + 1];
        assert_rejected(VerifierProofStream::new(PROOF_ID, &oversized));

        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover.proof.resize(MAX_PROOF_STREAM_BYTES + 1, 0);
        assert_rejected(prover.finish_checked());
    }

    #[test]
    fn nested_frames_are_checked_borrowed_and_transactional() {
        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover
            .send_nested(|transcript| {
                transcript.append_message(b"child", b"semantic-message");
                Ok(b"borrowed-child".to_vec())
            })
            .unwrap();
        let mut expected_challenge = [0u8; 32];
        prover.challenge(b"after-child", &mut expected_challenge);
        let proof = prover.finish();

        let mut verifier = VerifierProofStream::new(PROOF_ID, &proof).unwrap();
        assert_rejected(
            verifier.receive_nested(|transcript, payload| -> Result<()> {
                assert_eq!(payload, b"borrowed-child");
                transcript.append_message(b"child", b"semantic-message");
                Err(stream_error())
            }),
        );
        let payload_len = verifier
            .receive_nested(|transcript, payload| {
                transcript.append_message(b"child", b"semantic-message");
                Ok(payload.len())
            })
            .unwrap();
        assert_eq!(payload_len, b"borrowed-child".len());
        let mut actual_challenge = [0u8; 32];
        verifier.challenge(b"after-child", &mut actual_challenge);
        verifier.finish().unwrap();
        assert_eq!(actual_challenge, expected_challenge);

        let malformed = proof_with_body(&[0, 0, 0, 0, 0, 0, 0, 5, 1, 2]);
        let mut malformed_verifier = VerifierProofStream::new(PROOF_ID, &malformed).unwrap();
        assert_rejected(malformed_verifier.receive_nested(|_, _| Ok(())));

        let overflow = proof_with_body(&u64::MAX.to_be_bytes());
        let mut overflow_verifier = VerifierProofStream::new(PROOF_ID, &overflow).unwrap();
        assert_rejected(overflow_verifier.receive_nested(|_, _| Ok(())));
    }

    #[test]
    fn nested_raw_length_and_payload_are_not_observed() {
        let challenge_for = |payload: &'static [u8]| {
            let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
            prover
                .send_nested(|transcript| {
                    transcript.append_message(b"child", b"same-semantic-message");
                    Ok(payload.to_vec())
                })
                .unwrap();
            let mut challenge = [0u8; 32];
            prover.challenge(b"after-child", &mut challenge);
            (challenge, prover.finish())
        };

        let (short_challenge, short_proof) = challenge_for(b"short");
        let (long_challenge, long_proof) = challenge_for(b"a different raw payload");
        assert_ne!(short_proof, long_proof);
        assert_eq!(short_challenge, long_challenge);
    }

    #[test]
    fn failed_nested_prover_child_rolls_back_the_shared_transcript() {
        let mut attempted = ProverProofStream::new(PROOF_ID).unwrap();
        assert_rejected(attempted.send_nested(|transcript| {
            transcript.append_message(b"failed-child", b"must roll back");
            Err(stream_error())
        }));
        attempted.send_bytes(b"message", b"accepted");
        let mut attempted_challenge = [0u8; 32];
        attempted.challenge(b"challenge", &mut attempted_challenge);

        let mut direct = ProverProofStream::new(PROOF_ID).unwrap();
        direct.send_bytes(b"message", b"accepted");
        let mut direct_challenge = [0u8; 32];
        direct.challenge(b"challenge", &mut direct_challenge);

        assert_eq!(attempted.finish(), direct.finish());
        assert_eq!(attempted_challenge, direct_challenge);
    }

    #[test]
    fn verifier_finish_rejects_trailing_bytes() {
        let mut proof = ProverProofStream::new(PROOF_ID).unwrap().finish();
        proof.push(0);
        let verifier = VerifierProofStream::new(PROOF_ID, &proof).unwrap();
        assert_rejected(verifier.finish());
    }

    #[cfg(feature = "halo2curves-secp256k1")]
    #[test]
    fn cycle_curve_is_strict_and_keeps_its_encoding_domain_separate() {
        use bulletproofs_cycle::Cycle;
        use ff::Field;
        use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
        use golden_halo2curves::Secp256k1Cycle;
        use group::Group;

        type SecpCycleCurve = CycleCurve<Secp256k1Cycle>;
        type GoldenSecpCurve = GoldenCurve<Secp256k1GoldenGroup>;

        let point = <Secp256k1Cycle as Cycle>::Point::generator();
        let point_bytes = SecpCycleCurve::encode_point(&point);
        assert_eq!(point_bytes.len(), SecpCycleCurve::POINT_BYTES);
        assert_eq!(SecpCycleCurve::decode_point(&point_bytes).unwrap(), point);
        assert_rejected(SecpCycleCurve::decode_point(
            &point_bytes[..point_bytes.len() - 1],
        ));
        assert_rejected(SecpCycleCurve::decode_point(
            &[0xff; <SecpCycleCurve as ProofStreamCurve>::POINT_BYTES],
        ));

        let scalar = <Secp256k1Cycle as Cycle>::Scalar::ONE;
        let scalar_bytes = SecpCycleCurve::encode_scalar(&scalar);
        assert_eq!(scalar_bytes.len(), 32);
        assert_eq!(
            SecpCycleCurve::decode_scalar(&scalar_bytes).unwrap(),
            scalar
        );
        assert_rejected(SecpCycleCurve::decode_scalar(&scalar_bytes[..31]));
        assert_rejected(SecpCycleCurve::decode_scalar(&[0xff; 32]));

        let identity = <Secp256k1Cycle as Cycle>::Point::identity();
        let mut prover = ProverProofStream::new(PROOF_ID).unwrap();
        prover
            .send_point::<SecpCycleCurve>(b"identity", &identity, IdentityPolicy::Allow)
            .unwrap();
        assert_rejected(prover.observe_point::<SecpCycleCurve>(
            b"identity",
            &identity,
            IdentityPolicy::Reject,
        ));
        let proof = prover.finish();
        let mut verifier = VerifierProofStream::new(PROOF_ID, &proof).unwrap();
        assert_eq!(
            verifier
                .receive_point::<SecpCycleCurve>(b"identity", IdentityPolicy::Allow)
                .unwrap(),
            identity
        );
        verifier.finish().unwrap();

        let golden_identity = Secp256k1GoldenGroup::identity();
        let golden_identity_bytes = GoldenSecpCurve::encode_point(&golden_identity);
        let cycle_identity_bytes = SecpCycleCurve::encode_point(&identity);
        assert_ne!(golden_identity_bytes, cycle_identity_bytes);
        assert_rejected(SecpCycleCurve::decode_point(&golden_identity_bytes));
        assert_rejected(GoldenSecpCurve::decode_point(&cycle_identity_bytes));
    }

    fn proof_with_body(body: &[u8]) -> Vec<u8> {
        let mut proof = ProverProofStream::new(PROOF_ID).unwrap().finish();
        proof.extend_from_slice(body);
        proof
    }

    fn verify_mixed_stream(proof: &[u8]) -> Result<()> {
        let point = P256Backend::generator();
        let scalar = <P256Backend as GoldenGroup>::Scalar::from_u64(17).unwrap();
        let mut verifier = VerifierProofStream::new(PROOF_ID, proof)?;
        verifier.observe_bytes(b"public", b"statement");
        if verifier.receive_bytes(b"prefix", 3)? != b"abc" {
            return Err(stream_error());
        }
        if verifier.receive_point::<P256Curve>(b"point", IdentityPolicy::Reject)? != point {
            return Err(stream_error());
        }
        let mut ignored_challenge = [0u8; 16];
        verifier.challenge(b"midstream", &mut ignored_challenge);
        if verifier.receive_scalar::<P256Curve>(b"scalar")? != scalar {
            return Err(stream_error());
        }
        verifier.receive_nested(|transcript, payload| {
            if payload != b"child-payload" {
                return Err(stream_error());
            }
            transcript.append_message(b"child", b"semantic-message");
            Ok(())
        })?;
        if verifier.receive_bytes(b"suffix", 2)? != b"xy" {
            return Err(stream_error());
        }
        verifier.finish()
    }

    fn assert_rejected<T>(result: Result<T>) {
        assert_eq!(result.err(), Some(Error::ProofVerificationFailed));
    }
}
