//! Focused concrete-proof coverage; broad workflow cases use core's insecure checker.
use ff::Field;
use golden_core::{
    aggregate_public, complete, deal, verify_dealer_message, DealerMessageRef, DealerProofRef,
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind, DkgOutput, DkgPublicOutput, Error, OwnDealing, ParticipantIndex,
    ParticipantRegistry, Result, SessionId,
};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::{CryptoRng, RngCore};
use std::sync::Mutex;

struct FirstFieldZero {
    remaining: usize,
    inner: ChaCha20Rng,
}
impl RngCore for FirstFieldZero {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        let n = self.remaining.min(bytes.len());
        bytes[..n].fill(0);
        self.remaining -= n;
        self.inner.fill_bytes(&mut bytes[n..]);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for FirstFieldZero {}
struct Capture<G: DkgGroup, P> {
    inner: P,
    proofs: Mutex<Vec<(DealerProofStatement<G>, Vec<u8>)>>,
}
impl<G: DkgGroup, P: DealerProofSystem<G>> DealerProofSystem<G> for Capture<G, P> {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let proof = self.inner.prove(config, statement, witness, rng)?;
        self.proofs
            .lock()
            .unwrap()
            .push((statement.clone(), proof.clone()));
        Ok(proof)
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        self.inner.verify(config, statement, proof)
    }
    fn verify_batch(&self, config: &DkgConfig<G>, proofs: &[DealerProofRef<'_, G>]) -> Result<()> {
        self.inner.verify_batch(config, proofs)
    }
}
fn configuration<G: DkgGroup>(singleton: bool) -> DkgConfig<G> {
    let count = if singleton { 1 } else { 2 };
    let entries = (1..=count)
        .map(|index| {
            let participant = ParticipantIndex::new(index).unwrap();
            (
                participant,
                G::mul_generator(&G::Scalar::from(u64::from(index))),
            )
        })
        .collect();
    DkgConfig::new(
        1,
        SessionId([92; 32]),
        ParticipantRegistry::new(entries).unwrap(),
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    )
    .unwrap()
}
fn real_workflow<G: DkgGroup, P: DealerProofSystem<G>>(
    prepare: impl Fn(&DkgConfig<G>) -> (P, Vec<u8>, usize),
    restore: impl Fn(&[u8]) -> (P, Vec<u8>, usize),
) {
    let config = configuration::<G>(false);
    let (_, bytes, capacity) = prepare(&config);
    let (proofs, restored_bytes, restored_capacity) = restore(&bytes);
    assert_eq!(bytes, restored_bytes);
    assert_eq!(capacity, restored_capacity);
    let capture = Capture {
        inner: proofs,
        proofs: Mutex::new(Vec::new()),
    };
    let one = ParticipantIndex::new(1).unwrap();
    let two = ParticipantIndex::new(2).unwrap();
    let mut rng1 = FirstFieldZero {
        remaining: 64,
        inner: ChaCha20Rng::from_seed([81; 32]),
    };
    let mut rng2 = FirstFieldZero {
        remaining: 64,
        inner: ChaCha20Rng::from_seed([82; 32]),
    };
    let own = deal(&capture, &config, one, &G::Scalar::ONE, &mut rng1).unwrap();
    let peer = deal(&capture, &config, two, &G::Scalar::from(2), &mut rng2).unwrap();
    {
        let captured = capture.proofs.lock().unwrap();
        // The proof-system seam permits repeated proofs; board uniqueness is
        // enforced by core. Reuse the fixture to cross a worker-sized chunk.
        let mut batch = (0..=p3_maybe_rayon::prelude::current_num_threads())
            .map(|index| {
                let (statement, proof) = &captured[index % captured.len()];
                DealerProofRef { statement, proof }
            })
            .collect::<Vec<_>>();
        capture.verify_batch(&config, &batch).unwrap();
        batch.last_mut().unwrap().proof = b"malformed";
        assert_eq!(
            capture.verify_batch(&config, &batch),
            Err(Error::InvalidProof)
        );
    }
    let board = [
        DealerMessageRef {
            expected_dealer: one,
            bytes: own.broadcast_bytes(),
        },
        DealerMessageRef {
            expected_dealer: two,
            bytes: peer.broadcast_bytes(),
        },
    ];
    let public = aggregate_public(&capture, &config, &board).unwrap();
    let output = complete(&capture, &config, &G::Scalar::ONE, &own, &board[1..]).unwrap();
    assert_eq!(public.completion_root(), output.completion_root());
    assert!(bool::from(
        public.instance(0).unwrap().public_key().is_identity()
    ));
    assert!(bool::from(output.secret_share(0).unwrap().is_zero()));
    assert!(bool::from(output.secret_share(1).unwrap().is_zero()));
    let mut corrupted = own.broadcast_bytes().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_invalid_proof(&capture, &config, one, &corrupted, "constant response");
    let (zero, zero_bytes, zero_capacity) = prepare(&configuration::<G>(true));
    assert_eq!(zero_capacity, 0);
    assert!(zero_bytes.len() < 256);
    {
        let captured = capture.proofs.lock().unwrap();
        assert!(matches!(
            zero.verify(&config, &captured.last().unwrap().0, b"malformed"),
            Err(Error::InsufficientProofCapacity { available: 0, .. })
        ));
    }
    // Reuse the restored mixed-shape generator prefix for smaller single-instance
    // circuits and a repeated-Random batch, without implicit preparation/growth.
    for (seed, kinds) in [
        (93u8, vec![DkgInstanceKind::Random]),
        (94u8, vec![DkgInstanceKind::Zero]),
        (95u8, vec![DkgInstanceKind::Random, DkgInstanceKind::Random]),
    ] {
        let case =
            DkgConfig::new(2, SessionId([seed; 32]), config.registry().clone(), kinds).unwrap();
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let own = deal(&capture, &case, one, &G::Scalar::ONE, &mut rng).unwrap();
        let peer = deal(&capture, &case, two, &G::Scalar::from(2), &mut rng).unwrap();
        let own = OwnDealing::from_bytes(&case, one, &own.to_bytes().unwrap()).unwrap();
        let peer = OwnDealing::from_bytes(&case, two, &peer.to_bytes().unwrap()).unwrap();
        let board = [
            DealerMessageRef {
                expected_dealer: one,
                bytes: own.broadcast_bytes(),
            },
            DealerMessageRef {
                expected_dealer: two,
                bytes: peer.broadcast_bytes(),
            },
        ];
        let public = aggregate_public(&capture, &case, &board).unwrap();
        // These bytes have trusted provenance from the immediately verified board.
        let restored_public =
            DkgPublicOutput::from_bytes(&case, &public.to_bytes().unwrap()).unwrap();
        let output = complete(&capture, &case, &G::Scalar::ONE, &own, &board[1..]).unwrap();
        let restored_output =
            DkgOutput::from_bytes(&case, one, &output.to_bytes().unwrap()).unwrap();
        assert_eq!(public.completion_root(), output.completion_root());
        assert_eq!(restored_public.completion_root(), output.completion_root());
        assert_eq!(restored_output.completion_root(), output.completion_root());
        for position in 0..case.instances().len() {
            let local = output.secret_share(position).unwrap();
            assert_eq!(
                G::mul_generator(local),
                *public
                    .instance(position)
                    .unwrap()
                    .public_key_share(one)
                    .unwrap(),
            );
            assert_eq!(restored_output.secret_share(position), Some(local));
        }
        if case.instances() == [DkgInstanceKind::Random, DkgInstanceKind::Random] {
            reject_publicly_valid_mutations(&capture, &case, one, own.broadcast_bytes());
        }
    }
}

fn assert_invalid_proof<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    bytes: &[u8],
    mutation: &str,
) {
    assert_eq!(
        verify_dealer_message(proofs, config, dealer, bytes),
        Err(Error::InvalidDealerProofs {
            dealers: vec![dealer]
        }),
        "publicly valid mutation was not rejected at the proof boundary: {mutation}",
    );
}

fn reject_publicly_valid_mutations<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    dealer: ParticipantIndex,
    message: &[u8],
) {
    let header = 8 + b"golden-dkg-wire-v4".len() + 32 + 4;
    let receivers = config.registry().len() - 1;
    let slot_bytes = G::POINT_BYTES + 32;
    let block_bytes = 32 + config.threshold() * G::POINT_BYTES + receivers * slot_bytes;
    let first_constant = header + 32;
    let first_pad = first_constant + config.threshold() * G::POINT_BYTES;
    let first_cipher = first_pad + G::POINT_BYTES;
    let mut mutations = Vec::new();

    let mut nonce = message.to_vec();
    nonce[header] ^= 1;
    mutations.push(("nonce", nonce));

    let pad = G::decode_point(&message[first_pad..first_pad + G::POINT_BYTES]).unwrap();
    let cipher = G::decode_scalar(&message[first_cipher..first_cipher + 32]).unwrap();
    let mut delta = G::Scalar::ONE;
    if bool::from((pad + G::mul_generator(&delta)).is_identity()) {
        delta += G::Scalar::ONE;
    }
    let mut paired = message.to_vec();
    paired[first_pad..first_pad + G::POINT_BYTES]
        .copy_from_slice(&G::encode_point(&(pad + G::mul_generator(&delta))));
    paired[first_cipher..first_cipher + 32].copy_from_slice(&G::encode_scalar(&(cipher + delta)));
    mutations.push(("paired pad/ciphertext", paired));

    let constant =
        G::decode_point(&message[first_constant..first_constant + G::POINT_BYTES]).unwrap();
    let mut shifted = message.to_vec();
    shifted[first_constant..first_constant + G::POINT_BYTES].copy_from_slice(&G::encode_point(
        &(constant + G::mul_generator(&G::Scalar::ONE)),
    ));
    // Adding one to A_0 adds one to every receiver's Feldman evaluation;
    // shift each ciphertext by the same amount to retain the public equation.
    for receiver in 0..receivers {
        let offset = first_cipher + receiver * slot_bytes;
        let value = G::decode_scalar(&message[offset..offset + 32]).unwrap();
        shifted[offset..offset + 32].copy_from_slice(&G::encode_scalar(&(value + G::Scalar::ONE)));
    }
    mutations.push(("constant/ciphertexts", shifted));

    let mut reordered = message.to_vec();
    let (first, rest) = reordered.split_at_mut(header + block_bytes);
    first[header..].swap_with_slice(&mut rest[..block_bytes]);
    mutations.push(("instance block order", reordered));

    // Constant proof widths are fixed by the inner protocol codec; their
    // positions are omitted from bytes and must remain transcript-bound.
    let proof_frame = header + config.instances().len() * block_bytes;
    let proof_start = proof_frame + 8;
    let mut reader = golden_core::wire::Reader::new(&message[proof_start..]);
    reader.framed().unwrap(); // expected concrete proof-family identifier
    reader.framed().unwrap(); // canonical nested R1CS payload
    let constant_bytes = G::POINT_BYTES + 32;
    assert_eq!(reader.remaining(), 2 * constant_bytes);
    let constant_start = message.len() - reader.remaining();
    let mut swapped = message.to_vec();
    let (first, second) = swapped[constant_start..].split_at_mut(constant_bytes);
    first.swap_with_slice(second);
    mutations.push(("Random constant proof order", swapped));

    for (name, bytes) in mutations {
        assert_invalid_proof(proofs, config, dealer, &bytes, name);
    }
}
#[cfg(feature = "secp-secq")]
#[test]
#[ignore = "real joint proofs; concrete backend nightly gate"]
fn secp_joint_native_parity_zero_random_constant_batch_and_restoration() {
    real_workflow::<golden_curves::Secp256k1Group, crate::SecpSecqBulletproofs>(
        |config| {
            let prepared = crate::SecpSecqPrepared::prepare_for(config).unwrap();
            let capacity = prepared.capacity();
            let bytes = prepared.to_bytes().unwrap();
            (
                crate::SecpSecqBulletproofs::from_prepared(prepared),
                bytes,
                capacity,
            )
        },
        |bytes| {
            let prepared = crate::SecpSecqPrepared::from_bytes(bytes).unwrap();
            let capacity = prepared.capacity();
            let bytes = prepared.to_bytes().unwrap();
            (
                crate::SecpSecqBulletproofs::from_prepared(prepared),
                bytes,
                capacity,
            )
        },
    );
}
#[cfg(feature = "jubjub-bls12-381")]
#[test]
#[ignore = "real joint proofs; concrete backend nightly gate"]
fn jubjub_joint_native_parity_zero_random_constant_batch_and_restoration() {
    real_workflow::<golden_curves::JubjubGroup, crate::BlsJubjubBulletproofs>(
        |config| {
            let prepared = crate::BlsJubjubPrepared::prepare_for(config).unwrap();
            let capacity = prepared.capacity();
            let bytes = prepared.to_bytes().unwrap();
            (
                crate::BlsJubjubBulletproofs::from_prepared(prepared),
                bytes,
                capacity,
            )
        },
        |bytes| {
            let prepared = crate::BlsJubjubPrepared::from_bytes(bytes).unwrap();
            let capacity = prepared.capacity();
            let bytes = prepared.to_bytes().unwrap();
            (
                crate::BlsJubjubBulletproofs::from_prepared(prepared),
                bytes,
                capacity,
            )
        },
    );
}

fn malformed_artifact<C: crate::driver::Backend>() {
    use crate::prepared::Prepared;
    let zero = Prepared::<C>::prepare_for(&configuration::<C::Dkg>(true)).unwrap();
    let encoded = zero.to_bytes().unwrap();
    assert_eq!(Prepared::<C>::from_bytes(&encoded).unwrap().capacity, 0);
    let mut bad = encoded.clone();
    bad.push(0);
    assert!(matches!(
        Prepared::<C>::from_bytes(&bad),
        Err(Error::MalformedPreparedGenerators)
    ));
    assert!(matches!(
        Prepared::<C>::from_bytes(&encoded[..encoded.len() - 1]),
        Err(Error::MalformedPreparedGenerators)
    ));
    let mut version = encoded.clone();
    let offset = 8 + b"golden-dkg-prepared".len();
    version[offset + 3] ^= 1;
    assert!(matches!(
        Prepared::<C>::from_bytes(&version),
        Err(Error::MalformedPreparedGenerators)
    ));
    // Warmed/oversized owned tables must not leak past the declared prefix.
    let pc = bulletproofs_cycle::generators::PedersenGens::<C>::default();
    let bp = bulletproofs_cycle::generators::BulletproofGens::<C>::new(4, 1);
    let prefix = Prepared::<C> {
        capacity: 2,
        generators: Some((pc, bp)),
    };
    let bytes = prefix.to_bytes().unwrap();
    let restored = Prepared::<C>::from_bytes(&bytes).unwrap();
    assert_eq!(restored.capacity, 2);
    assert_eq!(restored.to_bytes().unwrap(), bytes);
    let point_start = bytes.len() - 6 * C::COMPRESSED_BYTES;
    let mut identity = bytes.clone();
    identity[point_start..point_start + C::COMPRESSED_BYTES]
        .copy_from_slice(C::compressed_as_bytes(&C::compressed_identity()));
    assert!(matches!(
        Prepared::<C>::from_bytes(&identity),
        Err(Error::MalformedPreparedGenerators)
    ));
    let mut noncanonical = bytes;
    noncanonical[point_start..point_start + C::COMPRESSED_BYTES].fill(255);
    assert!(matches!(
        Prepared::<C>::from_bytes(&noncanonical),
        Err(Error::MalformedPreparedGenerators)
    ));
}
#[cfg(feature = "secp-secq")]
#[test]
fn secp_artifact_metadata_and_exact_prefix() {
    malformed_artifact::<crate::outer::secp::SecqCycle>();
}
#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn jubjub_artifact_metadata_and_exact_prefix() {
    malformed_artifact::<crate::outer::cycle::Bls12_381G1Cycle>();
}

#[cfg(all(feature = "serde", feature = "secp-secq"))]
#[test]
fn secp_serde_uses_the_same_validated_artifact_bytes() {
    let prepared = crate::SecpSecqPrepared::prepare_for(&configuration(true)).unwrap();
    let bytes = postcard::to_allocvec(&prepared).unwrap();
    let restored: crate::SecpSecqPrepared = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(prepared.to_bytes().unwrap(), restored.to_bytes().unwrap());
}
#[cfg(all(feature = "serde", feature = "jubjub-bls12-381"))]
#[test]
fn jubjub_serde_uses_the_same_validated_artifact_bytes() {
    let prepared = crate::BlsJubjubPrepared::prepare_for(&configuration(true)).unwrap();
    let bytes = postcard::to_allocvec(&prepared).unwrap();
    let restored: crate::BlsJubjubPrepared = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(prepared.to_bytes().unwrap(), restored.to_bytes().unwrap());
}
