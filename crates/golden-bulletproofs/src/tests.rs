//! Focused concrete-proof coverage; broad workflow cases use core's insecure checker.
use ff::Field;
use golden_core::{
    aggregate_public, complete, deal, verify_dealer_message, DealerMessageRef, DealerProofRef,
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind, Error, ParticipantIndex, ParticipantRegistry, Result, SessionId,
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
    statement: Mutex<Option<DealerProofStatement<G>>>,
}
impl<G: DkgGroup, P: DealerProofSystem<G>> DealerProofSystem<G> for Capture<G, P> {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>> {
        *self.statement.lock().unwrap() = Some(statement.clone());
        self.inner.prove(config, statement, witness, rng)
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
        statement: Mutex::new(None),
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
    assert_eq!(
        verify_dealer_message(&capture, &config, one, &corrupted),
        Err(Error::InvalidDealerProofs { dealers: vec![one] })
    );
    let (zero, zero_bytes, zero_capacity) = prepare(&configuration::<G>(true));
    assert_eq!(zero_capacity, 0);
    assert!(zero_bytes.len() < 256);
    let statement = capture.statement.lock().unwrap();
    assert!(matches!(
        zero.verify(&config, statement.as_ref().unwrap(), b"malformed"),
        Err(Error::InsufficientProofCapacity { available: 0, .. })
    ));
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
