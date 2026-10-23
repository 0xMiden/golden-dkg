//! Public workflow invariants run on both supported native adapters.
#![cfg(feature = "insecure-revealed-witness")]
#![allow(clippy::unwrap_used, clippy::panic)]

use ff::Field;
use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, deal, verify_dealer_messages, DealerMessageRef, DealerProofRef,
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Zero},
    DkgOutput, Error, OwnDealing, ParticipantIndex, ParticipantRegistry, Result, SessionId,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

fn participant(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}
fn credential<G: DkgGroup>(index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(u64::from(index.get()) + 10)
}
fn configuration<G: DkgGroup>(
    n: u32,
    threshold: usize,
    kinds: Vec<DkgInstanceKind>,
) -> DkgConfig<G> {
    let entries = (1..=n)
        .map(|index| {
            let id = participant(index);
            (id, G::mul_generator(&credential::<G>(id)))
        })
        .collect();
    DkgConfig::new(
        threshold,
        SessionId([7; 32]),
        ParticipantRegistry::new(entries).unwrap(),
        kinds,
    )
    .unwrap()
}
fn dealings<G: DkgGroup>(config: &DkgConfig<G>) -> BTreeMap<ParticipantIndex, OwnDealing<G>> {
    let mut rng = ChaCha20Rng::from_seed([8; 32]);
    config
        .registry()
        .indexes()
        .map(|id| {
            (
                id,
                deal(
                    &InsecureRevealedWitnessProof,
                    config,
                    id,
                    &credential::<G>(id),
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect()
}
fn board<G: DkgGroup>(
    own: &BTreeMap<ParticipantIndex, OwnDealing<G>>,
) -> Vec<DealerMessageRef<'_>> {
    own.iter()
        .map(|(id, own)| DealerMessageRef {
            expected_dealer: *id,
            bytes: own.broadcast_bytes(),
        })
        .collect()
}
fn peers<G: DkgGroup>(
    own: &BTreeMap<ParticipantIndex, OwnDealing<G>>,
    me: ParticipantIndex,
) -> Vec<DealerMessageRef<'_>> {
    board(own)
        .into_iter()
        .filter(|item| item.expected_dealer != me)
        .collect()
}

fn mixed_workflow<G: DkgGroup>() {
    for threshold in [1, 2] {
        for kinds in [
            vec![Random],
            vec![Zero],
            vec![Random, Zero],
            vec![Zero, Random, Random],
        ] {
            let config = configuration::<G>(3, threshold, kinds.clone());
            let own = dealings(&config);
            let public =
                aggregate_public(&InsecureRevealedWitnessProof, &config, &board(&own)).unwrap();
            for id in config.registry().indexes() {
                let output = complete(
                    &InsecureRevealedWitnessProof,
                    &config,
                    &credential::<G>(id),
                    &own[&id],
                    &peers(&own, id),
                )
                .unwrap();
                assert_eq!(output.completion_root(), public.completion_root());
                for (position, kind) in kinds.iter().enumerate() {
                    let instance = public.instance(position).unwrap();
                    assert_eq!(instance.kind(), *kind);
                    assert_eq!(
                        Some(&G::mul_generator(output.secret_share(position).unwrap())),
                        instance.public_key_share(id)
                    );
                    if *kind == Zero {
                        assert!(bool::from(instance.public_key().is_identity()));
                    }
                }
                assert!(output.secret_share(kinds.len()).is_none());
            }
            assert_eq!(public.instances().len(), kinds.len());
            assert!(public.instance(kinds.len()).is_none());
        }
    }
}

#[derive(Default)]
struct Recording {
    batches: AtomicUsize,
    singles: AtomicUsize,
}
impl<G: DkgGroup> DealerProofSystem<G> for Recording {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl rand_chacha::rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>> {
        InsecureRevealedWitnessProof.prove(config, statement, witness, rng)
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        self.singles.fetch_add(1, Ordering::SeqCst);
        InsecureRevealedWitnessProof.verify(config, statement, proof)
    }
    fn verify_batch(&self, config: &DkgConfig<G>, proofs: &[DealerProofRef<'_, G>]) -> Result<()> {
        self.batches.fetch_add(1, Ordering::SeqCst);
        for item in proofs {
            InsecureRevealedWitnessProof.verify(config, item.statement, item.proof)?;
        }
        Ok(())
    }
}
fn validation_order_and_retry<G: DkgGroup>() {
    let config = configuration::<G>(3, 2, vec![Random, Zero]);
    let own = dealings(&config);
    let mut altered: Vec<_> = board(&own)
        .iter()
        .map(|item| (item.expected_dealer, item.bytes.to_vec()))
        .collect();
    altered[0].1.truncate(1);
    altered[2].1.push(0);
    let candidates: Vec<_> = altered
        .iter()
        .rev()
        .map(|(id, bytes)| DealerMessageRef {
            expected_dealer: *id,
            bytes,
        })
        .collect();
    let recording = Recording::default();
    assert_eq!(
        verify_dealer_messages(&recording, &config, &candidates),
        Err(Error::InvalidDealerMessages {
            dealers: vec![participant(1), participant(3)]
        })
    );
    assert_eq!(recording.batches.load(Ordering::SeqCst), 0);
    assert_eq!(recording.singles.load(Ordering::SeqCst), 0);

    let mut altered: Vec<_> = board(&own)
        .iter()
        .map(|item| (item.expected_dealer, item.bytes.to_vec()))
        .collect();
    for position in [0, 2] {
        let last = altered[position].1.len() - 1;
        altered[position].1[last] ^= 1;
    }
    let candidates: Vec<_> = altered
        .iter()
        .map(|(id, bytes)| DealerMessageRef {
            expected_dealer: *id,
            bytes,
        })
        .collect();
    assert_eq!(
        verify_dealer_messages(&recording, &config, &candidates),
        Err(Error::InvalidDealerProofs {
            dealers: vec![participant(1), participant(3)]
        })
    );
    assert_eq!(recording.batches.load(Ordering::SeqCst), 1);
    assert_eq!(recording.singles.load(Ordering::SeqCst), 3);

    let me = participant(2);
    let bad_peers: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|item| item.expected_dealer != me)
        .collect();
    assert!(matches!(
        complete(
            &recording,
            &config,
            &credential::<G>(me),
            &own[&me],
            &bad_peers
        ),
        Err(Error::InvalidDealerProofs { .. })
    ));
    let retried = complete(
        &recording,
        &config,
        &credential::<G>(me),
        &own[&me],
        &peers(&own, me),
    )
    .unwrap();
    let public = aggregate_public(&recording, &config, &board(&own)).unwrap();
    assert_eq!(retried.completion_root(), public.completion_root());
    verify_dealer_messages(&recording, &config, &board(&own)[..1]).unwrap();
    assert!(matches!(
        aggregate_public(&recording, &config, &board(&own)[..1]),
        Err(Error::MissingDealer { .. })
    ));
}

struct NoProofCalls;
impl<G: DkgGroup> DealerProofSystem<G> for NoProofCalls {
    fn prove(
        &self,
        _: &DkgConfig<G>,
        _: &DealerProofStatement<G>,
        _: &DealerProofWitness<G>,
        _: &mut impl rand_chacha::rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>> {
        panic!("singleton proving")
    }
    fn verify(&self, _: &DkgConfig<G>, _: &DealerProofStatement<G>, _: &[u8]) -> Result<()> {
        panic!("singleton verification")
    }
    fn verify_batch(&self, _: &DkgConfig<G>, _: &[DealerProofRef<'_, G>]) -> Result<()> {
        panic!("singleton batch")
    }
}
fn singleton<G: DkgGroup>() {
    let config = configuration::<G>(1, 1, vec![Random, Zero, Random]);
    let me = participant(1);
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let own = deal(&NoProofCalls, &config, me, &credential::<G>(me), &mut rng).unwrap();
    let board = [DealerMessageRef {
        expected_dealer: me,
        bytes: own.broadcast_bytes(),
    }];
    verify_dealer_messages(&NoProofCalls, &config, &board).unwrap();
    let public = aggregate_public(&NoProofCalls, &config, &board).unwrap();
    let local = complete(&NoProofCalls, &config, &credential::<G>(me), &own, &[]).unwrap();
    assert_eq!(public.completion_root(), local.completion_root());
    assert_eq!(local.secret_share(1), Some(&G::Scalar::ZERO));
    let mut malformed = own.broadcast_bytes().to_vec();
    malformed.push(1);
    assert!(verify_dealer_messages(
        &NoProofCalls,
        &config,
        &[DealerMessageRef {
            expected_dealer: me,
            bytes: &malformed
        }]
    )
    .is_err());
}

fn contextual_persistence<G: DkgGroup>() {
    let config = configuration::<G>(3, 2, vec![Random, Zero]);
    let own = dealings(&config);
    let restored_config = DkgConfig::<G>::from_bytes(&config.to_bytes().unwrap()).unwrap();
    assert_eq!(restored_config.root(), config.root());
    let me = participant(1);
    let restored_own = OwnDealing::from_bytes(&config, me, &own[&me].to_bytes().unwrap()).unwrap();
    assert_eq!(restored_own.broadcast_bytes(), own[&me].broadcast_bytes());
    assert!(
        OwnDealing::<G>::from_bytes(&config, participant(2), &own[&me].to_bytes().unwrap())
            .is_err()
    );
    let output = complete(
        &InsecureRevealedWitnessProof,
        &config,
        &credential::<G>(me),
        &restored_own,
        &peers(&own, me),
    )
    .unwrap();
    let bytes = output.to_bytes().unwrap();
    let restored = DkgOutput::from_bytes(&config, me, &bytes).unwrap();
    assert_eq!(restored.completion_root(), output.completion_root());
    assert_eq!(restored.secret_share(0), output.secret_share(0));
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(DkgOutput::<G>::from_bytes(&config, me, &corrupted).is_err());
    assert!(DkgOutput::<G>::from_bytes(&config, participant(2), &bytes).is_err());
    let restored_public =
        golden_core::DkgPublicOutput::from_bytes(&config, &output.public().to_bytes().unwrap())
            .unwrap();
    assert_eq!(restored_public.completion_root(), output.completion_root());
    let rows: Vec<_> = config
        .registry()
        .indexes()
        .map(|id| {
            (
                id,
                *output
                    .public()
                    .instance(0)
                    .unwrap()
                    .public_key_share(id)
                    .unwrap(),
                *output
                    .public()
                    .instance(1)
                    .unwrap()
                    .public_key_share(id)
                    .unwrap(),
            )
        })
        .collect();
    let expected_root = golden_core::output::ehtdh1_completion_root::<G>(
        config.root(),
        output.public().instance(0).unwrap().public_key(),
        &rows,
    )
    .unwrap();
    assert_eq!(expected_root, output.completion_root());
    for debug in [
        format!("{:?}", own[&me]),
        format!("{output:?}"),
        format!("{:?}", own[&me].snapshot().unwrap()),
    ] {
        assert!(debug.contains("<redacted>"));
    }
}

macro_rules! both {
    ($name:ident, $function:ident) => {
        #[test]
        fn $name() {
            $function::<Secp256k1Group>();
            $function::<JubjubGroup>();
        }
    };
}
both!(mixed_random_zero_public_and_local_agree, mixed_workflow);
both!(
    all_dealer_attribution_precedes_proofs_and_retry_is_atomic,
    validation_order_and_retry
);
both!(singleton_bypasses_every_proof_system_method, singleton);
both!(
    contextual_snapshots_bind_owner_and_public_results,
    contextual_persistence
);

struct BatchFailure {
    operational: bool,
    singles: AtomicUsize,
}
impl<G: DkgGroup> DealerProofSystem<G> for BatchFailure {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl rand_chacha::rand_core::CryptoRngCore,
    ) -> Result<Vec<u8>> {
        InsecureRevealedWitnessProof.prove(config, statement, witness, rng)
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        self.singles.fetch_add(1, Ordering::SeqCst);
        InsecureRevealedWitnessProof.verify(config, statement, proof)
    }
    fn verify_batch(&self, _: &DkgConfig<G>, _: &[DealerProofRef<'_, G>]) -> Result<()> {
        if self.operational {
            Err(Error::InsufficientProofCapacity {
                required: 8,
                available: 4,
            })
        } else {
            Err(Error::InvalidProof)
        }
    }
}
fn batch_error_classes<G: DkgGroup>() {
    let config = configuration::<G>(3, 2, vec![Random]);
    let own = dealings(&config);
    for operational in [false, true] {
        let proofs = BatchFailure {
            operational,
            singles: AtomicUsize::new(0),
        };
        let expected = if operational {
            Error::InsufficientProofCapacity {
                required: 8,
                available: 4,
            }
        } else {
            Error::BatchVerificationFailed
        };
        assert_eq!(
            verify_dealer_messages(&proofs, &config, &board(&own)),
            Err(expected)
        );
        assert_eq!(
            proofs.singles.load(Ordering::SeqCst),
            if operational { 0 } else { 3 }
        );
    }
}
both!(
    operational_errors_never_trigger_dealer_blame_or_fallback,
    batch_error_classes
);

// Model a native decoding operation that fails independently of the received
// bytes. Thread-local injection keeps the genuine adapter and parallel cases
// isolated, and permits configuration/dealing creation before the failure.
std::thread_local! {
    static FAIL_POINT_DECODING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodeFailure<G: DkgGroup>(std::marker::PhantomData<G>);
impl<G: DkgGroup> DkgGroup for DecodeFailure<G> {
    type Scalar = G::Scalar;
    type Point = G::Point;
    type BaseField = G::BaseField;
    const GROUP_ID: &'static str = G::GROUP_ID;
    const POINT_BYTES: usize = G::POINT_BYTES;
    fn encode_point(point: &Self::Point) -> Vec<u8> {
        G::encode_point(point)
    }
    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        if FAIL_POINT_DECODING.with(|fail| fail.get()) {
            return Err(Error::ProofOperationFailed);
        }
        G::decode_point(bytes)
    }
    fn encode_scalar(value: &Self::Scalar) -> [u8; 32] {
        G::encode_scalar(value)
    }
    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        G::decode_scalar(bytes)
    }
    fn base_field_byte_order() -> golden_core::FieldByteOrder {
        G::base_field_byte_order()
    }
    fn hash_to_point(domain: &[u8], input: &[u8]) -> Result<Self::Point> {
        G::hash_to_point(domain, input)
    }
    fn affine_x(point: &Self::Point) -> Result<Self::BaseField> {
        G::affine_x(point)
    }
    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar {
        G::reduce_base_field(value)
    }
    fn mul_generator(value: &Self::Scalar) -> Self::Point {
        G::mul_generator(value)
    }
}
fn parse_operational_error<G: DkgGroup>() {
    let config = configuration::<DecodeFailure<G>>(2, 1, vec![Random]);
    let own = dealings(&config);
    let recording = Recording::default();
    let result = FAIL_POINT_DECODING.with(|fail| {
        fail.set(true);
        let result = verify_dealer_messages(&recording, &config, &board(&own));
        fail.set(false);
        result
    });
    assert_eq!(result, Err(Error::ProofOperationFailed));
    assert_eq!(recording.batches.load(Ordering::SeqCst), 0);
    assert_eq!(recording.singles.load(Ordering::SeqCst), 0);
    // The same immutable board remains valid after the operational failure.
    verify_dealer_messages(&recording, &config, &board(&own)).unwrap();
}
both!(
    operational_parse_failures_do_not_blame_dealers_or_interpret_proofs,
    parse_operational_error
);

// A deliberately faulted native adapter makes negligible-probability pad
// degeneracy deterministic without weakening either production adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PadFault<G: DkgGroup, const ZERO_EXPONENT: bool>(std::marker::PhantomData<G>);
impl<G: DkgGroup, const ZERO_EXPONENT: bool> DkgGroup for PadFault<G, ZERO_EXPONENT> {
    type Scalar = G::Scalar;
    type Point = G::Point;
    type BaseField = G::BaseField;
    const GROUP_ID: &'static str = "fault-injection-test-only";
    const POINT_BYTES: usize = G::POINT_BYTES;
    fn encode_point(point: &Self::Point) -> Vec<u8> {
        G::encode_point(point)
    }
    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        G::decode_point(bytes)
    }
    fn encode_scalar(value: &Self::Scalar) -> [u8; 32] {
        G::encode_scalar(value)
    }
    fn decode_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        G::decode_scalar(bytes)
    }
    fn base_field_byte_order() -> golden_core::FieldByteOrder {
        G::base_field_byte_order()
    }
    fn hash_to_point(_: &[u8], _: &[u8]) -> Result<Self::Point> {
        Ok(G::mul_generator(&G::Scalar::from(3)))
    }
    fn affine_x(point: &Self::Point) -> Result<Self::BaseField> {
        if bool::from(point.is_identity()) {
            return Err(Error::RelationEvaluationFailed);
        }
        if !ZERO_EXPONENT && *point == G::mul_generator(&G::Scalar::from(132)) {
            Ok(G::BaseField::ONE)
        } else {
            Ok(G::BaseField::ZERO)
        }
    }
    fn reduce_base_field(value: &Self::BaseField) -> Self::Scalar {
        G::reduce_base_field(value)
    }
    fn mul_generator(value: &Self::Scalar) -> Self::Point {
        G::mul_generator(value)
    }
}
fn degenerate_local_relation<G: DkgGroup>() {
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let id = participant(1);
    let config = configuration::<PadFault<G, false>>(2, 1, vec![Random]);
    let result = deal(&NoProofCalls, &config, id, &credential::<G>(id), &mut rng);
    assert!(matches!(result, Err(Error::DegenerateEvrfOutput)));
    let config = configuration::<PadFault<G, true>>(2, 1, vec![Random]);
    let result = deal(&NoProofCalls, &config, id, &credential::<G>(id), &mut rng);
    assert!(matches!(result, Err(Error::RelationEvaluationFailed)));
}
both!(
    zero_pads_retry_but_zero_dh_exponents_fail_without_proving,
    degenerate_local_relation
);

struct ZeroSamples;
impl rand_chacha::rand_core::RngCore for ZeroSamples {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
    fn try_fill_bytes(
        &mut self,
        bytes: &mut [u8],
    ) -> core::result::Result<(), rand_chacha::rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl rand_chacha::rand_core::CryptoRng for ZeroSamples {}
fn identity_shares_and_pad_rejection<G: DkgGroup>() {
    // Synthetic zero samples exercise valid zero Random openings and equal
    // raw nonces. Applications must use a real cryptographic RNG.
    let config = configuration::<G>(2, 1, vec![Random, Zero]);
    let mut rng = ZeroSamples;
    let own: BTreeMap<_, _> = config
        .registry()
        .indexes()
        .map(|id| {
            (
                id,
                deal(
                    &InsecureRevealedWitnessProof,
                    &config,
                    id,
                    &credential::<G>(id),
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect();
    let public = aggregate_public(&InsecureRevealedWitnessProof, &config, &board(&own)).unwrap();
    for instance in public.instances() {
        assert!(bool::from(instance.public_key().is_identity()));
    }
    for id in config.registry().indexes() {
        let local = complete(
            &InsecureRevealedWitnessProof,
            &config,
            &credential::<G>(id),
            &own[&id],
            &peers(&own, id),
        )
        .unwrap();
        assert_eq!(local.secret_share(0), Some(&G::Scalar::ZERO));
    }
    let mut bytes = own[&participant(1)].broadcast_bytes().to_vec();
    let offset = 8 + b"golden-dkg-wire-v4".len() + 32 + 4 + 32 + G::POINT_BYTES;
    bytes[offset..offset + G::POINT_BYTES].copy_from_slice(&G::encode_point(&G::Point::identity()));
    let recording = Recording::default();
    assert_eq!(
        verify_dealer_messages(
            &recording,
            &config,
            &[DealerMessageRef {
                expected_dealer: participant(1),
                bytes: &bytes
            }]
        ),
        Err(Error::InvalidDealerMessages {
            dealers: vec![participant(1)]
        })
    );
    assert_eq!(recording.batches.load(Ordering::SeqCst), 0);
}
both!(
    identity_shares_are_valid_but_identity_pad_commitments_fail_publicly,
    identity_shares_and_pad_rejection
);
