//! Public tests for opaque dealer-message generation.

#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use golden_core::{
    complete, deal, max_dealer_message_bytes, DealerMessageError, DealerProofRef,
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgInstanceKind, Error,
    GoldenGroup, GoldenScalar, OwnDealing, ParticipantIndex, ParticipantRegistry, Result,
    SessionId,
};
use golden_evrf::InsecureRevealedWitnessProof;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, CryptoRngCore, Error as RandError, RngCore, SeedableRng};

#[derive(Default)]
struct CountingProofSystem {
    prove_calls: AtomicUsize,
    verify_calls: AtomicUsize,
    batch_calls: AtomicUsize,
}

impl CountingProofSystem {
    fn prove_calls(&self) -> usize {
        self.prove_calls.load(Ordering::SeqCst)
    }

    fn verify_calls(&self) -> usize {
        self.verify_calls.load(Ordering::SeqCst)
    }

    fn batch_calls(&self) -> usize {
        self.batch_calls.load(Ordering::SeqCst)
    }
}

impl DealerProofSystem<P256Backend> for CountingProofSystem {
    fn prove(
        &self,
        config: &DkgConfig<P256Backend>,
        statement: &DealerProofStatement<P256Backend>,
        witness: &DealerProofWitness<P256Backend>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.prove_calls.fetch_add(1, Ordering::SeqCst);
        <InsecureRevealedWitnessProof as DealerProofSystem<P256Backend>>::prove(
            &InsecureRevealedWitnessProof,
            config,
            statement,
            witness,
            rng,
        )
    }

    fn verify(
        &self,
        config: &DkgConfig<P256Backend>,
        statement: &DealerProofStatement<P256Backend>,
        proof: &[u8],
    ) -> Result<()> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        <InsecureRevealedWitnessProof as DealerProofSystem<P256Backend>>::verify(
            &InsecureRevealedWitnessProof,
            config,
            statement,
            proof,
        )
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<P256Backend>,
        proofs: &[DealerProofRef<'_, P256Backend>],
    ) -> Result<()> {
        self.batch_calls.fetch_add(1, Ordering::SeqCst);
        <InsecureRevealedWitnessProof as DealerProofSystem<P256Backend>>::verify_batch(
            &InsecureRevealedWitnessProof,
            config,
            proofs,
        )
    }
}

#[derive(Clone)]
enum VerificationMode {
    Accept,
    Invalid(Vec<ParticipantIndex>),
    BatchOnlyFailure,
    BatchOperationalFailure,
    IndividualOperationalFailure(ParticipantIndex),
}

struct ScriptedProofSystem {
    mode: Mutex<VerificationMode>,
    batch_dealers: Mutex<Vec<Vec<ParticipantIndex>>>,
    individual_dealers: Mutex<Vec<ParticipantIndex>>,
}

impl Default for ScriptedProofSystem {
    fn default() -> Self {
        Self {
            mode: Mutex::new(VerificationMode::Accept),
            batch_dealers: Mutex::new(Vec::new()),
            individual_dealers: Mutex::new(Vec::new()),
        }
    }
}

impl ScriptedProofSystem {
    fn set_mode(&self, mode: VerificationMode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn batch_dealers(&self) -> Vec<Vec<ParticipantIndex>> {
        self.batch_dealers.lock().unwrap().clone()
    }

    fn individual_dealers(&self) -> Vec<ParticipantIndex> {
        self.individual_dealers.lock().unwrap().clone()
    }

    fn expected_proof(statement: &DealerProofStatement<P256Backend>) -> [u8; 4] {
        statement.dealer().get().to_be_bytes()
    }
}

impl DealerProofSystem<P256Backend> for ScriptedProofSystem {
    fn prove(
        &self,
        _config: &DkgConfig<P256Backend>,
        statement: &DealerProofStatement<P256Backend>,
        _witness: &DealerProofWitness<P256Backend>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        Ok(Self::expected_proof(statement).to_vec())
    }

    fn verify(
        &self,
        _config: &DkgConfig<P256Backend>,
        statement: &DealerProofStatement<P256Backend>,
        proof: &[u8],
    ) -> Result<()> {
        let dealer = statement.dealer();
        self.individual_dealers.lock().unwrap().push(dealer);
        if proof != Self::expected_proof(statement) {
            return Err(Error::ProofVerificationFailed);
        }

        match &*self.mode.lock().unwrap() {
            VerificationMode::Invalid(dealers) if dealers.contains(&dealer) => {
                Err(Error::ProofVerificationFailed)
            }
            VerificationMode::IndividualOperationalFailure(failing) if *failing == dealer => {
                Err(Error::ProofGenerationFailed)
            }
            _ => Ok(()),
        }
    }

    fn verify_batch(
        &self,
        _config: &DkgConfig<P256Backend>,
        proofs: &[DealerProofRef<'_, P256Backend>],
    ) -> Result<()> {
        self.batch_dealers.lock().unwrap().push(
            proofs
                .iter()
                .map(|proof| proof.statement.dealer())
                .collect(),
        );

        match &*self.mode.lock().unwrap() {
            VerificationMode::BatchOperationalFailure => Err(Error::ProofGenerationFailed),
            VerificationMode::Invalid(_)
            | VerificationMode::BatchOnlyFailure
            | VerificationMode::IndividualOperationalFailure(_) => {
                Err(Error::ProofVerificationFailed)
            }
            VerificationMode::Accept => {
                if proofs
                    .iter()
                    .all(|proof| proof.proof == Self::expected_proof(proof.statement).as_slice())
                {
                    Ok(())
                } else {
                    Err(Error::ProofVerificationFailed)
                }
            }
        }
    }
}

struct CountingRng {
    inner: ChaCha20Rng,
    calls: usize,
}

impl CountingRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
            calls: 0,
        }
    }
}

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.calls += 1;
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.calls += 1;
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.calls += 1;
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
        self.calls += 1;
        self.inner.try_fill_bytes(dest)
    }
}

impl CryptoRng for CountingRng {}

fn participant(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
    P256Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
}

fn config(
    participant_count: u32,
    threshold: usize,
    instances: Vec<DkgInstanceKind>,
) -> DkgConfig<P256Backend> {
    config_with_session(participant_count, threshold, instances, 42)
}

fn config_with_session(
    participant_count: u32,
    threshold: usize,
    instances: Vec<DkgInstanceKind>,
    session_byte: u8,
) -> DkgConfig<P256Backend> {
    let registry = ParticipantRegistry::new(
        (1..=participant_count)
            .map(participant)
            .map(|participant| {
                (
                    participant,
                    P256Backend::mul_generator(&identity_secret(participant)),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(
        threshold,
        SessionId([session_byte; 32]),
        registry,
        instances,
    )
    .unwrap()
}

fn make_dealings<P: DealerProofSystem<P256Backend>>(
    proof_system: &P,
    config: &DkgConfig<P256Backend>,
    seed: u8,
) -> BTreeMap<ParticipantIndex, OwnDealing<P256Backend>> {
    config
        .registry()
        .indexes()
        .map(|dealer| {
            let mut rng = ChaCha20Rng::from_seed(
                [seed.wrapping_add(u8::try_from(dealer.get()).unwrap()); 32],
            );
            let secret = identity_secret(dealer);
            let dealing = deal(proof_system, config, dealer, &secret, &mut rng).unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn peer_candidates(
    dealings: &BTreeMap<ParticipantIndex, OwnDealing<P256Backend>>,
    participant: ParticipantIndex,
) -> Vec<(ParticipantIndex, Vec<u8>)> {
    let mut candidates = dealings
        .iter()
        .filter(|(dealer, _)| **dealer != participant)
        .map(|(dealer, dealing)| (*dealer, dealing.dealer_message_bytes().to_vec()))
        .collect::<Vec<_>>();
    candidates.reverse();
    candidates
}

fn replace_candidate(
    candidates: &mut [(ParticipantIndex, Vec<u8>)],
    dealer: ParticipantIndex,
    bytes: Vec<u8>,
) {
    candidates
        .iter_mut()
        .find(|(candidate_dealer, _)| *candidate_dealer == dealer)
        .unwrap()
        .1 = bytes;
}

fn first_random_receiver_pad_offset(config: &DkgConfig<P256Backend>) -> usize {
    assert_eq!(config.instance(0), Some(DkgInstanceKind::Random));
    b"golden-dkg-dealer".len()
        + 4 // dealer-message codec version
        + 4 // protocol version
        + 8 // curve identifier length
        + P256Backend::CURVE_ID.len()
        + 32 // configuration root
        + 4 // dealer participant
        + 32 // first instance nonce
        + config.threshold() * P256Backend::ELEMENT_REPR_BYTES
}

#[test]
fn mixed_deal_returns_one_opaque_message_and_invokes_one_exact_proof() {
    let config = config(
        3,
        2,
        vec![
            DkgInstanceKind::Random,
            DkgInstanceKind::Zero,
            DkgInstanceKind::Random,
        ],
    );
    let dealer = participant(2);
    let proof_system = CountingProofSystem::default();
    let mut rng = CountingRng::from_seed([7; 32]);

    let own_dealing = deal(
        &proof_system,
        &config,
        dealer,
        &identity_secret(dealer),
        &mut rng,
    )
    .unwrap();

    assert_eq!(own_dealing.participant(), dealer);
    assert!(!own_dealing.dealer_message_bytes().is_empty());
    assert_eq!(proof_system.prove_calls(), 1);
}

#[test]
fn identity_mismatch_fails_before_randomness_or_proof_work() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let dealer = participant(1);
    let wrong_secret = identity_secret(participant(2));
    let proof_system = CountingProofSystem::default();
    let mut rng = CountingRng::from_seed([8; 32]);

    let error = deal(&proof_system, &config, dealer, &wrong_secret, &mut rng).unwrap_err();

    assert_eq!(error, Error::IdentityKeyMismatch);
    assert_eq!(rng.calls, 0);
    assert_eq!(proof_system.prove_calls(), 0);
}

#[test]
fn single_participant_random_zero_and_mixed_deals_skip_the_proof_system() {
    let cases = [
        vec![DkgInstanceKind::Random],
        vec![DkgInstanceKind::Zero],
        vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
    ];

    for (case, instances) in cases.into_iter().enumerate() {
        let config = config(1, 1, instances);
        let dealer = participant(1);
        let proof_system = CountingProofSystem::default();
        let mut rng = CountingRng::from_seed([20 + case as u8; 32]);

        let own_dealing = deal(
            &proof_system,
            &config,
            dealer,
            &identity_secret(dealer),
            &mut rng,
        )
        .unwrap();

        assert_eq!(own_dealing.participant(), dealer);
        assert!(!own_dealing.dealer_message_bytes().is_empty());
        assert_eq!(proof_system.prove_calls(), 0);
    }
}

#[test]
fn own_dealing_clone_preserves_bytes_and_debug_redacts_private_state() {
    let config = config(1, 1, vec![DkgInstanceKind::Random]);
    let dealer = participant(1);
    let proof_system = CountingProofSystem::default();
    let mut rng = CountingRng::from_seed([31; 32]);
    let own_dealing = deal(
        &proof_system,
        &config,
        dealer,
        &identity_secret(dealer),
        &mut rng,
    )
    .unwrap();

    let cloned = own_dealing.clone();
    assert_eq!(cloned.participant(), own_dealing.participant());
    assert_eq!(
        cloned.dealer_message_bytes(),
        own_dealing.dealer_message_bytes()
    );

    let debug = format!("{own_dealing:?}");
    assert!(debug.contains("OwnDealing"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&format!("{:?}", own_dealing.dealer_message_bytes())));
    assert!(!debug.contains(&format!("{:?}", identity_secret(dealer))));
}

#[test]
fn mixed_completion_returns_equal_common_results_and_participant_local_shares() {
    let config = config(3, 2, vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
    let proof_system = InsecureRevealedWitnessProof;
    let dealings = make_dealings(&proof_system, &config, 60);
    let mut outputs = Vec::new();

    for participant in config.registry().indexes() {
        let candidates = peer_candidates(&dealings, participant);
        let secret = identity_secret(participant);
        let output = complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&participant],
            &candidates,
        )
        .unwrap();

        assert_eq!(output.participant(), participant);
        assert_eq!(output.configuration_root(), config.root());
        assert_eq!(output.instances().len(), 2);
        assert!(output.instance(0).is_some());
        assert!(output.instance(1).is_some());
        assert!(output.instance(2).is_none());
        for instance in output.instances() {
            let local_public_share = P256Backend::mul_generator(instance.secret_share());
            assert_eq!(
                instance.public_key_shares().get(&participant),
                Some(&local_public_share)
            );
        }
        assert!(bool::from(P256Backend::is_identity(
            output.instance(1).unwrap().public_key()
        )));
        outputs.push(output);
    }

    for output in &outputs[1..] {
        assert_eq!(output.completion_root(), outputs[0].completion_root());
        for position in 0..2 {
            let expected = outputs[0].instance(position).unwrap();
            let actual = output.instance(position).unwrap();
            assert_eq!(actual.public_key(), expected.public_key());
            assert_eq!(actual.public_key_shares(), expected.public_key_shares());
        }
    }
}

#[test]
fn candidate_set_errors_identify_the_exact_dealer() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 70);
    let receiver = participant(1);
    let dealer_2 = participant(2);
    let dealer_3 = participant(3);
    let unexpected = participant(4);
    let honest = peer_candidates(&dealings, receiver);

    let missing = honest
        .iter()
        .filter(|(dealer, _)| *dealer != dealer_2)
        .cloned()
        .collect();
    let mut duplicate = honest.clone();
    duplicate.push((
        dealer_3,
        dealings[&dealer_3].dealer_message_bytes().to_vec(),
    ));
    let mut extra = honest.clone();
    extra.push((
        unexpected,
        dealings[&dealer_2].dealer_message_bytes().to_vec(),
    ));
    let mut self_duplicate = honest;
    self_duplicate.push((
        receiver,
        dealings[&receiver].dealer_message_bytes().to_vec(),
    ));

    let cases = [
        (
            "missing",
            missing,
            Error::MissingDealer { dealer: dealer_2 },
        ),
        (
            "duplicate",
            duplicate,
            Error::DuplicateDealer { dealer: dealer_3 },
        ),
        (
            "unexpected",
            extra,
            Error::UnexpectedDealer { dealer: unexpected },
        ),
        (
            "self duplicate",
            self_duplicate,
            Error::DuplicateDealer { dealer: receiver },
        ),
    ];

    for (case, candidates, expected) in cases {
        let secret = identity_secret(receiver);
        let error = complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &candidates,
        )
        .unwrap_err();
        assert_eq!(error, expected, "{case}");
    }
}

#[test]
fn malformed_oversized_legacy_and_misrouted_candidates_are_coarsely_attributed() {
    const LEGACY_DEALER_MESSAGE_PREFIX: &[u8] = b"golden-dkg-wire-v4\x07dealer-message-v4";
    const DEALER_MESSAGE_MAGIC: &[u8] = b"golden-dkg-dealer";

    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let other_config = config_with_session(3, 2, vec![DkgInstanceKind::Random], 43);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 80);
    let other_dealings = make_dealings(&proof_system, &other_config, 81);
    let receiver = participant(1);
    let dealer_2 = participant(2);
    let dealer_3 = participant(3);
    let honest = peer_candidates(&dealings, receiver);

    let mut bad_magic = dealings[&dealer_2].dealer_message_bytes().to_vec();
    bad_magic[0] ^= 1;
    let mut wrong_codec = dealings[&dealer_2].dealer_message_bytes().to_vec();
    let codec_offset = DEALER_MESSAGE_MAGIC.len();
    wrong_codec[codec_offset..codec_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut wrong_protocol = dealings[&dealer_2].dealer_message_bytes().to_vec();
    let protocol_offset = codec_offset + 4;
    wrong_protocol[protocol_offset..protocol_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut noncanonical_point = dealings[&dealer_2].dealer_message_bytes().to_vec();
    let point_offset = first_random_receiver_pad_offset(&config);
    noncanonical_point[point_offset..point_offset + P256Backend::ELEMENT_REPR_BYTES].fill(0xff);
    let malformed_cases = [
        ("truncated", vec![0u8; 3]),
        ("bad magic", bad_magic),
        ("wrong codec version", wrong_codec),
        ("wrong protocol version", wrong_protocol),
        ("noncanonical point", noncanonical_point),
        ("legacy", LEGACY_DEALER_MESSAGE_PREFIX.to_vec()),
    ];
    for (case, bytes) in malformed_cases {
        let mut candidates = honest.clone();
        replace_candidate(&mut candidates, dealer_2, bytes);
        let secret = identity_secret(receiver);
        assert_eq!(
            complete(
                &proof_system,
                &config,
                &secret,
                &dealings[&receiver],
                &candidates,
            )
            .unwrap_err(),
            Error::InvalidDealerMessage {
                dealer: dealer_2,
                reason: DealerMessageError::Malformed,
            },
            "{case}"
        );
    }

    let maximum = max_dealer_message_bytes();
    let mut oversized = honest.clone();
    replace_candidate(&mut oversized, dealer_2, vec![0u8; maximum + 1]);
    let secret = identity_secret(receiver);
    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &oversized,
        )
        .unwrap_err(),
        Error::InvalidDealerMessage {
            dealer: dealer_2,
            reason: DealerMessageError::TooLarge {
                actual: maximum + 1,
                maximum,
            },
        }
    );

    let mut wrong_configuration = honest.clone();
    replace_candidate(
        &mut wrong_configuration,
        dealer_2,
        other_dealings[&dealer_2].dealer_message_bytes().to_vec(),
    );
    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &wrong_configuration,
        )
        .unwrap_err(),
        Error::InvalidDealerMessage {
            dealer: dealer_2,
            reason: DealerMessageError::ConfigurationMismatch,
        }
    );

    let mut misrouted = honest;
    replace_candidate(
        &mut misrouted,
        dealer_2,
        dealings[&dealer_3].dealer_message_bytes().to_vec(),
    );
    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &misrouted,
        )
        .unwrap_err(),
        Error::InvalidDealerMessage {
            dealer: dealer_2,
            reason: DealerMessageError::DealerMismatch { encoded: dealer_3 },
        }
    );
}

#[test]
fn invalid_public_relation_is_rejected_before_any_proof_verification() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 85);
    let receiver = participant(1);
    let corrupted_dealer = participant(2);
    let mut candidates = peer_candidates(&dealings, receiver);
    let bytes = &mut candidates
        .iter_mut()
        .find(|(dealer, _)| *dealer == corrupted_dealer)
        .unwrap()
        .1;
    let pad_offset = first_random_receiver_pad_offset(&config);
    let pad_end = pad_offset + P256Backend::ELEMENT_REPR_BYTES;
    let mut replacement = P256Backend::encode_element(&P256Backend::generator());
    if bytes[pad_offset..pad_end] == *replacement.as_ref() {
        replacement = P256Backend::encode_element(&P256Backend::mul_generator(
            &P256Scalar::from_u64(2).unwrap(),
        ));
    }
    assert!(!bool::from(P256Backend::is_identity(
        &P256Backend::decode_element(&replacement).unwrap()
    )));
    bytes[pad_offset..pad_end].copy_from_slice(&replacement);

    let secret = identity_secret(receiver);
    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &candidates,
        )
        .unwrap_err(),
        Error::InvalidDealerMessage {
            dealer: corrupted_dealer,
            reason: DealerMessageError::InvalidPublicRelations,
        }
    );
    assert!(proof_system.batch_dealers().is_empty());
    assert!(proof_system.individual_dealers().is_empty());
}

#[test]
fn share_decryption_failure_occurs_only_after_the_complete_proof_batch_is_accepted() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 86);
    let receiver = participant(1);
    let corrupted_dealer = participant(2);
    let mut candidates = peer_candidates(&dealings, receiver);
    let bytes = &mut candidates
        .iter_mut()
        .find(|(dealer, _)| *dealer == corrupted_dealer)
        .unwrap()
        .1;
    let pad_offset = first_random_receiver_pad_offset(&config);
    let pad_end = pad_offset + P256Backend::ELEMENT_REPR_BYTES;
    let encrypted_share_end = pad_end + P256Scalar::REPR_BYTES;

    let pad_repr: [u8; 33] = bytes[pad_offset..pad_end].try_into().unwrap();
    let pad = P256Backend::decode_element(&pad_repr).unwrap();
    let shifted_pad = P256Backend::add(&pad, &P256Backend::generator());
    assert!(!bool::from(P256Backend::is_identity(&shifted_pad)));
    bytes[pad_offset..pad_end].copy_from_slice(P256Backend::encode_element(&shifted_pad).as_ref());

    let encrypted_share_repr: [u8; 32] = bytes[pad_end..encrypted_share_end].try_into().unwrap();
    let encrypted_share = P256Scalar::from_repr(&encrypted_share_repr).unwrap();
    let shifted_encrypted_share = encrypted_share.add(&P256Scalar::one());
    bytes[pad_end..encrypted_share_end].copy_from_slice(shifted_encrypted_share.to_repr().as_ref());

    let secret = identity_secret(receiver);
    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &candidates,
        )
        .unwrap_err(),
        Error::ShareDecryptionFailed {
            dealer: corrupted_dealer,
        }
    );
    assert_eq!(
        proof_system.batch_dealers(),
        vec![vec![participant(1), participant(2), participant(3)]]
    );
    assert!(proof_system.individual_dealers().is_empty());
}

#[test]
fn proof_fallback_attributes_all_invalid_dealers_in_canonical_order() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 90);
    let receiver = participant(2);
    let dealer_1 = participant(1);
    let dealer_3 = participant(3);
    let candidates = peer_candidates(&dealings, receiver);
    proof_system.set_mode(VerificationMode::Invalid(vec![dealer_3, dealer_1]));

    let secret = identity_secret(receiver);
    let error = complete(
        &proof_system,
        &config,
        &secret,
        &dealings[&receiver],
        &candidates,
    )
    .unwrap_err();

    assert_eq!(
        error,
        Error::InvalidDealerProofs {
            dealers: vec![dealer_1, dealer_3],
        }
    );
    assert_eq!(
        proof_system.batch_dealers(),
        vec![vec![participant(1), participant(2), participant(3)]]
    );
    assert_eq!(
        proof_system.individual_dealers(),
        vec![participant(1), participant(2), participant(3)]
    );
}

#[test]
fn unexplained_batch_and_operational_failures_are_not_converted_to_dealer_blame() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let receiver = participant(1);
    let all_dealers = vec![participant(1), participant(2), participant(3)];

    for (case, mode, expected, expected_individuals) in [
        (
            "unexplained batch failure",
            VerificationMode::BatchOnlyFailure,
            Error::BatchVerificationFailed,
            Some(all_dealers.clone()),
        ),
        (
            "batch operational failure",
            VerificationMode::BatchOperationalFailure,
            Error::ProofGenerationFailed,
            Some(Vec::new()),
        ),
        (
            "individual operational failure",
            VerificationMode::IndividualOperationalFailure(participant(2)),
            Error::ProofGenerationFailed,
            None,
        ),
    ] {
        let proof_system = ScriptedProofSystem::default();
        let dealings = make_dealings(&proof_system, &config, 100);
        let candidates = peer_candidates(&dealings, receiver);
        proof_system.set_mode(mode);
        let secret = identity_secret(receiver);

        assert_eq!(
            complete(
                &proof_system,
                &config,
                &secret,
                &dealings[&receiver],
                &candidates,
            )
            .unwrap_err(),
            expected,
            "{case}"
        );
        assert_eq!(proof_system.batch_dealers(), vec![all_dealers.clone()]);
        if let Some(expected) = expected_individuals {
            assert_eq!(proof_system.individual_dealers(), expected, "{case}");
        } else {
            assert!(
                proof_system.individual_dealers().contains(&participant(2)),
                "{case}"
            );
        }
    }
}

#[test]
fn trailing_proof_bytes_fail_atomically_and_the_same_own_dealing_can_retry() {
    let config = config(3, 2, vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 110);
    let receiver = participant(1);
    let corrupted_dealer = participant(3);
    let honest = peer_candidates(&dealings, receiver);
    let mut corrupted = honest.clone();
    corrupted
        .iter_mut()
        .find(|(dealer, _)| *dealer == corrupted_dealer)
        .unwrap()
        .1
        .push(0xff);
    let secret = identity_secret(receiver);

    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &dealings[&receiver],
            &corrupted,
        )
        .unwrap_err(),
        Error::InvalidDealerProofs {
            dealers: vec![corrupted_dealer],
        }
    );

    let output = complete(
        &proof_system,
        &config,
        &secret,
        &dealings[&receiver],
        &honest,
    )
    .unwrap();
    assert_eq!(output.participant(), receiver);
    assert_eq!(output.instances().len(), 2);
}

#[test]
fn own_dealing_from_another_configuration_is_rejected_before_completion() {
    let config = config(3, 2, vec![DkgInstanceKind::Random]);
    let other_config = config_with_session(3, 2, vec![DkgInstanceKind::Random], 43);
    let proof_system = ScriptedProofSystem::default();
    let dealings = make_dealings(&proof_system, &config, 120);
    let other_dealings = make_dealings(&proof_system, &other_config, 121);
    let receiver = participant(1);
    let candidates = peer_candidates(&dealings, receiver);
    let secret = identity_secret(receiver);

    assert_eq!(
        complete(
            &proof_system,
            &config,
            &secret,
            &other_dealings[&receiver],
            &candidates,
        )
        .unwrap_err(),
        Error::OwnDealingMismatch
    );
}

#[test]
fn single_participant_threshold_one_completes_without_any_proof_calls() {
    let config = config(1, 1, vec![DkgInstanceKind::Random, DkgInstanceKind::Zero]);
    let proof_system = CountingProofSystem::default();
    let receiver = participant(1);
    let secret = identity_secret(receiver);
    let mut rng = ChaCha20Rng::from_seed([125; 32]);
    let own_dealing = deal(&proof_system, &config, receiver, &secret, &mut rng).unwrap();

    let output = complete(&proof_system, &config, &secret, &own_dealing, &[]).unwrap();

    assert_eq!(proof_system.prove_calls(), 0);
    assert_eq!(proof_system.batch_calls(), 0);
    assert_eq!(proof_system.verify_calls(), 0);
    assert_eq!(output.participant(), receiver);
    assert_eq!(output.instances().len(), 2);
    assert!(bool::from(P256Backend::is_identity(
        output.instance(1).unwrap().public_key()
    )));
}
