//! Public tests for opaque dealer-message generation.

#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};

use golden_core::{
    deal, DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgInstanceKind,
    Error, GoldenGroup, GoldenScalar, ParticipantIndex, ParticipantRegistry, Result, SessionId,
};
use golden_evrf::InsecureRevealedWitnessProof;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, CryptoRngCore, Error as RandError, RngCore, SeedableRng};

#[derive(Default)]
struct CountingProofSystem {
    prove_calls: AtomicUsize,
}

impl CountingProofSystem {
    fn prove_calls(&self) -> usize {
        self.prove_calls.load(Ordering::SeqCst)
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
        <InsecureRevealedWitnessProof as DealerProofSystem<P256Backend>>::verify(
            &InsecureRevealedWitnessProof,
            config,
            statement,
            proof,
        )
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
    DkgConfig::new(threshold, SessionId([42; 32]), registry, instances).unwrap()
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
