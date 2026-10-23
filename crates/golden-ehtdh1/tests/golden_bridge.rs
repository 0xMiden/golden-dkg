//! One opaque `[Random, Zero]` batch is the complete EHTDH1 setup boundary.
#![allow(clippy::unwrap_used)]
use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, deal, DealerMessageRef, DealerProofSystem, DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Zero},
    DkgOutput, ParticipantIndex, ParticipantRegistry, SessionId,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use golden_ehtdh1::{material_from_dkg_output, Combiner, Ehtdh1Material, Error, UnsealingShare};
use rand_chacha::{
    rand_core::{CryptoRngCore, SeedableRng},
    ChaCha20Rng,
};
use std::collections::BTreeMap;

fn id(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}
fn credential<G: DkgGroup>(participant: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(100 + u64::from(participant.get()))
}
fn config<G: DkgGroup>(n: u32, threshold: usize, kinds: Vec<DkgInstanceKind>) -> DkgConfig<G> {
    let registry = ParticipantRegistry::new(
        (1..=n)
            .map(|value| {
                let participant = id(value);
                (participant, G::mul_generator(&credential::<G>(participant)))
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(threshold, SessionId([42; 32]), registry, kinds).unwrap()
}
fn outputs<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    rng: &mut impl CryptoRngCore,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let own: BTreeMap<_, _> = config
        .registry()
        .indexes()
        .map(|participant| {
            (
                participant,
                deal(
                    proofs,
                    config,
                    participant,
                    &credential::<G>(participant),
                    rng,
                )
                .unwrap(),
            )
        })
        .collect();
    let board: Vec<_> = own
        .iter()
        .map(|(participant, own)| DealerMessageRef {
            expected_dealer: *participant,
            bytes: own.broadcast_bytes(),
        })
        .collect();
    let public = aggregate_public(proofs, config, &board).unwrap();
    own.iter()
        .map(|(participant, own)| {
            let peers: Vec<_> = board
                .iter()
                .copied()
                .filter(|item| item.expected_dealer != *participant)
                .collect();
            let output =
                complete(proofs, config, &credential::<G>(*participant), own, &peers).unwrap();
            assert_eq!(output.completion_root(), public.completion_root());
            (*participant, output)
        })
        .collect()
}
fn assert_online<G: DkgGroup>(
    config: &DkgConfig<G>,
    outputs: &BTreeMap<ParticipantIndex, DkgOutput<G>>,
) {
    let materials: Vec<Ehtdh1Material<G>> = outputs
        .values()
        .map(|output| material_from_dkg_output(config, output, [8; 32]).unwrap())
        .collect();
    let first = &materials[0];
    for material in &materials {
        assert_eq!(material.sealing_key, first.sealing_key);
        assert_eq!(material.public_key_set, first.public_key_set);
        assert_eq!(material.setup_context, first.setup_context);
        assert_eq!(material.setup_context.session_id, config.session_id());
        assert_eq!(material.setup_context.config_root, config.root());
    }
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let message = first
        .sealing_key
        .seal_bytes_with_associated_data(&mut rng, b"vault payload", b"record id")
        .unwrap();
    let shares: Vec<_> = materials
        .iter()
        .map(|material| {
            UnsealingShare::new(material.secret_share.clone())
                .decrypt_share_with_associated_data(
                    &mut rng,
                    &material.setup_context,
                    &message,
                    b"request",
                    b"record id",
                )
                .unwrap()
        })
        .collect();
    let opened = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())
        .unwrap()
        .combine_exact_with_associated_data(
            &message,
            b"request",
            b"record id",
            &shares[..config.threshold()],
        )
        .unwrap();
    assert_eq!(opened, b"vault payload");
}
fn native_bridge<G: DkgGroup>() {
    for threshold in [1, 2] {
        let config = config::<G>(3, threshold, vec![Random, Zero]);
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, &mut rng);
        assert_online(&config, &outputs);
        let changed = DkgConfig::new(
            config.threshold(),
            SessionId([99; 32]),
            config.registry().clone(),
            config.instances().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            material_from_dkg_output(&changed, &outputs[&id(1)], [8; 32]),
            Err(Error::InvalidBridge(_))
        ));
        let first = material_from_dkg_output(&config, &outputs[&id(1)], [8; 32]).unwrap();
        let changed_epoch = material_from_dkg_output(&config, &outputs[&id(1)], [9; 32]).unwrap();
        assert_ne!(
            first.setup_context.root(),
            changed_epoch.setup_context.root()
        );
    }
}
fn required_order<G: DkgGroup>() {
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    for kinds in [
        vec![Random],
        vec![Zero, Random],
        vec![Random, Random],
        vec![Random, Zero, Zero],
    ] {
        let config = config::<G>(1, 1, kinds);
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, &mut rng);
        assert!(matches!(
            material_from_dkg_output(&config, &outputs[&id(1)], [8; 32]),
            Err(Error::InvalidBridge(_))
        ));
    }
}
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
fn identity_decryption_key<G: DkgGroup>() {
    let config = config::<G>(1, 1, vec![Random, Zero]);
    // Valid Random grammar can produce zero; EHTDH1 must reject that key.
    let outputs = outputs(&InsecureRevealedWitnessProof, &config, &mut ZeroSamples);
    assert!(matches!(
        material_from_dkg_output(&config, &outputs[&id(1)], [8; 32]),
        Err(Error::InvalidBridge(_))
    ));
}
macro_rules! both {
    ($name:ident, $body:ident) => {
        #[test]
        fn $name() {
            $body::<Secp256k1Group>();
            $body::<JubjubGroup>();
        }
    };
}
both!(one_completed_batch_opens_online_payloads, native_bridge);
both!(bridge_requires_exact_random_zero_order, required_order);
both!(
    bridge_rejects_a_valid_zero_random_aggregate,
    identity_decryption_key
);

#[test]
#[ignore = "expensive production Secp/Secq proof and composition gate"]
fn secp_secq_production_bridge() {
    use golden_bulletproofs::{SecpSecqBulletproofs, SecpSecqPrepared};
    let config = config::<Secp256k1Group>(2, 1, vec![Random, Zero]);
    let prepared = SecpSecqPrepared::prepare_for(&config).unwrap();
    let proofs = SecpSecqBulletproofs::from_prepared(prepared);
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let outputs = outputs(&proofs, &config, &mut rng);
    assert_online(&config, &outputs);
}
#[test]
#[ignore = "expensive production Jubjub/BLS proof and composition gate"]
fn bls_jubjub_production_bridge() {
    use golden_bulletproofs::{BlsJubjubBulletproofs, BlsJubjubPrepared};
    let config = config::<JubjubGroup>(2, 1, vec![Random, Zero]);
    let prepared = BlsJubjubPrepared::prepare_for(&config).unwrap();
    let proofs = BlsJubjubBulletproofs::from_prepared(prepared);
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let outputs = outputs(&proofs, &config, &mut rng);
    assert_online(&config, &outputs);
}
