//! Golden DKG to EHTDH1 bridge tests.

#![cfg(any(feature = "prototype-bridge", feature = "halo2curves-secp256k1"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use golden_core::{
    complete, complete_reshare, create_dealing_with_secret, create_reshare_dealing, DealerMessage,
    DkgConfig, DkgDealing, DkgOutput, GoldenGroup, GoldenScalar, IdentityKeyProof,
    ParticipantIndex, ParticipantRegistry, ReshareConfig, ResharePredecessor, SessionId,
};
use golden_ehtdh1::{
    derive_context_session_id, derive_reshare_context_session_id, material_from_dkg_outputs,
    material_from_reshare_outputs, Ciphertext, CombineError, Combiner, DecryptionShare,
    Ehtdh1Material, Error, SetupContext, UnsealingShare,
};
use golden_evrf::prototype::ShareOpeningBackend;
use golden_rustcrypto::{P256Backend, P256Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

type G = P256Backend;

fn idx(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}

fn scalar(value: u64) -> P256Scalar {
    P256Scalar::from_u64(value).unwrap()
}

fn participants() -> [ParticipantIndex; 3] {
    [idx(1), idx(2), idx(3)]
}

fn identity_secret(participant: ParticipantIndex) -> P256Scalar {
    scalar(100 + u64::from(participant.get()))
}

fn config(session_id: SessionId) -> DkgConfig<G> {
    config_with_identity_offset(session_id, 0)
}

fn config_with_identity_offset(session_id: SessionId, offset: u64) -> DkgConfig<G> {
    let registry = ParticipantRegistry::new(
        participants()
            .iter()
            .map(|participant| {
                let identity_secret = scalar(100 + offset + u64::from(participant.get()));
                (
                    *participant,
                    G::mul_generator(&identity_secret),
                    IdentityKeyProof::prove(&identity_secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap();
    DkgConfig::new(2, session_id, scalar(77), registry).unwrap()
}

fn dealings(
    config: &DkgConfig<G>,
    identity: &impl Fn(ParticipantIndex) -> P256Scalar,
    rng: &mut ChaCha20Rng,
    secret_for_dealer: impl Fn(ParticipantIndex) -> P256Scalar,
) -> BTreeMap<ParticipantIndex, DkgDealing<G>> {
    config
        .registry
        .indexes()
        .map(|dealer| {
            let dealing = create_dealing_with_secret::<G, ShareOpeningBackend>(
                dealer,
                &identity(dealer),
                secret_for_dealer(dealer),
                config,
                rng,
            )
            .unwrap();
            (dealer, dealing)
        })
        .collect()
}

fn peer_dealings(
    receiver: ParticipantIndex,
    dealings: &BTreeMap<ParticipantIndex, DkgDealing<G>>,
) -> BTreeMap<ParticipantIndex, DealerMessage<G>> {
    dealings
        .iter()
        .filter_map(|(dealer, dealing)| {
            (*dealer != receiver).then_some((*dealer, dealing.message.clone()))
        })
        .collect()
}

fn outputs(
    config: &DkgConfig<G>,
    rng: &mut ChaCha20Rng,
    secret_for_dealer: impl Fn(ParticipantIndex) -> P256Scalar,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    committee_outputs(config, identity_secret, rng, secret_for_dealer)
}

/// Every member's output of a plain DKG whose members hold the identity
/// secrets `identity`.
fn committee_outputs(
    config: &DkgConfig<G>,
    identity: impl Fn(ParticipantIndex) -> P256Scalar,
    rng: &mut ChaCha20Rng,
    secret_for_dealer: impl Fn(ParticipantIndex) -> P256Scalar,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let dealings = dealings(config, &identity, rng, secret_for_dealer);
    config
        .registry
        .indexes()
        .map(|receiver| {
            let output = complete::<G, ShareOpeningBackend>(
                receiver,
                &identity(receiver),
                dealings.get(&receiver).unwrap(),
                &peer_dealings(receiver, &dealings),
                config,
            )
            .unwrap();
            (receiver, output)
        })
        .collect()
}

#[test]
fn golden_outputs_open_ehtdh1_payload() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let decryption_config = config(SessionId([42u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(20 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());
    let epoch = [8u8; 32];
    let materials = participants()
        .iter()
        .map(|participant| {
            (
                *participant,
                material_from_dkg_outputs(
                    &decryption_config,
                    decryption_outputs.get(participant).unwrap(),
                    &context_config,
                    context_outputs.get(participant).unwrap(),
                    epoch,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let first = materials.get(&idx(1)).unwrap();
    let mut seal_rng = ChaCha20Rng::from_seed([2u8; 32]);
    let message = first
        .sealing_key
        .seal_bytes_with_associated_data(&mut seal_rng, b"vault payload", b"ad")
        .unwrap();
    let mut share_rng = ChaCha20Rng::from_seed([3u8; 32]);
    let shares = materials
        .values()
        .map(|material| {
            UnsealingShare::new(material.secret_share.clone())
                .decrypt_share(&mut share_rng, &material.setup_context, &message, b"dc")
                .unwrap()
        })
        .collect::<Vec<_>>();

    let opened = Combiner::new(first.public_key_set.clone(), first.setup_context.clone())
        .unwrap()
        .combine_exact(&message, b"dc", &shares[..2])
        .unwrap();

    assert_eq!(opened, b"vault payload");
}

#[test]
fn bridge_rejects_nonzero_context_sharing() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let decryption_config = config(SessionId([43u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(30 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| scalar(1));

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [9u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("zero-sharing public key is not identity")
    );
}

#[test]
fn bridge_rejects_identity_decryption_public_key() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let decryption_config = config(SessionId([49u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |_| P256Scalar::zero());
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [15u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("decryption public key is identity")
    );
}

#[test]
fn bridge_requires_derived_context_session() {
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let decryption_config = config(SessionId([44u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let wrong_context_config = config(SessionId([99u8; 32]));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(40 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [10u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("context session mismatch")
    );
}

#[test]
fn bridge_rejects_threshold_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let decryption_config = config(SessionId([45u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let mut wrong_context_config = context_config.clone();
    wrong_context_config.threshold = 3;
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(50 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [11u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("threshold mismatch")
    );
}

#[test]
fn bridge_rejects_registry_root_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let decryption_config = config(SessionId([46u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let wrong_context_config = config_with_identity_offset(
        derive_context_session_id(decryption_config.session_id),
        1_000,
    );
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(60 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &wrong_context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [12u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("registry root mismatch")
    );
}

#[test]
fn bridge_rejects_local_participant_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let decryption_config = config(SessionId([47u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(70 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());

    let result = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(2)).unwrap(),
        [13u8; 32],
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("local participant mismatch")
    );
}

#[test]
fn dkg_transcript_roots_affect_setup_context_root() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let decryption_config = config(SessionId([48u8; 32]));
    let context_config = config(derive_context_session_id(decryption_config.session_id));
    let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
        scalar(80 + u64::from(dealer.get()))
    });
    let context_outputs = outputs(&context_config, &mut rng, |_| P256Scalar::zero());
    let material = material_from_dkg_outputs(
        &decryption_config,
        decryption_outputs.get(&idx(1)).unwrap(),
        &context_config,
        context_outputs.get(&idx(1)).unwrap(),
        [14u8; 32],
    )
    .unwrap();
    let original = material.setup_context.root();
    let mut changed_decryption = material.setup_context.clone();
    changed_decryption.decryption_transcript_root[0] ^= 1;
    let mut changed_context = material.setup_context.clone();
    changed_context.context_transcript_root[0] ^= 1;

    assert_ne!(changed_decryption.root(), original);
    assert_ne!(changed_context.root(), original);
}

const RESHARE_EPOCH: [u8; 32] = [16u8; 32];
const REQUEST: &[u8] = b"dc";
const RECORDS: [(&[u8], &[u8]); 2] = [(b"vault payload", b"ad"), (b"second record", b"other ad")];

/// Identity secret of member `participant` of committee generation
/// `generation`. Every generation holds distinct keys, so a member of both
/// committees of one reshare deals and receives under different keys.
fn credential(generation: u64, participant: ParticipantIndex) -> P256Scalar {
    scalar(1_000 * (generation + 1) + u64::from(participant.get()))
}

fn registry(generation: u64, members: &[u32]) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        members
            .iter()
            .map(|member| {
                let secret = credential(generation, idx(*member));
                (
                    idx(*member),
                    G::mul_generator(&secret),
                    IdentityKeyProof::prove(&secret).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}

/// The EHTDH1 context run of `config`: a plain zero sharing DKG by its new
/// committee, under the session derived from the reshare configuration root.
fn reshare_context_config(config: &ReshareConfig<G>) -> DkgConfig<G> {
    DkgConfig::new(
        config.threshold(),
        derive_reshare_context_session_id(config),
        scalar(77),
        config.receivers().clone(),
    )
    .unwrap()
}

/// One EHTDH1 setup held by committee generation `number`: every member's
/// decryption run output and material.
struct Generation {
    number: u64,
    predecessor: ResharePredecessor<G>,
    outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
    materials: BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
}

impl Generation {
    /// A fresh setup among `members`: a plain decryption run and its zero
    /// sharing run.
    fn fresh(members: &[u32], threshold: usize, seed: u8) -> Self {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let decryption_config = DkgConfig::new(
            threshold,
            SessionId([seed; 32]),
            scalar(77),
            registry(0, members),
        )
        .unwrap();
        let context_config = DkgConfig::new(
            threshold,
            derive_context_session_id(decryption_config.session_id),
            scalar(77),
            registry(0, members),
        )
        .unwrap();
        let identity = |member| credential(0, member);
        let outputs = committee_outputs(&decryption_config, identity, &mut rng, |dealer| {
            scalar(500 + 10 * u64::from(seed) + u64::from(dealer.get()))
        });
        let context_outputs =
            committee_outputs(&context_config, identity, &mut rng, |_| P256Scalar::zero());
        let materials = outputs
            .iter()
            .map(|(member, output)| {
                let material = material_from_dkg_outputs(
                    &decryption_config,
                    output,
                    &context_config,
                    &context_outputs[member],
                    RESHARE_EPOCH,
                )
                .unwrap();
                (*member, material)
            })
            .collect();
        let predecessor =
            ResharePredecessor::from_dkg_output(&decryption_config, &outputs[&idx(members[0])])
                .unwrap();
        Self {
            number: 0,
            predecessor,
            outputs,
            materials,
        }
    }

    fn threshold(&self) -> usize {
        self.predecessor.threshold()
    }

    /// A reshare of this generation's key from `dealers` to the next
    /// generation's `receivers` under session `[session; 32]`, declaring the
    /// largest corruption bound the threshold and committee size allow.
    fn reshare_config(
        &self,
        session: u8,
        dealers: &[u32],
        receivers: &[u32],
        threshold: usize,
    ) -> ReshareConfig<G> {
        let max_corrupt_receivers = (threshold - 1).min(receivers.len() - threshold);
        ReshareConfig::new(
            threshold,
            max_corrupt_receivers,
            SessionId([session; 32]),
            scalar(77),
            registry(self.number, dealers),
            registry(self.number + 1, receivers),
            self.predecessor.clone(),
        )
        .unwrap()
    }

    /// Every receiver's output of `config`, dealt by this generation's
    /// declared members.
    fn reshare_outputs(
        &self,
        config: &ReshareConfig<G>,
        rng: &mut ChaCha20Rng,
    ) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
        let board: BTreeMap<_, _> = config
            .dealers()
            .indexes()
            .map(|dealer| {
                let message = create_reshare_dealing::<G, ShareOpeningBackend>(
                    dealer,
                    &credential(self.number, dealer),
                    &self.outputs[&dealer].secret_share,
                    config,
                    rng,
                )
                .unwrap();
                (dealer, message)
            })
            .collect();
        config
            .receivers()
            .indexes()
            .map(|receiver| {
                let output = complete_reshare::<G, ShareOpeningBackend>(
                    receiver,
                    &credential(self.number + 1, receiver),
                    &board,
                    config,
                )
                .unwrap();
                (receiver, output)
            })
            .collect()
    }

    /// The next generation's setup: `config`'s reshare as the decryption run
    /// and its context run.
    fn reshared(&self, config: &ReshareConfig<G>, seed: u8) -> Self {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let outputs = self.reshare_outputs(config, &mut rng);
        let context_config = reshare_context_config(config);
        let number = self.number + 1;
        let context_outputs = committee_outputs(
            &context_config,
            |member| credential(number, member),
            &mut rng,
            |_| P256Scalar::zero(),
        );
        let materials = outputs
            .iter()
            .map(|(member, output)| {
                let material = material_from_reshare_outputs(
                    config,
                    output,
                    &context_config,
                    &context_outputs[member],
                    RESHARE_EPOCH,
                )
                .unwrap();
                (*member, material)
            })
            .collect();
        let predecessor =
            ResharePredecessor::from_reshare_output(config, outputs.values().next().unwrap())
                .unwrap();
        Self {
            number,
            predecessor,
            outputs,
            materials,
        }
    }

    fn reshare(&self, session: u8, dealers: &[u32], receivers: &[u32], threshold: usize) -> Self {
        self.reshared(
            &self.reshare_config(session, dealers, receivers, threshold),
            session,
        )
    }

    fn material(&self) -> &Ehtdh1Material<G> {
        self.materials.values().next().unwrap()
    }

    fn setup(&self) -> &SetupContext {
        &self.material().setup_context
    }

    fn combiner(&self) -> Combiner<G> {
        Combiner::new(self.material().public_key_set.clone(), self.setup().clone()).unwrap()
    }

    /// `holder`'s decryption share of `record` under `setup`.
    fn share(
        &self,
        holder: ParticipantIndex,
        setup: &SetupContext,
        record: &Ciphertext<G>,
        rng: &mut ChaCha20Rng,
    ) -> DecryptionShare<G> {
        UnsealingShare::new(self.materials[&holder].secret_share.clone())
            .decrypt_share(rng, setup, record, REQUEST)
            .unwrap()
    }

    /// Decryption shares of `record` from `holders` under this setup.
    fn shares(
        &self,
        holders: &[ParticipantIndex],
        record: &Ciphertext<G>,
        rng: &mut ChaCha20Rng,
    ) -> Vec<DecryptionShare<G>> {
        holders
            .iter()
            .map(|holder| self.share(*holder, self.setup(), record, rng))
            .collect()
    }
}

/// A fresh setup among `1..=4` at threshold 3, records sealed under its key,
/// and the stream that sealed them.
fn sealed(seed: u8) -> (Generation, Vec<Ciphertext<G>>, ChaCha20Rng) {
    let fresh = Generation::fresh(&[1, 2, 3, 4], 3, seed);
    let mut rng = ChaCha20Rng::from_seed([seed + 1; 32]);
    let records = RECORDS
        .iter()
        .map(|(payload, associated_data)| {
            fresh
                .material()
                .sealing_key
                .seal_bytes_with_associated_data(&mut rng, payload, associated_data)
                .unwrap()
        })
        .collect();
    (fresh, records, rng)
}

/// `fresh` reshared to a larger committee at a higher threshold.
fn up(fresh: &Generation) -> Generation {
    fresh.reshare(41, &[1, 2, 4], &[2, 3, 5, 6, 7], 4)
}

/// `fresh` reshared to a smaller committee at a lower threshold.
fn down(fresh: &Generation) -> Generation {
    fresh.reshare(42, &[1, 3, 4], &[3, 8, 9], 2)
}

/// `generation`'s holders open every record, and its last threshold holders
/// open the first.
fn assert_opens(generation: &Generation, records: &[Ciphertext<G>], rng: &mut ChaCha20Rng) {
    let combiner = generation.combiner();
    let holders: Vec<_> = generation.materials.keys().copied().collect();
    for (record, (payload, associated_data)) in records.iter().zip(RECORDS) {
        let shares = generation.shares(&holders, record, rng);
        let opened = combiner
            .combine_quorum_with_associated_data(record, REQUEST, associated_data, &shares)
            .unwrap();
        assert_eq!(opened, payload);
    }
    let quorum = &holders[holders.len() - generation.threshold()..];
    let shares = generation.shares(quorum, &records[0], rng);
    let opened = combiner
        .combine_exact(&records[0], REQUEST, &shares)
        .unwrap();
    assert_eq!(opened, RECORDS[0].0);
}

/// Every material of `next` keeps `previous`'s sealing key under a setup bound
/// to `config`, its receiver registry and threshold, and both runs.
fn assert_successor(previous: &Generation, next: &Generation, config: &ReshareConfig<G>) {
    let decryption_session_id = SessionId(config.root());
    let first = next.material();
    assert_eq!(
        next.materials.keys().copied().collect::<Vec<_>>(),
        config.receivers().indexes().collect::<Vec<_>>()
    );
    for (holder, material) in &next.materials {
        assert_eq!(material.secret_share.participant, *holder);
        assert_eq!(material.sealing_key, previous.material().sealing_key);
        assert_eq!(material.public_key_set, first.public_key_set);
        assert_eq!(material.setup_context, first.setup_context);
    }
    assert_eq!(first.public_key_set.threshold, config.threshold());
    let setup = next.setup();
    assert_eq!(setup.threshold, config.threshold());
    assert_eq!(setup.registry_root, config.receivers().root());
    assert!(setup
        .participants
        .iter()
        .copied()
        .eq(config.receivers().indexes()));
    assert_eq!(setup.decryption_session_id, decryption_session_id);
    let context_session_id = derive_reshare_context_session_id(config);
    assert_eq!(
        context_session_id,
        derive_context_session_id(decryption_session_id)
    );
    assert_eq!(setup.context_session_id, context_session_id);
    assert_eq!(
        setup.decryption_transcript_root,
        next.outputs.values().next().unwrap().transcript_root
    );
    assert_eq!(setup.epoch, previous.setup().epoch);
    assert_ne!(setup.root(), previous.setup().root());
}

/// A decryption share issued under one of the two setups never verifies or
/// combines under the other, whichever secret or setup it was issued with.
fn assert_separated(
    first: &Generation,
    second: &Generation,
    record: &Ciphertext<G>,
    rng: &mut ChaCha20Rng,
) {
    for (from, to) in [(first, second), (second, first)] {
        let member = *from
            .materials
            .keys()
            .find(|holder| to.materials.contains_key(holder))
            .unwrap();
        let quorum: Vec<_> = std::iter::once(member)
            .chain(
                to.materials
                    .keys()
                    .copied()
                    .filter(|holder| *holder != member),
            )
            .take(to.threshold())
            .collect();
        let combiner = to.combiner();
        let honest = to.shares(&quorum, record, rng);
        assert!(combiner.combine_exact(record, REQUEST, &honest).is_ok());
        let crossing = [
            from.share(member, from.setup(), record, rng),
            from.share(member, to.setup(), record, rng),
            to.share(member, from.setup(), record, rng),
        ];
        let rejected = Err(CombineError::MalformedShares(vec![member.get()]));
        for share in crossing {
            let mixed: Vec<_> = std::iter::once(share)
                .chain(honest[1..].iter().cloned())
                .collect();
            assert_eq!(combiner.combine_exact(record, REQUEST, &mixed), rejected);
            assert_eq!(combiner.combine_quorum(record, REQUEST, &mixed), rejected);
        }
        let holders: Vec<_> = from.materials.keys().copied().collect();
        let foreign = from.shares(&holders, record, rng);
        assert_eq!(
            combiner.combine_quorum(record, REQUEST, &foreign),
            Err(CombineError::MalformedShares(
                holders.iter().map(|holder| holder.get()).collect()
            ))
        );
    }
}

const RUN_RECEIVERS: [u32; 3] = [2, 4, 5];

/// One reshare of a fresh setup, run up to the bridge: its configuration,
/// every receiver's output and the honest context run.
struct ReshareRun {
    fresh: Generation,
    config: ReshareConfig<G>,
    outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
    context_config: DkgConfig<G>,
    context_outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
}

impl ReshareRun {
    /// `1..=3` at threshold 2 reshared from `{1, 3}` to [`RUN_RECEIVERS`] at
    /// threshold 2.
    fn new(seed: u8) -> Self {
        let fresh = Generation::fresh(&[1, 2, 3], 2, seed);
        let config = fresh.reshare_config(seed + 1, &[1, 3], &RUN_RECEIVERS, 2);
        let mut rng = ChaCha20Rng::from_seed([seed + 2; 32]);
        let outputs = fresh.reshare_outputs(&config, &mut rng);
        let context_config = reshare_context_config(&config);
        let context_outputs = committee_outputs(
            &context_config,
            |member| credential(1, member),
            &mut rng,
            |_| P256Scalar::zero(),
        );
        Self {
            fresh,
            config,
            outputs,
            context_config,
            context_outputs,
        }
    }

    /// Receiver 2's zero sharing output of a context run under
    /// `context_config` by the new committee.
    fn context_output(&self, context_config: &DkgConfig<G>, seed: u8) -> DkgOutput<G> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        committee_outputs(
            context_config,
            |member| credential(1, member),
            &mut rng,
            |_| P256Scalar::zero(),
        )
        .remove(&idx(2))
        .unwrap()
    }

    /// Bridge receiver 2's reshare output with `context_config` and its
    /// context output.
    fn bridge(
        &self,
        context_config: &DkgConfig<G>,
        context_output: &DkgOutput<G>,
    ) -> Result<Ehtdh1Material<G>, Error> {
        material_from_reshare_outputs(
            &self.config,
            &self.outputs[&idx(2)],
            context_config,
            context_output,
            RESHARE_EPOCH,
        )
    }

    /// The reshare that differs from this one only in `dealers` or the
    /// predecessor `from`: same session, new committee and threshold.
    fn sibling(&self, from: &Generation, dealers: &[u32]) -> ReshareConfig<G> {
        let sibling = from.reshare_config(
            self.config.session_id().0[0],
            dealers,
            &RUN_RECEIVERS,
            self.config.threshold(),
        );
        assert_eq!(sibling.session_id(), self.config.session_id());
        assert_eq!(sibling.receivers(), self.config.receivers());
        assert_eq!(sibling.threshold(), self.config.threshold());
        assert_ne!(sibling.root(), self.config.root());
        sibling
    }
}

#[test]
fn reshare_bridge_binds_the_reshare_configuration() {
    let fresh = Generation::fresh(&[1, 2, 3], 2, 20);
    let config = fresh.reshare_config(21, &[1, 3], &[2, 4, 5, 6], 3);
    let reshared = fresh.reshared(&config, 22);

    assert_successor(&fresh, &reshared, &config);
    assert_eq!(
        reshared.material().public_key_set.joint_public_key,
        *config.predecessor().public_key()
    );
}

#[test]
fn records_open_after_a_reshare_up() {
    let (fresh, records, mut rng) = sealed(23);
    assert_opens(&fresh, &records, &mut rng);
    let up = up(&fresh);
    assert!(up.threshold() > fresh.threshold());

    assert_opens(&up, &records, &mut rng);
    assert_separated(&fresh, &up, &records[0], &mut rng);
}

#[test]
fn records_open_after_a_reshare_down() {
    let (fresh, records, mut rng) = sealed(24);
    let down = down(&fresh);
    assert!(down.threshold() < fresh.threshold());

    assert_opens(&down, &records, &mut rng);
    assert_separated(&fresh, &down, &records[0], &mut rng);
}

#[test]
fn records_open_after_a_chained_reshare() {
    let (fresh, records, mut rng) = sealed(25);
    let down = down(&fresh);
    let config = down.reshare_config(43, &[3, 9], &[1, 3, 10, 11], 3);
    let chained = down.reshared(&config, 43);

    assert_successor(&down, &chained, &config);
    assert_eq!(chained.material().sealing_key, fresh.material().sealing_key);
    assert_opens(&chained, &records, &mut rng);
    assert_separated(&down, &chained, &records[0], &mut rng);
}

#[test]
fn sibling_reshares_reject_each_others_shares() {
    let (fresh, records, mut rng) = sealed(26);
    let sibling = fresh.reshare(44, &[1, 2, 3], &[3, 5, 6], 2);

    assert_separated(&down(&fresh), &sibling, &records[1], &mut rng);
}

#[test]
fn reshare_bridge_rejects_a_key_other_than_the_predecessors() {
    let run = ReshareRun::new(50);
    let other = Generation::fresh(&[1, 2, 3], 2, 53);
    let other_config = run.sibling(&other, &[1, 3]);
    let mut rng = ChaCha20Rng::from_seed([54u8; 32]);
    let other_output = other
        .reshare_outputs(&other_config, &mut rng)
        .remove(&idx(2))
        .unwrap();
    assert_ne!(
        other_output.public_key,
        *run.config.predecessor().public_key()
    );

    let result = material_from_reshare_outputs(
        &run.config,
        &other_output,
        &run.context_config,
        &run.context_outputs[&idx(2)],
        RESHARE_EPOCH,
    );

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("reshared key mismatch")
    );
}

#[test]
fn reshare_bridge_rejects_a_context_run_over_another_registry() {
    let run = ReshareRun::new(55);
    let context_config = DkgConfig::new(
        run.config.threshold(),
        run.context_config.session_id,
        scalar(77),
        registry(0, &[2, 3, 5, 6, 7]),
    )
    .unwrap();

    let result = run.bridge(&context_config, &run.context_outputs[&idx(2)]);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("registry root mismatch")
    );
}

#[test]
fn reshare_bridge_rejects_a_context_run_at_another_threshold() {
    let run = ReshareRun::new(58);
    let context_config = DkgConfig::new(
        run.config.threshold() + 1,
        run.context_config.session_id,
        scalar(77),
        run.config.receivers().clone(),
    )
    .unwrap();
    let context_output = run.context_output(&context_config, 61);

    let result = run.bridge(&context_config, &context_output);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("threshold mismatch")
    );
}

#[test]
fn reshare_bridge_requires_the_derived_context_session() {
    let run = ReshareRun::new(62);
    let context_config = DkgConfig::new(
        run.config.threshold(),
        SessionId([99u8; 32]),
        scalar(77),
        run.config.receivers().clone(),
    )
    .unwrap();
    let context_output = run.context_output(&context_config, 65);

    let result = run.bridge(&context_config, &context_output);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("context session mismatch")
    );
}

#[test]
fn reshare_bridge_rejects_the_context_run_of_a_reshare_by_other_dealers() {
    let run = ReshareRun::new(66);
    let sibling = run.sibling(&run.fresh, &[2, 3]);
    // The sibling shares the reshare's session id, so only a context session
    // derived from the configuration root tells the two reshares apart.
    for session_id in [
        derive_reshare_context_session_id(&sibling),
        derive_context_session_id(sibling.session_id()),
    ] {
        let context_config = DkgConfig::new(
            sibling.threshold(),
            session_id,
            scalar(77),
            sibling.receivers().clone(),
        )
        .unwrap();
        let context_output = run.context_output(&context_config, 69);

        let result = run.bridge(&context_config, &context_output);

        assert_eq!(
            result.unwrap_err(),
            Error::InvalidBridge("context session mismatch")
        );
    }
}

#[test]
fn reshare_bridge_rejects_the_context_run_of_a_reshare_of_another_predecessor() {
    let run = ReshareRun::new(70);
    let other = Generation::fresh(&[1, 2, 3], 2, 73);
    let sibling = run.sibling(&other, &[1, 3]);
    let context_config = reshare_context_config(&sibling);
    let context_output = run.context_output(&context_config, 74);

    let result = run.bridge(&context_config, &context_output);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("context session mismatch")
    );
}

#[test]
fn reshare_bridge_rejects_the_context_run_of_a_plain_dkg() {
    let run = ReshareRun::new(75);
    let plain_config = DkgConfig::new(
        run.config.threshold(),
        run.config.session_id(),
        scalar(77),
        run.config.receivers().clone(),
    )
    .unwrap();
    let context_config = DkgConfig::new(
        plain_config.threshold,
        derive_context_session_id(plain_config.session_id),
        scalar(77),
        plain_config.registry.clone(),
    )
    .unwrap();
    let context_output = run.context_output(&context_config, 78);

    let result = run.bridge(&context_config, &context_output);

    assert_eq!(
        result.unwrap_err(),
        Error::InvalidBridge("context session mismatch")
    );
}

#[cfg(feature = "halo2curves-secp256k1")]
mod secp_secq {
    use std::collections::BTreeMap;

    use golden_core::{
        complete, complete_reshare, create_dealing_with_secret, create_reshare_dealing,
        DealerMessage, DkgConfig, DkgDealing, DkgOutput, GoldenGroup, GoldenScalar,
        IdentityKeyProof, ParticipantIndex, ParticipantRegistry, ReshareConfig, ResharePredecessor,
        SessionId,
    };
    use golden_ehtdh1::{
        derive_context_session_id, derive_reshare_context_session_id, material_from_dkg_outputs,
        material_from_reshare_outputs, Combiner, SealingKey, UnsealingShare,
    };
    use golden_evrf::paper::secp_secq::SecpSecqBackend;
    use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    type PaperGroup = Secp256k1GoldenGroup;

    fn idx(value: u32) -> ParticipantIndex {
        ParticipantIndex::new(value).unwrap()
    }

    fn scalar(value: u64) -> Secp256k1Scalar {
        Secp256k1Scalar::from_u64(value).unwrap()
    }

    fn participants() -> [ParticipantIndex; 2] {
        [idx(1), idx(2)]
    }

    fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
        scalar(100 + u64::from(participant.get()))
    }

    fn config(session_id: SessionId, threshold: usize) -> DkgConfig<PaperGroup> {
        let registry = ParticipantRegistry::new(
            participants()
                .iter()
                .map(|participant| {
                    let identity_secret = identity_secret(*participant);
                    (
                        *participant,
                        PaperGroup::mul_generator(&identity_secret),
                        IdentityKeyProof::prove(&identity_secret).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap();
        DkgConfig::new(threshold, session_id, scalar(77), registry).unwrap()
    }

    fn dealings(
        config: &DkgConfig<PaperGroup>,
        identity: &impl Fn(ParticipantIndex) -> Secp256k1Scalar,
        rng: &mut ChaCha20Rng,
        secret_for_dealer: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
    ) -> BTreeMap<ParticipantIndex, DkgDealing<PaperGroup>> {
        config
            .registry
            .indexes()
            .map(|dealer| {
                let dealing = create_dealing_with_secret::<PaperGroup, SecpSecqBackend>(
                    dealer,
                    &identity(dealer),
                    secret_for_dealer(dealer),
                    config,
                    rng,
                )
                .unwrap();
                (dealer, dealing)
            })
            .collect()
    }

    fn peer_dealings(
        receiver: ParticipantIndex,
        dealings: &BTreeMap<ParticipantIndex, DkgDealing<PaperGroup>>,
    ) -> BTreeMap<ParticipantIndex, DealerMessage<PaperGroup>> {
        dealings
            .iter()
            .filter_map(|(dealer, dealing)| {
                (*dealer != receiver).then_some((*dealer, dealing.message.clone()))
            })
            .collect()
    }

    fn outputs(
        config: &DkgConfig<PaperGroup>,
        rng: &mut ChaCha20Rng,
        secret_for_dealer: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
    ) -> BTreeMap<ParticipantIndex, DkgOutput<PaperGroup>> {
        committee_outputs(config, identity_secret, rng, secret_for_dealer)
    }

    /// Every member's output of a plain DKG whose members hold the identity
    /// secrets `identity`.
    fn committee_outputs(
        config: &DkgConfig<PaperGroup>,
        identity: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
        rng: &mut ChaCha20Rng,
        secret_for_dealer: impl Fn(ParticipantIndex) -> Secp256k1Scalar,
    ) -> BTreeMap<ParticipantIndex, DkgOutput<PaperGroup>> {
        let dealings = dealings(config, &identity, rng, secret_for_dealer);
        config
            .registry
            .indexes()
            .map(|receiver| {
                let output = complete::<PaperGroup, SecpSecqBackend>(
                    receiver,
                    &identity(receiver),
                    dealings.get(&receiver).unwrap(),
                    &peer_dealings(receiver, &dealings),
                    config,
                )
                .unwrap();
                (receiver, output)
            })
            .collect()
    }

    /// Open one sealed payload with every contiguous quorum of `threshold` shares.
    fn assert_paper_backend_outputs_open_ehtdh1_payload(threshold: usize) {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let decryption_config = config(SessionId([55u8; 32]), threshold);
        let context_config = config(
            derive_context_session_id(decryption_config.session_id),
            threshold,
        );
        let decryption_outputs = outputs(&decryption_config, &mut rng, |dealer| {
            scalar(60 + u64::from(dealer.get()))
        });
        let context_outputs = outputs(&context_config, &mut rng, |_| Secp256k1Scalar::zero());
        let materials = participants()
            .iter()
            .map(|participant| {
                (
                    *participant,
                    material_from_dkg_outputs(
                        &decryption_config,
                        decryption_outputs.get(participant).unwrap(),
                        &context_config,
                        context_outputs.get(participant).unwrap(),
                        [12u8; 32],
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let first = materials.get(&idx(1)).unwrap();
        let mut seal_rng = ChaCha20Rng::from_seed([13u8; 32]);
        let message = first
            .sealing_key
            .seal_bytes(&mut seal_rng, b"paper")
            .unwrap();
        let mut share_rng = ChaCha20Rng::from_seed([14u8; 32]);
        let shares = materials
            .values()
            .map(|material| {
                UnsealingShare::new(material.secret_share.clone())
                    .decrypt_share(&mut share_rng, &material.setup_context, &message, b"dc")
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let combiner =
            Combiner::new(first.public_key_set.clone(), first.setup_context.clone()).unwrap();
        for quorum in shares.windows(threshold) {
            let opened = combiner.combine_exact(&message, b"dc", quorum).unwrap();
            assert_eq!(opened, b"paper");
        }
    }

    #[test]
    #[ignore = "slow: proves paper Secp/Secq eVRF dealings"]
    fn paper_backend_outputs_open_ehtdh1_payload() {
        assert_paper_backend_outputs_open_ehtdh1_payload(2);
    }

    #[test]
    #[ignore = "slow: proves paper Secp/Secq eVRF dealings"]
    fn paper_backend_threshold_one_outputs_open_ehtdh1_payload() {
        assert_paper_backend_outputs_open_ehtdh1_payload(1);
    }

    /// Receiver-role identity secret of member `participant` of the new
    /// committee, distinct from every dealer key.
    fn receiver_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
        scalar(200 + u64::from(participant.get()))
    }

    #[test]
    #[ignore = "slow: proves paper Secp/Secq eVRF dealings"]
    fn paper_backend_reshared_outputs_open_ehtdh1_payload() {
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        let plain_config = config(SessionId([56u8; 32]), 2);
        let plain_outputs = outputs(&plain_config, &mut rng, |dealer| {
            scalar(80 + u64::from(dealer.get()))
        });
        let plain_output = plain_outputs.get(&idx(1)).unwrap();
        let predecessor = ResharePredecessor::from_dkg_output(&plain_config, plain_output).unwrap();
        let sealing_key = SealingKey::new(plain_output.public_key).unwrap();
        let mut seal_rng = ChaCha20Rng::from_seed([16u8; 32]);
        let message = sealing_key.seal_bytes(&mut seal_rng, b"reshared").unwrap();

        let receivers = ParticipantRegistry::new(
            [idx(1), idx(2), idx(3)]
                .iter()
                .map(|participant| {
                    let secret = receiver_secret(*participant);
                    (
                        *participant,
                        PaperGroup::mul_generator(&secret),
                        IdentityKeyProof::prove(&secret).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap();
        let reshare_config = ReshareConfig::new(
            2,
            1,
            SessionId([57u8; 32]),
            scalar(77),
            plain_config.registry.clone(),
            receivers.clone(),
            predecessor,
        )
        .unwrap();
        let board: BTreeMap<_, _> = plain_config
            .registry
            .indexes()
            .map(|dealer| {
                let message = create_reshare_dealing::<PaperGroup, SecpSecqBackend>(
                    dealer,
                    &identity_secret(dealer),
                    &plain_outputs.get(&dealer).unwrap().secret_share,
                    &reshare_config,
                    &mut rng,
                )
                .unwrap();
                (dealer, message)
            })
            .collect();
        let context_config = DkgConfig::new(
            2,
            derive_reshare_context_session_id(&reshare_config),
            scalar(77),
            receivers.clone(),
        )
        .unwrap();
        let context_outputs = committee_outputs(&context_config, receiver_secret, &mut rng, |_| {
            Secp256k1Scalar::zero()
        });
        let materials = receivers
            .indexes()
            .map(|receiver| {
                let output = complete_reshare::<PaperGroup, SecpSecqBackend>(
                    receiver,
                    &receiver_secret(receiver),
                    &board,
                    &reshare_config,
                )
                .unwrap();
                let material = material_from_reshare_outputs(
                    &reshare_config,
                    &output,
                    &context_config,
                    context_outputs.get(&receiver).unwrap(),
                    [17u8; 32],
                )
                .unwrap();
                assert_eq!(material.sealing_key, sealing_key);
                material
            })
            .collect::<Vec<_>>();
        let mut share_rng = ChaCha20Rng::from_seed([18u8; 32]);
        let shares = materials
            .iter()
            .map(|material| {
                UnsealingShare::new(material.secret_share.clone())
                    .decrypt_share(&mut share_rng, &material.setup_context, &message, b"dc")
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let combiner = Combiner::new(
            materials[0].public_key_set.clone(),
            materials[0].setup_context.clone(),
        )
        .unwrap();
        for quorum in shares.windows(2) {
            let opened = combiner.combine_exact(&message, b"dc", quorum).unwrap();
            assert_eq!(opened, b"reshared");
        }
    }
}
