//! One opaque `[Random, Zero]` or `[Reshare, Zero]` batch is the complete EHTDH1 setup boundary.
#![allow(clippy::unwrap_used)]
use ff::Field;
use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::output::ehtdh1_completion_root;
use golden_core::{
    aggregate_public, complete, complete_reshare, deal, deal_reshare, DealerMessageRef,
    DealerProofSystem, DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Reshare, Zero},
    DkgOutput, ParticipantIndex, ParticipantRegistry, ResharePredecessor, SessionId,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use golden_ehtdh1::{
    material_from_dkg_output, Ciphertext, CombineError, Combiner, DecryptionShare, Ehtdh1Material,
    Error, PublicKeySet, PublicShare, SetupContext, UnsealingShare,
};
use group::Group;
use rand_chacha::{
    rand_core::{CryptoRngCore, SeedableRng},
    ChaCha20Rng,
};
use std::collections::BTreeMap;

const REQUEST: &[u8] = b"request";
const RECORDS: [(&[u8], &[u8]); 3] = [
    (b"first vault payload", b"record 1"),
    (b"second vault payload", b"record 2"),
    (b"third vault payload", b"record 3"),
];

fn id(value: u32) -> ParticipantIndex {
    ParticipantIndex::new(value).unwrap()
}
/// Identity credential of `participant` in committee generation `generation`, so a member of
/// both committees of one reshare deals and receives under different keys.
fn credential<G: DkgGroup>(generation: u64, participant: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(100 + 1000 * generation + u64::from(participant.get()))
}
fn registry<G: DkgGroup>(
    generation: u64,
    indexes: impl IntoIterator<Item = u32>,
) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        indexes
            .into_iter()
            .map(|value| {
                let participant = id(value);
                (
                    participant,
                    G::mul_generator(&credential::<G>(generation, participant)),
                )
            })
            .collect(),
    )
    .unwrap()
}
fn config<G: DkgGroup>(n: u32, threshold: usize, kinds: Vec<DkgInstanceKind>) -> DkgConfig<G> {
    DkgConfig::new(threshold, SessionId([42; 32]), registry(0, 1..=n), kinds).unwrap()
}
/// Every share holder's output of `config`, dealt from `previous`'s key shares when `config`
/// reshares its key.
fn outputs<G: DkgGroup, P: DealerProofSystem<G>>(
    proofs: &P,
    config: &DkgConfig<G>,
    previous: Option<&Generation<G>>,
    rng: &mut impl CryptoRngCore,
) -> BTreeMap<ParticipantIndex, DkgOutput<G>> {
    let own: BTreeMap<_, _> = config
        .dealers()
        .indexes()
        .map(|dealer| {
            let own = match previous {
                None => deal(proofs, config, dealer, &credential::<G>(0, dealer), rng),
                Some(previous) => {
                    let share = previous.outputs[&dealer].secret_share(0).unwrap();
                    let identity = credential::<G>(previous.number, dealer);
                    deal_reshare(proofs, config, dealer, &identity, share, rng)
                }
            };
            (dealer, own.unwrap())
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
    let generation = previous.map_or(0, |previous| previous.number + 1);
    config
        .registry()
        .indexes()
        .map(|participant| {
            let identity = credential::<G>(generation, participant);
            let output = match previous {
                None => {
                    let peers: Vec<_> = board
                        .iter()
                        .copied()
                        .filter(|item| item.expected_dealer != participant)
                        .collect();
                    complete(proofs, config, &identity, &own[&participant], &peers)
                }
                Some(_) => complete_reshare(proofs, config, &identity, participant, &board),
            }
            .unwrap();
            assert_eq!(output.completion_root(), public.completion_root());
            (participant, output)
        })
        .collect()
}

/// One completed sharing of a group key, every share holder's output and EHTDH1 material, all
/// of committee generation `number`.
struct Generation<G: DkgGroup> {
    number: u64,
    config: DkgConfig<G>,
    outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
    materials: BTreeMap<ParticipantIndex, Ehtdh1Material<G>>,
}
impl<G: DkgGroup> Generation<G> {
    fn new(
        number: u64,
        config: DkgConfig<G>,
        outputs: BTreeMap<ParticipantIndex, DkgOutput<G>>,
    ) -> Self {
        let materials: BTreeMap<_, _> = outputs
            .iter()
            .map(|(holder, output)| {
                let material = material_from_dkg_output(&config, output, [8; 32]).unwrap();
                (*holder, material)
            })
            .collect();
        let first = materials.values().next().unwrap();
        for material in materials.values() {
            assert_eq!(material.sealing_key, first.sealing_key);
            assert_eq!(material.public_key_set, first.public_key_set);
            assert_eq!(material.setup_context, first.setup_context);
        }
        Self {
            number,
            config,
            outputs,
            materials,
        }
    }
    /// A fresh `[Random, Zero]` setup among `1..=n`.
    fn fresh(n: u32, threshold: usize) -> Self {
        let config = config(n, threshold, vec![Random, Zero]);
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, None, &mut rng);
        Self::new(0, config, outputs)
    }
    /// Reshare of this generation's key from its `dealers` to the next generation's
    /// `receivers`, tolerating `threshold - 1` corrupt receivers.
    fn reshare_config(
        &self,
        dealers: &[u32],
        receivers: &[u32],
        threshold: usize,
        instances: Vec<DkgInstanceKind>,
    ) -> DkgConfig<G> {
        let public = self.outputs.values().next().unwrap().public();
        DkgConfig::new_reshare(
            threshold,
            threshold - 1,
            SessionId([u8::try_from(self.number).unwrap() + 100; 32]),
            registry(self.number, dealers.iter().copied()),
            registry(self.number + 1, receivers.iter().copied()),
            ResharePredecessor::from_output(&self.config, public, 0).unwrap(),
            instances,
        )
        .unwrap()
    }
    /// The `[Reshare, Zero]` successor of this generation.
    fn reshare(&self, dealers: &[u32], receivers: &[u32], threshold: usize) -> Self {
        let config = self.reshare_config(dealers, receivers, threshold, vec![Reshare, Zero]);
        let mut rng = ChaCha20Rng::from_seed([u8::try_from(self.number).unwrap() + 2; 32]);
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, Some(self), &mut rng);
        Self::new(self.number + 1, config, outputs)
    }
    fn material(&self) -> &Ehtdh1Material<G> {
        self.materials.values().next().unwrap()
    }
    fn threshold(&self) -> usize {
        self.config.threshold()
    }
    fn setup(&self) -> &SetupContext {
        &self.material().setup_context
    }
    fn combiner(&self) -> Combiner<G> {
        let material = self.material();
        Combiner::new(
            material.public_key_set.clone(),
            material.setup_context.clone(),
        )
        .unwrap()
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
    /// Decryption shares of `record` from `holders` under this generation's setup.
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

fn assert_online<G: DkgGroup>(
    config: &DkgConfig<G>,
    outputs: &BTreeMap<ParticipantIndex, DkgOutput<G>>,
) {
    let materials: Vec<Ehtdh1Material<G>> = outputs
        .values()
        .map(|output| material_from_dkg_output(config, output, [8; 32]).unwrap())
        .collect();
    let first = &materials[0];
    if config.threshold() > 1 {
        // Ensure this deterministic setup exercises context-share cancellation.
        assert!(materials
            .iter()
            .any(|material| !bool::from(material.secret_share.context().is_zero())));
    }
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
    let combiner =
        Combiner::new(first.public_key_set.clone(), first.setup_context.clone()).unwrap();
    let opened = combiner
        .combine_exact_with_associated_data(
            &message,
            b"request",
            b"record id",
            &shares[..config.threshold()],
        )
        .unwrap();
    assert_eq!(opened, b"vault payload");
    let mut mixed = shares[..config.threshold()].to_vec();
    mixed[0] = UnsealingShare::new(first.secret_share.clone())
        .decrypt_share_with_associated_data(
            &mut rng,
            &first.setup_context,
            &message,
            b"other request",
            b"record id",
        )
        .unwrap();
    assert!(matches!(
        combiner.combine_exact_with_associated_data(&message, b"request", b"record id", &mixed),
        Err(CombineError::MalformedShares(_))
    ));
}
fn native_bridge<G: DkgGroup>() {
    for threshold in [1, 2] {
        let config = config::<G>(3, threshold, vec![Random, Zero]);
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, None, &mut rng);
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
    let predecessor = Generation::<G>::fresh(1, 1);
    let plain = [
        vec![Random],
        vec![Zero, Random],
        vec![Random, Random],
        vec![Random, Zero, Zero],
    ]
    .map(|kinds| (config::<G>(1, 1, kinds), None));
    let reshare = [
        vec![Reshare],
        vec![Zero, Reshare],
        vec![Reshare, Zero, Zero],
        vec![Zero, Reshare, Zero],
    ]
    .map(|kinds| {
        let config = predecessor.reshare_config(&[1], &[1], 1, kinds);
        (config, Some(&predecessor))
    });
    for (config, previous) in plain.into_iter().chain(reshare) {
        let outputs = outputs(&InsecureRevealedWitnessProof, &config, previous, &mut rng);
        assert!(matches!(
            material_from_dkg_output(&config, &outputs[&id(1)], [8; 32]),
            Err(Error::InvalidBridge(_))
        ));
    }
    let next = predecessor.reshare(&[1], &[2], 1);
    for (config, output) in [
        (&predecessor.config, &next.outputs[&id(2)]),
        (&next.config, &predecessor.outputs[&id(1)]),
    ] {
        assert!(matches!(
            material_from_dkg_output(config, output, [8; 32]),
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
    let outputs = outputs(
        &InsecureRevealedWitnessProof,
        &config,
        None,
        &mut ZeroSamples,
    );
    assert!(matches!(
        material_from_dkg_output(&config, &outputs[&id(1)], [8; 32]),
        Err(Error::InvalidBridge(_))
    ));
}

/// Canonical `(participant, X_i, Z_i)` rows of `public`.
fn rows<G: DkgGroup>(public: &PublicKeySet<G>) -> Vec<(ParticipantIndex, G::Point, G::Point)> {
    public
        .public_shares
        .iter()
        .map(|(participant, share)| (*participant, share.decryption, share.context))
        .collect()
}
/// One column of `public` in canonical order: `Z_i` if `context`, else `X_i`.
fn column<G: DkgGroup>(
    public: &PublicKeySet<G>,
    context: bool,
) -> Vec<(ParticipantIndex, G::Point)> {
    public
        .public_shares
        .iter()
        .map(|(participant, share)| {
            let point = if context {
                share.context
            } else {
                share.decryption
            };
            (*participant, point)
        })
        .collect()
}
/// The polynomial through the first `threshold` points of `column`, evaluated at `at`.
fn evaluate<G: DkgGroup>(
    column: &[(ParticipantIndex, G::Point)],
    threshold: usize,
    at: ParticipantIndex,
) -> G::Point {
    let basis = &column[..threshold];
    let x = G::Scalar::from(u64::from(at.get()));
    basis
        .iter()
        .fold(G::Point::identity(), |sum, (participant, point)| {
            let x_i = G::Scalar::from(u64::from(participant.get()));
            let lambda = basis.iter().filter(|(other, _)| other != participant).fold(
                G::Scalar::ONE,
                |lambda, (other, _)| {
                    let x_j = G::Scalar::from(u64::from(other.get()));
                    lambda * (x - x_j) * (x_i - x_j).invert().unwrap()
                },
            );
            sum + *point * lambda
        })
}
/// `public` with one column moved by the zero-constant line `i * G`. The result still passes
/// every interpolation check for thresholds of at least two.
fn shifted<G: DkgGroup>(public: &PublicKeySet<G>, context: bool) -> PublicKeySet<G> {
    let shares: BTreeMap<_, _> = public
        .public_shares
        .iter()
        .map(|(participant, share)| {
            let line = G::mul_generator(&G::Scalar::from(u64::from(participant.get())));
            let moved = if context {
                PublicShare {
                    decryption: share.decryption,
                    context: share.context + line,
                }
            } else {
                PublicShare {
                    decryption: share.decryption + line,
                    context: share.context,
                }
            };
            (*participant, moved)
        })
        .collect();
    PublicKeySet::new(public.threshold, public.joint_public_key, shares).unwrap()
}

/// `generation`'s holders open every record, and its last threshold holders open the first.
fn assert_opens<G: DkgGroup>(
    generation: &Generation<G>,
    records: &[Ciphertext<G>],
    rng: &mut ChaCha20Rng,
) {
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

/// `next` holds `previous`'s key under its own committee, threshold and setup, with columns
/// that are not `previous`'s polynomials evaluated at the new indexes.
fn assert_successor<G: DkgGroup>(previous: &Generation<G>, next: &Generation<G>) {
    let (before, after) = (previous.material(), next.material());
    assert_eq!(after.sealing_key, before.sealing_key);
    assert_eq!(after.public_key_set.threshold, next.threshold());
    let setup = &after.setup_context;
    assert_eq!(setup.threshold, next.threshold());
    assert!(setup
        .participants
        .iter()
        .copied()
        .eq(next.config.registry().indexes()));
    assert_eq!(setup.session_id, next.config.session_id());
    assert_eq!(setup.config_root, next.config.root());
    let output = next.outputs.values().next().unwrap();
    assert_eq!(setup.completion_root, output.completion_root());
    assert_eq!(setup.epoch, before.setup_context.epoch);
    assert_ne!(setup.root(), before.setup_context.root());
    for context in [false, true] {
        let old = column(&before.public_key_set, context);
        for (receiver, point) in column(&after.public_key_set, context) {
            assert_ne!(point, evaluate::<G>(&old, previous.threshold(), receiver));
        }
    }
}

/// A decryption share issued under one of the two setups never verifies or combines under the
/// other, whichever key or setup it was issued with.
fn assert_separated<G: DkgGroup>(
    first: &Generation<G>,
    second: &Generation<G>,
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

/// `next`'s combiner accepts only its own key set under a setup whose completion root it
/// recomputes from that key set and the setup's configuration root.
fn assert_setup_binding<G: DkgGroup>(previous: &Generation<G>, next: &Generation<G>) {
    let (public, setup) = (&next.material().public_key_set, next.setup());
    let before = previous.material();
    let root = |kind, public: &PublicKeySet<G>| {
        ehtdh1_completion_root::<G>(
            kind,
            setup.config_root,
            &public.joint_public_key,
            &rows(public),
        )
    };
    let kind = next.config.instance(0).unwrap();
    let other = if kind == Random { Reshare } else { Random };
    assert_eq!(root(kind, public), Ok(setup.completion_root));
    assert_ne!(root(other, public), Ok(setup.completion_root));
    assert_eq!(root(Zero, public), Err(golden_core::Error::InvalidEncoding));
    Combiner::new(public.clone(), setup.clone()).unwrap();
    // The setup context does not record the decryption kind, so either kind's root is accepted.
    let mut other_kind = setup.clone();
    other_kind.completion_root = root(other, public).unwrap();
    Combiner::new(public.clone(), other_kind).unwrap();

    let mut rejected = vec![
        (before.public_key_set.clone(), setup.clone()),
        (public.clone(), before.setup_context.clone()),
    ];
    let mut changed = setup.clone();
    changed.config_root = before.setup_context.config_root;
    rejected.push((public.clone(), changed));
    let mut changed = setup.clone();
    changed.completion_root = before.setup_context.completion_root;
    rejected.push((public.clone(), changed));
    for context in [false, true] {
        let tampered = shifted(public, context);
        rejected.push((tampered.clone(), setup.clone()));
        for kind in [Random, Reshare] {
            let mut changed = setup.clone();
            changed.completion_root = root(kind, &tampered).unwrap();
            rejected.push((public.clone(), changed));
        }
    }
    for (public, setup) in rejected {
        assert!(matches!(
            Combiner::new(public, setup),
            Err(Error::InvalidBridge(_))
        ));
    }
}

/// A fresh `[Random, Zero]` setup among `1..=4` with threshold 3, the records sealed under its
/// key, and the stream that sealed them.
fn sealed<G: DkgGroup>() -> (Generation<G>, Vec<Ciphertext<G>>, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let fresh = Generation::<G>::fresh(4, 3);
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

/// `fresh` reshared to a larger committee with a higher threshold.
fn up<G: DkgGroup>(fresh: &Generation<G>) -> Generation<G> {
    fresh.reshare(&[1, 2, 4], &[2, 3, 5, 6, 7], 4)
}

/// `fresh` reshared to a smaller committee with a lower threshold.
fn down<G: DkgGroup>(fresh: &Generation<G>) -> Generation<G> {
    fresh.reshare(&[1, 3, 4], &[3, 8, 9], 2)
}

/// `next` opens `records` and is the bound, separated successor of `previous`.
fn assert_reshared<G: DkgGroup>(
    previous: &Generation<G>,
    next: &Generation<G>,
    records: &[Ciphertext<G>],
    rng: &mut ChaCha20Rng,
) {
    assert_opens(next, records, rng);
    assert_successor(previous, next);
    assert_setup_binding(previous, next);
    assert_separated(previous, next, &records[0], rng);
}

fn reshare_up<G: DkgGroup>() {
    let (fresh, records, mut rng) = sealed::<G>();
    assert_opens(&fresh, &records, &mut rng);
    let up = up(&fresh);
    assert!(up.threshold() > fresh.threshold());
    assert_reshared(&fresh, &up, &records, &mut rng);
}

fn reshare_down<G: DkgGroup>() {
    let (fresh, records, mut rng) = sealed::<G>();
    let down = down(&fresh);
    assert!(down.threshold() < fresh.threshold());
    assert_reshared(&fresh, &down, &records, &mut rng);
}

fn chained_reshare<G: DkgGroup>() {
    let (fresh, records, mut rng) = sealed::<G>();
    let up = up(&fresh);
    let chained = up.reshare(&[3, 5, 6, 7], &[1, 3, 10], 2);
    assert_reshared(&up, &chained, &records, &mut rng);
}

fn sibling_reshares<G: DkgGroup>() {
    let (fresh, records, mut rng) = sealed::<G>();
    assert_separated(&up(&fresh), &down(&fresh), &records[1], &mut rng);
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
both!(
    bridge_requires_exact_random_zero_or_reshare_zero_order,
    required_order
);
both!(
    bridge_rejects_a_valid_zero_random_aggregate,
    identity_decryption_key
);
both!(fresh_records_open_after_a_reshare_up, reshare_up);
both!(fresh_records_open_after_a_reshare_down, reshare_down);
both!(fresh_records_open_after_a_chained_reshare, chained_reshare);
both!(sibling_reshares_reject_each_others_shares, sibling_reshares);

#[test]
#[ignore = "expensive production Secp/Secq proof and composition gate"]
fn secp_secq_production_bridge() {
    use golden_bulletproofs::{SecpSecqBulletproofs, SecpSecqPrepared};
    let config = config::<Secp256k1Group>(2, 2, vec![Random, Zero]);
    let prepared = SecpSecqPrepared::prepare_for(&config).unwrap();
    let proofs = SecpSecqBulletproofs::from_prepared(prepared);
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let outputs = outputs(&proofs, &config, None, &mut rng);
    assert_online(&config, &outputs);
}
#[test]
#[ignore = "expensive production Jubjub/BLS proof and composition gate"]
fn bls_jubjub_production_bridge() {
    use golden_bulletproofs::{BlsJubjubBulletproofs, BlsJubjubPrepared};
    let config = config::<JubjubGroup>(2, 2, vec![Random, Zero]);
    let prepared = BlsJubjubPrepared::prepare_for(&config).unwrap();
    let proofs = BlsJubjubBulletproofs::from_prepared(prepared);
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let outputs = outputs(&proofs, &config, None, &mut rng);
    assert_online(&config, &outputs);
}
