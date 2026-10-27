//! Reshare configuration construction, identity, persistence and predecessor validation.

use golden_core::{
    DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Reshare, Zero},
    Error, ParticipantIndex, ParticipantRegistry, Polynomial, ResharePredecessor, Result,
    SessionId, PROTOCOL_VERSION,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use group::Group;
use std::collections::BTreeSet;

use super::support::{participant, Generation};

const RESHARE_LABEL: &[u8] = b"golden-dkg/reshare";

fn key<G: DkgGroup>(value: u64) -> G::Point {
    G::mul_generator(&G::Scalar::from(value))
}
fn registry<G: DkgGroup>(entries: &[(u32, G::Point)]) -> ParticipantRegistry<G> {
    ParticipantRegistry::new(
        entries
            .iter()
            .map(|(index, point)| (participant(*index), *point))
            .collect(),
    )
    .unwrap()
}
/// Group key and public shares at `indexes` of a fixed degree-`threshold - 1` polynomial.
fn column<G: DkgGroup>(
    threshold: usize,
    indexes: &[u32],
) -> (G::Point, Vec<(ParticipantIndex, G::Point)>) {
    let coefficients: Vec<G::Scalar> = (0u64..)
        .take(threshold)
        .map(|degree| G::Scalar::from(7 * degree + 3))
        .collect();
    let polynomial = Polynomial::from_coefficients(&coefficients).unwrap();
    let shares = indexes
        .iter()
        .map(|index| {
            let id = participant(*index);
            (
                id,
                G::mul_generator(polynomial.evaluate(id).unwrap().value()),
            )
        })
        .collect();
    (G::mul_generator(&coefficients[0]), shares)
}
fn predecessor<G: DkgGroup>(completion_root: [u8; 32]) -> ResharePredecessor<G> {
    let (public_key, shares) = column::<G>(2, &[1, 2, 3]);
    ResharePredecessor::new(2, public_key, shares, [1; 32], completion_root).unwrap()
}

struct Topology<G: DkgGroup> {
    dealers: ParticipantRegistry<G>,
    receivers: ParticipantRegistry<G>,
    predecessor: ResharePredecessor<G>,
}
impl<G: DkgGroup> Topology<G> {
    fn new() -> Self {
        Self {
            dealers: registry(&[(1, key::<G>(101)), (2, key::<G>(102))]),
            receivers: registry(&[
                (1, key::<G>(201)),
                (2, key::<G>(202)),
                (3, key::<G>(203)),
                (4, key::<G>(204)),
            ]),
            predecessor: predecessor([2; 32]),
        }
    }
    fn config(
        &self,
        threshold: usize,
        max_corrupt_receivers: usize,
        instances: Vec<DkgInstanceKind>,
    ) -> Result<DkgConfig<G>> {
        DkgConfig::new_reshare(
            threshold,
            max_corrupt_receivers,
            SessionId([5; 32]),
            self.dealers.clone(),
            self.receivers.clone(),
            self.predecessor.clone(),
            instances,
        )
    }
    fn with_dealers(&self, dealers: &[(u32, G::Point)]) -> Result<DkgConfig<G>> {
        Self {
            dealers: registry(dealers),
            receivers: self.receivers.clone(),
            predecessor: self.predecessor.clone(),
        }
        .config(2, 1, vec![Reshare, Zero])
    }
    fn with_receivers(&self, receivers: &[(u32, G::Point)]) -> Result<DkgConfig<G>> {
        Self {
            dealers: self.dealers.clone(),
            receivers: registry(receivers),
            predecessor: self.predecessor.clone(),
        }
        .config(2, 1, vec![Reshare, Zero])
    }
}

fn constructor_rejections<G: DkgGroup>() {
    let topology = Topology::<G>::new();
    for (threshold, max_corrupt_receivers) in [(0, 0), (5, 1)] {
        assert_eq!(
            topology
                .config(threshold, max_corrupt_receivers, vec![Reshare, Zero])
                .err(),
            Some(Error::InvalidThreshold {
                threshold,
                participants: 4
            })
        );
    }
    for max_corrupt_receivers in [2, 3] {
        assert_eq!(
            topology.config(2, max_corrupt_receivers, Vec::new()).err(),
            Some(Error::InsecureReshareThreshold {
                threshold: 2,
                max_corrupt_receivers
            })
        );
    }
    assert_eq!(
        topology.config(2, 1, Vec::new()).err(),
        Some(Error::EmptyDkgBatch)
    );
    for instances in [
        vec![Zero],
        vec![Random],
        vec![Reshare, Reshare],
        vec![Reshare, Random],
        vec![Random, Reshare, Zero],
    ] {
        assert_eq!(
            topology.config(2, 1, instances).err(),
            Some(Error::InvalidReshareConfiguration)
        );
    }
    for instances in [vec![Reshare], vec![Zero, Reshare, Zero]] {
        assert_eq!(
            topology
                .config(2, 1, instances.clone())
                .unwrap()
                .instances(),
            instances
        );
    }

    assert_eq!(
        topology
            .with_dealers(&[(1, key::<G>(101)), (4, key::<G>(104))])
            .err(),
        Some(Error::InvalidReshareConfiguration)
    );
    assert_eq!(
        topology.with_dealers(&[(1, key::<G>(101))]).err(),
        Some(Error::InvalidReshareConfiguration)
    );
    assert_eq!(
        topology
            .with_dealers(&[(1, key::<G>(201)), (4, key::<G>(104))])
            .err(),
        Some(Error::InvalidReshareConfiguration)
    );

    for dealers in [
        [(1, key::<G>(201)), (2, key::<G>(102))],
        [(1, -key::<G>(201)), (2, key::<G>(102))],
        [(1, key::<G>(101)), (2, -key::<G>(101))],
    ] {
        assert_eq!(
            topology.with_dealers(&dealers).err(),
            Some(Error::ReshareKeyCollision)
        );
    }
    assert_eq!(
        topology
            .with_receivers(&[(1, key::<G>(201)), (2, -key::<G>(201))])
            .err(),
        Some(Error::ReshareKeyCollision)
    );
    assert_eq!(
        topology
            .with_receivers(&[(1, key::<G>(201)), (2, -key::<G>(102))])
            .err(),
        Some(Error::ReshareKeyCollision)
    );

    for instances in [vec![Reshare], vec![Reshare, Zero], vec![Random, Reshare]] {
        assert_eq!(
            DkgConfig::new(2, SessionId([5; 32]), topology.receivers.clone(), instances).err(),
            Some(Error::InvalidReshareConfiguration)
        );
    }
}
both!(
    constructors_reject_invalid_reshare_configurations,
    constructor_rejections
);

fn root_binding_and_accessors<G: DkgGroup>() {
    let topology = Topology::<G>::new();
    let config = topology.config(2, 1, vec![Reshare, Zero]).unwrap();
    let plain = DkgConfig::new(
        2,
        SessionId([5; 32]),
        topology.receivers.clone(),
        vec![Random, Zero],
    )
    .unwrap();

    let mut prefix = PROTOCOL_VERSION.to_be_bytes().to_vec();
    prefix.extend_from_slice(&u64::try_from(RESHARE_LABEL.len()).unwrap().to_be_bytes());
    prefix.extend_from_slice(RESHARE_LABEL);
    prefix.extend_from_slice(&u64::try_from(G::GROUP_ID.len()).unwrap().to_be_bytes());
    prefix.extend_from_slice(G::GROUP_ID.as_bytes());
    assert!(config.canonical_bytes().starts_with(&prefix));
    assert_ne!(config.canonical_bytes(), plain.canonical_bytes());

    let other_session = DkgConfig::new_reshare(
        2,
        1,
        SessionId([6; 32]),
        topology.dealers.clone(),
        topology.receivers.clone(),
        topology.predecessor.clone(),
        vec![Reshare, Zero],
    )
    .unwrap();
    let other_completion = Topology {
        predecessor: predecessor([3; 32]),
        ..Topology::new()
    };
    let (public_key, shares) = column::<G>(2, &[1, 2, 3]);
    let other_lineage = Topology {
        predecessor: ResharePredecessor::new(2, public_key, shares, [4; 32], [2; 32]).unwrap(),
        ..Topology::new()
    };
    let receivers = |last: (u32, u64)| {
        topology
            .with_receivers(&[
                (1, key::<G>(201)),
                (2, key::<G>(202)),
                (3, key::<G>(203)),
                (last.0, key::<G>(last.1)),
            ])
            .unwrap()
    };
    // Dealers 1, 2 and 3 under one predecessor key and roots, varying its threshold or column.
    let three_dealers = |threshold: usize, (public_key, shares)| {
        Topology {
            dealers: registry(&[(1, key::<G>(101)), (2, key::<G>(102)), (3, key::<G>(103))]),
            predecessor: ResharePredecessor::new(threshold, public_key, shares, [1; 32], [2; 32])
                .unwrap(),
            ..Topology::new()
        }
        .config(2, 1, vec![Reshare, Zero])
        .unwrap()
    };
    let roots: BTreeSet<_> = [
        config.clone(),
        plain.clone(),
        other_session,
        topology.config(3, 1, vec![Reshare, Zero]).unwrap(),
        topology.config(2, 0, vec![Reshare, Zero]).unwrap(),
        topology.config(2, 1, vec![Zero, Reshare]).unwrap(),
        topology
            .with_dealers(&[(1, key::<G>(101)), (3, key::<G>(103))])
            .unwrap(),
        other_completion.config(2, 1, vec![Reshare, Zero]).unwrap(),
        other_lineage.config(2, 1, vec![Reshare, Zero]).unwrap(),
        receivers((4, 205)),
        receivers((5, 204)),
        three_dealers(2, column::<G>(2, &[1, 2, 3])),
        three_dealers(3, column::<G>(2, &[1, 2, 3])),
        three_dealers(3, column::<G>(3, &[1, 2, 3])),
    ]
    .iter()
    .map(DkgConfig::root)
    .collect();
    assert_eq!(roots.len(), 14);

    assert_eq!(config.threshold(), 2);
    assert_eq!(config.registry(), &topology.receivers);
    assert_eq!(config.dealers(), &topology.dealers);
    assert_eq!(config.predecessor(), Some(&topology.predecessor));
    assert_eq!(config.max_corrupt_receivers(), Some(1));
    assert_eq!(config.instances(), [Reshare, Zero]);
    assert_eq!(
        config.dealer_public_key(participant(1)),
        Some(&key::<G>(101))
    );
    assert_eq!(config.dealer_public_key(participant(3)), None);
    assert_eq!(
        config.identity_public_key(participant(1)),
        Some(&key::<G>(201))
    );
    assert_eq!(config.receiver_count(), 4);
    for dealer in topology.dealers.indexes() {
        assert!(config.receivers(dealer).eq(topology.receivers.entries()));
    }

    assert_eq!(plain.predecessor(), None);
    assert_eq!(plain.max_corrupt_receivers(), None);
    assert_eq!(plain.dealers(), plain.registry());
    assert_eq!(plain.receiver_count(), 3);
    assert!(plain
        .receivers(participant(1))
        .map(|(index, _)| index)
        .eq([2, 3, 4].map(participant)));
}
both!(reshare_root_binds_every_field, root_binding_and_accessors);

/// Replace the trailing `length`-byte payload of a state envelope.
fn replace_payload(state: &[u8], length: usize, payload: &[u8]) -> Vec<u8> {
    let header = state.len() - length - 8;
    let mut out = state[..header].to_vec();
    out.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}
/// Replace the canonical payload inside a configuration state envelope.
fn rewrap<G: DkgGroup>(config: &DkgConfig<G>, payload: &[u8]) -> Vec<u8> {
    replace_payload(
        &config.to_bytes().unwrap(),
        config.canonical_bytes().len(),
        payload,
    )
}

fn persistence<G: DkgGroup>() {
    let config = Topology::<G>::new()
        .config(2, 1, vec![Reshare, Zero])
        .unwrap();
    let bytes = config.to_bytes().unwrap();
    assert_eq!(rewrap(&config, config.canonical_bytes()), bytes);
    let restored = DkgConfig::<G>::from_bytes(&bytes).unwrap();
    assert_eq!(restored, config);
    assert_eq!(restored.root(), config.root());
    assert_eq!(restored.canonical_bytes(), config.canonical_bytes());
    assert_eq!(restored.to_bytes().unwrap(), bytes);
    assert_eq!(config.snapshot().unwrap().restore().unwrap(), config);

    let canonical = config.canonical_bytes();
    let fields = 4 + 8 + RESHARE_LABEL.len() + 8 + G::GROUP_ID.len();
    let entry = 4 + G::POINT_BYTES;
    let receivers = fields + 4 + 4 + 32;
    let dealers = receivers + 4 + 4 * entry;
    let predecessor_threshold = dealers + 4 + 2 * entry;
    let field =
        |offset: usize| u32::from_be_bytes(canonical[offset..offset + 4].try_into().unwrap());
    assert_eq!(
        [
            fields,
            fields + 4,
            receivers,
            receivers + 4 + entry,
            dealers,
            predecessor_threshold
        ]
        .map(field),
        [2, 1, 4, 2, 2, 2]
    );
    assert_eq!(canonical[canonical.len() - 3..], [2, 2, 1]);
    let set = |offset: usize, value: &[u8]| {
        let mut payload = canonical.to_vec();
        payload[offset..offset + value.len()].copy_from_slice(value);
        payload
    };
    let mut renamed = canonical.to_vec();
    renamed[12] ^= 1;
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    for payload in [
        renamed,
        trailing,
        canonical[..canonical.len() - 1].to_vec(),
        set(fields + 4, &2u32.to_be_bytes()),
        set(receivers + 4 + entry, &1u32.to_be_bytes()),
        set(predecessor_threshold, &4u32.to_be_bytes()),
        set(canonical.len() - 1, &[0]),
        set(canonical.len() - 1, &[2]),
    ] {
        assert_ne!(payload, canonical);
        assert_eq!(
            DkgConfig::<G>::from_bytes(&rewrap(&config, &payload)).err(),
            Some(Error::InvalidPersistedState)
        );
    }

    let plain = DkgConfig::<G>::new(
        2,
        SessionId([5; 32]),
        Topology::<G>::new().receivers,
        vec![Random, Zero],
    )
    .unwrap();
    let mut tagged = plain.canonical_bytes().to_vec();
    *tagged.last_mut().unwrap() = 2;
    assert_eq!(
        DkgConfig::<G>::from_bytes(&rewrap(&plain, &tagged)).err(),
        Some(Error::InvalidPersistedState)
    );
}
both!(reshare_configuration_round_trips_strictly, persistence);

fn predecessor_validation<G: DkgGroup>() {
    let (public_key, shares) = column::<G>(2, &[1, 2, 3]);
    let reversed: Vec<_> = shares.iter().rev().copied().collect();
    let valid = ResharePredecessor::<G>::new(2, public_key, reversed, [1; 32], [2; 32]).unwrap();
    assert_eq!(valid.threshold(), 2);
    assert_eq!(valid.public_key(), &public_key);
    assert!(valid
        .public_key_shares()
        .map(|(index, point)| (index, *point))
        .eq(shares.iter().copied()));
    assert_eq!(valid.public_key_share(participant(2)), Some(&shares[1].1));
    assert_eq!(valid.public_key_share(participant(4)), None);
    assert_eq!(valid.config_root(), [1; 32]);
    assert_eq!(valid.completion_root(), [2; 32]);
    let (_, quadratic) = column::<G>(3, &[1, 2, 3]);
    assert_eq!(
        ResharePredecessor::<G>::new(3, public_key, quadratic, [1; 32], [2; 32])
            .unwrap()
            .public_key(),
        &public_key
    );

    let generator = G::Point::generator();
    let replace = |position: usize, point: G::Point| {
        let mut changed = shares.clone();
        changed[position].1 = point;
        changed
    };
    let mut duplicate = shares.clone();
    duplicate[2].0 = participant(2);
    let mut repeated = shares.clone();
    repeated.push(shares[0]);
    // Shares at 1, 2 and 3 on `constant + slope·x`. The identity key and the repeated entry
    // below pass every interpolation check; only structural rules reject them.
    let line = |constant: G::Point, slope: G::Point| -> Vec<_> {
        (1..=3)
            .map(|index| {
                let x = G::Scalar::from(u64::from(index));
                (participant(index), constant + slope * x)
            })
            .collect()
    };
    // The column of 1 - x holds the identity at index 1 on the polynomial, as a corrupt dealer
    // and receiver can force.
    let zero_share =
        ResharePredecessor::<G>::new(2, generator, line(generator, -generator), [1; 32], [2; 32])
            .unwrap();
    assert!(bool::from(
        zero_share
            .public_key_share(participant(1))
            .unwrap()
            .is_identity()
    ));
    for (threshold, key, entries) in [
        (
            2,
            G::Point::identity(),
            line(G::Point::identity(), generator),
        ),
        (2, public_key, repeated),
        (0, public_key, shares.clone()),
        (4, public_key, shares.clone()),
        (2, public_key, duplicate),
        (2, public_key, replace(2, G::Point::identity())),
        (2, G::Point::identity(), shares.clone()),
        (2, public_key + generator, shares.clone()),
        (2, public_key, replace(0, shares[0].1 + generator)),
        (2, public_key, replace(2, shares[2].1 + generator)),
        (1, public_key, shares.clone()),
    ] {
        assert_eq!(
            ResharePredecessor::<G>::new(threshold, key, entries, [1; 32], [2; 32]).err(),
            Some(Error::InvalidPredecessor)
        );
    }
}
both!(
    predecessor_rejects_inconsistent_key_sets,
    predecessor_validation
);

fn predecessor_from_output<G: DkgGroup>() {
    let Generation { config, public, .. } = Generation::<G>::plain(&[1, 2, 3], 2, 7);
    let derived = ResharePredecessor::from_output(&config, &public, 0).unwrap();
    let instance = public.instance(0).unwrap();
    assert_eq!(derived.threshold(), config.threshold());
    assert_eq!(derived.public_key(), instance.public_key());
    assert!(derived.public_key_shares().eq(instance.public_key_shares()));
    assert_eq!(derived.config_root(), config.root());
    assert_eq!(derived.completion_root(), public.completion_root());

    let other = DkgConfig::new(
        config.threshold(),
        SessionId([9; 32]),
        config.registry().clone(),
        config.instances().to_vec(),
    )
    .unwrap();
    for (config, position) in [(&config, 1), (&config, 2), (&other, 0)] {
        assert_eq!(
            ResharePredecessor::from_output(config, &public, position).err(),
            Some(Error::InvalidPredecessor)
        );
    }
}
both!(
    predecessor_derives_from_validated_output,
    predecessor_from_output
);
