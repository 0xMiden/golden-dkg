//! Reshare dealing and output state persistence, and tampered or relabelled plain public state.

use ff::Field;
#[cfg(any(feature = "serde", feature = "miden-serde"))]
use golden_core::persistence::{
    DkgConfigSnapshot, DkgOutputSnapshot, DkgPublicOutputSnapshot, OwnDealingSnapshot,
};
use golden_core::{
    aggregate_public, complete_reshare, verify_dealer_message, DkgConfig, DkgGroup,
    DkgInstanceKind::{self, Random, Reshare, Zero},
    DkgOutput, DkgPublicOutput, Error, OwnDealing, ResharePredecessor, SessionId, TranscriptRoot,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use group::Group;

use super::support::{board, credential, participant, Generation, PROOFS};

const INVALID: Option<Error> = Some(Error::InvalidPersistedState);
/// Offset of the dealer index in a broadcast, after the framed wire magic and the root.
const BROADCAST_DEALER: usize = 8 + b"golden-dkg-wire-v4".len() + 32;

/// Reshare of `plain` by dealers 1 and 3 to receivers 2 to 5 at threshold 3.
fn reshare_config<G: DkgGroup>(
    plain: &Generation<G>,
    session: u8,
    instances: Vec<DkgInstanceKind>,
) -> DkgConfig<G> {
    plain.reshare_config_in(session, &[1, 3], &[2, 3, 4, 5], 3, instances)
}
/// Every dealing of the reshare of `plain` with `instances`, its public aggregation and every
/// receiver's completion.
fn reshare<G: DkgGroup>(plain: &Generation<G>, instances: Vec<DkgInstanceKind>) -> Generation<G> {
    plain.reshare(reshare_config(plain, 5, instances), 6)
}

/// Configurations that differ from `config`, a reshare of `plain`, beyond their roots: the
/// predecessor, a reshare of `rival`, the kinds rotated, and a plain configuration over the
/// receivers with `Random` in place of `Reshare`.
fn distinct<G: DkgGroup>(
    plain: &Generation<G>,
    rival: &Generation<G>,
    config: &DkgConfig<G>,
) -> Vec<DkgConfig<G>> {
    let instances = config.instances().to_vec();
    let mut rotated = instances.clone();
    rotated.rotate_left(1);
    let random = instances
        .iter()
        .map(|kind| if *kind == Reshare { Random } else { *kind })
        .collect();
    vec![
        plain.config.clone(),
        reshare_config(rival, 5, instances),
        reshare_config(plain, 5, rotated),
        DkgConfig::new(3, SessionId([5; 32]), config.registry().clone(), random).unwrap(),
    ]
}
/// `config` under another session, differing only in its root.
fn other_session<G: DkgGroup>(plain: &Generation<G>, config: &DkgConfig<G>) -> DkgConfig<G> {
    reshare_config(plain, 6, config.instances().to_vec())
}

/// Envelope bytes preceding a state payload.
fn header<G: DkgGroup>() -> usize {
    8 + b"golden-dkg-state".len() + 4 + 1 + 8 + G::GROUP_ID.len() + 8
}
/// `state` with every occurrence of `from` replaced by `to`.
fn rerooted(state: &[u8], from: TranscriptRoot, to: TranscriptRoot) -> Vec<u8> {
    let mut out = state.to_vec();
    let mut offset = 0;
    while let Some(found) = out[offset..].windows(32).position(|window| window == from) {
        offset += found;
        out[offset..offset + 32].copy_from_slice(&to);
        offset += 32;
    }
    assert_ne!(out, state);
    out
}
/// `state` with the participant index at each of `offsets` replaced by `index`.
fn with_index(state: &[u8], offsets: &[usize], index: u32) -> Vec<u8> {
    let mut out = state.to_vec();
    for offset in offsets {
        out[*offset..*offset + 4].copy_from_slice(&index.to_be_bytes());
    }
    out
}
/// `state` with its payload replaced by `payload`.
fn with_payload<G: DkgGroup>(state: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = state[..header::<G>() - 8].to_vec();
    out.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}
/// Own-dealing `state` holding no shares, carrying `shares` instead.
fn with_own_shares<G: DkgGroup>(state: &[u8], shares: &[G::Scalar]) -> Vec<u8> {
    let mut payload = state[header::<G>()..state.len() - 4].to_vec();
    payload.extend_from_slice(&u32::try_from(shares.len()).unwrap().to_be_bytes());
    for share in shares {
        payload.extend_from_slice(&G::encode_scalar(share));
    }
    with_payload::<G>(state, &payload)
}
/// The state of `public` rebuilt from its columns under `root`, with kind tags `tags`.
fn rebuilt<G: DkgGroup>(public: &DkgPublicOutput<G>, root: TranscriptRoot, tags: &[u8]) -> Vec<u8> {
    let count = |value: usize| u32::try_from(value).unwrap().to_be_bytes();
    let mut payload = root.to_vec();
    payload.extend_from_slice(&count(tags.len()));
    for (position, (tag, instance)) in tags.iter().zip(public.instances()).enumerate() {
        payload.extend_from_slice(&count(position));
        payload.push(*tag);
        payload.extend_from_slice(&G::encode_point(instance.public_key()));
        payload.extend_from_slice(&count(instance.public_key_shares().count()));
        for (index, point) in instance.public_key_shares() {
            payload.extend_from_slice(&index.get().to_be_bytes());
            payload.extend_from_slice(&G::encode_point(point));
        }
    }
    with_payload::<G>(&public.to_bytes().unwrap(), &payload)
}
/// Offsets of the key and then of every public share of the column at `position` of the public
/// payload at `start`, which has `holders` shares per column.
fn column<G: DkgGroup>(start: usize, holders: usize, position: usize) -> Vec<usize> {
    let point = G::POINT_BYTES;
    let column = 4 + 1 + point + 4 + holders * (4 + point);
    let key = start + 32 + 4 + position * column + 4 + 1;
    let shares = (0..holders).map(|row| key + point + 4 + row * (4 + point) + 4);
    core::iter::once(key).chain(shares).collect()
}
/// `state` with `delta` added to the point at each of `offsets`.
fn moved<G: DkgGroup>(state: &[u8], offsets: &[usize], delta: G::Point) -> Vec<u8> {
    let point = G::POINT_BYTES;
    let mut out = state.to_vec();
    for offset in offsets {
        let moved = G::decode_point(&state[*offset..*offset + point]).unwrap() + delta;
        out[*offset..*offset + point].copy_from_slice(&G::encode_point(&moved));
    }
    out
}
/// `state` with `delta` added to the key and every public share of the column at `position`
/// of the public payload at `start`, which has `holders` shares per column. A shifted column
/// still lies on one polynomial, but its key moves.
fn shifted<G: DkgGroup>(
    state: &[u8],
    start: usize,
    holders: usize,
    position: usize,
    delta: G::Point,
) -> Vec<u8> {
    moved::<G>(state, &column::<G>(start, holders, position), delta)
}

/// The `Reshare` key of `public` is the predecessor key of `plain`, and every `Zero` key is
/// the identity.
fn assert_pinned<G: DkgGroup>(
    config: &DkgConfig<G>,
    public: &DkgPublicOutput<G>,
    plain: &Generation<G>,
) {
    assert_eq!(public.config_root(), config.root());
    assert_eq!(
        config.predecessor().map(ResharePredecessor::public_key),
        Some(&plain.key())
    );
    assert!(public
        .instances()
        .map(|instance| instance.kind())
        .eq(config.instances().iter().copied()));
    for instance in public.instances() {
        let pinned = if instance.kind() == Reshare {
            plain.key()
        } else {
            G::Point::identity()
        };
        assert_eq!(*instance.public_key(), pinned);
    }
}

const RESHARE_FIRST: &[DkgInstanceKind] = &[Reshare, Zero];
const RESHARE_BETWEEN_ZEROS: &[DkgInstanceKind] = &[Zero, Reshare, Zero];

fn own_dealing_state<G: DkgGroup>(
    plain: &Generation<G>,
    rival: &Generation<G>,
    reshared: &Generation<G>,
) {
    let config = &reshared.config;
    let restored: Vec<_> = reshared
        .own
        .iter()
        .map(|dealing| {
            let dealer = dealing.participant();
            let state = dealing.to_bytes().unwrap();
            let snapshot = dealing.snapshot().unwrap().restore(config, dealer).unwrap();
            assert_eq!(snapshot.to_bytes().unwrap(), state);
            let restored = OwnDealing::from_bytes(config, dealer, &state).unwrap();
            assert_eq!(restored.participant(), dealer);
            assert_eq!(restored.config_root(), config.root());
            assert_eq!(restored.broadcast_bytes(), dealing.broadcast_bytes());
            assert_eq!(restored.to_bytes().unwrap(), state);
            verify_dealer_message(&PROOFS, config, dealer, restored.broadcast_bytes()).unwrap();
            restored
        })
        .collect();
    let board = board(&restored);
    assert_eq!(
        aggregate_public(&PROOFS, config, &board)
            .unwrap()
            .to_bytes()
            .unwrap(),
        reshared.public.to_bytes().unwrap()
    );
    for output in reshared.outputs.values() {
        let receiver = output.participant();
        let identity = credential::<G>(1, receiver);
        let completed = complete_reshare(&PROOFS, config, &identity, receiver, &board);
        assert_eq!(
            completed.unwrap().to_bytes().unwrap(),
            output.to_bytes().unwrap()
        );
    }

    let dealer = reshared.own[0].participant();
    let state = reshared.own[0].to_bytes().unwrap();
    let start = header::<G>();
    let indexes = [start + 32, start + 32 + 4 + 8 + BROADCAST_DEALER];
    assert_eq!(with_index(&state, &indexes, dealer.get()), state);
    assert_eq!(
        OwnDealing::from_bytes(config, participant(3), &state).err(),
        INVALID
    );
    // The other declared dealer, two receivers that do not deal, and a stranger.
    for claimed in [3, 2, 4, 9] {
        let forged = with_index(&state, &indexes, claimed);
        assert_eq!(
            OwnDealing::from_bytes(config, participant(claimed), &forged).err(),
            INVALID
        );
    }
    assert_eq!(with_own_shares::<G>(&state, &[]), state);
    let instances = config.instances().len();
    for shares in [
        vec![G::Scalar::ZERO],
        vec![G::Scalar::ZERO; instances],
        vec![plain.share(dealer); instances],
    ] {
        assert_eq!(
            OwnDealing::from_bytes(config, dealer, &with_own_shares::<G>(&state, &shares)).err(),
            INVALID
        );
    }
    let session = other_session(plain, config);
    assert_eq!(
        OwnDealing::from_bytes(&session, dealer, &state).err(),
        INVALID
    );
    for other in distinct(plain, rival, config) {
        for candidate in [state.clone(), rerooted(&state, config.root(), other.root())] {
            assert_eq!(
                OwnDealing::from_bytes(&other, dealer, &candidate).err(),
                INVALID
            );
        }
        let snapshot = reshared.own[0].snapshot().unwrap();
        assert_eq!(snapshot.restore(&other, dealer).err(), INVALID);
    }
}

/// The plain columns relabelled `Reshare` restore under a reshare to the same holders, and a
/// shifted `Random` column restores only while its key is not pinned.
fn relabelled_plain_state<G: DkgGroup>(plain: &Generation<G>) {
    let state = plain.public.to_bytes().unwrap();
    assert_eq!(rebuilt(&plain.public, plain.config.root(), &[0, 1]), state);
    let pinning = plain.reshare_config_in(5, &[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let relabelled = rebuilt(&plain.public, pinning.root(), &[2, 1]);
    let restored = DkgPublicOutput::from_bytes(&pinning, &relabelled).unwrap();
    assert_pinned(&pinning, &restored, plain);
    let (start, holders) = (header::<G>(), plain.config.registry().len());
    let generator = G::Point::generator();
    let moved_plain = shifted::<G>(&state, start, holders, 0, generator);
    assert!(DkgPublicOutput::from_bytes(&plain.config, &moved_plain).is_ok());
    let moved_relabelled = shifted::<G>(&relabelled, start, holders, 0, generator);
    assert_eq!(
        DkgPublicOutput::from_bytes(&pinning, &moved_relabelled).err(),
        INVALID
    );
}

fn public_output_state<G: DkgGroup>(
    plain: &Generation<G>,
    rival: &Generation<G>,
    reshared: &Generation<G>,
) {
    let config = &reshared.config;
    let state = reshared.public.to_bytes().unwrap();
    for output in reshared.outputs.values() {
        assert_eq!(output.public().to_bytes().unwrap(), state);
    }
    for restored in [
        DkgPublicOutput::from_bytes(config, &state).unwrap(),
        reshared.public.snapshot().unwrap().restore(config).unwrap(),
    ] {
        assert_eq!(restored.to_bytes().unwrap(), state);
        assert_eq!(
            restored.completion_root(),
            reshared.public.completion_root()
        );
        assert_pinned(config, &restored, plain);
    }

    let start = header::<G>();
    let holders = config.registry().len();
    for position in 0..config.instances().len() {
        assert_eq!(
            shifted::<G>(&state, start, holders, position, G::Point::identity()),
            state
        );
        let forged = shifted::<G>(&state, start, holders, position, G::Point::generator());
        assert_eq!(DkgPublicOutput::from_bytes(config, &forged).err(), INVALID);
    }
    let session = other_session(plain, config);
    assert_eq!(DkgPublicOutput::from_bytes(&session, &state).err(), INVALID);
    for other in distinct(plain, rival, config) {
        for candidate in [state.clone(), rerooted(&state, config.root(), other.root())] {
            assert_eq!(
                DkgPublicOutput::from_bytes(&other, &candidate).err(),
                INVALID
            );
        }
    }
}

/// Restoring the state of `public` under `config` rejects any one key or public share moved
/// alone, whether or not its column's key is pinned.
fn assert_points_bound<G: DkgGroup>(config: &DkgConfig<G>, public: &DkgPublicOutput<G>) {
    let state = public.to_bytes().unwrap();
    let holders = config.registry().len();
    for (position, instance) in public.instances().enumerate() {
        let points: Vec<_> = core::iter::once(instance.public_key())
            .chain(instance.public_key_shares().map(|(_, point)| point))
            .collect();
        let offsets = column::<G>(header::<G>(), holders, position);
        assert_eq!(offsets.len(), points.len());
        for (offset, point) in offsets.into_iter().zip(points) {
            assert_eq!(
                &state[offset..offset + G::POINT_BYTES],
                G::encode_point(point).as_slice()
            );
            let forged = moved::<G>(&state, &[offset], G::Point::generator());
            assert_eq!(DkgPublicOutput::from_bytes(config, &forged).err(), INVALID);
        }
    }
}

fn local_output_state<G: DkgGroup>(
    plain: &Generation<G>,
    rival: &Generation<G>,
    reshared: &Generation<G>,
) {
    let config = &reshared.config;
    let instances = config.instances().len();
    for output in reshared.outputs.values() {
        let receiver = output.participant();
        let state = output.to_bytes().unwrap();
        for restored in [
            DkgOutput::from_bytes(config, receiver, &state).unwrap(),
            output
                .snapshot()
                .unwrap()
                .restore(config, receiver)
                .unwrap(),
        ] {
            assert_eq!(restored.to_bytes().unwrap(), state);
            assert_eq!(restored.participant(), receiver);
            assert_eq!(
                restored.completion_root(),
                reshared.public.completion_root()
            );
            assert_pinned(config, restored.public(), plain);
            for position in 0..instances {
                assert_eq!(
                    restored.secret_share(position),
                    output.secret_share(position)
                );
            }
        }
    }

    let output = reshared.outputs.values().next().unwrap();
    let receiver = output.participant();
    let state = output.to_bytes().unwrap();
    let start = header::<G>();
    assert_eq!(with_index(&state, &[start], receiver.get()), state);
    assert_eq!(
        DkgOutput::from_bytes(config, participant(3), &state).err(),
        INVALID
    );
    for outsider in [1, 9] {
        let forged = with_index(&state, &[start], outsider);
        assert_eq!(
            DkgOutput::from_bytes(config, participant(outsider), &forged).err(),
            INVALID
        );
    }
    let shares = state.len() - 32 * instances;
    for position in 0..instances {
        let offset = shares + 32 * position;
        let mut forged = state.clone();
        let share = *output.secret_share(position).unwrap() + G::Scalar::ONE;
        forged[offset..offset + 32].copy_from_slice(&G::encode_scalar(&share));
        assert_eq!(
            DkgOutput::from_bytes(config, receiver, &forged).err(),
            INVALID
        );
    }
    let holders = config.registry().len();
    for position in 0..instances {
        let public = start + 4 + 8;
        assert_eq!(
            shifted::<G>(&state, public, holders, position, G::Point::identity()),
            state
        );
        let forged = shifted::<G>(&state, public, holders, position, G::Point::generator());
        assert_eq!(
            DkgOutput::from_bytes(config, receiver, &forged).err(),
            INVALID
        );
    }
    let session = other_session(plain, config);
    assert_eq!(
        DkgOutput::from_bytes(&session, receiver, &state).err(),
        INVALID
    );
    for other in distinct(plain, rival, config) {
        for candidate in [state.clone(), rerooted(&state, config.root(), other.root())] {
            assert_eq!(
                DkgOutput::from_bytes(&other, receiver, &candidate).err(),
                INVALID
            );
        }
    }
}

/// Encodes a snapshot through one serialization adapter and decodes it, rejecting a
/// truncation.
#[cfg(any(feature = "serde", feature = "miden-serde"))]
trait Adapter<T> {
    fn roundtrip(snapshot: &T) -> T;
}
#[cfg(feature = "serde")]
struct Postcard;
#[cfg(feature = "serde")]
impl<T: serde::Serialize + serde::de::DeserializeOwned> Adapter<T> for Postcard {
    fn roundtrip(snapshot: &T) -> T {
        let encoded = zeroize::Zeroizing::new(postcard::to_allocvec(snapshot).unwrap());
        assert!(postcard::from_bytes::<T>(&encoded[..encoded.len() - 1]).is_err());
        postcard::from_bytes(&encoded).unwrap()
    }
}
#[cfg(feature = "miden-serde")]
struct Miden;
#[cfg(feature = "miden-serde")]
impl<T> Adapter<T> for Miden
where
    T: miden_serde_utils::Serializable + miden_serde_utils::Deserializable,
{
    fn roundtrip(snapshot: &T) -> T {
        let encoded = zeroize::Zeroizing::new(miden_serde_utils::Serializable::to_bytes(snapshot));
        assert!(T::read_from_bytes_with_budget(&encoded, encoded.len() - 1).is_err());
        T::read_from_bytes(&encoded).unwrap()
    }
}

/// Reshare configuration, dealing and output snapshots restore after `A` round trips them,
/// and only against the reshare configuration.
#[cfg(any(feature = "serde", feature = "miden-serde"))]
fn snapshots<G: DkgGroup, A>(plain: &Generation<G>, reshared: &Generation<G>)
where
    A: Adapter<DkgConfigSnapshot<G>>
        + Adapter<OwnDealingSnapshot<G>>
        + Adapter<DkgPublicOutputSnapshot<G>>
        + Adapter<DkgOutputSnapshot<G>>,
{
    let config = A::roundtrip(&reshared.config.snapshot().unwrap())
        .restore()
        .unwrap();
    assert_eq!(config, reshared.config);
    assert_eq!(config.canonical_bytes(), reshared.config.canonical_bytes());
    for dealing in &reshared.own {
        let dealer = dealing.participant();
        let snapshot = A::roundtrip(&dealing.snapshot().unwrap());
        let restored = snapshot.restore(&config, dealer).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), dealing.to_bytes().unwrap());
        assert!(snapshot.restore(&plain.config, dealer).is_err());
    }
    let snapshot = A::roundtrip(&reshared.public.snapshot().unwrap());
    let restored = snapshot.restore(&config).unwrap();
    assert_eq!(
        restored.to_bytes().unwrap(),
        reshared.public.to_bytes().unwrap()
    );
    assert_pinned(&config, &restored, plain);
    assert!(snapshot.restore(&plain.config).is_err());
    for output in reshared.outputs.values() {
        let receiver = output.participant();
        let snapshot = A::roundtrip(&output.snapshot().unwrap());
        let restored = snapshot.restore(&config, receiver).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), output.to_bytes().unwrap());
        assert!(snapshot.restore(&plain.config, receiver).is_err());
    }
}

fn plain_state<G: DkgGroup>() {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    relabelled_plain_state(&plain);
    assert_points_bound(&plain.config, &plain.public);
}
both!(
    plain_public_state_binds_its_points_and_pins_relabelled_keys,
    plain_state
);

fn reshare_state<G: DkgGroup>(layout: &[DkgInstanceKind]) {
    let plain = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    let rival = Generation::<G>::plain(&[1, 2, 3], 2, 2);
    let reshared = reshare(&plain, layout.to_vec());
    own_dealing_state(&plain, &rival, &reshared);
    public_output_state(&plain, &rival, &reshared);
    assert_points_bound(&reshared.config, &reshared.public);
    local_output_state(&plain, &rival, &reshared);
    #[cfg(feature = "serde")]
    snapshots::<G, Postcard>(&plain, &reshared);
    #[cfg(feature = "miden-serde")]
    snapshots::<G, Miden>(&plain, &reshared);
}
both!(
    reshare_state_restores_only_under_its_configuration,
    reshare_state,
    RESHARE_FIRST
);
both!(
    reshare_state_between_zero_columns_restores_only_under_its_configuration,
    reshare_state,
    RESHARE_BETWEEN_ZEROS
);
