//! Pinned plain and reshare configuration, broadcast and completion bytes on both native adapters.
#![cfg(feature = "insecure-revealed-witness")]
#![allow(clippy::unwrap_used)]

use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, complete_reshare, deal, deal_reshare, DealerMessageRef,
    DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind::{Random, Reshare, Zero},
    DkgOutput, DkgPublicOutput, EvrfMessage, OwnDealing, ParticipantIndex, ParticipantRegistry,
    ResharePredecessor, Result, SessionId,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use rand_chacha::{
    rand_core::{CryptoRngCore, SeedableRng},
    ChaCha20Rng,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;

struct Vectors {
    config_root: &'static str,
    canonical_sha256: &'static str,
    broadcast_sha256: [&'static str; 3],
    completion_root: &'static str,
    first_effective_message: &'static str,
}

const SECP256K1: Vectors = Vectors {
    config_root: "4d082fcaa1e1e39a65c2910d85ce90f11d0013d329681443b15c397d5119269a",
    canonical_sha256: "f8d37461f9632b6555c651b2ca7b2660f51b4935b4aabd667c5df97ad5446eee",
    broadcast_sha256: [
        "74527e37afda8c6f4011ba9be495b63280615cd81a3b01b6402c7908faa0cb87",
        "61c3e8f8aedbdc97c1f0fe160515f6020d91e33f7de1201682ed67e236d20b77",
        "306b14373939cce9a28cd91420450c11184d41ba47b76915dc5f2a72bb7389fd",
    ],
    completion_root: "687b72b77e075ed46400c71b303e36e872c95130fbe549c3dc9ed0eefdc501c4",
    first_effective_message: "442b27bb06aac35069e9ac26224c560d10c7bf371ec6920cd45ebb9e2de4c716",
};

const JUBJUB: Vectors = Vectors {
    config_root: "f6a23ad7483280f033ab893e25a7f84f3a15049a0dcadca490dce66327358719",
    canonical_sha256: "786d6220ca65379743053b8aec4af0e98c487663d26bc20c81e1ebfd35b966d7",
    broadcast_sha256: [
        "2e5a962ad623f35b31478fca8fb0e3da092191de6796a981f797b6babb44625b",
        "d46efa68bb64bb74058a9ce9fa0ce8c68f5d49a7f4924493503e5fe64a201e28",
        "1e272ad9ce74214bb3749b732ac2f156e32993aa43721bd366bff7c14b7046d8",
    ],
    completion_root: "90b025c7b5bc972faa89d603873999d97ec73a7298ea42d8f7dab8a2913d036d",
    first_effective_message: "43d89a1ccfba104cfd93d0416b91092238357bd712b719878f38ca0c41d3eaaa",
};

struct ReshareVectors {
    config_root: &'static str,
    canonical_sha256: &'static str,
    broadcast_sha256: [&'static str; 2],
    completion_root: &'static str,
    first_effective_message: &'static str,
}

const SECP256K1_RESHARE: ReshareVectors = ReshareVectors {
    config_root: "e3e03b1c1993dcd86be8920eaf0343a9197f8bcdda7f2d93d7e62db0d577a417",
    canonical_sha256: "8f835cd728670044f0b33dede02a75051d9e13417bd8465d3479fcdf60655279",
    broadcast_sha256: [
        "5e9ee39f60d4c98bec43087b730b018485f552860a101b2a28407beea424df20",
        "c7d274eb429c5390ae03af629f62e96841b7b22bc3c6e664aa41723972f57837",
    ],
    completion_root: "27e9038ff7f40924394d5e35c58efa765f9e0adfaf6842e3432b166c1f385514",
    first_effective_message: "2eaad77fad09d987d88b584454d15f80d90c40ef853cdd8b3ac8592083cf9260",
};

const JUBJUB_RESHARE: ReshareVectors = ReshareVectors {
    config_root: "f42475e6ac9a898e46c1005ba295a4de08f30d6a40e9c19b7fb6cf44504ac294",
    canonical_sha256: "18d26fb7c44b1f15fe0b5a33714abc60265993fa935cd8ccc56685f9d8eaca07",
    broadcast_sha256: [
        "8e7a1f798e8ae56409c9508834d7d2a8adbb5f85757182511e26b2ffa7e7e92b",
        "0f8781f6d130e729efb887219eec9c774093ee7b51eeb2df1b0a048a4fcdfa76",
    ],
    completion_root: "eac6000ea36cd921fc064e16dd425329fbf4f451896d73d6c2793a2277d49664",
    first_effective_message: "e26b94dec4cfda6be9d6f8bc0bd23eb2b982655f95e8fb17e1c25a64f213653b",
};

/// Delegates to the insecure proof and records each proven statement's first effective message.
#[derive(Default)]
struct Capture(Mutex<Vec<EvrfMessage>>);
impl<G: DkgGroup> DealerProofSystem<G> for Capture {
    fn prove(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        witness: &DealerProofWitness<G>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let first = statement.instance(0).unwrap().effective_message();
        self.0.lock().unwrap().push(first);
        InsecureRevealedWitnessProof.prove(config, statement, witness, rng)
    }
    fn verify(
        &self,
        config: &DkgConfig<G>,
        statement: &DealerProofStatement<G>,
        proof: &[u8],
    ) -> Result<()> {
        InsecureRevealedWitnessProof.verify(config, statement, proof)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn credential<G: DkgGroup>(offset: u64, index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(u64::from(index.get()) + offset)
}
fn registry<G: DkgGroup>(offset: u64, indexes: &[u32]) -> ParticipantRegistry<G> {
    let entries = indexes
        .iter()
        .map(|index| {
            let id = ParticipantIndex::new(*index).unwrap();
            (id, G::mul_generator(&credential::<G>(offset, id)))
        })
        .collect();
    ParticipantRegistry::new(entries).unwrap()
}
/// Pins each broadcast and the first captured effective message, returning the board.
fn pin_dealings<'a, G: DkgGroup>(
    proofs: &Capture,
    own: &'a [OwnDealing<G>],
    broadcast_sha256: &[&str],
    first_effective_message: &str,
) -> Vec<DealerMessageRef<'a>> {
    let broadcasts: Vec<_> = own
        .iter()
        .map(|dealing| sha256(dealing.broadcast_bytes()))
        .collect();
    assert_eq!(broadcasts, broadcast_sha256);
    let captured = proofs.0.lock().unwrap();
    assert_eq!(captured.len(), own.len());
    assert_eq!(hex(&captured[0].0), first_effective_message);
    own.iter()
        .map(|dealing| DealerMessageRef {
            expected_dealer: dealing.participant(),
            bytes: dealing.broadcast_bytes(),
        })
        .collect()
}

/// Runs the pinned plain DKG among `{1, 2, 3}`, returning its configuration, public output and
/// every holder's local output.
fn check_plain<G: DkgGroup>(
    expected: &Vectors,
) -> (
    DkgConfig<G>,
    DkgPublicOutput<G>,
    BTreeMap<ParticipantIndex, DkgOutput<G>>,
) {
    let config = DkgConfig::<G>::new(
        2,
        SessionId([0x5a; 32]),
        registry(10, &[1, 2, 3]),
        vec![Random, Zero],
    )
    .unwrap();
    assert_eq!(hex(&config.root()), expected.config_root);
    assert_eq!(sha256(config.canonical_bytes()), expected.canonical_sha256);

    let proofs = Capture::default();
    let mut rng = ChaCha20Rng::from_seed([0x3c; 32]);
    let own: Vec<OwnDealing<G>> = config
        .registry()
        .indexes()
        .map(|id| deal(&proofs, &config, id, &credential::<G>(10, id), &mut rng).unwrap())
        .collect();
    let board = pin_dealings(
        &proofs,
        &own,
        &expected.broadcast_sha256,
        expected.first_effective_message,
    );
    let public = aggregate_public(&InsecureRevealedWitnessProof, &config, &board).unwrap();
    assert_eq!(hex(&public.completion_root()), expected.completion_root);
    let outputs = own
        .iter()
        .map(|dealing| {
            let me = dealing.participant();
            let peers: Vec<_> = board
                .iter()
                .copied()
                .filter(|item| item.expected_dealer != me)
                .collect();
            let output = complete(
                &InsecureRevealedWitnessProof,
                &config,
                &credential::<G>(10, me),
                dealing,
                &peers,
            )
            .unwrap();
            assert_eq!(hex(&output.completion_root()), expected.completion_root);
            (me, output)
        })
        .collect();
    (config, public, outputs)
}

/// Reshares the pinned plain group key from dealers `{1, 3}` to receivers `{1, 2, 4}`.
fn check_reshare<G: DkgGroup>(plain: &Vectors, expected: &ReshareVectors) {
    let (plain_config, plain_public, plain_outputs) = check_plain::<G>(plain);
    let predecessor = ResharePredecessor::from_output(&plain_config, &plain_public, 0).unwrap();
    let config = DkgConfig::<G>::new_reshare(
        2,
        1,
        SessionId([0x6b; 32]),
        registry(20, &[1, 3]),
        registry(30, &[1, 2, 4]),
        predecessor,
        vec![Reshare, Zero],
    )
    .unwrap();
    assert_eq!(hex(&config.root()), expected.config_root);
    assert_eq!(sha256(config.canonical_bytes()), expected.canonical_sha256);

    let proofs = Capture::default();
    let mut rng = ChaCha20Rng::from_seed([0x4d; 32]);
    let own: Vec<OwnDealing<G>> = config
        .dealers()
        .indexes()
        .map(|id| {
            let share = plain_outputs[&id].secret_share(0).unwrap();
            deal_reshare(
                &proofs,
                &config,
                id,
                &credential::<G>(20, id),
                share,
                &mut rng,
            )
            .unwrap()
        })
        .collect();
    let board = pin_dealings(
        &proofs,
        &own,
        &expected.broadcast_sha256,
        expected.first_effective_message,
    );
    let public = aggregate_public(&InsecureRevealedWitnessProof, &config, &board).unwrap();
    assert_eq!(hex(&public.completion_root()), expected.completion_root);
    for receiver in config.registry().indexes() {
        let output = complete_reshare(
            &InsecureRevealedWitnessProof,
            &config,
            &credential::<G>(30, receiver),
            receiver,
            &board,
        )
        .unwrap();
        assert_eq!(hex(&output.completion_root()), expected.completion_root);
    }
}

#[test]
fn secp256k1_plain_vectors() {
    check_plain::<Secp256k1Group>(&SECP256K1);
}

#[test]
fn jubjub_plain_vectors() {
    check_plain::<JubjubGroup>(&JUBJUB);
}

#[test]
fn secp256k1_reshare_vectors() {
    check_reshare::<Secp256k1Group>(&SECP256K1, &SECP256K1_RESHARE);
}

#[test]
fn jubjub_reshare_vectors() {
    check_reshare::<JubjubGroup>(&JUBJUB, &JUBJUB_RESHARE);
}
