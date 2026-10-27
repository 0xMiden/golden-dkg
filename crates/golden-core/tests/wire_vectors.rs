//! Pinned plain-DKG configuration, broadcast and completion bytes on both native adapters.
#![cfg(feature = "insecure-revealed-witness")]
#![allow(clippy::unwrap_used)]

use golden_core::insecure::InsecureRevealedWitnessProof;
use golden_core::{
    aggregate_public, complete, deal, DealerMessageRef, DealerProofStatement, DealerProofSystem,
    DealerProofWitness, DkgConfig, DkgGroup,
    DkgInstanceKind::{Random, Zero},
    EvrfMessage, OwnDealing, ParticipantIndex, ParticipantRegistry, Result, SessionId,
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use rand_chacha::{
    rand_core::{CryptoRngCore, SeedableRng},
    ChaCha20Rng,
};
use sha2::{Digest, Sha256};
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
fn credential<G: DkgGroup>(index: ParticipantIndex) -> G::Scalar {
    G::Scalar::from(u64::from(index.get()) + 10)
}

fn check<G: DkgGroup>(expected: &Vectors) {
    let entries = (1..=3)
        .map(|index| {
            let id = ParticipantIndex::new(index).unwrap();
            (id, G::mul_generator(&credential::<G>(id)))
        })
        .collect();
    let config = DkgConfig::<G>::new(
        2,
        SessionId([0x5a; 32]),
        ParticipantRegistry::new(entries).unwrap(),
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
        .map(|id| deal(&proofs, &config, id, &credential::<G>(id), &mut rng).unwrap())
        .collect();
    let broadcasts: Vec<_> = own
        .iter()
        .map(|dealing| sha256(dealing.broadcast_bytes()))
        .collect();
    assert_eq!(broadcasts, expected.broadcast_sha256);
    let captured = proofs.0.lock().unwrap();
    assert_eq!(captured.len(), own.len());
    assert_eq!(hex(&captured[0].0), expected.first_effective_message);

    let board: Vec<_> = own
        .iter()
        .map(|dealing| DealerMessageRef {
            expected_dealer: dealing.participant(),
            bytes: dealing.broadcast_bytes(),
        })
        .collect();
    let public = aggregate_public(&InsecureRevealedWitnessProof, &config, &board).unwrap();
    assert_eq!(hex(&public.completion_root()), expected.completion_root);
    for dealing in &own {
        let me = dealing.participant();
        let peers: Vec<_> = board
            .iter()
            .copied()
            .filter(|item| item.expected_dealer != me)
            .collect();
        let output = complete(
            &InsecureRevealedWitnessProof,
            &config,
            &credential::<G>(me),
            dealing,
            &peers,
        )
        .unwrap();
        assert_eq!(hex(&output.completion_root()), expected.completion_root);
    }
}

#[test]
fn secp256k1_plain_vectors() {
    check::<Secp256k1Group>(&SECP256K1);
}

#[test]
fn jubjub_plain_vectors() {
    check::<JubjubGroup>(&JUBJUB);
}
