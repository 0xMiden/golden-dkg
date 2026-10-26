//! Check reviewed disposable-identity fixtures. Regeneration is explicitly opt-in.
#[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
mod enabled {
    use golden_core::{
        aggregate_public, complete, deal, DealerMessageRef, DealerProofSystem, DkgConfig, DkgGroup,
        DkgInstanceKind, DkgOutput, DkgPublicOutput, OwnDealing, ParticipantIndex,
        ParticipantRegistry, SessionId,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::{
        error::Error as StdError,
        fs,
        path::{Path, PathBuf},
    };

    type Result<T> = std::result::Result<T, Box<dyn StdError>>;
    fn config<G: DkgGroup>() -> Result<DkgConfig<G>> {
        let entries = [11u64, 22]
            .into_iter()
            .enumerate()
            .map(|(position, secret)| {
                Ok((
                    ParticipantIndex::new(u32::try_from(position + 1)?)?,
                    G::mul_generator(&G::Scalar::from(secret)),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DkgConfig::new(
            2,
            SessionId([71; 32]),
            ParticipantRegistry::new(entries)?,
            vec![DkgInstanceKind::Random, DkgInstanceKind::Zero],
        )?)
    }
    fn write(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        fs::write(path.join(name), bytes)?;
        Ok(())
    }
    fn read(path: &Path, name: &str) -> Result<Vec<u8>> {
        Ok(fs::read(path.join(name)).map_err(|error| {
            format!(
                "{}: {error}; regenerate explicitly with --regenerate",
                path.join(name).display()
            )
        })?)
    }
    fn suite<G: DkgGroup, P: DealerProofSystem<G>>(
        name: &str,
        regenerate: bool,
        prepare: impl Fn(&DkgConfig<G>) -> golden_core::Result<(P, Vec<u8>)>,
        restore: impl Fn(&[u8]) -> golden_core::Result<P>,
    ) -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        let expected = config::<G>()?;
        if regenerate {
            fs::create_dir_all(&path)?;
            let (proofs, prepared) = prepare(&expected)?;
            write(&path, "config.bin", &expected.to_bytes()?)?;
            write(&path, "prepared.bin", &prepared)?;
            let mut rng = ChaCha20Rng::from_seed([19; 32]);
            for (position, secret) in [11u64, 22].into_iter().enumerate() {
                let participant = ParticipantIndex::new(u32::try_from(position + 1)?)?;
                let own = deal(
                    &proofs,
                    &expected,
                    participant,
                    &G::Scalar::from(secret),
                    &mut rng,
                )?;
                write(
                    &path,
                    &format!("own-{}.bin", position + 1),
                    &own.to_bytes()?,
                )?;
                write(
                    &path,
                    &format!("message-{}.bin", position + 1),
                    own.broadcast_bytes(),
                )?;
            }
        }
        // Every persisted component is read independently, even after regeneration.
        let config = DkgConfig::<G>::from_bytes(&read(&path, "config.bin")?)?;
        if config.root() != expected.root() {
            return Err("fixture configuration differs from its declared shape".into());
        }
        let proofs = restore(&read(&path, "prepared.bin")?)?;
        let mut own = Vec::new();
        let mut messages = Vec::new();
        for position in 1..=2u32 {
            let local = OwnDealing::<G>::from_bytes(
                &config,
                ParticipantIndex::new(position)?,
                &read(&path, &format!("own-{position}.bin"))?,
            )?;
            let message = read(&path, &format!("message-{position}.bin"))?;
            if local.broadcast_bytes() != message {
                return Err("own state and independently stored broadcast disagree".into());
            }
            own.push(local);
            messages.push(message);
        }
        let board = messages
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                Ok(DealerMessageRef {
                    expected_dealer: ParticipantIndex::new(u32::try_from(index + 1)?)?,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let public = aggregate_public(&proofs, &config, &board)?;
        if regenerate {
            write(&path, "public.bin", &public.to_bytes()?)?;
            write(&path, "completion-root.bin", &public.completion_root())?;
        }
        let restored_public =
            DkgPublicOutput::<G>::from_bytes(&config, &read(&path, "public.bin")?)?;
        if restored_public.completion_root() != public.completion_root()
            || read(&path, "completion-root.bin")? != public.completion_root()
        {
            return Err("fixture public identity mismatch".into());
        }
        for (position, secret) in [11u64, 22].into_iter().enumerate() {
            let peers = board
                .iter()
                .copied()
                .filter(|item| item.expected_dealer != own[position].participant())
                .collect::<Vec<_>>();
            let output = complete(
                &proofs,
                &config,
                &G::Scalar::from(secret),
                &own[position],
                &peers,
            )?;
            if output.completion_root() != public.completion_root() {
                return Err("production completion disagrees with public aggregation".into());
            }
            let filename = format!("output-{}.bin", position + 1);
            if regenerate {
                write(&path, &filename, &output.to_bytes()?)?;
            }
            let restored = DkgOutput::<G>::from_bytes(
                &config,
                own[position].participant(),
                &read(&path, &filename)?,
            )?;
            if restored.completion_root() != output.completion_root()
                || (0..config.instances().len())
                    .any(|i| restored.secret_share(i) != output.secret_share(i))
            {
                return Err(
                    "persisted participant output differs from production completion".into(),
                );
            }
        }
        println!("checked {name}: n=2 t=2 [Random, Zero], {}", path.display());
        Ok(())
    }
    pub fn run() -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let regenerate = match args.as_slice() {
            [] => false,
            [flag] if flag == "--regenerate" => true,
            _ => return Err("usage: check_fixtures [--regenerate]".into()),
        };
        #[cfg(feature = "secp-secq")]
        suite::<golden_curves::Secp256k1Group, golden_bulletproofs::SecpSecqBulletproofs>(
            "secp-secq",
            regenerate,
            |config| {
                let prepared = golden_bulletproofs::SecpSecqPrepared::prepare_for(config)?;
                let bytes = prepared.to_bytes()?;
                Ok((
                    golden_bulletproofs::SecpSecqBulletproofs::from_prepared(prepared),
                    bytes,
                ))
            },
            |bytes| {
                let prepared = golden_bulletproofs::SecpSecqPrepared::from_bytes(bytes)?;
                if prepared.to_bytes() != Ok(bytes.to_vec()) {
                    return Err(golden_core::Error::MalformedPreparedGenerators);
                }
                Ok(golden_bulletproofs::SecpSecqBulletproofs::from_prepared(
                    prepared,
                ))
            },
        )?;
        #[cfg(feature = "jubjub-bls12-381")]
        suite::<golden_curves::JubjubGroup, golden_bulletproofs::BlsJubjubBulletproofs>(
            "jubjub-bls12-381",
            regenerate,
            |config| {
                let prepared = golden_bulletproofs::BlsJubjubPrepared::prepare_for(config)?;
                let bytes = prepared.to_bytes()?;
                Ok((
                    golden_bulletproofs::BlsJubjubBulletproofs::from_prepared(prepared),
                    bytes,
                ))
            },
            |bytes| {
                let prepared = golden_bulletproofs::BlsJubjubPrepared::from_bytes(bytes)?;
                if prepared.to_bytes() != Ok(bytes.to_vec()) {
                    return Err(golden_core::Error::MalformedPreparedGenerators);
                }
                Ok(golden_bulletproofs::BlsJubjubBulletproofs::from_prepared(
                    prepared,
                ))
            },
        )?;
        let _ = regenerate;
        #[cfg(not(any(feature = "secp-secq", feature = "jubjub-bls12-381")))]
        return Err("enable secp-secq and/or jubjub-bls12-381".into());
        #[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
        Ok(())
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    #[cfg(any(feature = "secp-secq", feature = "jubjub-bls12-381"))]
    {
        enabled::run()
    }
    #[cfg(not(any(feature = "secp-secq", feature = "jubjub-bls12-381")))]
    {
        Err("enable secp-secq and/or jubjub-bls12-381".into())
    }
}
