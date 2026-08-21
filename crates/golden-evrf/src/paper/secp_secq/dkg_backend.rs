//! Golden DKG adapter for the Secp/Secq paper eVRF.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use golden_core::{
    main_golden, DealerProofRef, DealerProofStatement, DealerProofSystem, DealerProofWitness,
    DkgConfig, DkgInstanceKind, Error, EvrfMessage, EvrfProofBackend, EvrfStatement, EvrfWitness,
    GoldenGroup, Result,
};
use golden_halo2curves::golden_group::{
    scalar_to_r1cs_field, Secp256k1Element, Secp256k1GoldenGroup, Secp256k1Scalar,
};
use halo2curves::secp256k1::{Fp, Fq};
use rand_core::CryptoRngCore;

use super::{
    affine, evrf_batched_prove, evrf_batched_verify_many, fp_to_fq, h_gin_1, h_gin_2,
    main_golden_batched_prove, main_golden_batched_verify, main_golden_batched_verify_many,
    parse_batched_proof_stream, parse_main_golden_proof_stream, validate_batched_public_relations,
    validate_main_golden_public_relations, BatchedDealingStatement, BatchedEvrfPublicParams,
    BatchedEvrfStatement, BatchedEvrfWitness, BatchedReceiverStatement, Gin,
    MainGoldenProofContext, BATCHED_PROOF_ID, MESSAGE_BYTES,
};

/// Compute the paper eVRF pad `r = beta * T_1.x + T_2.x` as an `Fp`
/// element, where `T_1 = H_{G_in,1}(msg)^k`, `T_2 = H_{G_in,2}(msg)^k`,
/// and `k = int(S.x)` for `S = PK_j^sk_1`.
fn compute_pad_fp(msg: &[u8; MESSAGE_BYTES], sk1: &Fq, pkj: &Gin, beta: &Fp) -> Result<Fp> {
    let sj = *pkj * sk1;
    let (s_x, _) = affine(&sj)?;
    let k_fq = fp_to_fq(&s_x);
    let h1 = h_gin_1(msg);
    let h2 = h_gin_2(msg);
    let t1j = h1 * k_fq;
    let t2j = h2 * k_fq;
    let (t1_x, _) = affine(&t1j)?;
    let (t2_x, _) = affine(&t2j)?;
    Ok(*beta * t1_x + t2_x)
}

/// Concrete Secp/Secq paper eVRF backend for the DKG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpSecqBackend;

fn batched_statement(
    statement: &EvrfStatement<Secp256k1GoldenGroup>,
) -> Result<BatchedEvrfStatement> {
    preflight_statement_shape(statement)?;
    let beta = scalar_to_r1cs_field(&statement.beta).ok_or(Error::ProofVerificationFailed)?;
    let dealings = statement
        .dealings
        .iter()
        .map(|dealing| {
            let h1 = h_gin_1(&dealing.message.0);
            let h2 = h_gin_2(&dealing.message.0);
            BatchedDealingStatement {
                msg: dealing.message.0,
                constant_is_explicit: dealing.commitment.constant().is_some(),
                commitment: dealing.commitment.clone(),
                receivers: dealing
                    .receivers
                    .iter()
                    .map(|receiver| BatchedReceiverStatement {
                        receiver: receiver.receiver,
                        pkj: receiver.receiver_public_key.0,
                        h1,
                        h2,
                        share_commitment: receiver.share_commitment.0,
                        pad_commitment: receiver.pad_commitment.0,
                        encrypted_share: receiver.encrypted_share.0,
                    })
                    .collect(),
            }
        })
        .collect();
    let threshold = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?
        .commitment
        .threshold();
    Ok(BatchedEvrfStatement {
        pk1: statement.dealer_public_key.0,
        beta,
        threshold,
        dealer_message_root: statement.dealer_message_root,
        dealings,
    })
}

fn preflight_statement_shape(statement: &EvrfStatement<Secp256k1GoldenGroup>) -> Result<()> {
    let first_dealing = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?;
    let threshold = first_dealing.commitment.threshold();
    let receiver_count = first_dealing.receivers.len();
    BatchedEvrfPublicParams::validated_shape(threshold, statement.dealings.len(), receiver_count)?;
    if statement.dealings.iter().any(|dealing| {
        dealing.commitment.threshold() != threshold || dealing.receivers.len() != receiver_count
    }) {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(())
}

fn same_shape(left: &BatchedEvrfStatement, right: &BatchedEvrfStatement) -> bool {
    left.threshold == right.threshold
        && left.dealings.len() == right.dealings.len()
        && left.dealings.first().map(|dealing| dealing.receivers.len())
            == right
                .dealings
                .first()
                .map(|dealing| dealing.receivers.len())
}

fn public_params(
    statement: &BatchedEvrfStatement,
) -> Result<std::sync::Arc<BatchedEvrfPublicParams>> {
    #[cfg(test)]
    PUBLIC_PARAMS_REQUESTS.with(|requests| requests.set(requests.get() + 1));

    let first_dealing = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?;
    BatchedEvrfPublicParams::shared(
        statement.threshold,
        statement.dealings.len(),
        first_dealing.receivers.len(),
    )
}

#[cfg(test)]
std::thread_local! {
    static PUBLIC_PARAMS_REQUESTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProofShape {
    threshold: usize,
    instance_count: usize,
    receiver_count: usize,
}

type ParameterResult = Result<Arc<BatchedEvrfPublicParams>>;
type ParameterCell = Arc<OnceLock<ParameterResult>>;

/// Stateful Secp/Secq Bulletproof implementation of the fixed Main Golden
/// dealer relation.
///
/// The proof system owns its reusable parameter state. Prepared-capacity
/// construction and persistence are added by the dedicated generator ticket;
/// this implementation already keeps generator state on the injected value.
#[derive(Clone, Default)]
pub struct SecpSecqBulletproofs {
    parameters: Arc<Mutex<HashMap<ProofShape, ParameterCell>>>,
}

impl core::fmt::Debug for SecpSecqBulletproofs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecpSecqBulletproofs")
            .finish_non_exhaustive()
    }
}

impl SecpSecqBulletproofs {
    /// Construct an initially empty reusable proof-system value.
    pub fn new() -> Self {
        Self::default()
    }

    fn parameters(&self, statement: &BatchedEvrfStatement) -> Result<Arc<BatchedEvrfPublicParams>> {
        let shape = proof_shape(statement)?;
        let cell = {
            let mut parameters = self
                .parameters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                parameters
                    .entry(shape)
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        };
        cell.get_or_init(|| {
            BatchedEvrfPublicParams::setup(
                shape.threshold,
                shape.instance_count,
                shape.receiver_count,
            )
            .map(Arc::new)
        })
        .clone()
    }
}

fn proof_shape(statement: &BatchedEvrfStatement) -> Result<ProofShape> {
    let receiver_count = statement
        .dealings
        .first()
        .ok_or(Error::ProofVerificationFailed)?
        .receivers
        .len();
    if statement
        .dealings
        .iter()
        .any(|dealing| dealing.receivers.len() != receiver_count)
    {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(ProofShape {
        threshold: statement.threshold,
        instance_count: statement.dealings.len(),
        receiver_count,
    })
}

fn main_golden_statement(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    statement: &DealerProofStatement<Secp256k1GoldenGroup>,
) -> Result<BatchedEvrfStatement> {
    if statement.instance_count() != config.instances().len()
        || config
            .registry()
            .public_key(statement.dealer())
            .map_err(|_| Error::ProofVerificationFailed)?
            != statement.dealer_public_key()
    {
        return Err(Error::ProofVerificationFailed);
    }

    let receiver_count = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofVerificationFailed)?;
    let mut dealings = Vec::with_capacity(statement.instance_count());
    for position in 0..statement.instance_count() {
        let instance = statement
            .instance(position)
            .ok_or(Error::ProofVerificationFailed)?;
        let kind = config
            .instance(position)
            .ok_or(Error::ProofVerificationFailed)?;
        if instance.commitment_coefficients().len() != config.threshold()
            || instance.receiver_count() != receiver_count
        {
            return Err(Error::ProofVerificationFailed);
        }
        let commitment = golden_core::FeldmanCommitment::<Secp256k1GoldenGroup>::from_coefficients(
            instance.commitment_coefficients().to_vec(),
        )
        .map_err(|_| Error::ProofVerificationFailed)?;
        let constant_is_explicit = matches!(kind, DkgInstanceKind::Random);
        if !constant_is_explicit
            && !bool::from(Secp256k1GoldenGroup::is_identity(
                instance
                    .commitment_coefficients()
                    .first()
                    .ok_or(Error::ProofVerificationFailed)?,
            ))
        {
            return Err(Error::ProofVerificationFailed);
        }

        let mut receivers = Vec::with_capacity(receiver_count);
        for (receiver_position, (participant, public_key)) in config
            .registry()
            .entries()
            .filter(|(participant, _)| *participant != statement.dealer())
            .enumerate()
        {
            let receiver = instance
                .receiver(receiver_position)
                .ok_or(Error::ProofVerificationFailed)?;
            if receiver.participant() != participant || receiver.public_key() != public_key {
                return Err(Error::ProofVerificationFailed);
            }
            let h1 = main_golden::h1::<Secp256k1GoldenGroup>(
                instance.effective_message(),
                statement.dealer_public_key(),
                receiver.public_key(),
            )
            .map_err(|_| Error::ProofVerificationFailed)?;
            let h2 = main_golden::h2::<Secp256k1GoldenGroup>(
                instance.effective_message(),
                statement.dealer_public_key(),
                receiver.public_key(),
            )
            .map_err(|_| Error::ProofVerificationFailed)?;
            receivers.push(BatchedReceiverStatement {
                receiver: receiver.participant(),
                pkj: receiver.public_key().0,
                h1: h1.0,
                h2: h2.0,
                share_commitment: receiver.share_commitment().0,
                pad_commitment: receiver.pad_commitment().0,
                encrypted_share: receiver.encrypted_share().0,
            });
        }
        if receivers.len() != receiver_count {
            return Err(Error::ProofVerificationFailed);
        }
        dealings.push(BatchedDealingStatement {
            msg: instance.effective_message().0,
            commitment,
            constant_is_explicit,
            receivers,
        });
    }

    let statement = BatchedEvrfStatement {
        pk1: statement.dealer_public_key().0,
        beta: main_golden::beta::<Secp256k1GoldenGroup>()
            .map_err(|_| Error::ProofVerificationFailed)?,
        threshold: config.threshold(),
        dealer_message_root: statement.dealer_message_root(),
        dealings,
    };
    validate_main_golden_public_relations(&statement)?;
    Ok(statement)
}

fn main_golden_witness(
    statement: &DealerProofStatement<Secp256k1GoldenGroup>,
    witness: &DealerProofWitness<Secp256k1GoldenGroup>,
) -> Result<BatchedEvrfWitness> {
    if witness.instance_count() != statement.instance_count() {
        return Err(Error::ProofVerificationFailed);
    }
    let polynomial_constants = (0..witness.instance_count())
        .map(|position| {
            witness
                .instance(position)
                .ok_or(Error::ProofVerificationFailed)
                .map(|instance| instance.polynomial_constant().map(|constant| constant.0))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BatchedEvrfWitness {
        sk1: witness.identity_secret().0,
        polynomial_constants,
    })
}

fn main_golden_context(
    config: &DkgConfig<Secp256k1GoldenGroup>,
    statement: &DealerProofStatement<Secp256k1GoldenGroup>,
) -> MainGoldenProofContext {
    MainGoldenProofContext {
        configuration_root: config.root(),
        dealer: statement.dealer(),
    }
}

fn normalize_proving_error(error: Error) -> Error {
    match error {
        Error::ProofVerificationFailed => Error::ProofGenerationFailed,
        other => other,
    }
}

impl EvrfProofBackend<Secp256k1GoldenGroup> for SecpSecqBackend {
    const PROOF_ID: &'static [u8] = BATCHED_PROOF_ID;

    fn derive_pad(
        message: EvrfMessage,
        beta: &Secp256k1Scalar,
        identity_secret: &Secp256k1Scalar,
        peer_public_key: &Secp256k1Element,
        _receiver_public_key: &Secp256k1Element,
    ) -> Result<Secp256k1Scalar> {
        let beta_fp = scalar_to_r1cs_field(beta).ok_or(Error::ProofVerificationFailed)?;
        let r = compute_pad_fp(&message.0, &identity_secret.0, &peer_public_key.0, &beta_fp)?;
        Ok(Secp256k1Scalar(fp_to_fq(&r)))
    }

    fn prove_batch(
        statement: &EvrfStatement<Secp256k1GoldenGroup>,
        witness: &EvrfWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        witness.validate_shape(statement)?;
        let statement = batched_statement(statement)?;
        validate_batched_public_relations(&statement)?;
        let witness = BatchedEvrfWitness {
            sk1: witness.identity_secret.0,
            polynomial_constants: witness
                .dealings
                .iter()
                .map(|dealing| dealing.polynomial_constant.map(|constant| constant.0))
                .collect(),
        };
        let params = public_params(&statement)?;
        evrf_batched_prove(&params, &statement, &witness, rng)
    }

    fn verify_batch(statement: &EvrfStatement<Secp256k1GoldenGroup>, proof: &[u8]) -> Result<()> {
        let statement = batched_statement(statement)?;
        validate_batched_public_relations(&statement)?;
        parse_batched_proof_stream(&statement, proof)?;
        let params = public_params(&statement)?;
        evrf_batched_verify_many(&params, &[(&statement, proof)])
    }

    fn verify_proof_batch(batches: &[(&EvrfStatement<Secp256k1GoldenGroup>, &[u8])]) -> Result<()> {
        if batches.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        let statements = batches
            .iter()
            .map(|(statement, _)| batched_statement(statement))
            .collect::<Result<Vec<_>>>()?;
        let first = statements.first().ok_or(Error::ProofVerificationFailed)?;
        for (statement, (_, proof)) in statements.iter().zip(batches) {
            if !same_shape(first, statement) {
                return Err(Error::ProofVerificationFailed);
            }
            validate_batched_public_relations(statement)?;
            parse_batched_proof_stream(statement, proof)?;
        }
        let params = public_params(first)?;
        let instances = statements
            .iter()
            .zip(batches)
            .map(|(statement, (_, proof))| (statement, *proof))
            .collect::<Vec<_>>();
        evrf_batched_verify_many(&params, &instances)
    }
}

impl DealerProofSystem<Secp256k1GoldenGroup> for SecpSecqBulletproofs {
    fn prove(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        witness: &DealerProofWitness<Secp256k1GoldenGroup>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        main_golden::check_dealer_relation(config, statement, witness)
            .map_err(normalize_proving_error)?;
        let batched_statement =
            main_golden_statement(config, statement).map_err(normalize_proving_error)?;
        let batched_witness =
            main_golden_witness(statement, witness).map_err(normalize_proving_error)?;
        let parameters = self
            .parameters(&batched_statement)
            .map_err(normalize_proving_error)?;
        main_golden_batched_prove(
            &parameters,
            main_golden_context(config, statement),
            &batched_statement,
            &batched_witness,
            rng,
        )
        .map_err(normalize_proving_error)
    }

    fn verify(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        statement: &DealerProofStatement<Secp256k1GoldenGroup>,
        proof: &[u8],
    ) -> Result<()> {
        let batched_statement = main_golden_statement(config, statement)?;
        let context = main_golden_context(config, statement);
        parse_main_golden_proof_stream(context, &batched_statement, proof)?;
        let parameters = self.parameters(&batched_statement)?;
        main_golden_batched_verify(&parameters, context, &batched_statement, proof)
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        proofs: &[DealerProofRef<'_, Secp256k1GoldenGroup>],
    ) -> Result<()> {
        if proofs.is_empty() {
            return Ok(());
        }

        let statements = proofs
            .iter()
            .map(|item| main_golden_statement(config, item.statement))
            .collect::<Result<Vec<_>>>()?;
        let first = statements.first().ok_or(Error::ProofVerificationFailed)?;
        let mut previous_dealer = None;
        for (statement, item) in statements.iter().zip(proofs) {
            let dealer = item.statement.dealer();
            if previous_dealer.is_some_and(|previous| previous >= dealer)
                || !same_shape(first, statement)
            {
                return Err(Error::ProofVerificationFailed);
            }
            previous_dealer = Some(dealer);
            validate_main_golden_public_relations(statement)?;
            parse_main_golden_proof_stream(
                main_golden_context(config, item.statement),
                statement,
                item.proof,
            )?;
        }

        let parameters = self.parameters(first)?;
        let instances = statements
            .iter()
            .zip(proofs)
            .map(|(statement, item)| {
                (
                    main_golden_context(config, item.statement),
                    statement,
                    item.proof,
                )
            })
            .collect::<Vec<_>>();
        main_golden_batched_verify_many(&parameters, config.root(), &instances)
    }
}

#[cfg(test)]
mod tests {
    use crate::proof_stream::ProofStreamCurve;
    use golden_core::{
        deal, DealerProofStatement, DealerProofSystem, DealerProofWitness, DkgConfig,
        EvrfDealingStatement, EvrfReceiverStatement, FeldmanCommitment, GoldenGroup, GoldenScalar,
        ParticipantIndex, ParticipantRegistry, SessionId,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use super::super::{GoutStreamCurve, MAIN_GOLDEN_PROOF_ID};
    use super::*;

    fn minimal_statement() -> EvrfStatement<Secp256k1GoldenGroup> {
        let receiver = ParticipantIndex::new(2).unwrap();
        let dealer_secret = Secp256k1Scalar::from_u64(3).unwrap();
        let receiver_secret = Secp256k1Scalar::from_u64(5).unwrap();
        let share = Secp256k1Scalar::from_u64(13).unwrap();
        let pad = Secp256k1Scalar::from_u64(7).unwrap();

        EvrfStatement {
            dealer_public_key: Secp256k1GoldenGroup::mul_generator(&dealer_secret),
            beta: Secp256k1Scalar::from_u64(17).unwrap(),
            dealer_message_root: [3u8; 32],
            dealings: vec![EvrfDealingStatement {
                message: EvrfMessage([9u8; MESSAGE_BYTES]),
                commitment: FeldmanCommitment::from_coefficients(vec![
                    Secp256k1GoldenGroup::mul_generator(&share),
                ])
                .unwrap(),
                receivers: vec![EvrfReceiverStatement {
                    receiver,
                    receiver_public_key: Secp256k1GoldenGroup::mul_generator(&receiver_secret),
                    share_commitment: Secp256k1GoldenGroup::mul_generator(&share),
                    pad_commitment: Secp256k1GoldenGroup::mul_generator(&pad),
                    encrypted_share: Secp256k1Scalar::add(&share, &pad),
                }],
            }],
        }
    }

    fn public_params_requests() -> usize {
        PUBLIC_PARAMS_REQUESTS.with(core::cell::Cell::get)
    }

    #[derive(Default)]
    struct CapturingSecpSecq {
        inner: SecpSecqBulletproofs,
        proofs: std::sync::Mutex<Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)>>,
    }

    impl DealerProofSystem<Secp256k1GoldenGroup> for CapturingSecpSecq {
        fn prove(
            &self,
            config: &DkgConfig<Secp256k1GoldenGroup>,
            statement: &DealerProofStatement<Secp256k1GoldenGroup>,
            witness: &DealerProofWitness<Secp256k1GoldenGroup>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            let proof = self.inner.prove(config, statement, witness, rng)?;
            self.proofs
                .lock()
                .unwrap()
                .push((statement.clone(), proof.clone()));
            Ok(proof)
        }

        fn verify(
            &self,
            config: &DkgConfig<Secp256k1GoldenGroup>,
            statement: &DealerProofStatement<Secp256k1GoldenGroup>,
            proof: &[u8],
        ) -> Result<()> {
            self.inner.verify(config, statement, proof)
        }
    }

    fn tamper_nested_r1cs_scalar(mut proof: Vec<u8>) -> Vec<u8> {
        const PROOF_ID_LEN_BYTES: usize = 4;
        const NESTED_LEN_BYTES: usize = 8;

        let encoded_id_len = u32::from_be_bytes(
            proof[..PROOF_ID_LEN_BYTES]
                .try_into()
                .expect("proof ID length prefix"),
        ) as usize;
        assert_eq!(encoded_id_len, MAIN_GOLDEN_PROOF_ID.len());
        assert_eq!(
            &proof[PROOF_ID_LEN_BYTES..PROOF_ID_LEN_BYTES + encoded_id_len],
            MAIN_GOLDEN_PROOF_ID
        );
        let nested_len_start = PROOF_ID_LEN_BYTES + encoded_id_len;
        let payload_start = nested_len_start + NESTED_LEN_BYTES;
        let payload_len = u64::from_be_bytes(
            proof[nested_len_start..payload_start]
                .try_into()
                .expect("nested R1CS length prefix"),
        ) as usize;
        assert!(payload_start + payload_len <= proof.len());

        let version = proof[payload_start];
        assert!(
            matches!(version, 0 | 1),
            "unexpected R1CS proof version {version}"
        );
        let phase_commitments = if version == 0 { 3 } else { 6 };
        let t_x_start = payload_start + 1 + (phase_commitments + 5) * GoutStreamCurve::POINT_BYTES;
        let t_x = &mut proof[t_x_start..t_x_start + 32];
        if t_x.iter().all(|byte| *byte == 0) {
            t_x[0] = 1;
        } else {
            t_x.fill(0);
        }
        proof
    }

    #[test]
    #[ignore = "slow: builds two full Main Golden dealer proofs for optimized batch verification"]
    fn main_golden_proof_system_exercises_single_and_optimized_batch_paths() {
        let first_dealer = ParticipantIndex::new(1).unwrap();
        let second_dealer = ParticipantIndex::new(2).unwrap();
        let receiver = ParticipantIndex::new(3).unwrap();
        let first_secret = Secp256k1Scalar::from_u64(3).unwrap();
        let second_secret = Secp256k1Scalar::from_u64(5).unwrap();
        let receiver_secret = Secp256k1Scalar::from_u64(7).unwrap();
        let registry = ParticipantRegistry::new(vec![
            (
                first_dealer,
                Secp256k1GoldenGroup::mul_generator(&first_secret),
            ),
            (
                second_dealer,
                Secp256k1GoldenGroup::mul_generator(&second_secret),
            ),
            (
                receiver,
                Secp256k1GoldenGroup::mul_generator(&receiver_secret),
            ),
        ])
        .unwrap();
        let config = DkgConfig::new_zero(1, SessionId([41u8; 32]), registry.clone()).unwrap();
        let proof_system = CapturingSecpSecq::default();
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        deal(
            &proof_system,
            &config,
            first_dealer,
            &first_secret,
            &mut rng,
        )
        .unwrap();
        deal(
            &proof_system,
            &config,
            second_dealer,
            &second_secret,
            &mut rng,
        )
        .unwrap();
        let captured = proof_system.proofs.lock().unwrap().clone();
        assert_eq!(captured.len(), 2);

        proof_system
            .inner
            .verify(&config, &captured[0].0, &captured[0].1)
            .unwrap();

        let other_config = DkgConfig::new_zero(1, SessionId([43u8; 32]), registry).unwrap();
        assert_eq!(
            proof_system
                .inner
                .verify(&other_config, &captured[0].0, &captured[0].1)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );

        let honest_batch = [
            DealerProofRef {
                statement: &captured[0].0,
                proof: &captured[0].1,
            },
            DealerProofRef {
                statement: &captured[1].0,
                proof: &captured[1].1,
            },
        ];
        proof_system
            .inner
            .verify_batch(&config, &honest_batch)
            .unwrap();

        let reordered = [honest_batch[1].clone(), honest_batch[0].clone()];
        assert_eq!(
            proof_system
                .inner
                .verify_batch(&config, &reordered)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );

        let mismatched = [
            DealerProofRef {
                statement: &captured[0].0,
                proof: &captured[1].1,
            },
            DealerProofRef {
                statement: &captured[1].0,
                proof: &captured[0].1,
            },
        ];
        assert_eq!(
            proof_system
                .inner
                .verify_batch(&config, &mismatched)
                .unwrap_err(),
            Error::BatchVerificationFailed
        );

        let tampered_proof = tamper_nested_r1cs_scalar(captured[0].1.clone());
        let tampered_batch = [
            DealerProofRef {
                statement: &captured[0].0,
                proof: &tampered_proof,
            },
            honest_batch[1].clone(),
        ];
        assert_eq!(
            proof_system
                .inner
                .verify_batch(&config, &tampered_batch)
                .unwrap_err(),
            Error::BatchVerificationFailed
        );
        assert_eq!(
            proof_system
                .inner
                .verify(&config, &captured[0].0, &tampered_proof)
                .unwrap_err(),
            Error::ProofVerificationFailed
        );
    }

    #[test]
    fn malformed_proof_is_rejected_before_public_parameter_lookup() {
        let statement = minimal_statement();
        let before = public_params_requests();

        assert_eq!(
            SecpSecqBackend::verify_batch(&statement, &[]).unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(public_params_requests(), before);
    }

    #[test]
    fn oversized_repeated_receiver_shape_is_rejected_before_conversion_or_params() {
        let mut statement = minimal_statement();
        let receiver = statement.dealings[0].receivers[0].clone();
        statement.dealings[0].receivers = vec![receiver; 295];
        let before = public_params_requests();

        assert_eq!(
            SecpSecqBackend::verify_batch(&statement, &[]).unwrap_err(),
            Error::ProofVerificationFailed
        );
        assert_eq!(public_params_requests(), before);
    }
}
