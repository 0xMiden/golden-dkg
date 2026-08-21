//! Golden DKG adapter for the Secp/Secq paper eVRF.

use std::sync::Arc;

use bulletproofs_cycle::generators::BulletproofGens;
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
    MainGoldenProofContext, R1csCycle, BATCHED_PROOF_ID, MESSAGE_BYTES,
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

/// Persistence format version for prepared Secp/Secq generator artifacts.
#[cfg(feature = "serde")]
const PREPARED_GENERATORS_VERSION: u32 = 1;
/// Curve-cycle identity carried by prepared generator artifacts.
#[cfg(feature = "serde")]
const PREPARED_GENERATORS_CURVE: [u8; 19] = *b"secp256k1/secq256k1";
/// Bulletproof generator tables for this circuit support one aggregated party.
#[cfg(feature = "serde")]
const PREPARED_GENERATORS_PARTY_CAPACITY: u32 = 1;
const PREPARED_GENERATORS_PARTY_CAPACITY_USIZE: usize = 1;

/// Explicit deterministic generator prefix prepared for Secp/Secq dealer proofs.
///
/// Persistence is intended for authenticated application storage. Restoration
/// validates the artifact's metadata, point encodings, and exact dimensions,
/// but deliberately does not rederive the deterministic prefix.
#[derive(Clone)]
pub struct SecpSecqPreparedGenerators {
    capacity: usize,
    bp_gens: Arc<BulletproofGens<R1csCycle>>,
}

impl core::fmt::Debug for SecpSecqPreparedGenerators {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecpSecqPreparedGenerators")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SecpSecqPreparedGenerators {
    /// Prepare the smallest supported generator prefix for `config`.
    pub fn prepare_for(config: &DkgConfig<Secp256k1GoldenGroup>) -> Result<Self> {
        let shape = proof_shape(config)?;
        Ok(Self {
            capacity: shape.generator_capacity,
            bp_gens: Arc::new(BulletproofGens::new(
                shape.generator_capacity,
                PREPARED_GENERATORS_PARTY_CAPACITY_USIZE,
            )),
        })
    }

    /// Return the declared padded Bulletproof generator capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Serialize this prepared artifact for authenticated application storage.
    #[cfg(feature = "serde")]
    pub fn to_persistence_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::MalformedPreparedGenerators)
    }

    /// Restore one complete artifact from authenticated storage, rejecting trailing bytes.
    #[cfg(feature = "serde")]
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self> {
        let (prepared, trailing) =
            postcard::take_from_bytes(bytes).map_err(|_| Error::MalformedPreparedGenerators)?;
        if !trailing.is_empty() {
            return Err(Error::MalformedPreparedGenerators);
        }
        Ok(prepared)
    }
}

#[cfg(feature = "serde")]
#[derive(Clone, Copy)]
enum PreparedGeneratorPrefix {
    G,
    H,
}

#[cfg(feature = "serde")]
struct PreparedGeneratorPrefixRef<'a> {
    generators: &'a BulletproofGens<R1csCycle>,
    capacity: usize,
    prefix: PreparedGeneratorPrefix,
}

#[cfg(feature = "serde")]
impl serde::Serialize for PreparedGeneratorPrefixRef<'_> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{Error as _, SerializeSeq as _};

        let share = self.generators.share(0);
        let mut sequence = serializer.serialize_seq(Some(self.capacity))?;
        let mut written = 0usize;
        match self.prefix {
            PreparedGeneratorPrefix::G => {
                for point in share.G(self.capacity) {
                    sequence.serialize_element(point)?;
                    written += 1;
                }
            }
            PreparedGeneratorPrefix::H => {
                for point in share.H(self.capacity) {
                    sequence.serialize_element(point)?;
                    written += 1;
                }
            }
        }
        if written != self.capacity {
            return Err(S::Error::custom(
                "prepared generator prefix is shorter than its declared capacity",
            ));
        }
        sequence.end()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecpSecqPreparedGenerators {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{Error as _, SerializeTuple as _};

        if !supported_prepared_capacity(self.capacity)
            || self.bp_gens.gens_capacity != self.capacity
            || self.bp_gens.party_capacity != PREPARED_GENERATORS_PARTY_CAPACITY_USIZE
        {
            return Err(S::Error::custom(
                "prepared generator dimensions do not match their metadata",
            ));
        }

        let capacity = u64::try_from(self.capacity)
            .map_err(|_| S::Error::custom("prepared generator capacity does not fit u64"))?;
        let mut tuple = serializer.serialize_tuple(6)?;
        tuple.serialize_element(&PREPARED_GENERATORS_VERSION)?;
        tuple.serialize_element(&PREPARED_GENERATORS_CURVE)?;
        tuple.serialize_element(&PREPARED_GENERATORS_PARTY_CAPACITY)?;
        tuple.serialize_element(&capacity)?;
        tuple.serialize_element(&PreparedGeneratorPrefixRef {
            generators: self.bp_gens.as_ref(),
            capacity: self.capacity,
            prefix: PreparedGeneratorPrefix::G,
        })?;
        tuple.serialize_element(&PreparedGeneratorPrefixRef {
            generators: self.bp_gens.as_ref(),
            capacity: self.capacity,
            prefix: PreparedGeneratorPrefix::H,
        })?;
        tuple.end()
    }
}

#[cfg(feature = "serde")]
type PreparedGeneratorAffine = <R1csCycle as bulletproofs_cycle::Cycle>::Affine;

#[cfg(feature = "serde")]
struct PreparedGeneratorPrefixSeed {
    expected: usize,
}

#[cfg(feature = "serde")]
impl<'de> serde::de::DeserializeSeed<'de> for PreparedGeneratorPrefixSeed {
    type Value = Vec<PreparedGeneratorAffine>;

    fn deserialize<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(PreparedGeneratorPrefixVisitor {
            expected: self.expected,
        })
    }
}

#[cfg(feature = "serde")]
struct PreparedGeneratorPrefixVisitor {
    expected: usize,
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for PreparedGeneratorPrefixVisitor {
    type Value = Vec<PreparedGeneratorAffine>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "exactly {} canonical non-identity generator points",
            self.expected
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error as _;

        if let Some(actual) = sequence.size_hint() {
            if actual != self.expected {
                return Err(A::Error::invalid_length(actual, &self));
            }
        }

        let mut points = Vec::new();
        points
            .try_reserve_exact(self.expected)
            .map_err(|_| A::Error::custom("prepared generator allocation failed"))?;
        for index in 0..self.expected {
            let point: PreparedGeneratorAffine = sequence
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(index, &self))?;
            if <R1csCycle as bulletproofs_cycle::Cycle>::compressed_is_identity(
                &<R1csCycle as bulletproofs_cycle::Cycle>::affine_compress(&point),
            ) {
                return Err(A::Error::custom(
                    "prepared generator must not be the identity",
                ));
            }
            points.push(point);
        }
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(A::Error::invalid_length(self.expected + 1, &self));
        }
        Ok(points)
    }
}

#[cfg(feature = "serde")]
struct PreparedGeneratorsVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for PreparedGeneratorsVisitor {
    type Value = SecpSecqPreparedGenerators;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded six-field Secp/Secq prepared generator artifact")
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error as _;

        let version: u32 = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("missing prepared generator version"))?;
        if version != PREPARED_GENERATORS_VERSION {
            return Err(A::Error::custom("unsupported prepared generator version"));
        }

        let curve: [u8; 19] = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("missing prepared generator curve"))?;
        if curve != PREPARED_GENERATORS_CURVE {
            return Err(A::Error::custom("wrong prepared generator curve"));
        }

        let party_capacity: u32 = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("missing prepared generator party capacity"))?;
        if party_capacity != PREPARED_GENERATORS_PARTY_CAPACITY {
            return Err(A::Error::custom("wrong prepared generator party capacity"));
        }

        let encoded_capacity: u64 = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("missing prepared generator capacity"))?;
        let capacity = usize::try_from(encoded_capacity)
            .map_err(|_| A::Error::custom("prepared generator capacity does not fit usize"))?;
        if !supported_prepared_capacity(capacity) {
            return Err(A::Error::custom("unsupported prepared generator capacity"));
        }

        let g_prefix = sequence
            .next_element_seed(PreparedGeneratorPrefixSeed { expected: capacity })?
            .ok_or_else(|| A::Error::custom("missing prepared G generator prefix"))?;
        let h_prefix = sequence
            .next_element_seed(PreparedGeneratorPrefixSeed { expected: capacity })?
            .ok_or_else(|| A::Error::custom("missing prepared H generator prefix"))?;
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "unexpected field after prepared generator prefixes",
            ));
        }

        let generators = BulletproofGens::from_single_party_exact(g_prefix, h_prefix)
            .ok_or_else(|| A::Error::custom("invalid exact prepared generator prefixes"))?;

        Ok(SecpSecqPreparedGenerators {
            capacity,
            bp_gens: Arc::new(generators),
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecpSecqPreparedGenerators {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_tuple(6, PreparedGeneratorsVisitor)
    }
}

#[cfg(feature = "serde")]
fn supported_prepared_capacity(capacity: usize) -> bool {
    (capacity == 0 || capacity.is_power_of_two())
        && capacity <= super::MAX_BATCHED_GENERATOR_CAPACITY
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProofShape {
    threshold: usize,
    instance_count: usize,
    receiver_count: usize,
    multiplier_count: usize,
    generator_capacity: usize,
}

/// Stateful Secp/Secq Bulletproof implementation of the fixed Main Golden
/// dealer relation.
///
/// The proof system owns one immutable prepared prefix and can serve any
/// compatible configuration whose exact requirement does not exceed it.
#[derive(Clone)]
pub struct SecpSecqBulletproofs {
    prepared: SecpSecqPreparedGenerators,
}

impl core::fmt::Debug for SecpSecqBulletproofs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecpSecqBulletproofs")
            .field("capacity", &self.prepared.capacity())
            .finish_non_exhaustive()
    }
}

impl SecpSecqBulletproofs {
    /// Prepare a reusable proof-system value for `config`.
    pub fn prepare_for(config: &DkgConfig<Secp256k1GoldenGroup>) -> Result<Self> {
        Ok(Self::from_prepared(
            SecpSecqPreparedGenerators::prepare_for(config)?,
        ))
    }

    /// Consume a restored prepared generator artifact.
    pub fn from_prepared(prepared: SecpSecqPreparedGenerators) -> Self {
        Self { prepared }
    }

    fn ensure_capacity(&self, config: &DkgConfig<Secp256k1GoldenGroup>) -> Result<ProofShape> {
        let shape = proof_shape(config)?;
        if shape.generator_capacity > self.prepared.capacity {
            return Err(Error::InsufficientProofCapacity {
                required: shape.generator_capacity,
                available: self.prepared.capacity,
            });
        }
        Ok(shape)
    }

    fn parameters(&self, shape: ProofShape) -> Arc<BatchedEvrfPublicParams> {
        Arc::new(BatchedEvrfPublicParams::from_shape(
            shape.threshold,
            shape.instance_count,
            shape.receiver_count,
            shape.multiplier_count,
            Arc::clone(&self.prepared.bp_gens),
        ))
    }
}

fn prepared_shape(
    threshold: usize,
    instance_count: usize,
    receiver_count: usize,
) -> Result<ProofShape> {
    if receiver_count == 0 {
        if threshold != 1 || instance_count == 0 {
            return Err(Error::ProofGenerationFailed);
        }
        return Ok(ProofShape {
            threshold,
            instance_count,
            receiver_count,
            multiplier_count: 0,
            generator_capacity: 0,
        });
    }

    let (multiplier_count, generator_capacity) =
        BatchedEvrfPublicParams::validated_shape(threshold, instance_count, receiver_count)
            .map_err(|_| Error::ProofGenerationFailed)?;
    Ok(ProofShape {
        threshold,
        instance_count,
        receiver_count,
        multiplier_count,
        generator_capacity,
    })
}

fn proof_shape(config: &DkgConfig<Secp256k1GoldenGroup>) -> Result<ProofShape> {
    let receiver_count = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofGenerationFailed)?;
    prepared_shape(config.threshold(), config.instances().len(), receiver_count)
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
        let shape = self.ensure_capacity(config)?;
        main_golden::check_dealer_relation(config, statement, witness)
            .map_err(normalize_proving_error)?;
        let batched_statement =
            main_golden_statement(config, statement).map_err(normalize_proving_error)?;
        let batched_witness =
            main_golden_witness(statement, witness).map_err(normalize_proving_error)?;
        let parameters = self.parameters(shape);
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
        let shape = self.ensure_capacity(config)?;
        let batched_statement = main_golden_statement(config, statement)?;
        let context = main_golden_context(config, statement);
        parse_main_golden_proof_stream(context, &batched_statement, proof)?;
        let parameters = self.parameters(shape);
        main_golden_batched_verify(&parameters, context, &batched_statement, proof)
    }

    fn verify_batch(
        &self,
        config: &DkgConfig<Secp256k1GoldenGroup>,
        proofs: &[DealerProofRef<'_, Secp256k1GoldenGroup>],
    ) -> Result<()> {
        let shape = self.ensure_capacity(config)?;
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

        let parameters = self.parameters(shape);
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

    struct CapturingSecpSecq {
        inner: SecpSecqBulletproofs,
        proofs: std::sync::Mutex<Vec<(DealerProofStatement<Secp256k1GoldenGroup>, Vec<u8>)>>,
    }

    impl CapturingSecpSecq {
        fn from_prepared(prepared: SecpSecqPreparedGenerators) -> Self {
            Self {
                inner: SecpSecqBulletproofs::from_prepared(prepared),
                proofs: std::sync::Mutex::new(Vec::new()),
            }
        }
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

    type CapturedInputs = (
        DealerProofStatement<Secp256k1GoldenGroup>,
        DealerProofWitness<Secp256k1GoldenGroup>,
    );

    #[derive(Default)]
    struct CapturingInputs {
        inputs: std::sync::Mutex<Option<CapturedInputs>>,
    }

    impl DealerProofSystem<Secp256k1GoldenGroup> for CapturingInputs {
        fn prove(
            &self,
            _config: &DkgConfig<Secp256k1GoldenGroup>,
            statement: &DealerProofStatement<Secp256k1GoldenGroup>,
            witness: &DealerProofWitness<Secp256k1GoldenGroup>,
            _rng: &mut impl CryptoRngCore,
        ) -> Result<Vec<u8>> {
            *self.inputs.lock().unwrap() = Some((statement.clone(), witness.clone()));
            Ok(Vec::new())
        }

        fn verify(
            &self,
            _config: &DkgConfig<Secp256k1GoldenGroup>,
            _statement: &DealerProofStatement<Secp256k1GoldenGroup>,
            _proof: &[u8],
        ) -> Result<()> {
            Err(Error::ProofVerificationFailed)
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
        let preparation_config = DkgConfig::new(
            1,
            SessionId([40u8; 32]),
            registry.clone(),
            vec![DkgInstanceKind::Zero; 3],
        )
        .unwrap();
        let prepared = SecpSecqPreparedGenerators::prepare_for(&preparation_config).unwrap();
        assert!(prepared.capacity() > proof_shape(&config).unwrap().generator_capacity);
        let proof_system = CapturingSecpSecq::from_prepared(prepared);
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

    fn config_with_shape(
        participant_count: u32,
        instance_count: usize,
    ) -> DkgConfig<Secp256k1GoldenGroup> {
        let entries = (1..=participant_count)
            .map(|index| {
                let participant = ParticipantIndex::new(index).unwrap();
                let secret = Secp256k1Scalar::from_u64(u64::from(index) + 10).unwrap();
                (participant, Secp256k1GoldenGroup::mul_generator(&secret))
            })
            .collect();
        let registry = ParticipantRegistry::new(entries).unwrap();
        DkgConfig::new(
            1,
            SessionId([u8::try_from(participant_count).unwrap(); 32]),
            registry,
            vec![DkgInstanceKind::Zero; instance_count],
        )
        .unwrap()
    }

    #[test]
    fn prepared_capacity_is_minimal_and_reusable_by_smaller_shapes() {
        let single_participant = config_with_shape(1, 1);
        let two_participants = config_with_shape(2, 1);
        let three_participants = config_with_shape(3, 1);
        let larger_shape = config_with_shape(4, 2);

        assert_eq!(
            SecpSecqPreparedGenerators::prepare_for(&single_participant)
                .unwrap()
                .capacity(),
            0
        );
        assert_eq!(
            SecpSecqPreparedGenerators::prepare_for(&two_participants)
                .unwrap()
                .capacity(),
            8_192
        );
        let prepared = SecpSecqPreparedGenerators::prepare_for(&three_participants).unwrap();
        assert_eq!(prepared.capacity(), 16_384);
        assert_eq!(
            proof_shape(&larger_shape).unwrap().generator_capacity,
            32_768
        );
        assert!(prepared_shape(1, usize::MAX, 2).is_err());

        let proof_system = SecpSecqBulletproofs::from_prepared(prepared);
        assert!(proof_system.ensure_capacity(&three_participants).is_ok());
        assert!(proof_system.ensure_capacity(&two_participants).is_ok());
        assert!(proof_system.ensure_capacity(&single_participant).is_ok());
    }

    #[test]
    fn under_capacity_precedes_even_the_empty_batch_fast_path_and_never_grows() {
        let smaller_config = config_with_shape(2, 1);
        let larger_config = config_with_shape(3, 1);
        let prepared = SecpSecqPreparedGenerators::prepare_for(&smaller_config).unwrap();
        let proof_system = SecpSecqBulletproofs::from_prepared(prepared.clone());

        let capture = CapturingInputs::default();
        let dealer = ParticipantIndex::new(1).unwrap();
        let dealer_secret = Secp256k1Scalar::from_u64(11).unwrap();
        let mut rng = ChaCha20Rng::from_seed([91u8; 32]);
        deal(&capture, &smaller_config, dealer, &dealer_secret, &mut rng).unwrap();
        let (statement, witness) = capture.inputs.lock().unwrap().take().unwrap();

        assert_eq!(
            proof_system
                .prove(&larger_config, &statement, &witness, &mut rng)
                .unwrap_err(),
            Error::InsufficientProofCapacity {
                required: 16_384,
                available: 8_192,
            }
        );
        assert_eq!(
            proof_system
                .verify(&larger_config, &statement, &[])
                .unwrap_err(),
            Error::InsufficientProofCapacity {
                required: 16_384,
                available: 8_192,
            }
        );

        assert_eq!(
            proof_system.verify_batch(&larger_config, &[]).unwrap_err(),
            Error::InsufficientProofCapacity {
                required: 16_384,
                available: 8_192,
            }
        );
        assert_eq!(prepared.capacity(), 8_192);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn prepared_generator_persistence_validates_metadata_dimensions_and_points() {
        use group::Group as _;

        type Affine = <R1csCycle as bulletproofs_cycle::Cycle>::Affine;

        fn encode_artifact<G, H>(
            version: u32,
            curve: [u8; 19],
            party_capacity: u32,
            capacity: u64,
            g_prefix: &G,
            h_prefix: &H,
        ) -> Vec<u8>
        where
            G: serde::Serialize + ?Sized,
            H: serde::Serialize + ?Sized,
        {
            postcard::to_allocvec(&(version, curve, party_capacity, capacity, g_prefix, h_prefix))
                .expect("encode prepared generator test artifact")
        }

        let larger_cached_prefix = BulletproofGens::<R1csCycle>::new(16, 1);
        let prepared = SecpSecqPreparedGenerators {
            capacity: 8,
            bp_gens: Arc::new(BulletproofGens::new(8, 1)),
        };
        let expected_g = larger_cached_prefix
            .share(0)
            .G(8)
            .copied()
            .collect::<Vec<_>>();
        let expected_h = larger_cached_prefix
            .share(0)
            .H(8)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            prepared.bp_gens.share(0).G(8).copied().collect::<Vec<_>>(),
            expected_g
        );
        assert_eq!(
            prepared.bp_gens.share(0).H(8).copied().collect::<Vec<_>>(),
            expected_h
        );

        let encoded = prepared
            .to_persistence_bytes()
            .expect("serialize prepared generators");
        let decoded = SecpSecqPreparedGenerators::from_persistence_bytes(&encoded)
            .expect("restore prepared generators");
        assert_eq!(decoded.capacity(), 8);
        assert_eq!(
            decoded.bp_gens.share(0).G(8).copied().collect::<Vec<_>>(),
            expected_g
        );
        assert_eq!(
            decoded.bp_gens.share(0).H(8).copied().collect::<Vec<_>>(),
            expected_h
        );
        assert_eq!(
            decoded
                .to_persistence_bytes()
                .expect("reserialize prepared generators"),
            encoded
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&encoded[..encoded.len() - 1])
                .unwrap_err(),
            Error::MalformedPreparedGenerators
        );
        let mut encoded_with_trailing_byte = encoded.clone();
        encoded_with_trailing_byte.push(0);
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&encoded_with_trailing_byte)
                .unwrap_err(),
            Error::MalformedPreparedGenerators
        );

        let zero = SecpSecqPreparedGenerators::prepare_for(&config_with_shape(1, 1)).unwrap();
        let encoded_zero = zero
            .to_persistence_bytes()
            .expect("serialize zero capacity");
        let decoded_zero = SecpSecqPreparedGenerators::from_persistence_bytes(&encoded_zero)
            .expect("restore zero capacity");
        assert_eq!(decoded_zero.capacity(), 0);
        assert!(SecpSecqBulletproofs::from_prepared(decoded_zero)
            .ensure_capacity(&config_with_shape(1, 1))
            .is_ok());

        let g_points = prepared.bp_gens.share(0).G(8).copied().collect::<Vec<_>>();
        let h_points = prepared.bp_gens.share(0).H(8).copied().collect::<Vec<_>>();
        let mut wrong_curve = PREPARED_GENERATORS_CURVE;
        wrong_curve[0] ^= 1;
        let invalid_metadata = [
            encode_artifact(
                PREPARED_GENERATORS_VERSION + 1,
                PREPARED_GENERATORS_CURVE,
                PREPARED_GENERATORS_PARTY_CAPACITY,
                8,
                &g_points,
                &h_points,
            ),
            encode_artifact(
                PREPARED_GENERATORS_VERSION,
                wrong_curve,
                PREPARED_GENERATORS_PARTY_CAPACITY,
                8,
                &g_points,
                &h_points,
            ),
            encode_artifact(
                PREPARED_GENERATORS_VERSION,
                PREPARED_GENERATORS_CURVE,
                PREPARED_GENERATORS_PARTY_CAPACITY + 1,
                8,
                &g_points,
                &h_points,
            ),
            encode_artifact(
                PREPARED_GENERATORS_VERSION,
                PREPARED_GENERATORS_CURVE,
                PREPARED_GENERATORS_PARTY_CAPACITY,
                4,
                &g_points,
                &h_points,
            ),
        ];
        for invalid in invalid_metadata {
            assert_eq!(
                SecpSecqPreparedGenerators::from_persistence_bytes(&invalid).unwrap_err(),
                Error::MalformedPreparedGenerators
            );
        }

        let no_points = Vec::<Affine>::new();
        let oversized_capacity = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            u64::try_from(super::super::MAX_BATCHED_GENERATOR_CAPACITY).unwrap() + 1,
            &no_points,
            &no_points,
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&oversized_capacity).unwrap_err(),
            Error::MalformedPreparedGenerators
        );

        let non_padded_capacity = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            3,
            &g_points[..3],
            &h_points[..3],
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&non_padded_capacity).unwrap_err(),
            Error::MalformedPreparedGenerators
        );

        let wrong_point_count = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            8,
            &g_points[..7],
            &h_points,
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&wrong_point_count).unwrap_err(),
            Error::MalformedPreparedGenerators
        );
        let extra_point_count = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            4,
            &g_points[..5],
            &h_points[..4],
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&extra_point_count).unwrap_err(),
            Error::MalformedPreparedGenerators
        );

        let identity = <R1csCycle as bulletproofs_cycle::Cycle>::point_to_affine(
            &<R1csCycle as bulletproofs_cycle::Cycle>::Point::identity(),
        );
        let identity_prefix = vec![identity];
        let identity_point = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            1,
            &identity_prefix,
            &identity_prefix,
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&identity_point).unwrap_err(),
            Error::MalformedPreparedGenerators
        );

        let noncanonical = halo2curves::serde::Repr::<33>::from([0xff; 33]);
        let noncanonical_prefix = vec![noncanonical];
        let noncanonical_point = encode_artifact(
            PREPARED_GENERATORS_VERSION,
            PREPARED_GENERATORS_CURVE,
            PREPARED_GENERATORS_PARTY_CAPACITY,
            1,
            &noncanonical_prefix,
            &noncanonical_prefix,
        );
        assert_eq!(
            SecpSecqPreparedGenerators::from_persistence_bytes(&noncanonical_point).unwrap_err(),
            Error::MalformedPreparedGenerators
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
