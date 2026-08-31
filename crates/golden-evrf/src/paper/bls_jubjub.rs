//! BLS12-381/Jubjub paper eVRF backend.
//!
//! `Gout` is BLS12-381 G1 (the Bulletproofs commitment group); the R1CS
//! field is BLS12-381's scalar field. `Gin` is Jubjub, a twisted Edwards
//! curve defined exactly over that same field (`jubjub::Fq` is a re-export
//! of `bls12_381::Scalar`), satisfying the paper's requirement that `Gin`'s
//! base field equal `Gout`'s scalar field, without needing a foreign-field
//! conversion between them.
//!
//! This mirrors `super::secp_secq`'s relation and proof structure (see
//! that module's doc for the paper-step breakdown), with one deliberate
//! gadget-level difference: Secp256k1 is short Weierstrass, so `secp_secq`
//! uses the paper's "chord rule" exponentiation gadget (Section 4.3), built
//! specifically to dodge Weierstrass's exceptional doubling case via a
//! precomputed correction generator. Jubjub is twisted Edwards, whose
//! addition law is *unified* (the same formula handles doubling and general
//! addition, with no exceptional case to dodge), so this module uses a
//! plain additive ladder over that unified law instead of the chord rule's
//! correction-generator machinery — see `edwards_add_r1cs`. The ladder is
//! windowed the same way `secp_secq`'s chord rule is (2 bits per step,
//! `secp_secq`'s exact trick, reused here — see
//! `edwards_exponentiate_windowed_r1cs`), so both backends share the same
//! per-bit-halving optimization; what differs is only the underlying
//! addition formula each curve needs.
//!
//! (`super::secp_secq` and this module are each gated behind their own
//! optional feature — `halo2curves-secp256k1` and `bls12-381-jubjub`
//! respectively — so the cross-references above are plain code spans, not
//! intra-doc links: `secp_secq` is not always in scope when this module is
//! compiled.)
//!
//! The prover is not constant-time: witness generation branches on secret
//! exponent bits (e.g. `edwards_windowed_ladder_witness`), and the
//! Bulletproofs prover itself runs variable-time MSMs over witness vectors
//! that embed those bits. Same as `secp_secq`.

use super::{CryptoRngCore, Error, ParticipantIndex, Result, TranscriptRoot};

use crate::proof_stream::{
    decode_point, CycleCurve, IdentityPolicy, Observe, ProofStreamCurve, ProverProofStream,
    VerifierProofStream,
};
use bls12_381::{G1Projective, Scalar};
use bulletproofs_cycle::{
    cycle::random_scalar,
    generators::{BulletproofGens, PedersenGens},
    r1cs::{Prover, Verifier},
    ConstraintSystem, Cycle, LinearCombination, R1CSError, R1CSProof, Variable,
    VerificationEquation,
};
use ff::{Field, PrimeField};
use golden_bls_jubjub::{Bls12_381G1Cycle, JubjubCycle};
use group::Group;
use jubjub::{ExtendedPoint, Fr, SubgroupPoint};
use merlin::Transcript;
use p3_maybe_rayon::prelude::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::Digest;

/// R1CS field: BLS12-381's scalar field (also Jubjub's base field `Fq`).
pub type R1csField = Scalar;
/// R1CS commitment group: BLS12-381 G1 (`G_out`).
pub type R1csCycle = Bls12_381G1Cycle;
/// `G_in` group: Jubjub's prime-order subgroup.
pub type Gin = SubgroupPoint;
/// `G_in` scalar field: Jubjub's own scalar field `Fr`.
pub type GinScalar = Fr;
/// `G_out` commitment group: BLS12-381 G1. Exposed so integration tests can
/// construct random `R_j` points without re-deriving the cycle alias.
pub type Gout = G1Projective;
/// `G_out` compressed point.
pub type GoutCompressed = <R1csCycle as Cycle>::Compressed;

/// Public statement for the one-receiver paper eVRF relation.
#[derive(Clone, Debug)]
pub struct BlsJubjubEvrfStatement {
    /// Paper dealer message `msg_i`.
    pub msg: [u8; MESSAGE_BYTES],
    /// Dealer identity public key `PK_1 = g_in^sk_1` in `G_in`.
    pub pk1: Gin,
    /// Receiver identity public key `PK_2` in `G_in`.
    pub pk2: Gin,
    /// DH shared point `S = PK_2^sk_1` in `G_in`. Public in this backend
    /// because the Chaum-Pedersen proof of steps 0 and 1 reveals `S`.
    pub s: Gin,
    /// Random oracle `H_{G_in,1}(msg)` in `G_in`.
    pub h1: Gin,
    /// Random oracle `H_{G_in,2}(msg)` in `G_in`.
    pub h2: Gin,
    /// `T_1 = H_{G_in,1}(msg)^k` in `G_in`, public, proven in R1CS.
    pub t1: Gin,
    /// `T_2 = H_{G_in,2}(msg)^k` in `G_in`, public, proven in R1CS.
    pub t2: Gin,
    /// eVRF output commitment `R = g_out^r` in `G_out`.
    pub r_point: Gout,
    /// Public coefficient `beta` in `Fp`.
    pub beta: R1csField,
}

/// Witness for the one-receiver paper eVRF relation.
#[derive(Clone)]
pub struct BlsJubjubEvrfWitness {
    /// Dealer identity secret `sk_1` in `Fr`.
    pub sk1: GinScalar,
}

impl core::fmt::Debug for BlsJubjubEvrfWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlsJubjubEvrfWitness")
            .field("sk1", &"<redacted>")
            .finish()
    }
}

/// Byte length of the paper `msg_i` nonce (256-bit security parameter).
pub const MESSAGE_BYTES: usize = 256 / 8;

/// Versioned proof-stream grammar for the standalone one-receiver relation.
const ONE_RECEIVER_PROOF_ID: &[u8] = b"golden-paper-evrf-bls-jubjub-one-receiver-v1";
/// Proof protocol identifier for the batched dealer relation.
const BATCHED_PROOF_ID: &[u8] = b"golden-paper-evrf-bls-jubjub-batched-v1";

type GinStreamCurve = CycleCurve<JubjubCycle>;
type GoutStreamCurve = CycleCurve<R1csCycle>;

/// Observe the complete standalone public statement in one canonical order.
fn observe_one_receiver_statement(
    stream: &mut impl Observe,
    statement: &BlsJubjubEvrfStatement,
) -> Result<()> {
    stream.observe_bytes(b"statement.msg", &statement.msg);
    stream.observe_point::<GinStreamCurve>(
        b"statement.pk1",
        &statement.pk1,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GinStreamCurve>(
        b"statement.pk2",
        &statement.pk2,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GinStreamCurve>(b"statement.s", &statement.s, IdentityPolicy::Reject)?;
    stream.observe_point::<GinStreamCurve>(
        b"statement.h1",
        &statement.h1,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GinStreamCurve>(
        b"statement.h2",
        &statement.h2,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GinStreamCurve>(
        b"statement.t1",
        &statement.t1,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GinStreamCurve>(
        b"statement.t2",
        &statement.t2,
        IdentityPolicy::Reject,
    )?;
    stream.observe_point::<GoutStreamCurve>(
        b"statement.r",
        &statement.r_point,
        IdentityPolicy::Allow,
    )?;
    stream.observe_scalar::<GoutStreamCurve>(b"statement.beta", &statement.beta)
}

// ------------------------------------------------------------------
// Batched dealer proof (paper Section 4, batched across receivers).
// ------------------------------------------------------------------

/// Per-receiver public inputs for the batched dealer proof.
#[derive(Clone, Debug)]
pub struct BatchedReceiverStatement {
    /// Receiver participant index.
    pub receiver: ParticipantIndex,
    /// Receiver identity public key `PK_j` in `G_in`.
    pub pkj: Gin,
    /// Public commitment `g_in^share_j` to the receiver share.
    pub share_commitment: Gin,
    /// Published pad commitment `g_in^pad_j` in the dealer broadcast.
    pub pad_commitment: Gin,
    /// Published encrypted share scalar `share_j + pad_j`.
    pub encrypted_share: GinScalar,
}

/// Public statement for the batched dealer proof.
#[derive(Clone, Debug)]
pub struct BatchedEvrfStatement {
    /// Paper dealer message `msg_i` (shared across the batch).
    pub msg: [u8; MESSAGE_BYTES],
    /// Dealer identity public key `PK_1 = g_in^sk_1` in `G_in` (shared).
    pub pk1: Gin,
    /// Public coefficient `beta` in `Fp` (shared).
    pub beta: R1csField,
    /// DKG threshold.
    pub threshold: usize,
    /// Ordered Feldman commitment coefficients for the dealer polynomial.
    pub commitment_coefficients: Vec<Gin>,
    /// Full DKG `EvrfStatement` roots, in the same canonical receiver
    /// order as `receivers`.
    pub statement_roots: Vec<TranscriptRoot>,
    /// Per-receiver statements, in the canonical ordered receiver list.
    pub receivers: Vec<BatchedReceiverStatement>,
}

/// Reusable transparent parameters for one batched dealer circuit shape.
pub struct BatchedEvrfPublicParams {
    threshold: usize,
    receiver_count: usize,
    multiplier_count: usize,
    pc_gens: PedersenGens<R1csCycle>,
    bp_gens: BulletproofGens<R1csCycle>,
}

// `BatchedEvrfPublicParams` intentionally has no `serde` impl here, unlike
// `secp_secq`'s: that impl requires `Cycle::Affine: Serialize`, which
// `secp_secq` gets from `halo2curves`'s own `derive_serde` feature.
// `Bls12_381G1Cycle::Affine` is `blst::blst_p1_affine`, an FFI struct with
// no serde support and no local type this crate could add one to (the
// orphan rule blocks implementing the foreign `serde::Serialize` trait for
// it here). Serializing these params would need a local wrapper type
// around it instead — deferred; nothing in this module needs it today.

impl BatchedEvrfPublicParams {
    fn validated_shape(threshold: usize, receiver_count: usize) -> Result<(usize, usize)> {
        let multiplier_count = batched_multiplier_count(threshold, receiver_count)?;
        let gens_capacity = multiplier_count
            .checked_next_power_of_two()
            .ok_or(Error::ProofVerificationFailed)?;
        Ok((multiplier_count, gens_capacity))
    }

    fn from_shape(
        threshold: usize,
        receiver_count: usize,
        multiplier_count: usize,
        gens_capacity: usize,
    ) -> Self {
        Self {
            threshold,
            receiver_count,
            multiplier_count,
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(gens_capacity, 1),
        }
    }

    /// Build transparent parameters for a DKG threshold and receiver count.
    pub fn setup(threshold: usize, receiver_count: usize) -> Result<Self> {
        let (multiplier_count, gens_capacity) = Self::validated_shape(threshold, receiver_count)?;
        Ok(Self::from_shape(
            threshold,
            receiver_count,
            multiplier_count,
            gens_capacity,
        ))
    }

    /// Return process-wide shared parameters for one exact circuit shape.
    pub fn shared(threshold: usize, receiver_count: usize) -> Result<std::sync::Arc<Self>> {
        type CacheEntry =
            std::sync::Arc<std::sync::OnceLock<std::sync::Arc<BatchedEvrfPublicParams>>>;
        type Cache = std::sync::Mutex<std::collections::HashMap<(usize, usize), CacheEntry>>;
        static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();

        let (multiplier_count, gens_capacity) = Self::validated_shape(threshold, receiver_count)?;
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        let entry = {
            let mut cache = cache.lock().map_err(|_| Error::ProofVerificationFailed)?;
            std::sync::Arc::clone(
                cache
                    .entry((threshold, receiver_count))
                    .or_insert_with(|| std::sync::Arc::new(std::sync::OnceLock::new())),
            )
        };
        let params = entry.get_or_init(|| {
            std::sync::Arc::new(Self::from_shape(
                threshold,
                receiver_count,
                multiplier_count,
                gens_capacity,
            ))
        });
        Ok(std::sync::Arc::clone(params))
    }

    /// DKG threshold retained for statement-shape validation.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of non-dealer receivers used to size these parameters.
    pub fn receiver_count(&self) -> usize {
        self.receiver_count
    }

    /// Exact number of multipliers in the configured circuit shape.
    pub fn multiplier_count(&self) -> usize {
        self.multiplier_count
    }

    /// Padded Bulletproof generator capacity.
    pub fn gens_capacity(&self) -> usize {
        self.bp_gens.gens_capacity
    }

    /// Exact wire length, in bytes, of one batched dealer proof at this
    /// shape — without building it. Mirrors `secp_secq`'s method of the same
    /// name: every batched-eVRF proof here is single-phase too (the relation
    /// never calls `specify_randomized_constraints`), so wire length is an
    /// exact function of `gens_capacity` (hence the inner-product-proof fold
    /// count) alone.
    pub fn batched_proof_wire_len(threshold: usize, receiver_count: usize) -> Result<usize> {
        let (_, gens_capacity) = Self::validated_shape(threshold, receiver_count)?;
        let lg_n = gens_capacity.trailing_zeros() as usize;

        const PROOF_ID_LEN_PREFIX_BYTES: usize = 4;
        const PAYLOAD_LEN_PREFIX_BYTES: usize = 8;
        let envelope =
            PROOF_ID_LEN_PREFIX_BYTES + BATCHED_PROOF_ID.len() + PAYLOAD_LEN_PREFIX_BYTES;
        let constant_term_proof = <GinStreamCurve as ProofStreamCurve>::POINT_BYTES
            + <GinStreamCurve as ProofStreamCurve>::SCALAR_BYTES;

        Ok(envelope + R1CSProof::<R1csCycle>::single_phase_wire_len(lg_n) + constant_term_proof)
    }

    fn validate_statement(&self, statement: &BatchedEvrfStatement) -> Result<()> {
        if self.threshold != statement.threshold || self.receiver_count != statement.receivers.len()
        {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    }
}

/// Witness for the batched dealer proof.
#[derive(Clone)]
pub struct BatchedEvrfWitness {
    /// Dealer identity secret `sk_1` in `Fr` (shared across the batch).
    pub sk1: GinScalar,
    /// Opening `a_0` of the constant Feldman commitment `A_0 = a_0 * G_in`.
    pub polynomial_constant: GinScalar,
}

impl core::fmt::Debug for BatchedEvrfWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchedEvrfWitness")
            .field("sk1", &"<redacted>")
            .field("polynomial_constant", &"<redacted>")
            .finish()
    }
}

/// Extract affine `(u, v)` coordinates of a non-identity `G_in` point.
fn affine(point: &Gin) -> Result<(R1csField, R1csField)> {
    if is_identity(point) {
        return Err(Error::ProofVerificationFailed);
    }
    let extended: ExtendedPoint = (*point).into();
    let aff = jubjub::AffinePoint::from(extended);
    Ok((aff.get_u(), aff.get_v()))
}

fn is_identity(point: &Gin) -> bool {
    bool::from(Group::is_identity(point))
}

/// Batch-convert `points` to affine `(u, v)` coordinates with a single field
/// inversion (Montgomery's trick via `jubjub::batch_normalize`), instead of
/// one inversion per point via [`affine`].
fn batch_affine(points: &[Gin]) -> Result<Vec<(R1csField, R1csField)>> {
    let mut extended: Vec<ExtendedPoint> = points.iter().map(|p| (*p).into()).collect();
    jubjub::batch_normalize(&mut extended)
        .map(|aff| Ok((aff.get_u(), aff.get_v())))
        .collect()
}

// ------------------------------------------------------------------
// Field constants.
// ------------------------------------------------------------------

/// Bit length used for the `k = int(S.u)` decomposition, matching the
/// paper's security parameter `lambda = 256` (a security-parameter choice,
/// not tied to any specific field's bit length; BLS12-381's scalar field
/// needs only 255 bits, so the top bit is always forced to zero by the
/// range check in [`bit_decompose_bounded_n`], the same guard-bit mechanism
/// `secp_secq` relies on).
const K_BITS: usize = 256;

/// BLS12-381 scalar-field modulus `p` (the R1CS field, also Jubjub's base
/// field), encoded little-endian.
/// `p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
const R1CS_FIELD_MODULUS_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
    0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
];

/// Jubjub scalar-field modulus `q` (`G_in`'s own scalar field `Fr`), encoded
/// little-endian.
/// `q = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`.
const GIN_SCALAR_MODULUS_LE: [u8; 32] = [
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
];

/// `p - 8*q`, encoded little-endian. `p` is roughly `8.00000...q` (BLS12-381
/// G1's cofactor-8 relationship between Jubjub's base field, `p`, and
/// Jubjub's own prime-order-subgroup scalar field, `q`, unlike Secp256k1's
/// base and scalar fields, which are within `O(sqrt(p))` of each other by
/// the Hasse bound). Reducing an `R1csField` value `r < p` into a valid
/// `Gin` scalar therefore needs a quotient `m = floor(r/q) in {0,...,8}`,
/// not just a single conditional subtraction the way `secp_secq` handles
/// its (much closer) `p`/`q` pair. See [`reduce_pad_r1cs`] for the
/// soundness argument this bound supports.
const R1CS_FIELD_MODULUS_MINUS_8_GIN_SCALAR_MODULUS_LE: [u8; 32] = [
    0x49, 0x9a, 0x46, 0x48, 0x08, 0x8d, 0x47, 0x7b, 0xe8, 0xd7, 0xbd, 0x99, 0x64, 0x9f, 0x7c, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Bound `9` (as `9 = 0b1001`) for the 4-bit `m in {0,...,8}` range check in
/// [`reduce_pad_r1cs`].
const NINE_LE: [u8; 1] = [9];

fn modulus_bit(modulus_le: &[u8], j: usize) -> bool {
    let byte_idx = j / 8;
    let bit_idx = j % 8;
    byte_idx < modulus_le.len() && (modulus_le[byte_idx] >> bit_idx) & 1 == 1
}

/// Jubjub curve coefficient `a = -1` in `-u^2 + v^2 = 1 + d*u^2*v^2`.
fn edwards_a() -> R1csField {
    -R1csField::ONE
}

/// Jubjub curve coefficient `d = -(10240/10241)`, reconstructed from the
/// same raw limbs `jubjub`'s own (private) `EDWARDS_D` constant uses —
/// `jubjub::Fq` is `bls12_381::Scalar`, so `Scalar::from_raw` on those limbs
/// reproduces the exact same field element. Cross-checked independently
/// against the `-(10240/10241)` definition in
/// `edwards_d_matches_its_defining_fraction`.
fn edwards_d() -> R1csField {
    R1csField::from_raw([
        0x0106_5fd6_d634_3eb1,
        0x292d_7f6d_3757_9d26,
        0xf5fd_9207_e6bd_7fd4,
        0x2a93_18e7_4bfa_2b48,
    ])
}

/// Jubjub's own scalar-field modulus `q`, as an `R1csField` element (used by
/// [`reduce_pad_r1cs`] to constrain `pad = r - m*q`).
fn gin_scalar_modulus_as_r1cs_field() -> R1csField {
    R1csField::from_raw([
        0xd097_0e5e_d6f7_2cb7,
        0xa668_2093_ccc8_1082,
        0x0667_3b01_0134_3b00,
        0x0e7d_b4ea_6533_afa9,
    ])
}

// ------------------------------------------------------------------
// R1CS gadgets
// ------------------------------------------------------------------

/// Compute `2^j` as an `R1csField` element by repeated doubling.
fn power_of_two(j: usize) -> R1csField {
    let mut result = R1csField::ONE;
    for _ in 0..j {
        result = result.double();
    }
    result
}

/// Bit-decomposition gadget (paper Section 4.2), generalized to an
/// arbitrary bit width so the same implementation serves both the
/// `K_BITS + 1`-wide decompositions ([`bit_decompose`]/[`bit_decompose_q`])
/// and [`reduce_pad_r1cs`]'s small 4-bit quotient range check. Given a
/// committed variable `k_var` holding `k` and `num_bits` bit assignments,
/// constrains:
/// - `k_j * (1 - k_j) = 0` for each `j` (each `k_j` is binary)
/// - `k = sum_{j=0}^{num_bits-1} 2^j * k_j` (the bits reconstruct `k`)
/// - `sum 2^j * k_j < bound`, where `bound` is `modulus_le`
///
/// Returns the allocated bit variables, LSB first.
fn bit_decompose_bounded_n<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    k_var: Variable<R1csField>,
    bit_assignments: &[Option<R1csField>],
    modulus_le: &[u8],
    num_bits: usize,
) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
    if bit_assignments.len() != num_bits {
        return Err(R1CSError::FormatError);
    }
    let mut bit_vars = Vec::with_capacity(num_bits);
    let mut k_lc = LinearCombination::default();

    for (j, &bit) in bit_assignments.iter().enumerate() {
        let (left, right, out) =
            cs.allocate_multiplier(bit.map(|bit| (bit, R1csField::ONE - bit)))?;
        cs.constrain(right - (LinearCombination::from(R1csField::ONE) - left));
        cs.constrain(out.into());
        bit_vars.push(left);

        k_lc = k_lc + left * power_of_two(j);
    }

    cs.constrain(k_lc - k_var);

    // Before the modulus's own highest set bit, `prefix_equal` is
    // provably the constant `1` (every bit above it is required to be 0
    // by the modulus's own leading zeros): the `product = prefix_equal *
    // bit_j` multiplier that follows would just reduce to `product =
    // bit_j`, so constrain `bit_j = 0` directly instead of paying a gate
    // to multiply by a known constant.
    let mut prefix_equal = LinearCombination::from(R1csField::ONE);
    let mut prefix_equal_assignment = Some(R1csField::ONE);
    let mut prefix_is_trivially_one = true;
    for j in (0..num_bits).rev() {
        let bound_bit = modulus_bit(modulus_le, j);
        if prefix_is_trivially_one && !bound_bit {
            cs.constrain(bit_vars[j].into());
            continue;
        }
        prefix_is_trivially_one = false;

        let bit_assignment = bit_assignments[j];
        let product_assignment = match (prefix_equal_assignment, bit_assignment) {
            (Some(eq), Some(bit)) => Some((eq, bit)),
            _ => None,
        };
        let (left, right, out) = cs.allocate_multiplier(product_assignment)?;
        cs.constrain(left - prefix_equal.clone());
        cs.constrain(right - bit_vars[j]);

        let product_lc: LinearCombination<R1csField> = out.into();
        if bound_bit {
            prefix_equal = product_lc;
            prefix_equal_assignment = match (prefix_equal_assignment, bit_assignment) {
                (Some(eq), Some(bit)) => Some(eq * bit),
                _ => None,
            };
        } else {
            cs.constrain(product_lc.clone());
            prefix_equal = prefix_equal - product_lc;
            prefix_equal_assignment = match (prefix_equal_assignment, bit_assignment) {
                (Some(eq), Some(bit)) => Some(eq * (R1csField::ONE - bit)),
                _ => None,
            };
        }
    }
    cs.constrain(prefix_equal);

    Ok(bit_vars)
}

fn bit_decompose<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    k_var: Variable<R1csField>,
    bit_assignments: &[Option<R1csField>],
) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
    bit_decompose_bounded_n(
        cs,
        k_var,
        bit_assignments,
        &R1CS_FIELD_MODULUS_LE,
        K_BITS + 1,
    )
}

fn bit_decompose_q<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    k_var: Variable<R1csField>,
    bit_assignments: &[Option<R1csField>],
) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
    bit_decompose_bounded_n(
        cs,
        k_var,
        bit_assignments,
        &GIN_SCALAR_MODULUS_LE,
        K_BITS + 1,
    )
}

fn constrain_bits_lt_bound_when<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    bit_vars: &[Variable<R1csField>],
    bit_assignments: &[Option<R1csField>],
    bound_le: &[u8],
    condition_var: Variable<R1csField>,
) -> core::result::Result<(), R1CSError> {
    let num_bits = bit_vars.len();
    if bit_assignments.len() != num_bits {
        return Err(R1CSError::FormatError);
    }

    let condition_lc = LinearCombination::from(condition_var);

    // Every bit at or above the bound's own highest set bit sits where the
    // bound is implicitly 0, so it must be 0 whenever `condition` holds.
    // `bit_vars` are already boolean-constrained by the caller's bit
    // decomposition (which builds `bit_vars` before calling this), so a
    // single `condition * sum(high bits) = 0` is equivalent to per-bit
    // chaining through this whole range — a sum of 0/1 terms is 0 iff every
    // term is 0 — replacing what would otherwise be two gates per high bit
    // with one gate for the entire range.
    let highest_bound_bit = (0..num_bits).rev().find(|&j| modulus_bit(bound_le, j));
    let lower_bits_start = highest_bound_bit.map_or(0, |msb| msb + 1);
    if lower_bits_start < num_bits {
        let high_bits_sum = bit_vars[lower_bits_start..]
            .iter()
            .fold(LinearCombination::default(), |lc, &bit| {
                lc + LinearCombination::from(bit)
            });
        let (_, _, high_violation) = cs.multiply(condition_lc.clone(), high_bits_sum);
        cs.constrain(high_violation.into());
    }

    // Whenever `condition` holds, the check above already forces every bit
    // above `lower_bits_start` to 0, matching the bound's own implicit
    // high zeros exactly — so the prefix genuinely-still-equal state
    // entering this loop is the constant `1`, regardless of whether it was
    // computed via the (now-elided) per-bit chain above.
    let mut prefix_equal = LinearCombination::from(R1csField::ONE);
    let mut prefix_equal_assignment = Some(R1csField::ONE);
    for j in (0..lower_bits_start).rev() {
        let bit_assignment = bit_assignments[j];
        let product_assignment = match (prefix_equal_assignment, bit_assignment) {
            (Some(eq), Some(bit)) => Some((eq, bit)),
            _ => None,
        };
        let (left, right, out) = cs.allocate_multiplier(product_assignment)?;
        cs.constrain(left - prefix_equal.clone());
        cs.constrain(right - bit_vars[j]);

        let product_lc: LinearCombination<R1csField> = out.into();
        if modulus_bit(bound_le, j) {
            prefix_equal = product_lc;
            prefix_equal_assignment = match (prefix_equal_assignment, bit_assignment) {
                (Some(eq), Some(bit)) => Some(eq * bit),
                _ => None,
            };
        } else {
            let (_, _, violation) = cs.multiply(condition_lc.clone(), product_lc.clone());
            cs.constrain(violation.into());
            prefix_equal = prefix_equal - product_lc;
            prefix_equal_assignment = match (prefix_equal_assignment, bit_assignment) {
                (Some(eq), Some(bit)) => Some(eq * (R1csField::ONE - bit)),
                _ => None,
            };
        }
    }

    let (_, _, equality_violation) = cs.multiply(condition_lc, prefix_equal);
    cs.constrain(equality_violation.into());

    Ok(())
}

/// Core unified twisted-Edwards addition step: given the running
/// accumulator's coordinates `(acc_u, acc_v)` and a step point's coordinates
/// `(u_step, v_step)`, both as linear combinations, constrains
/// `(u_out, v_out) = (acc_u, acc_v) + (u_step, v_step)` using the complete
/// (unified) law
/// `u3 = (u1*v2 + v1*u2) / (1 + d*u1*u2*v1*v2)`,
/// `v3 = (v1*v2 - a*u1*u2) / (1 - d*u1*u2*v1*v2)`.
/// The `u3` numerator is folded into one cross multiply,
/// `(u1+v1)*(u2+v2) - u1*u2 - v1*v2`, rather than the two multiplies
/// `u1*v2` and `v1*u2` a direct reading of the formula suggests.
///
/// `u_out`/`v_out` are each allocated via [`ConstraintSystem::allocate_multiplier`]
/// directly against their own divisor, `(1+t)`/`(1-t)`, instead of a plain
/// `allocate` followed by a separate `multiply` check:
/// `allocate_multiplier((u3, 1+t))` gives `u_out * u_out_right = u_out_check`
/// as one gate, and `u_out_right = 1+t` / `u_out_check = u_out_num` bind the
/// other two wires via free linear constraints, enforcing exactly the same
/// relation `u_out*(1+t) = u_out_num` as `allocate` + `multiply` did, in one
/// fewer gate. Total: 6 multiplier gates (4 explicit `cs.multiply` calls
/// plus the two `allocate_multiplier` calls), regardless of how many bits
/// `(u_step, v_step)` encodes (a single bit via
/// [`edwards_conditional_add_r1cs`], or several via
/// [`edwards_exponentiate_windowed_r1cs`]'s windowed selection).
///
/// `result` is the prover's witness value of the sum (computed off-circuit
/// via real Jubjub arithmetic); `witness_coords` is the concrete
/// `(acc_u, acc_v, u_step, v_step)` values needed to compute `t`'s own
/// witness value for the `allocate_multiplier` calls above. Both are `None`
/// on the verifier side.
fn edwards_add_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    acc_u: LinearCombination<R1csField>,
    acc_v: LinearCombination<R1csField>,
    u_step: LinearCombination<R1csField>,
    v_step: LinearCombination<R1csField>,
    result: Option<(R1csField, R1csField)>,
    witness_coords: Option<(R1csField, R1csField, R1csField, R1csField)>,
) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
    let a = edwards_a();
    let d = edwards_d();

    let (_, _, m1) = cs.multiply(acc_u.clone(), u_step.clone());
    let (_, _, m2) = cs.multiply(acc_v.clone(), v_step.clone());
    let (_, _, t) = cs.multiply(LinearCombination::from(m1) * d, m2.into());
    // u3's numerator u1*v2 + v1*u2 via one cross multiply instead of two:
    // (u1+v1)*(u2+v2) = u1*u2 + u1*v2 + v1*u2 + v1*v2, so
    // u1*v2 + v1*u2 = cross - m1 - m2.
    let (_, _, cross) = cs.multiply(acc_u + acc_v, u_step + v_step);

    let u_out_num = LinearCombination::from(cross) - m1 - m2;
    let v_out_num = LinearCombination::from(m2) - LinearCombination::from(m1) * a;

    let t_value = witness_coords.map(|(au, av, us, vs)| d * (au * us) * (av * vs));

    let u3 = result.map(|(u, _)| u);
    let (u_out, u_out_right, u_out_check) =
        cs.allocate_multiplier(u3.zip(t_value.map(|t| R1csField::ONE + t)))?;
    cs.constrain(
        LinearCombination::from(u_out_right) - (LinearCombination::from(R1csField::ONE) + t),
    );
    cs.constrain(LinearCombination::from(u_out_check) - u_out_num);

    let v3 = result.map(|(_, v)| v);
    let (v_out, v_out_right, v_out_check) =
        cs.allocate_multiplier(v3.zip(t_value.map(|t| R1csField::ONE - t)))?;
    cs.constrain(
        LinearCombination::from(v_out_right) - (LinearCombination::from(R1csField::ONE) - t),
    );
    cs.constrain(LinearCombination::from(v_out_check) - v_out_num);

    Ok((u_out, v_out))
}

/// One single-bit step of the additive ladder: given the running
/// accumulator and a public per-bit candidate point
/// `(base_u, base_v) = 2^j * X`, constrains
/// `L_j = L_{j-1} + (bit ? (base_u, base_v) : identity)`.
///
/// Since `(base_u, base_v)` are public constants, the selected step point
/// `(bit*base_u, 1 + bit*(base_v-1))` is linear in `bit` — no extra
/// multiplier is needed to materialize it before handing it to
/// [`edwards_add_r1cs`]. `bit=0` reduces the addition formula algebraically
/// to `(u_out, v_out) = (acc_u, acc_v)` (adding the identity `(0,1)` is a
/// no-op under the complete law, no special base case needed); `bit=1`
/// reduces it to the direct sum of the accumulator and the base point. Both
/// are checked in `edwards_conditional_add_reduces_correctly_for_both_bits`.
///
/// Used only for bit 0 of the exponent (the base case) —
/// [`edwards_exponentiate_windowed_r1cs`] windows every other bit two at a
/// time via [`edwards_window_step_r1cs`].
#[allow(clippy::too_many_arguments)]
fn edwards_conditional_add_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    acc_u: LinearCombination<R1csField>,
    acc_v: LinearCombination<R1csField>,
    bit: Variable<R1csField>,
    base_u: R1csField,
    base_v: R1csField,
    result: Option<(R1csField, R1csField)>,
    step_witness: Option<(R1csField, R1csField)>,
) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
    let u_step = LinearCombination::from(bit) * base_u;
    let v_step = LinearCombination::from(R1csField::ONE)
        + LinearCombination::from(bit) * (base_v - R1csField::ONE);
    // The accumulator entering the bit-0 base case is always the identity
    // `(0, 1)`, a fixed constant — no witness lookup needed for it.
    let witness_coords = step_witness.map(|(su, sv)| (R1csField::ZERO, R1csField::ONE, su, sv));
    edwards_add_r1cs(cs, acc_u, acc_v, u_step, v_step, result, witness_coords)
}

/// One 2-bit-windowed step of the additive ladder, mirroring `secp_secq`'s
/// chord-rule windowing (see the module doc): given window bits
/// `(b0, b1) = (bit_{2w-1}, bit_{2w})`, their product `prod` (computed once
/// per window and shared across every exponentiation using the same bit
/// vector — see [`edwards_window_products`]), and the window's three
/// non-identity candidate points `Q10 = 2^{2w-1}*X`, `Q01 = 2^{2w}*X`,
/// `Q11 = Q10 + Q01` (affine; `Q00`, selected when `b0=b1=0`, is always the
/// identity `(0,1)` and so is never stored), constrains
/// `L_w = L_{w-1} + Q_{b0,b1}` via the standard multilinear selection
/// `Q_{b0,b1} = Q00 + (Q10-Q00)*b0 + (Q01-Q00)*b1 + (Q11-Q10-Q01+Q00)*prod`
/// (with `Q00 = (0,1)`), which is linear in `b0`, `b1`, `prod` and so needs
/// no extra multiplier beyond `prod` itself before handing the selected
/// step point to [`edwards_add_r1cs`]. `acc_witness`/`step_witness` are that
/// call's `witness_coords` split into the accumulator-entering and
/// selected-candidate halves; both `None` on the verifier side.
#[allow(clippy::too_many_arguments)]
fn edwards_window_step_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    acc_u: LinearCombination<R1csField>,
    acc_v: LinearCombination<R1csField>,
    b0: Variable<R1csField>,
    b1: Variable<R1csField>,
    prod: Variable<R1csField>,
    candidates: [(R1csField, R1csField); 3],
    result: Option<(R1csField, R1csField)>,
    acc_witness: Option<(R1csField, R1csField)>,
    step_witness: Option<(R1csField, R1csField)>,
) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
    let [q10, q01, q11] = candidates;

    let u_step = LinearCombination::from(b0) * q10.0
        + LinearCombination::from(b1) * q01.0
        + LinearCombination::from(prod) * (q11.0 - q10.0 - q01.0);
    let v_step = LinearCombination::from(R1csField::ONE)
        + LinearCombination::from(b0) * (q10.1 - R1csField::ONE)
        + LinearCombination::from(b1) * (q01.1 - R1csField::ONE)
        + LinearCombination::from(prod) * (q11.1 - q10.1 - q01.1 + R1csField::ONE);

    let witness_coords = acc_witness
        .zip(step_witness)
        .map(|((au, av), (su, sv))| (au, av, su, sv));
    edwards_add_r1cs(cs, acc_u, acc_v, u_step, v_step, result, witness_coords)
}

/// Compute the shared window AND products `bit_vars[2w-1] * bit_vars[2w]`
/// for `w = 1..=K_BITS/2`, one multiplier gate per window. Bit 0 (the base
/// case, handled by [`edwards_conditional_add_r1cs`]) is not included.
/// Reused across every exponentiation over the same bit vector — mirrors
/// `secp_secq`'s `chord_window_products` sharing (e.g. `T_1`/`T_2` in the
/// one-receiver relation both reuse `k`'s window products).
fn edwards_window_products<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    bit_vars: &[Variable<R1csField>],
) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
    if bit_vars.len() != K_BITS + 1 {
        return Err(R1CSError::FormatError);
    }
    let num_windows = K_BITS / 2;
    let mut products = Vec::with_capacity(num_windows);
    for w in 1..=num_windows {
        let (_, _, prod) = cs.multiply(bit_vars[2 * w - 1].into(), bit_vars[2 * w].into());
        products.push(prod);
    }
    Ok(products)
}

/// Precomputed windowed candidate points for one Edwards exponentiation
/// base `X`, for use with [`edwards_exponentiate_windowed_r1cs`].
#[derive(Clone, Debug)]
struct EdwardsWindowPrecomp {
    /// Affine coords of `P_0 = X`, bit 0's candidate point.
    bit0: (R1csField, R1csField),
    /// For `w = 1..=K_BITS/2` (window `w` covers bits `2w-1, 2w`):
    /// `[Q10, Q01, Q11]` affine coordinates (`Q00` is always the identity
    /// `(0,1)`, so it is never stored — see [`edwards_window_step_r1cs`]).
    windows: Vec<[(R1csField, R1csField); 3]>,
}

/// Multiply a public base point `X` by a witness-controlled scalar via its
/// `K_BITS + 1`-bit decomposition: bit 0 via [`edwards_conditional_add_r1cs`]
/// (the base case), then bits `1..=K_BITS` two at a time via
/// [`edwards_window_step_r1cs`] (`K_BITS / 2` windows). No correction
/// generator, unlike `secp_secq`'s chord-rule gadget (see the module doc) —
/// Edwards addition has no exceptional case to dodge in the first place.
///
/// `precomp` must be [`precompute_windowed_base_powers`]'s output for `X`.
/// `window_products` must be [`edwards_window_products`]'s output for the
/// same bit vector (reused across every exponentiation sharing that vector).
/// `witness`, when `Some`, must be [`edwards_windowed_ladder_witness`]'s
/// output (prover only). If `result` is `Some`, constrains the final
/// accumulator to equal it (used when the target point is already public,
/// e.g. `PK_1 = g_in^sk_1`); when `None`, the caller reads back the
/// returned variables instead (used when the target, e.g.
/// `T_1 = H1(msg)^k`, is itself committed to and observed as a public
/// statement field, so the gadget need not independently re-derive it).
#[allow(clippy::too_many_arguments)]
fn edwards_exponentiate_windowed_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    bit_vars: &[Variable<R1csField>],
    window_products: &[Variable<R1csField>],
    precomp: &EdwardsWindowPrecomp,
    result: Option<(R1csField, R1csField)>,
    witness: Option<&EdwardsWindowWitness>,
) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
    let num_windows = K_BITS / 2;
    if bit_vars.len() != K_BITS + 1
        || window_products.len() != num_windows
        || precomp.windows.len() != num_windows
    {
        return Err(R1CSError::FormatError);
    }
    if let Some(witness) = witness {
        if witness.window_results.len() != num_windows || witness.window_steps.len() != num_windows
        {
            return Err(R1CSError::FormatError);
        }
    }

    let (mut acc_u, mut acc_v) = edwards_conditional_add_r1cs(
        cs,
        LinearCombination::from(R1csField::ZERO),
        LinearCombination::from(R1csField::ONE),
        bit_vars[0],
        precomp.bit0.0,
        precomp.bit0.1,
        witness.map(|w| w.bit0_result),
        witness.map(|w| w.bit0_step),
    )?;
    // Tracks the accumulator's concrete value alongside its wire, so each
    // window step below can derive its own `edwards_add_r1cs`
    // multiplier-fold witness without re-deriving it from scratch.
    let mut acc_value = witness.map(|w| w.bit0_result);

    for w in 1..=num_windows {
        let step_result = witness.map(|w_| w_.window_results[w - 1]);
        let step_point = witness.map(|w_| w_.window_steps[w - 1]);
        let (u_var, v_var) = edwards_window_step_r1cs(
            cs,
            acc_u.into(),
            acc_v.into(),
            bit_vars[2 * w - 1],
            bit_vars[2 * w],
            window_products[w - 1],
            precomp.windows[w - 1],
            step_result,
            acc_value,
            step_point,
        )?;
        acc_u = u_var;
        acc_v = v_var;
        acc_value = step_result;
    }

    if let Some((rx, ry)) = result {
        cs.constrain(LinearCombination::from(acc_u) - rx);
        cs.constrain(LinearCombination::from(acc_v) - ry);
    }
    Ok((acc_u, acc_v))
}

/// Precompute `2^j * X` for `j = 0..=K_BITS`, as raw `G_in` points (for
/// [`edwards_windowed_ladder_witness`]).
fn base_power_points(x: &Gin) -> Vec<Gin> {
    let mut powers = Vec::with_capacity(K_BITS + 1);
    let mut p = *x;
    for _ in 0..=K_BITS {
        powers.push(p);
        p = p.double();
    }
    powers
}

/// Precompute [`EdwardsWindowPrecomp`] for base `X`, for use with
/// [`edwards_exponentiate_windowed_r1cs`].
fn precompute_windowed_base_powers(x: &Gin) -> Result<EdwardsWindowPrecomp> {
    let powers = base_power_points(x);
    let num_windows = K_BITS / 2;

    let mut points = Vec::with_capacity(1 + 3 * num_windows);
    points.push(powers[0]);
    for w in 1..=num_windows {
        let (j1, j2) = (2 * w - 1, 2 * w);
        points.push(powers[j1]);
        points.push(powers[j2]);
        points.push(powers[j1] + powers[j2]);
    }

    let affines = batch_affine(&points)?;
    let bit0 = affines[0];
    let windows = affines[1..].as_chunks::<3>().0.to_vec();
    Ok(EdwardsWindowPrecomp { bit0, windows })
}

/// Off-circuit reference computation of the windowed additive ladder: `L_0`
/// (after bit 0) and `L_w` at every window boundary (`w = 1..=K_BITS/2`),
/// using real Jubjub point arithmetic (the prover's witness-generation path
/// for [`edwards_exponentiate_windowed_r1cs`]). Also records each step's
/// own selected step point (`bit0_step`/`window_steps`, aligned with
/// `bit0_result`/`window_results`), which [`edwards_add_r1cs`] needs to
/// compute its own multiplier-fold witness value.
#[derive(Clone, Debug)]
struct EdwardsWindowWitness {
    bit0_result: (R1csField, R1csField),
    bit0_step: (R1csField, R1csField),
    window_results: Vec<(R1csField, R1csField)>,
    window_steps: Vec<(R1csField, R1csField)>,
}

fn edwards_windowed_ladder_witness(
    bits: &[bool],
    base_powers: &[Gin],
) -> Result<EdwardsWindowWitness> {
    if bits.len() != K_BITS + 1 || base_powers.len() != K_BITS + 1 {
        return Err(Error::ProofVerificationFailed);
    }
    let num_windows = K_BITS / 2;

    let bit0_step_point = if bits[0] {
        base_powers[0]
    } else {
        Gin::identity()
    };
    let mut acc = bit0_step_point;
    let mut running = Vec::with_capacity(1 + num_windows);
    let mut steps = Vec::with_capacity(1 + num_windows);
    running.push(acc);
    steps.push(bit0_step_point);
    for w in 1..=num_windows {
        let (j1, j2) = (2 * w - 1, 2 * w);
        let mut step_point = Gin::identity();
        if bits[j1] {
            step_point += base_powers[j1];
        }
        if bits[j2] {
            step_point += base_powers[j2];
        }
        acc += step_point;
        running.push(acc);
        steps.push(step_point);
    }

    let result_affines = batch_affine(&running)?;
    let step_affines = batch_affine(&steps)?;
    Ok(EdwardsWindowWitness {
        bit0_result: result_affines[0],
        bit0_step: step_affines[0],
        window_results: result_affines[1..].to_vec(),
        window_steps: step_affines[1..].to_vec(),
    })
}

/// Decompose an `R1csField` element into little-endian bits via its
/// canonical byte representation. Produces exactly `K_BITS + 1` bits (the
/// extra bit is the guard bit described at [`K_BITS`]).
fn decompose_k_fp(k: &R1csField, bits: &mut [bool]) {
    let repr = k.to_repr();
    for (i, b) in bits.iter_mut().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        *b = byte_idx < repr.len() && (repr[byte_idx] >> bit_idx) & 1 == 1;
    }
}

fn bit_options(bits: &[bool]) -> Vec<Option<R1csField>> {
    bits.iter()
        .map(|&b| Some(if b { R1csField::ONE } else { R1csField::ZERO }))
        .collect()
}

/// Convert an `R1csField` element to `GinScalar` by reinterpreting its
/// canonical LE bytes as raw limbs and reducing mod `Gin`'s scalar modulus
/// `q` (`GinScalar::from_raw` performs a genuine Montgomery reduction of its
/// input, valid for any raw limbs — see the module tests). Needed because
/// `p` (the R1CS field) is roughly `8q`, unlike Secp256k1 where `p` and `q`
/// are within `O(sqrt(p))` of each other.
fn fp_to_fr(fp: &R1csField) -> GinScalar {
    let bytes: [u8; 32] = fp.to_repr();
    let (chunks, _) = bytes.as_chunks::<8>();
    GinScalar::from_raw(core::array::from_fn(|i| u64::from_le_bytes(chunks[i])))
}

/// Convert a `GinScalar` element to `R1csField`. Always exact (an injective
/// embedding, not a reduction): `q < p`, so every canonical `GinScalar`
/// value is already a valid `R1csField` element.
fn fr_to_fp(fr: &GinScalar) -> R1csField {
    let bytes: [u8; 32] = fr.to_bytes();
    let (chunks, _) = bytes.as_chunks::<8>();
    R1csField::from_raw(core::array::from_fn(|i| u64::from_le_bytes(chunks[i])))
}

/// Off-circuit computation of `(pad, m)` such that `r = pad + m*q` with
/// `pad < q` and `m` the true quotient `floor(r/q)`. `m in {0,...,8}`
/// because `p < 9q` (in fact `p` is barely above `8q`). Matches
/// [`reduce_pad_r1cs`]'s constraints exactly; see that function's doc for
/// the soundness argument this quotient bound supports.
fn reduce_pad_witness(r: &R1csField) -> (R1csField, u8) {
    let q = gin_scalar_modulus_as_r1cs_field();
    let mut remaining = *r;
    let mut m: u8 = 0;
    while fp_canonical_ge(&remaining, &q) {
        remaining -= q;
        m += 1;
    }
    (remaining, m)
}

/// Compare two `R1csField` elements by their canonical integer value.
/// Returns true iff `a >= b`.
fn fp_canonical_ge(a: &R1csField, b: &R1csField) -> bool {
    let a_repr = a.to_repr();
    let b_repr = b.to_repr();
    for i in (0..a_repr.len()).rev() {
        if a_repr[i] != b_repr[i] {
            return a_repr[i] > b_repr[i];
        }
    }
    true
}

/// Constrain `pad_var = r - m*q` for a witness-supplied quotient
/// `m in {0,...,8}`, with `pad_var < q` (`Gin`'s own scalar modulus), so
/// `pad_var` is safe to use as a `Gin` exponent (e.g. `g_in^pad`). Returns
/// `pad_var` and its canonical `K_BITS + 1`-bit decomposition (already
/// produced internally to enforce the `pad_var < q` bound), so a caller
/// that also needs `pad_var`'s bits (e.g. for a windowed exponentiation)
/// does not have to decompose it a second time.
///
/// `m` needs 4 bits (`m <= 8 < 16`), range-checked to `m < 9` via
/// [`bit_decompose_bounded_n`]. The generic `pad < q` check alone is
/// insufficient at the boundary `m = 8`: a malicious prover could claim
/// `m = 8` for an `r` whose true quotient is smaller, and
/// `pad' = r - 8*q` (computed mod `p`) would wrap around to
/// `p - (8*q - r)`, which can alias into `[0, q)` for `r` close to `p`
/// unless ruled out separately (`p` is only barely above `8q`, so this
/// wraparound is a real risk, unlike `secp_secq`'s near-equal `p`/`q`
/// pair). The fix mirrors `secp_secq`'s own single-bit `reduce_q` case: an
/// *additional*, tighter bound `pad < p - 8q` applies whenever `m = 8`
/// (`m`'s top bit, `m_bit_vars[3]`, which the `m < 9` range check already
/// forces to imply `m = 8` exactly whenever it is set). Every other
/// `m in {0,...,7}` is safe under the generic `pad < q` bound alone,
/// because `p > 8q` rules out the analogous wraparound for those cases (see
/// `reduce_pad_soundness_tests` for the adversarial coverage).
fn reduce_pad_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    r_lc: LinearCombination<R1csField>,
    witness: Option<(R1csField, u8)>,
) -> core::result::Result<(Variable<R1csField>, Vec<Variable<R1csField>>), R1CSError> {
    let m_bit_assignments: Vec<Option<R1csField>> = (0..4)
        .map(|i| {
            witness.map(|(_, m)| {
                if (m >> i) & 1 == 1 {
                    R1csField::ONE
                } else {
                    R1csField::ZERO
                }
            })
        })
        .collect();
    let m_assignment = witness.map(|(_, m)| R1csField::from(u64::from(m)));
    let m_var = cs.allocate(m_assignment)?;
    let m_bit_vars = bit_decompose_bounded_n(cs, m_var, &m_bit_assignments, &NINE_LE, 4)?;

    let pad_assignment = witness.map(|(pad, _)| pad);
    let pad_var = cs.allocate(pad_assignment)?;
    let q = gin_scalar_modulus_as_r1cs_field();
    cs.constrain(pad_var - (r_lc - LinearCombination::from(m_var) * q));

    let pad_bit_assignments = bit_options_or_none(pad_assignment);
    let pad_bit_vars = bit_decompose_bounded_n(
        cs,
        pad_var,
        &pad_bit_assignments,
        &GIN_SCALAR_MODULUS_LE,
        K_BITS + 1,
    )?;

    constrain_bits_lt_bound_when(
        cs,
        &pad_bit_vars,
        &pad_bit_assignments,
        &R1CS_FIELD_MODULUS_MINUS_8_GIN_SCALAR_MODULUS_LE,
        m_bit_vars[3],
    )?;

    Ok((pad_var, pad_bit_vars))
}

/// Bit assignments for `value` (LSB first, `K_BITS + 1` wide), or all-`None`
/// when `value` is `None` (verifier side).
fn bit_options_or_none(value: Option<R1csField>) -> Vec<Option<R1csField>> {
    match value {
        Some(v) => {
            let mut bits = [false; K_BITS + 1];
            decompose_k_fp(&v, &mut bits);
            bit_options(&bits)
        }
        None => vec![None; K_BITS + 1],
    }
}

// ------------------------------------------------------------------
// Chaum-Pedersen proof (paper steps 0 and 1, outside R1CS).
// ------------------------------------------------------------------

fn random_nonzero_scalar<C: Cycle>(rng: &mut impl CryptoRngCore) -> C::Scalar {
    loop {
        let scalar = random_scalar::<C>(rng);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}

fn stream_challenge_scalar<C: Cycle>(stream: &mut impl Observe, label: &'static [u8]) -> C::Scalar {
    let mut bytes = [0u8; 64];
    stream.challenge(label, &mut bytes);
    C::scalar_from_wide(&bytes)
}

/// Send a Chaum-Pedersen proof of `log_{g_in}(PK_1) = log_{PK_2}(S)`.
fn chaum_pedersen_prove(
    stream: &mut ProverProofStream,
    g_in: &Gin,
    pk2: &Gin,
    sk1: &GinScalar,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let nonce = random_nonzero_scalar::<JubjubCycle>(rng);
    let r1 = *g_in * nonce;
    let r2 = *pk2 * nonce;
    stream.send_point::<GinStreamCurve>(b"cp.r1", &r1, IdentityPolicy::Reject)?;
    stream.send_point::<GinStreamCurve>(b"cp.r2", &r2, IdentityPolicy::Reject)?;
    let challenge = stream_challenge_scalar::<JubjubCycle>(stream, b"cp.challenge");
    let response = nonce + challenge * *sk1;
    stream.send_scalar::<GinStreamCurve>(b"cp.z", &response)
}

/// Receive and verify a Chaum-Pedersen proof of
/// `log_{g_in}(PK_1) = log_{PK_2}(S)`.
fn chaum_pedersen_verify(
    stream: &mut VerifierProofStream<'_>,
    g_in: &Gin,
    pk1: &Gin,
    pk2: &Gin,
    s: &Gin,
) -> Result<()> {
    let r1 = stream.receive_point::<GinStreamCurve>(b"cp.r1", IdentityPolicy::Reject)?;
    let r2 = stream.receive_point::<GinStreamCurve>(b"cp.r2", IdentityPolicy::Reject)?;
    let challenge = stream_challenge_scalar::<JubjubCycle>(stream, b"cp.challenge");
    let response = stream.receive_scalar::<GinStreamCurve>(b"cp.z")?;

    let first_equation_holds = *g_in * response == r1 + *pk1 * challenge;
    let second_equation_holds = *pk2 * response == r2 + *s * challenge;
    if !first_equation_holds || !second_equation_holds {
        return Err(Error::ProofVerificationFailed);
    }

    Ok(())
}

// ------------------------------------------------------------------
// Constant-term proof of knowledge for A_0 = a_0 * G_in.
// ------------------------------------------------------------------

/// Send a Schnorr proof of knowledge of the constant Feldman coefficient.
fn constant_term_prove(
    stream: &mut ProverProofStream,
    constant_commitment: &Gin,
    polynomial_constant: &GinScalar,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let generator = Gin::generator();
    if generator * *polynomial_constant != *constant_commitment {
        return Err(Error::ProofVerificationFailed);
    }

    let nonce = random_nonzero_scalar::<JubjubCycle>(rng);
    let nonce_commitment = generator * nonce;
    stream.send_point::<GinStreamCurve>(
        b"constant-term.a",
        &nonce_commitment,
        IdentityPolicy::Reject,
    )?;
    let challenge = stream_challenge_scalar::<JubjubCycle>(stream, b"constant-term.challenge");
    let response = nonce + challenge * *polynomial_constant;
    stream.send_scalar::<GinStreamCurve>(b"constant-term.t", &response)
}

/// Receive and verify the constant Feldman coefficient proof of knowledge.
fn constant_term_verify(
    stream: &mut VerifierProofStream<'_>,
    constant_commitment: &Gin,
) -> Result<()> {
    let nonce_commitment =
        stream.receive_point::<GinStreamCurve>(b"constant-term.a", IdentityPolicy::Reject)?;
    let challenge = stream_challenge_scalar::<JubjubCycle>(stream, b"constant-term.challenge");
    let response = stream.receive_scalar::<GinStreamCurve>(b"constant-term.t")?;

    if Gin::generator() * response != nonce_commitment + *constant_commitment * challenge {
        return Err(Error::ProofVerificationFailed);
    }

    Ok(())
}

// ------------------------------------------------------------------
// Discrete-log proof of knowledge for step 9 (R = g_out^r).
// ------------------------------------------------------------------

/// Send a Schnorr proof of knowledge of `r` such that `R = r * g_out`.
fn dlog_prove(
    stream: &mut ProverProofStream,
    g_out: &Gout,
    r: &R1csField,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let nonce = random_nonzero_scalar::<R1csCycle>(rng);
    let a = *g_out * nonce;
    stream.send_point::<GoutStreamCurve>(b"dlog.a", &a, IdentityPolicy::Reject)?;
    let challenge = stream_challenge_scalar::<R1csCycle>(stream, b"dlog.challenge");
    let response = nonce + challenge * *r;
    stream.send_scalar::<GoutStreamCurve>(b"dlog.t", &response)
}

/// Receive a Schnorr proof of knowledge of `r` and recompute its challenge.
fn dlog_verify(stream: &mut VerifierProofStream<'_>, g_out: &Gout, r_point: &Gout) -> Result<()> {
    let a = stream.receive_point::<GoutStreamCurve>(b"dlog.a", IdentityPolicy::Reject)?;
    let challenge = stream_challenge_scalar::<R1csCycle>(stream, b"dlog.challenge");
    let response = stream.receive_scalar::<GoutStreamCurve>(b"dlog.t")?;

    if *g_out * response != a + *r_point * challenge {
        return Err(Error::ProofVerificationFailed);
    }

    Ok(())
}

/// Check the Pedersen prefix link: `V_r == R + g_out,1`.
fn pedersen_prefix_link(g_out_blinding: &Gout, r_point: &Gout, v_r: &GoutCompressed) -> Result<()> {
    let expected = *r_point + *g_out_blinding;
    let expected_compressed = R1csCycle::point_compress(&expected);
    if expected_compressed.as_ref() != v_r.as_ref() {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(())
}

/// Parse a canonical R1CS proof with no trailing or non-canonical bytes.
fn parse_canonical_r1cs_proof(bytes: &[u8]) -> Result<R1CSProof<R1csCycle>> {
    let proof =
        R1CSProof::<R1csCycle>::from_bytes(bytes).map_err(|_| Error::ProofVerificationFailed)?;
    if proof.to_bytes() != bytes {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(proof)
}

/// Parse one canonical commitment prefix from the nested R1CS payload.
fn parse_nested_commitment(
    payload: &[u8],
    cursor: usize,
    identity: IdentityPolicy,
) -> Result<(GoutCompressed, usize)> {
    let end = cursor
        .checked_add(GoutStreamCurve::POINT_BYTES)
        .ok_or(Error::ProofVerificationFailed)?;
    let encoded = payload
        .get(cursor..end)
        .ok_or(Error::ProofVerificationFailed)?;
    let point = decode_point::<GoutStreamCurve>(encoded, identity)?;
    Ok((R1csCycle::point_compress(&point), end))
}

// ------------------------------------------------------------------
// Full one-receiver paper eVRF prove/verify path (paper Section 4).
//
// R1CS proves steps 2, 3, 4, 5, 8:
//   2: k = int(S.u)  (public input constraint tying committed k to S.u)
//   3: k = Sum 2^j * k_j  (bit-decomposition)
//   4: T_1 = H_{G_in,1}(msg)^k  (Edwards additive-ladder exponentiation)
//   5: T_2 = H_{G_in,2}(msg)^k  (Edwards additive-ladder exponentiation)
//   8: r = beta * r_1 + r_2  (linear, r_1 = T_1.u, r_2 = T_2.u)
// Steps 6, 7 (r_i = int(T_i.u)) are free: r_i is the u-coordinate variable
// from the exponentiation gadget.
// Steps 0, 1 (Chaum-Pedersen) and 9 (DLOG PoK + prefix link) are outside
// the R1CS, exactly as in `secp_secq`.
// ------------------------------------------------------------------

/// Bulletproofs generator capacity for the one-receiver relation. Each
/// [`edwards_add_r1cs`] call (one per bit-0 base case, one per 2-bit
/// window) costs 6 multiplier gates (see that function's doc), regardless
/// of whether the step covers 1 bit or 2, so windowing (`secp_secq`'s
/// chord-rule trick, reused here for the Edwards ladder — see the module
/// doc) roughly halves the per-bit cost: `K_BITS / 2 = 128` window steps
/// plus 1 base-case step per exponentiation, instead of `K_BITS + 1 = 257`
/// single-bit steps. For two exponentiations (`T_1`, `T_2`) sharing one set
/// of window AND products (`128` more multipliers) over one
/// `K_BITS + 1`-bit decomposition (`257` booleanity checks plus `255`
/// prefix-tracking gates — 2 of the 257 bits sit above
/// `R1CS_FIELD_MODULUS_LE`'s highest set bit and so cost no prefix-tracking
/// gate at all, see [`bit_decompose_bounded_n`] — `512` total):
/// `2 * (6 + 128 * 6) + 128 + 512 = 2188` multipliers, padded to the next
/// power of two. Checked exactly (not just bounded) in
/// `one_receiver_prover_uses_exactly_the_expected_multiplier_count`.
const R1CS_GENS_CAPACITY: usize = 4_096;

/// Process-wide cache for the single-receiver `BulletproofGens`.
fn shared_bp_gens() -> &'static BulletproofGens<R1csCycle> {
    static GEN: std::sync::OnceLock<BulletproofGens<R1csCycle>> = std::sync::OnceLock::new();
    GEN.get_or_init(|| BulletproofGens::new(R1CS_GENS_CAPACITY, 1))
}

/// Process-wide cache for the single-receiver `PedersenGens`.
fn shared_pc_gens() -> &'static PedersenGens<R1csCycle> {
    static GEN: std::sync::OnceLock<PedersenGens<R1csCycle>> = std::sync::OnceLock::new();
    GEN.get_or_init(PedersenGens::default)
}

/// Process-wide cache for `g_in`'s windowed additive-ladder precompute.
fn shared_g_in_window_precomp() -> &'static EdwardsWindowPrecomp {
    static PRECOMP: std::sync::OnceLock<EdwardsWindowPrecomp> = std::sync::OnceLock::new();
    PRECOMP.get_or_init(|| {
        precompute_windowed_base_powers(&Gin::generator())
            .expect("the generator is not the identity")
    })
}

/// Random-oracle domain tag for `H_{G_in,1}`.
const H_GIN_1_DOMAIN: &[u8] = b"golden-paper-evrf-bls-jubjub-H-Gin-1-v1";
/// Random-oracle domain tag for `H_{G_in,2}`.
const H_GIN_2_DOMAIN: &[u8] = b"golden-paper-evrf-bls-jubjub-H-Gin-2-v1";

/// Derive a domain-separated 64-byte seed for
/// [`golden_bls_jubjub::JubjubCycle::point_hash_from_uniform`], which takes
/// a single 64-byte buffer with no separate domain-tag parameter (unlike
/// `halo2curves::CurveExt::hash_to_curve(domain)(message)`'s two-stage API).
fn h_gin_seed(domain: &[u8], msg: &[u8; MESSAGE_BYTES]) -> [u8; 64] {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, domain);
    sha2::Digest::update(&mut hasher, msg);
    sha2::Digest::update(&mut hasher, [0u8]);
    let first: [u8; 32] = sha2::Digest::finalize(hasher).into();

    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, domain);
    sha2::Digest::update(&mut hasher, msg);
    sha2::Digest::update(&mut hasher, [1u8]);
    let second: [u8; 32] = sha2::Digest::finalize(hasher).into();

    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&first);
    seed[32..].copy_from_slice(&second);
    seed
}

/// Compute `H_{G_in,1}(msg)` as a `G_in` point.
fn h_gin_1(msg: &[u8; MESSAGE_BYTES]) -> Gin {
    JubjubCycle::point_hash_from_uniform(&h_gin_seed(H_GIN_1_DOMAIN, msg))
}

/// Compute `H_{G_in,2}(msg)` as a `G_in` point.
fn h_gin_2(msg: &[u8; MESSAGE_BYTES]) -> Gin {
    JubjubCycle::point_hash_from_uniform(&h_gin_seed(H_GIN_2_DOMAIN, msg))
}

/// Build the R1CS constraints for the one-receiver relation.
#[allow(clippy::too_many_arguments)]
fn build_one_receiver_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    var_k: Variable<R1csField>,
    var_r: Variable<R1csField>,
    s_u: R1csField,
    h1: &Gin,
    h2: &Gin,
    t1_u: R1csField,
    t1_v: R1csField,
    t2_u: R1csField,
    t2_v: R1csField,
    beta: R1csField,
    bit_assignments: &[Option<R1csField>],
    witness1: Option<&EdwardsWindowWitness>,
    witness2: Option<&EdwardsWindowWitness>,
) -> core::result::Result<(), R1CSError> {
    cs.constrain(var_k - s_u);

    let bit_vars = bit_decompose(cs, var_k, bit_assignments)?;
    // k's window AND products are shared by both exponentiations below
    // (T_1 = H1^k, T_2 = H2^k), which reuse the same bit vector.
    let k_window_products = edwards_window_products(cs, &bit_vars)?;

    let precomp1 = precompute_windowed_base_powers(h1).map_err(|_| R1CSError::VerificationError)?;
    let precomp2 = precompute_windowed_base_powers(h2).map_err(|_| R1CSError::VerificationError)?;

    let (x_t1, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &bit_vars,
        &k_window_products,
        &precomp1,
        Some((t1_u, t1_v)),
        witness1,
    )?;
    let (x_t2, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &bit_vars,
        &k_window_products,
        &precomp2,
        Some((t2_u, t2_v)),
        witness2,
    )?;

    cs.constrain(var_r - (x_t1 * beta + x_t2));

    Ok(())
}

/// Generate the full one-receiver paper eVRF proof.
pub fn evrf_prove(
    statement: &BlsJubjubEvrfStatement,
    witness: &BlsJubjubEvrfWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let g_in = Gin::generator();
    let mut stream = ProverProofStream::new(ONE_RECEIVER_PROOF_ID)?;
    observe_one_receiver_statement(&mut stream, statement)?;

    let s_computed = statement.pk2 * witness.sk1;
    if JubjubCycle::point_compress(&s_computed).as_ref()
        != JubjubCycle::point_compress(&statement.s).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }

    let (s_u, _) = affine(&statement.s)?;
    let k = s_u;

    let h1 = h_gin_1(&statement.msg);
    let h2 = h_gin_2(&statement.msg);
    if JubjubCycle::point_compress(&h1).as_ref()
        != JubjubCycle::point_compress(&statement.h1).as_ref()
        || JubjubCycle::point_compress(&h2).as_ref()
            != JubjubCycle::point_compress(&statement.h2).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }

    let mut bits = [false; K_BITS + 1];
    decompose_k_fp(&k, &mut bits);
    let bit_assignments = bit_options(&bits);

    let witness1 = edwards_windowed_ladder_witness(&bits, &base_power_points(&h1))?;
    let witness2 = edwards_windowed_ladder_witness(&bits, &base_power_points(&h2))?;

    let (t1_u, t1_v) = *witness1
        .window_results
        .last()
        .ok_or(Error::ProofVerificationFailed)?;
    let (t2_u, t2_v) = *witness2
        .window_results
        .last()
        .ok_or(Error::ProofVerificationFailed)?;

    let r = statement.beta * t1_u + t2_u;

    let g_out = Gout::generator();
    let r_computed = g_out * r;
    if R1csCycle::point_compress(&r_computed).as_ref()
        != R1csCycle::point_compress(&statement.r_point).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }

    chaum_pedersen_prove(&mut stream, &g_in, &statement.pk2, &witness.sk1, rng)?;

    let pc_gens = shared_pc_gens();
    let bp_gens = shared_bp_gens();
    stream.send_nested(|transcript| {
        let k_blinding = random_scalar::<R1csCycle>(rng);
        let r_blinding = R1csField::ONE;
        let mut prover = Prover::<R1csCycle, _>::new(pc_gens, transcript);
        let (v_k, var_k) = prover.commit(k, k_blinding);
        let (v_r, var_r) = prover.commit(r, r_blinding);
        build_one_receiver_r1cs(
            &mut prover,
            var_k,
            var_r,
            s_u,
            &h1,
            &h2,
            t1_u,
            t1_v,
            t2_u,
            t2_v,
            statement.beta,
            &bit_assignments,
            Some(&witness1),
            Some(&witness2),
        )
        .map_err(|_| Error::ProofVerificationFailed)?;
        let r1cs_proof = prover
            .prove(bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        let r1cs_bytes = r1cs_proof.to_bytes();
        let prefix_bytes = 2usize
            .checked_mul(R1csCycle::COMPRESSED_BYTES)
            .ok_or(Error::ProofVerificationFailed)?;
        let capacity = prefix_bytes
            .checked_add(r1cs_bytes.len())
            .ok_or(Error::ProofVerificationFailed)?;
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(R1csCycle::compressed_as_bytes(&v_k));
        payload.extend_from_slice(R1csCycle::compressed_as_bytes(&v_r));
        payload.extend_from_slice(&r1cs_bytes);
        Ok(payload)
    })?;

    dlog_prove(&mut stream, &g_out, &r, rng)?;

    Ok(stream.finish())
}

/// Verify the full one-receiver paper eVRF proof.
pub fn evrf_verify(
    statement: &BlsJubjubEvrfStatement,
    proof: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let g_in = Gin::generator();
    let g_out = Gout::generator();
    let pc_gens = shared_pc_gens();
    let bp_gens = shared_bp_gens();
    let mut stream = VerifierProofStream::new(ONE_RECEIVER_PROOF_ID, proof)?;
    observe_one_receiver_statement(&mut stream, statement)?;

    chaum_pedersen_verify(
        &mut stream,
        &g_in,
        &statement.pk1,
        &statement.pk2,
        &statement.s,
    )?;

    let (s_u, _) = affine(&statement.s)?;

    let h1 = h_gin_1(&statement.msg);
    let h2 = h_gin_2(&statement.msg);
    if JubjubCycle::point_compress(&h1).as_ref()
        != JubjubCycle::point_compress(&statement.h1).as_ref()
        || JubjubCycle::point_compress(&h2).as_ref()
            != JubjubCycle::point_compress(&statement.h2).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }

    let (t1_u, t1_v) = affine(&statement.t1)?;
    let (t2_u, t2_v) = affine(&statement.t2)?;

    stream.receive_nested(|transcript, payload| {
        let (v_k, cursor) = parse_nested_commitment(payload, 0, IdentityPolicy::Allow)?;
        let (v_r, cursor) = parse_nested_commitment(payload, cursor, IdentityPolicy::Allow)?;
        let r1cs_bytes = payload
            .get(cursor..)
            .ok_or(Error::ProofVerificationFailed)?;
        let r1cs_proof = parse_canonical_r1cs_proof(r1cs_bytes)?;

        pedersen_prefix_link(&pc_gens.B_blinding, &statement.r_point, &v_r)?;

        let mut verifier = Verifier::<R1csCycle, _>::new(transcript);
        let var_k = verifier.commit(v_k);
        let var_r = verifier.commit(v_r);
        let verifier_bits = vec![None; K_BITS + 1];
        build_one_receiver_r1cs(
            &mut verifier,
            var_k,
            var_r,
            s_u,
            &h1,
            &h2,
            t1_u,
            t1_v,
            t2_u,
            t2_v,
            statement.beta,
            &verifier_bits,
            None,
            None,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        verifier
            .verify(&r1cs_proof, pc_gens, bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)
    })?;

    dlog_verify(&mut stream, &g_out, &statement.r_point)?;

    stream.finish()
}

// ------------------------------------------------------------------
// Batched statement validation and transcript binding.
// ------------------------------------------------------------------

fn validate_batched_statement_shape(statement: &BatchedEvrfStatement) -> Result<()> {
    if statement.receivers.is_empty()
        || statement.receivers.len() < statement.threshold.saturating_sub(1)
        || statement.commitment_coefficients.is_empty()
        || statement.commitment_coefficients.len() != statement.threshold
        || statement.statement_roots.len() != statement.receivers.len()
    {
        return Err(Error::ProofVerificationFailed);
    }
    if statement
        .receivers
        .windows(2)
        .any(|pair| pair[0].receiver >= pair[1].receiver)
    {
        return Err(Error::ProofVerificationFailed);
    }
    Ok(())
}

fn validate_batched_public_relations(statement: &BatchedEvrfStatement) -> Result<()> {
    validate_batched_statement_shape(statement)?;
    if is_identity(&statement.pk1) {
        return Err(Error::ProofVerificationFailed);
    }
    statement.receivers.par_iter().try_for_each(|rec| {
        if is_identity(&rec.pkj)
            || is_identity(&rec.share_commitment)
            || is_identity(&rec.pad_commitment)
        {
            return Err(Error::ProofVerificationFailed);
        }
        if feldman_share_commitment(&statement.commitment_coefficients, rec.receiver)
            != rec.share_commitment
        {
            return Err(Error::ProofVerificationFailed);
        }
        if Gin::generator() * rec.encrypted_share != rec.share_commitment + rec.pad_commitment {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    })
}

/// Variable-time double-and-add multiplication by a small scalar.
fn mul_by_small_scalar(point: &Gin, scalar: u32) -> Gin {
    if scalar == 0 {
        return Gin::identity();
    }
    let mut acc = Gin::identity();
    for bit in (0..u32::BITS - scalar.leading_zeros()).rev() {
        acc = acc.double();
        if (scalar >> bit) & 1 == 1 {
            acc += *point;
        }
    }
    acc
}

/// Evaluate the Feldman commitment at `receiver` via Horner's method.
fn feldman_share_commitment(coefficients: &[Gin], receiver: ParticipantIndex) -> Gin {
    let x = receiver.get();
    let mut result = Gin::identity();
    for coefficient in coefficients.iter().rev() {
        result = mul_by_small_scalar(&result, x) + *coefficient;
    }
    result
}

/// Observe the complete batched dealer statement in its canonical order.
fn observe_batched_statement(
    stream: &mut impl Observe,
    statement: &BatchedEvrfStatement,
) -> Result<()> {
    stream.observe_bytes(b"msg", &statement.msg);
    stream.observe_scalar::<GoutStreamCurve>(b"beta", &statement.beta)?;
    stream.observe_bytes(b"threshold", &(statement.threshold as u64).to_le_bytes());
    stream.observe_point::<GinStreamCurve>(b"PK_1", &statement.pk1, IdentityPolicy::Reject)?;
    stream.observe_bytes(
        b"commitment-len",
        &(statement.commitment_coefficients.len() as u64).to_le_bytes(),
    );
    for coefficient in &statement.commitment_coefficients {
        stream.observe_point::<GinStreamCurve>(
            b"commitment",
            coefficient,
            IdentityPolicy::Allow,
        )?;
    }
    stream.observe_bytes(
        b"num-receivers",
        &(statement.receivers.len() as u64).to_le_bytes(),
    );
    for (j, rec) in statement.receivers.iter().enumerate() {
        stream.observe_bytes(b"idx", &(j as u64).to_le_bytes());
        stream.observe_bytes(b"statement-root", &statement.statement_roots[j]);
        stream.observe_bytes(b"receiver", &u64::from(rec.receiver.get()).to_le_bytes());
        stream.observe_point::<GinStreamCurve>(b"PK_j", &rec.pkj, IdentityPolicy::Reject)?;
        stream.observe_point::<GinStreamCurve>(
            b"share-commitment",
            &rec.share_commitment,
            IdentityPolicy::Reject,
        )?;
        stream.observe_point::<GinStreamCurve>(
            b"pad-commitment",
            &rec.pad_commitment,
            IdentityPolicy::Reject,
        )?;
        stream.observe_scalar::<GinStreamCurve>(b"encrypted-share", &rec.encrypted_share)?;
    }
    Ok(())
}

// ------------------------------------------------------------------
// Batched R1CS relation and prove/verify path.
// ------------------------------------------------------------------

/// Multipliers shared by every batched circuit: the dealer secret's
/// canonical bit decomposition and the `g^sk = PK_1` exponentiation. Exact
/// (not a margin — an earlier "generously rounded" guess here was actually
/// *below* the real per-receiver cost, silently relying on
/// `gens_capacity`'s power-of-two rounding to paper over the gap; that
/// happened to still round to a sufficient capacity for every shape this
/// crate tests, but was one bad receiver-count away from a hard proving
/// failure). Measured and pinned exactly in
/// `batched_multiplier_count_matches_real_circuit_shape`, which also checks
/// this formula's prediction covers the real count for several shapes.
const BATCHED_SHARED_MULTIPLIERS: usize = 1_412;
/// Multipliers added by one receiver relation (S_j exponentiation, k
/// bit-decompose, T_1/T_2 exponentiations, pad reduction, pad-commitment
/// exponentiation). Exact, same rationale as [`BATCHED_SHARED_MULTIPLIERS`].
/// `reduce_pad_r1cs`'s own bit decomposition of `pad_var` is reused
/// directly for the pad-commitment exponentiation below, instead of
/// decomposing `pad_var` a second time.
const BATCHED_RECEIVER_MULTIPLIERS: usize = 4_574;

/// Count multipliers from the exact public circuit shape.
fn batched_multiplier_count(threshold: usize, receiver_count: usize) -> Result<usize> {
    if threshold == 0 || receiver_count == 0 || receiver_count < threshold.saturating_sub(1) {
        return Err(Error::ProofVerificationFailed);
    }
    let receivers = receiver_count
        .checked_mul(BATCHED_RECEIVER_MULTIPLIERS)
        .ok_or(Error::ProofVerificationFailed)?;
    BATCHED_SHARED_MULTIPLIERS
        .checked_add(receivers)
        .ok_or(Error::ProofVerificationFailed)
}

#[derive(Clone, Debug)]
struct HiddenReceiverWitness {
    /// Additive-ladder witness for `S_j = PK_j^sk_1`.
    sk_pkj: EdwardsWindowWitness,
    /// Bits of `k_j = int(S_j.u)`.
    k_bits: Vec<Option<R1csField>>,
    /// Additive-ladder witness for `T_{1,j} = H1(msg)^k_j`.
    t1: EdwardsWindowWitness,
    /// Additive-ladder witness for `T_{2,j} = H2(msg)^k_j`.
    t2: EdwardsWindowWitness,
    /// `pad_j = beta * T_{1,j}.u + T_{2,j}.u`, reduced into `Gin`'s scalar
    /// range, and the reduction quotient. `reduce_pad_r1cs` bit-decomposes
    /// `pad` itself as part of enforcing `pad < q`, so no separate bit
    /// vector is carried here.
    pad: R1csField,
    m: u8,
    /// Additive-ladder witness for `g_in^pad_j`.
    pad_commitment: EdwardsWindowWitness,
}

#[allow(clippy::too_many_arguments)]
fn build_hidden_receiver_slot<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    rec: &BatchedReceiverStatement,
    sk_bit_vars: &[Variable<R1csField>],
    sk_window_products: &[Variable<R1csField>],
    precomp_h1: &EdwardsWindowPrecomp,
    precomp_h2: &EdwardsWindowPrecomp,
    beta: R1csField,
    witness: Option<&HiddenReceiverWitness>,
) -> core::result::Result<(), R1CSError> {
    let precomp_pkj =
        precompute_windowed_base_powers(&rec.pkj).map_err(|_| R1CSError::VerificationError)?;
    let (s_u, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        sk_bit_vars,
        sk_window_products,
        &precomp_pkj,
        None,
        witness.map(|w| &w.sk_pkj),
    )?;

    let verifier_k_bits = vec![None; K_BITS + 1];
    let k_bits = witness.map_or(verifier_k_bits.as_slice(), |w| w.k_bits.as_slice());
    let k_bit_vars = bit_decompose(cs, s_u, k_bits)?;
    // k's window AND products are shared by both exponentiations below
    // (T_1 = H1^k, T_2 = H2^k), which reuse the same bit vector.
    let k_window_products = edwards_window_products(cs, &k_bit_vars)?;

    let (x_t1, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &k_bit_vars,
        &k_window_products,
        precomp_h1,
        None,
        witness.map(|w| &w.t1),
    )?;
    let (x_t2, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &k_bit_vars,
        &k_window_products,
        precomp_h2,
        None,
        witness.map(|w| &w.t2),
    )?;

    let r_lc = x_t1 * beta + x_t2;
    // `reduce_pad_r1cs` already bit-decomposes `pad_var` (to enforce
    // `pad_var < q`); its bit vars are exactly `pad_var`'s canonical
    // decomposition, so the windowed exponentiation below reuses them
    // instead of decomposing `pad_var` a second time.
    let (_pad_var, pad_bit_vars) = reduce_pad_r1cs(cs, r_lc, witness.map(|w| (w.pad, w.m)))?;
    let pad_window_products = edwards_window_products(cs, &pad_bit_vars)?;

    let precomp_g_in = shared_g_in_window_precomp();
    let (pad_commitment_u, pad_commitment_v) =
        affine(&rec.pad_commitment).map_err(|_| R1CSError::VerificationError)?;
    edwards_exponentiate_windowed_r1cs(
        cs,
        &pad_bit_vars,
        &pad_window_products,
        precomp_g_in,
        Some((pad_commitment_u, pad_commitment_v)),
        witness.map(|w| &w.pad_commitment),
    )?;

    Ok(())
}

fn compute_hidden_receiver_witness(
    sk1: &GinScalar,
    rec: &BatchedReceiverStatement,
    beta: &R1csField,
    h1: &Gin,
    h2: &Gin,
) -> Result<HiddenReceiverWitness> {
    let g_in = Gin::generator();
    let sj = rec.pkj * *sk1;
    let (s_u, _) = affine(&sj)?;
    let mut k_bool_bits = [false; K_BITS + 1];
    decompose_k_fp(&s_u, &mut k_bool_bits);
    let k_bits = bit_options(&k_bool_bits);

    let t1_witness = edwards_windowed_ladder_witness(&k_bool_bits, &base_power_points(h1))?;
    let t2_witness = edwards_windowed_ladder_witness(&k_bool_bits, &base_power_points(h2))?;
    let (t1_u, _) = *t1_witness
        .window_results
        .last()
        .ok_or(Error::ProofVerificationFailed)?;
    let (t2_u, _) = *t2_witness
        .window_results
        .last()
        .ok_or(Error::ProofVerificationFailed)?;

    let r = *beta * t1_u + t2_u;
    let (pad, m) = reduce_pad_witness(&r);
    let pad_fr = fp_to_fr(&pad);

    let pad_commitment = g_in * pad_fr;
    if JubjubCycle::point_compress(&pad_commitment).as_ref()
        != JubjubCycle::point_compress(&rec.pad_commitment).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }

    let mut sk_bits = [false; K_BITS + 1];
    decompose_k_fp(&fr_to_fp(sk1), &mut sk_bits);
    let mut pad_bool_bits = [false; K_BITS + 1];
    decompose_k_fp(&pad, &mut pad_bool_bits);

    Ok(HiddenReceiverWitness {
        sk_pkj: edwards_windowed_ladder_witness(&sk_bits, &base_power_points(&rec.pkj))?,
        k_bits,
        t1: t1_witness,
        t2: t2_witness,
        pad,
        m,
        pad_commitment: edwards_windowed_ladder_witness(&pad_bool_bits, &base_power_points(&g_in))?,
    })
}

fn prove_batched_r1cs(
    params: &BatchedEvrfPublicParams,
    statement: &BatchedEvrfStatement,
    witness: &BatchedEvrfWitness,
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
) -> Result<Vec<u8>> {
    let g_in = Gin::generator();

    let pk1_computed = g_in * witness.sk1;
    if JubjubCycle::point_compress(&pk1_computed).as_ref()
        != JubjubCycle::point_compress(&statement.pk1).as_ref()
    {
        return Err(Error::ProofVerificationFailed);
    }
    let h1 = h_gin_1(&statement.msg);
    let h2 = h_gin_2(&statement.msg);
    // h1/h2's chord tables are receiver-independent; compute once and
    // share across every receiver slot below instead of rebuilding them
    // once per receiver.
    let precomp_h1 = precompute_windowed_base_powers(&h1)?;
    let precomp_h2 = precompute_windowed_base_powers(&h2)?;

    let mut prover = Prover::<R1csCycle, _>::new(&params.pc_gens, transcript);
    let sk_fp = fr_to_fp(&witness.sk1);
    let mut sk_bool_bits = [false; K_BITS + 1];
    decompose_k_fp(&sk_fp, &mut sk_bool_bits);
    let sk_bit_assignments = bit_options(&sk_bool_bits);
    let sk_var = prover
        .allocate(Some(sk_fp))
        .map_err(|_| Error::ProofVerificationFailed)?;
    let sk_bit_vars = bit_decompose_q(&mut prover, sk_var, &sk_bit_assignments)
        .map_err(|_| Error::ProofVerificationFailed)?;
    // sk's window AND products are shared by PK_1 = g_in^sk below and
    // every receiver's S_j = PK_j^sk exponentiation in the loop below.
    let sk_window_products = edwards_window_products(&mut prover, &sk_bit_vars)
        .map_err(|_| Error::ProofVerificationFailed)?;

    let pk1_witness = edwards_windowed_ladder_witness(&sk_bool_bits, &base_power_points(&g_in))?;
    let precomp_g_in = shared_g_in_window_precomp();
    let (pk1_u, pk1_v) = affine(&statement.pk1)?;
    edwards_exponentiate_windowed_r1cs(
        &mut prover,
        &sk_bit_vars,
        &sk_window_products,
        precomp_g_in,
        Some((pk1_u, pk1_v)),
        Some(&pk1_witness),
    )
    .map_err(|_| Error::ProofVerificationFailed)?;

    for rec in &statement.receivers {
        let rec_witness =
            compute_hidden_receiver_witness(&witness.sk1, rec, &statement.beta, &h1, &h2)?;
        build_hidden_receiver_slot(
            &mut prover,
            rec,
            &sk_bit_vars,
            &sk_window_products,
            &precomp_h1,
            &precomp_h2,
            statement.beta,
            Some(&rec_witness),
        )
        .map_err(|_| Error::ProofVerificationFailed)?;
    }

    let r1cs_proof = prover
        .prove(&params.bp_gens, rng)
        .map_err(|_| Error::ProofVerificationFailed)?;

    Ok(r1cs_proof.to_bytes())
}

/// Generate a Batched Dealer Proof containing a nested R1CS proof followed
/// by a native constant-term Schnorr proof on the same transcript.
pub fn evrf_batched_prove(
    params: &BatchedEvrfPublicParams,
    statement: &BatchedEvrfStatement,
    witness: &BatchedEvrfWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    params.validate_statement(statement)?;
    validate_batched_public_relations(statement)?;
    let mut stream = ProverProofStream::new(BATCHED_PROOF_ID)?;
    observe_batched_statement(&mut stream, statement)?;
    stream.send_nested(|transcript| {
        prove_batched_r1cs(params, statement, witness, rng, transcript)
    })?;
    constant_term_prove(
        &mut stream,
        &statement.commitment_coefficients[0],
        &witness.polynomial_constant,
        rng,
    )?;
    Ok(stream.finish())
}

fn build_batched_verifier<T>(
    statement: &BatchedEvrfStatement,
    transcript: T,
) -> Result<Verifier<R1csCycle, T>>
where
    T: core::borrow::BorrowMut<Transcript>,
{
    let h1 = h_gin_1(&statement.msg);
    let h2 = h_gin_2(&statement.msg);
    let precomp_h1 = precompute_windowed_base_powers(&h1)?;
    let precomp_h2 = precompute_windowed_base_powers(&h2)?;

    let mut verifier = Verifier::<R1csCycle, _>::new(transcript);
    let sk_var = verifier
        .allocate(None)
        .map_err(|_| Error::ProofVerificationFailed)?;
    let verifier_sk_bits = vec![None; K_BITS + 1];
    let sk_bit_vars = bit_decompose_q(&mut verifier, sk_var, &verifier_sk_bits)
        .map_err(|_| Error::ProofVerificationFailed)?;
    let sk_window_products = edwards_window_products(&mut verifier, &sk_bit_vars)
        .map_err(|_| Error::ProofVerificationFailed)?;

    let precomp_g_in = shared_g_in_window_precomp();
    let (pk1_u, pk1_v) = affine(&statement.pk1)?;
    edwards_exponentiate_windowed_r1cs(
        &mut verifier,
        &sk_bit_vars,
        &sk_window_products,
        precomp_g_in,
        Some((pk1_u, pk1_v)),
        None,
    )
    .map_err(|_| Error::ProofVerificationFailed)?;

    for rec in &statement.receivers {
        build_hidden_receiver_slot(
            &mut verifier,
            rec,
            &sk_bit_vars,
            &sk_window_products,
            &precomp_h1,
            &precomp_h2,
            statement.beta,
            None,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;
    }

    Ok(verifier)
}

fn prepare_batched_r1cs(
    params: &BatchedEvrfPublicParams,
    statement: &BatchedEvrfStatement,
    proof: &R1CSProof<R1csCycle>,
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
) -> Result<VerificationEquation<R1csCycle>> {
    let verifier = build_batched_verifier(statement, transcript)?;
    verifier
        .verification_equation(proof, &params.pc_gens, &params.bp_gens, rng)
        .map_err(|_| Error::ProofVerificationFailed)
}

fn prepare_batched_proof(
    params: &BatchedEvrfPublicParams,
    statement: &BatchedEvrfStatement,
    proof: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<VerificationEquation<R1csCycle>> {
    let mut stream = VerifierProofStream::new(BATCHED_PROOF_ID, proof)?;
    observe_batched_statement(&mut stream, statement)?;
    let equation = stream.receive_nested(|transcript, payload| {
        let r1cs_proof = parse_canonical_r1cs_proof(payload)?;
        prepare_batched_r1cs(params, statement, &r1cs_proof, rng, transcript)
    })?;
    constant_term_verify(&mut stream, &statement.commitment_coefficients[0])?;
    stream.finish()?;
    Ok(equation)
}

/// Verify a Batched Dealer Proof represented as a nested R1CS proof and a
/// trailing native constant-term Schnorr proof.
pub fn evrf_batched_verify(
    params: &BatchedEvrfPublicParams,
    statement: &BatchedEvrfStatement,
    proof: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    params.validate_statement(statement)?;
    validate_batched_public_relations(statement)?;
    let equation = prepare_batched_proof(params, statement, proof, rng)?;
    equation
        .verify()
        .map_err(|_| Error::ProofVerificationFailed)
}

/// Derive an independent per-proof RNG seed from the batch seed and the
/// proof's index.
fn per_proof_seed(batch_seed: &[u8; 32], index: usize) -> [u8; 32] {
    let mut transcript = Transcript::new(b"golden-paper-evrf-bls-jubjub-proof-batch-v1-per-proof");
    transcript.append_message(b"batch-seed", batch_seed);
    transcript.append_u64(b"proof-index", index as u64);
    let mut seed = [0u8; 32];
    transcript.challenge_bytes(b"proof-rng", &mut seed);
    seed
}

/// Verify several independent Batched Dealer Proofs with one shared MSM.
pub fn evrf_batched_verify_many(
    params: &BatchedEvrfPublicParams,
    instances: &[(&BatchedEvrfStatement, &[u8])],
) -> Result<()> {
    if instances.is_empty() {
        return Err(Error::ProofVerificationFailed);
    }
    for (statement, _) in instances {
        params.validate_statement(statement)?;
        validate_batched_public_relations(statement)?;
    }
    let mut batch_transcript = Transcript::new(b"golden-paper-evrf-bls-jubjub-proof-batch-v1");
    batch_transcript.append_u64(b"batch-len", instances.len() as u64);
    for (index, (statement, proof)) in instances.iter().enumerate() {
        batch_transcript.append_u64(b"proof-index", index as u64);
        observe_batched_statement(&mut batch_transcript, statement)?;
        batch_transcript.append_u64(b"proof-len", proof.len() as u64);
        batch_transcript.append_message(b"proof", proof);
    }
    let mut seed = [0u8; 32];
    batch_transcript.challenge_bytes(b"batch-rng", &mut seed);

    let equations = instances
        .par_iter()
        .enumerate()
        .map(|(index, (statement, proof))| {
            let mut proof_rng = ChaCha20Rng::from_seed(per_proof_seed(&seed, index));
            prepare_batched_proof(params, statement, proof, &mut proof_rng)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut rng = ChaCha20Rng::from_seed(seed);
    VerificationEquation::verify_batch(equations, &mut rng)
        .map_err(|_| Error::ProofVerificationFailed)
}

mod dkg_backend;

pub use dkg_backend::BlsJubjubBackend;

/// Test-only helpers exposed so integration tests under `tests/` can build
/// honest statements without re-implementing the protocol's derivation.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Build a valid `(statement, witness)` pair for the one-receiver
    /// relation, deriving all public values from `sk1`, `pk2`, `msg`, and
    /// `beta`. Mirrors the steps the prover runs internally.
    pub fn build_statement_witness(
        msg: &[u8; MESSAGE_BYTES],
        sk1: GinScalar,
        pk2: Gin,
        beta: R1csField,
    ) -> (BlsJubjubEvrfStatement, BlsJubjubEvrfWitness) {
        let g_in = Gin::generator();

        let pk1 = g_in * sk1;
        let s = pk2 * sk1;
        #[allow(clippy::unwrap_used)]
        let (k, _) = affine(&s).expect("S affine");
        let k_fr = fp_to_fr(&k);

        let h1 = h_gin_1(msg);
        let h2 = h_gin_2(msg);
        let t1 = h1 * k_fr;
        let t2 = h2 * k_fr;

        #[allow(clippy::unwrap_used)]
        let (t1_u, _) = affine(&t1).expect("T1 affine");
        #[allow(clippy::unwrap_used)]
        let (t2_u, _) = affine(&t2).expect("T2 affine");
        let r = beta * t1_u + t2_u;

        let g_out = Gout::generator();
        let r_point = g_out * r;

        let statement = BlsJubjubEvrfStatement {
            msg: *msg,
            pk1,
            pk2,
            s,
            h1,
            h2,
            t1,
            t2,
            r_point,
            beta,
        };
        let witness = BlsJubjubEvrfWitness { sk1 };
        (statement, witness)
    }

    /// Build a valid batched `(statement, witness)` pair for `n` receivers
    /// (one per `pkj`), deriving all public values from `sk1` and the
    /// receiver public keys.
    pub fn build_batched(
        msg: &[u8; MESSAGE_BYTES],
        sk1: GinScalar,
        pkjs: &[Gin],
        beta: R1csField,
    ) -> (BatchedEvrfStatement, BatchedEvrfWitness) {
        let g_in = Gin::generator();
        let pk1 = g_in * sk1;
        let h1 = h_gin_1(msg);
        let h2 = h_gin_2(msg);
        let commitment_coefficients = vec![g_in * GinScalar::from(10u64), g_in];

        let receivers: Vec<BatchedReceiverStatement> = pkjs
            .iter()
            .enumerate()
            .map(|(j, &pkj)| {
                let sj = pkj * sk1;
                #[allow(clippy::unwrap_used)]
                let (k, _) = affine(&sj).expect("S affine");
                let k_fr = fp_to_fr(&k);
                let t1j = h1 * k_fr;
                let t2j = h2 * k_fr;
                #[allow(clippy::unwrap_used)]
                let (t1_u, _) = affine(&t1j).expect("T1 affine");
                #[allow(clippy::unwrap_used)]
                let (t2_u, _) = affine(&t2j).expect("T2 affine");
                let r = beta * t1_u + t2_u;
                let pad = fp_to_fr(&r);
                #[allow(clippy::unwrap_used)]
                let receiver =
                    ParticipantIndex::new((j as u32) + 1).expect("nonzero receiver index");
                let share = GinScalar::from((j as u64) + 11);
                BatchedReceiverStatement {
                    receiver,
                    pkj,
                    share_commitment: g_in * share,
                    pad_commitment: g_in * pad,
                    encrypted_share: share + pad,
                }
            })
            .collect();

        let statement = BatchedEvrfStatement {
            msg: *msg,
            pk1,
            beta,
            threshold: commitment_coefficients.len(),
            commitment_coefficients,
            statement_roots: (0..receivers.len())
                .map(|j| {
                    let mut root = [0u8; 32];
                    root[..8].copy_from_slice(&(j as u64).to_le_bytes());
                    root
                })
                .collect(),
            receivers,
        };
        let witness = BatchedEvrfWitness {
            sk1,
            polynomial_constant: GinScalar::from(10u64),
        };
        (statement, witness)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod field_constant_tests {
    use super::*;

    #[test]
    fn edwards_d_matches_its_defining_fraction() {
        // d = -(10240/10241), independently derived (not from the raw
        // limbs edwards_d() reconstructs) to cross-check the constant.
        let numerator = -R1csField::from(10240u64);
        let denominator = R1csField::from(10241u64);
        let expected = numerator * denominator.invert().unwrap();
        assert_eq!(edwards_d(), expected);
    }

    #[test]
    fn edwards_curve_equation_holds_for_generator() {
        let g = Gin::generator();
        let (u, v) = affine(&g).unwrap();
        let a = edwards_a();
        let d = edwards_d();
        let lhs = a * u * u + v * v;
        let rhs = R1csField::ONE + d * u * u * v * v;
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn gin_scalar_modulus_constant_matches_jubjub_fr() {
        let expected = fr_to_fp(&(-GinScalar::ONE)) + R1csField::ONE;
        assert_eq!(gin_scalar_modulus_as_r1cs_field(), expected);
    }

    #[test]
    fn fp_to_fr_and_back_round_trips_for_small_values() {
        let small = R1csField::from(12345u64);
        let as_fr = fp_to_fr(&small);
        assert_eq!(fr_to_fp(&as_fr), small);
    }

    #[test]
    fn reduce_pad_witness_matches_fp_to_fr() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for _ in 0..32 {
            let r = R1csField::random(&mut rng);
            let (pad, m) = reduce_pad_witness(&r);
            assert!(m <= 8);
            let q = gin_scalar_modulus_as_r1cs_field();
            assert_eq!(pad + R1csField::from(u64::from(m)) * q, r);
            assert_eq!(fp_to_fr(&pad), fp_to_fr(&r));
        }
    }
}

/// Adversarial coverage for `reduce_pad_r1cs`'s `m = 8` wraparound argument
/// (see that function's doc comment for the soundness argument these tests
/// exercise).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod reduce_pad_soundness_tests {
    use super::*;
    use bulletproofs_cycle::r1cs::{Prover, Verifier};

    /// Drive `reduce_pad_r1cs` alone: commit `r`, run the gadget with the
    /// supplied `(pad, m)` witness, prove, then verify. Returns whether the
    /// proof both built and verified.
    fn run(r: R1csField, witness: (R1csField, u8)) -> bool {
        let pc_gens = PedersenGens::<R1csCycle>::default();
        let bp_gens = BulletproofGens::<R1csCycle>::new(2048, 1);

        let mut transcript = Transcript::new(b"reduce-pad-soundness");
        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let (v_r, var_r) = prover.commit(r, R1csField::from(9u64));
        if reduce_pad_r1cs(&mut prover, var_r.into(), Some(witness)).is_err() {
            return false;
        }
        let Ok(proof) = prover.prove(&bp_gens, &mut ChaCha20Rng::seed_from_u64(1)) else {
            return false;
        };

        let mut transcript = Transcript::new(b"reduce-pad-soundness");
        let mut verifier = Verifier::<R1csCycle, _>::new(&mut transcript);
        let var_r = verifier.commit(v_r);
        reduce_pad_r1cs(&mut verifier, var_r.into(), None).unwrap();
        verifier
            .verify(
                &proof,
                &pc_gens,
                &bp_gens,
                &mut ChaCha20Rng::seed_from_u64(2),
            )
            .is_ok()
    }

    #[test]
    fn honest_quotient_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        for _ in 0..3 {
            let r = R1csField::random(&mut rng);
            let w = reduce_pad_witness(&r);
            assert!(run(r, w), "honest (pad, m) must verify");
        }
    }

    #[test]
    fn honest_small_r_verifies() {
        let r = R1csField::from(12345u64);
        let w = reduce_pad_witness(&r);
        assert_eq!(w.1, 0);
        assert!(run(r, w));
    }

    /// The `m = 8` wraparound: for small `r`, `r - 8q` wraps to
    /// `r + (p - 8q)`, which still lands under the generic `pad < q` bound.
    /// Only the extra `pad < p - 8q` bound rules it out.
    #[test]
    fn claiming_the_maximum_quotient_for_a_small_r_is_rejected() {
        let q = gin_scalar_modulus_as_r1cs_field();
        let r = R1csField::from(12345u64);
        let fake_pad = r - R1csField::from(8u64) * q;
        // The fake pad passes the generic `pad < q` bound...
        assert!(!fp_canonical_ge(&fake_pad, &q), "fake pad must be < q");
        // ...and is only excluded by the tighter `m == 8` bound.
        let delta: R1csField = Option::from(R1csField::from_repr(
            R1CS_FIELD_MODULUS_MINUS_8_GIN_SCALAR_MODULUS_LE,
        ))
        .unwrap();
        assert!(
            fp_canonical_ge(&fake_pad, &delta),
            "fake pad must be >= p - 8q"
        );
        assert!(
            !run(r, (fake_pad, 8)),
            "wraparound quotient must be rejected"
        );
    }

    #[test]
    fn claiming_a_too_large_small_quotient_is_rejected() {
        let q = gin_scalar_modulus_as_r1cs_field();
        let r = R1csField::from(12345u64);
        for m in 1u8..=7 {
            let fake_pad = r - R1csField::from(u64::from(m)) * q;
            assert!(!run(r, (fake_pad, m)), "quotient {m} must be rejected");
        }
    }

    #[test]
    fn claiming_a_too_small_quotient_is_rejected() {
        let q = gin_scalar_modulus_as_r1cs_field();
        // Pick an r whose true quotient is 8, then understate it.
        let r = R1csField::from(8u64) * q + R1csField::from(7u64);
        let (_, m_true) = reduce_pad_witness(&r);
        assert_eq!(m_true, 8);
        for m in 0u8..8 {
            let fake_pad = r - R1csField::from(u64::from(m)) * q;
            assert!(
                !run(r, (fake_pad, m)),
                "understated quotient {m} must be rejected"
            );
        }
    }

    #[test]
    fn out_of_range_quotient_nine_is_rejected() {
        let r = R1csField::from(9u64) * gin_scalar_modulus_as_r1cs_field();
        let fake_pad = r - R1csField::from(9u64) * gin_scalar_modulus_as_r1cs_field();
        assert!(
            !run(r, (fake_pad, 9)),
            "m = 9 must fail the m < 9 range check"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod edwards_gadget_tests {
    use super::*;
    use bulletproofs_cycle::r1cs::{Prover, Verifier};

    fn small_gens() -> (PedersenGens<R1csCycle>, BulletproofGens<R1csCycle>) {
        (PedersenGens::default(), BulletproofGens::new(8192, 1))
    }

    /// Prove and verify `edwards_conditional_add_r1cs` in isolation, from an
    /// identity accumulator, for both possible bit values: `bit = 0` must
    /// reduce to the unchanged accumulator (adding the identity), and
    /// `bit = 1` must reduce to the direct sum with the base point.
    fn edwards_conditional_add_reduces_correctly_for_both_bits(bit: bool) {
        let base = Gin::generator();
        let (base_u, base_v) = affine(&base).unwrap();
        // The identity's affine coordinates are `(0, 1)`; `affine()` itself
        // rejects the identity, so it cannot be used for the `bit = 0`
        // expectation.
        let (expected_u, expected_v) = if bit {
            (base_u, base_v)
        } else {
            (R1csField::ZERO, R1csField::ONE)
        };

        let (pc_gens, bp_gens) = small_gens();
        let mut transcript = Transcript::new(b"edwards-conditional-add-test");
        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let bit_fp = if bit { R1csField::ONE } else { R1csField::ZERO };
        let bit_var = prover.allocate(Some(bit_fp)).unwrap();
        edwards_conditional_add_r1cs(
            &mut prover,
            LinearCombination::from(R1csField::ZERO),
            LinearCombination::from(R1csField::ONE),
            bit_var,
            base_u,
            base_v,
            Some((expected_u, expected_v)),
            Some((expected_u, expected_v)),
        )
        .unwrap();
        let proof = prover
            .prove(&bp_gens, &mut ChaCha20Rng::seed_from_u64(21))
            .unwrap();

        let mut transcript = Transcript::new(b"edwards-conditional-add-test");
        let mut verifier = Verifier::<R1csCycle, _>::new(&mut transcript);
        let verifier_bit_var = verifier.allocate(None).unwrap();
        edwards_conditional_add_r1cs(
            &mut verifier,
            LinearCombination::from(R1csField::ZERO),
            LinearCombination::from(R1csField::ONE),
            verifier_bit_var,
            base_u,
            base_v,
            Some((expected_u, expected_v)),
            None,
        )
        .unwrap();
        verifier
            .verify(
                &proof,
                &pc_gens,
                &bp_gens,
                &mut ChaCha20Rng::seed_from_u64(22),
            )
            .unwrap();
    }

    #[test]
    fn edwards_conditional_add_reduces_correctly_for_bit_zero() {
        edwards_conditional_add_reduces_correctly_for_both_bits(false);
    }

    #[test]
    fn edwards_conditional_add_reduces_correctly_for_bit_one() {
        edwards_conditional_add_reduces_correctly_for_both_bits(true);
    }

    /// Prove and verify a standalone `Y = k * X` statement using the
    /// windowed additive-ladder gadget in isolation (no DKG/eVRF wiring),
    /// mirroring `secp_secq`'s `chord_exp_honest_proof_verifies`.
    fn prove_and_verify_exponentiation(k: u64) {
        let x = Gin::generator();
        let precomp = precompute_windowed_base_powers(&x).unwrap();
        let k_fp = fr_to_fp(&GinScalar::from(k));
        let mut bits = [false; K_BITS + 1];
        decompose_k_fp(&k_fp, &mut bits);
        let bit_assignments = bit_options(&bits);
        let witness = edwards_windowed_ladder_witness(&bits, &base_power_points(&x)).unwrap();
        let (result_u, result_v) = *witness.window_results.last().unwrap();

        let expected = x * GinScalar::from(k);
        let expected_batch = batch_affine(&[expected]).unwrap();
        assert_eq!((result_u, result_v), expected_batch[0]);

        let (pc_gens, bp_gens) = small_gens();
        let mut transcript = Transcript::new(b"edwards-gadget-test");
        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let bit_vars: Vec<_> = bit_assignments
            .iter()
            .map(|&b| prover.allocate(b).unwrap())
            .collect();
        let window_products = edwards_window_products(&mut prover, &bit_vars).unwrap();
        edwards_exponentiate_windowed_r1cs(
            &mut prover,
            &bit_vars,
            &window_products,
            &precomp,
            Some((result_u, result_v)),
            Some(&witness),
        )
        .unwrap();
        let proof = prover
            .prove(&bp_gens, &mut ChaCha20Rng::seed_from_u64(1))
            .unwrap();

        let mut transcript = Transcript::new(b"edwards-gadget-test");
        let mut verifier = Verifier::<R1csCycle, _>::new(&mut transcript);
        let verifier_bit_vars: Vec<_> = (0..K_BITS + 1)
            .map(|_| verifier.allocate(None).unwrap())
            .collect();
        let verifier_window_products =
            edwards_window_products(&mut verifier, &verifier_bit_vars).unwrap();
        edwards_exponentiate_windowed_r1cs(
            &mut verifier,
            &verifier_bit_vars,
            &verifier_window_products,
            &precomp,
            Some((result_u, result_v)),
            None,
        )
        .unwrap();
        verifier
            .verify(
                &proof,
                &pc_gens,
                &bp_gens,
                &mut ChaCha20Rng::seed_from_u64(2),
            )
            .unwrap();
    }

    #[test]
    fn exponentiate_gadget_proves_zero() {
        prove_and_verify_exponentiation(0);
    }

    #[test]
    fn exponentiate_gadget_proves_one() {
        prove_and_verify_exponentiation(1);
    }

    #[test]
    fn exponentiate_gadget_proves_small_exponent() {
        prove_and_verify_exponentiation(0b1011_0110);
    }

    #[test]
    fn exponentiate_gadget_proves_full_width_exponent() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let k = GinScalar::random(&mut rng);
        let x = Gin::generator();
        let expected = x * k;
        let (expected_u, expected_v) = affine(&expected).unwrap();

        let precomp = precompute_windowed_base_powers(&x).unwrap();
        let k_fp = fr_to_fp(&k);
        let mut bits = [false; K_BITS + 1];
        decompose_k_fp(&k_fp, &mut bits);
        let bit_assignments = bit_options(&bits);
        let witness = edwards_windowed_ladder_witness(&bits, &base_power_points(&x)).unwrap();
        let (result_u, result_v) = *witness.window_results.last().unwrap();
        assert_eq!((result_u, result_v), (expected_u, expected_v));

        let (pc_gens, bp_gens) = small_gens();
        let mut transcript = Transcript::new(b"edwards-gadget-full-width");
        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let bit_vars: Vec<_> = bit_assignments
            .iter()
            .map(|&b| prover.allocate(b).unwrap())
            .collect();
        let window_products = edwards_window_products(&mut prover, &bit_vars).unwrap();
        edwards_exponentiate_windowed_r1cs(
            &mut prover,
            &bit_vars,
            &window_products,
            &precomp,
            Some((result_u, result_v)),
            Some(&witness),
        )
        .unwrap();
        let proof = prover
            .prove(&bp_gens, &mut ChaCha20Rng::seed_from_u64(3))
            .unwrap();

        let mut transcript = Transcript::new(b"edwards-gadget-full-width");
        let mut verifier = Verifier::<R1csCycle, _>::new(&mut transcript);
        let verifier_bit_vars: Vec<_> = (0..K_BITS + 1)
            .map(|_| verifier.allocate(None).unwrap())
            .collect();
        let verifier_window_products =
            edwards_window_products(&mut verifier, &verifier_bit_vars).unwrap();
        edwards_exponentiate_windowed_r1cs(
            &mut verifier,
            &verifier_bit_vars,
            &verifier_window_products,
            &precomp,
            Some((result_u, result_v)),
            None,
        )
        .unwrap();
        verifier
            .verify(
                &proof,
                &pc_gens,
                &bp_gens,
                &mut ChaCha20Rng::seed_from_u64(4),
            )
            .unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod one_receiver_tests {
    use super::*;

    #[test]
    fn one_receiver_prover_uses_exactly_the_expected_multiplier_count() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let sk1 = GinScalar::random(&mut rng);
        let sk2 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * sk2;
        let msg = [3u8; MESSAGE_BYTES];
        let beta = R1csField::from(11u64);
        let (statement, _witness) = testing::build_statement_witness(&msg, sk1, pk2, beta);

        let (s_u, _) = affine(&statement.s).unwrap();
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);
        let mut bits = [false; K_BITS + 1];
        decompose_k_fp(&s_u, &mut bits);
        let bit_assignments = bit_options(&bits);
        let witness1 = edwards_windowed_ladder_witness(&bits, &base_power_points(&h1)).unwrap();
        let witness2 = edwards_windowed_ladder_witness(&bits, &base_power_points(&h2)).unwrap();
        let (t1_u, t1_v) = *witness1.window_results.last().unwrap();
        let (t2_u, t2_v) = *witness2.window_results.last().unwrap();
        let r = beta * t1_u + t2_u;

        let pc_gens = PedersenGens::<R1csCycle>::default();
        let mut transcript = Transcript::new(b"metrics-check");
        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let (_, var_k) = prover.commit(s_u, R1csField::ONE);
        let (_, var_r) = prover.commit(r, R1csField::ONE);
        build_one_receiver_r1cs(
            &mut prover,
            var_k,
            var_r,
            s_u,
            &h1,
            &h2,
            t1_u,
            t1_v,
            t2_u,
            t2_v,
            beta,
            &bit_assignments,
            Some(&witness1),
            Some(&witness2),
        )
        .unwrap();

        let multipliers = ConstraintSystem::<R1csCycle>::metrics(&prover).multipliers;
        assert_eq!(multipliers, 2188);
        assert!(
            multipliers <= R1CS_GENS_CAPACITY,
            "circuit needs {multipliers} multipliers but R1CS_GENS_CAPACITY is only {R1CS_GENS_CAPACITY}"
        );
    }

    #[test]
    fn honest_one_receiver_proof_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let sk1 = GinScalar::random(&mut rng);
        let sk2 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * sk2;
        let msg = [7u8; MESSAGE_BYTES];
        let beta = R1csField::from(3u64);

        let (statement, witness) = testing::build_statement_witness(&msg, sk1, pk2, beta);
        let proof = evrf_prove(&statement, &witness, &mut rng).unwrap();
        evrf_verify(&statement, &proof, &mut rng).unwrap();
    }

    #[test]
    fn tampered_beta_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(43);
        let sk1 = GinScalar::random(&mut rng);
        let sk2 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * sk2;
        let msg = [9u8; MESSAGE_BYTES];
        let beta = R1csField::from(3u64);

        let (mut statement, witness) = testing::build_statement_witness(&msg, sk1, pk2, beta);
        let proof = evrf_prove(&statement, &witness, &mut rng).unwrap();
        statement.beta = R1csField::from(4u64);
        assert!(evrf_verify(&statement, &proof, &mut rng).is_err());
    }

    #[test]
    fn tampered_t1_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(44);
        let sk1 = GinScalar::random(&mut rng);
        let sk2 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * sk2;
        let msg = [1u8; MESSAGE_BYTES];
        let beta = R1csField::from(5u64);

        let (mut statement, witness) = testing::build_statement_witness(&msg, sk1, pk2, beta);
        let proof = evrf_prove(&statement, &witness, &mut rng).unwrap();
        statement.t1 += Gin::generator();
        assert!(evrf_verify(&statement, &proof, &mut rng).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod batched_tests {
    use super::*;

    fn batched_prover_multiplier_count(receiver_count: usize) -> usize {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let sk1 = GinScalar::random(&mut rng);
        let pkjs: Vec<Gin> = (0..receiver_count)
            .map(|_| Gin::generator() * GinScalar::random(&mut rng))
            .collect();
        let msg = [5u8; MESSAGE_BYTES];
        let beta = R1csField::from(13u64);
        let (statement, witness) = testing::build_batched(&msg, sk1, &pkjs, beta);

        let pc_gens = PedersenGens::<R1csCycle>::default();
        let mut transcript = Transcript::new(b"metrics-check-batched");
        let g_in = Gin::generator();
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);
        let precomp_h1 = precompute_windowed_base_powers(&h1).unwrap();
        let precomp_h2 = precompute_windowed_base_powers(&h2).unwrap();

        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, &mut transcript);
        let sk_fp = fr_to_fp(&witness.sk1);
        let mut sk_bool_bits = [false; K_BITS + 1];
        decompose_k_fp(&sk_fp, &mut sk_bool_bits);
        let sk_bit_assignments = bit_options(&sk_bool_bits);
        let sk_var = prover.allocate(Some(sk_fp)).unwrap();
        let sk_bit_vars = bit_decompose_q(&mut prover, sk_var, &sk_bit_assignments).unwrap();
        let sk_window_products = edwards_window_products(&mut prover, &sk_bit_vars).unwrap();
        let pk1_witness =
            edwards_windowed_ladder_witness(&sk_bool_bits, &base_power_points(&g_in)).unwrap();
        let precomp_g_in = shared_g_in_window_precomp();
        let (pk1_u, pk1_v) = affine(&statement.pk1).unwrap();
        edwards_exponentiate_windowed_r1cs(
            &mut prover,
            &sk_bit_vars,
            &sk_window_products,
            precomp_g_in,
            Some((pk1_u, pk1_v)),
            Some(&pk1_witness),
        )
        .unwrap();
        for rec in &statement.receivers {
            let rec_witness =
                compute_hidden_receiver_witness(&witness.sk1, rec, &statement.beta, &h1, &h2)
                    .unwrap();
            build_hidden_receiver_slot(
                &mut prover,
                rec,
                &sk_bit_vars,
                &sk_window_products,
                &precomp_h1,
                &precomp_h2,
                statement.beta,
                Some(&rec_witness),
            )
            .unwrap();
        }
        ConstraintSystem::<R1csCycle>::metrics(&prover).multipliers
    }

    #[test]
    fn batched_multiplier_count_matches_real_circuit_shape() {
        let one = batched_prover_multiplier_count(1);
        let two = batched_prover_multiplier_count(2);
        let per_receiver = two - one;
        let shared = one - per_receiver;
        // Document the exact real shape so BATCHED_SHARED_MULTIPLIERS /
        // BATCHED_RECEIVER_MULTIPLIERS can be tightened deliberately rather
        // than left at a loose guessed margin (see their doc comments).
        assert_eq!(
            (shared, per_receiver),
            (1412, 4574),
            "real batched circuit shape changed; update BATCHED_SHARED_MULTIPLIERS / \
             BATCHED_RECEIVER_MULTIPLIERS in lockstep"
        );
        for n in 1..=3 {
            let real = batched_prover_multiplier_count(n);
            let predicted = batched_multiplier_count(2, n).unwrap();
            assert!(
                predicted >= real,
                "predicted {predicted} must cover real {real} multipliers at receiver_count={n}"
            );
        }
    }

    #[test]
    fn honest_batched_proof_verifies_for_two_receivers() {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let sk1 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * GinScalar::random(&mut rng);
        let pk3 = Gin::generator() * GinScalar::random(&mut rng);
        let msg = [3u8; MESSAGE_BYTES];
        let beta = R1csField::from(7u64);

        let (statement, witness) = testing::build_batched(&msg, sk1, &[pk2, pk3], beta);
        let params =
            BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len()).unwrap();
        let proof = evrf_batched_prove(&params, &statement, &witness, &mut rng).unwrap();
        evrf_batched_verify(&params, &statement, &proof, &mut rng).unwrap();
    }

    #[test]
    fn batched_proof_wire_len_matches_a_real_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let sk1 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * GinScalar::random(&mut rng);
        let pk3 = Gin::generator() * GinScalar::random(&mut rng);
        let msg = [4u8; MESSAGE_BYTES];
        let beta = R1csField::from(11u64);

        let (statement, witness) = testing::build_batched(&msg, sk1, &[pk2, pk3], beta);
        let params =
            BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len()).unwrap();
        let proof = evrf_batched_prove(&params, &statement, &witness, &mut rng).unwrap();

        let predicted = BatchedEvrfPublicParams::batched_proof_wire_len(
            statement.threshold,
            statement.receivers.len(),
        )
        .unwrap();
        assert_eq!(predicted, proof.len());
    }

    #[test]
    fn tampered_encrypted_share_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let sk1 = GinScalar::random(&mut rng);
        let pk2 = Gin::generator() * GinScalar::random(&mut rng);
        let msg = [4u8; MESSAGE_BYTES];
        let beta = R1csField::from(9u64);

        let (mut statement, witness) = testing::build_batched(&msg, sk1, &[pk2], beta);
        let params =
            BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len()).unwrap();
        let proof = evrf_batched_prove(&params, &statement, &witness, &mut rng).unwrap();
        statement.receivers[0].encrypted_share += GinScalar::ONE;
        assert!(evrf_batched_verify(&params, &statement, &proof, &mut rng).is_err());
    }
}
