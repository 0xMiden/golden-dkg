//! Paper eVRF backend for the Golden DKG.
//!
//! The Milestone 1 backend targets the `halo2curves` Secp256k1/Secq256k1
//! curve cycle. The R1CS field is `Fp` (the Secp256k1 base field, equal to the
//! Secq256k1 scalar field), so the chord-rule constraints for the
//! exponentiation gadgets operate on native `Fp` coordinates. The Bulletproofs
//! commitment group is `Secq256k1` (`G_out`).
//!
//! The relation follows paper Section 4. Steps 0 and 1 (`PK_1 = g_in^sk_1`,
//! `S = PK_2^sk_1`) are proven outside the R1CS by a Chaum-Pedersen proof of
//! equal discrete logs, which avoids foreign-field bit-decomposition of
//! `sk_1` (an `Fq` element) in the `Fp` R1CS. Step 9 (`R = g_out^r`) is proven
//! outside the R1CS by a discrete-log proof of knowledge linked to the
//! Bulletproofs Pedersen prefix `theta = g_out,1 * g_out^r`.

#![allow(non_snake_case)]

#[cfg(feature = "halo2curves-secp256k1")]
use golden_core::{Error, ParticipantIndex, Result, TranscriptRoot};
#[cfg(feature = "halo2curves-secp256k1")]
use rand_core::CryptoRngCore;

/// Byte length of the paper `msg_i` nonce (256-bit security parameter).
pub const MESSAGE_BYTES: usize = 256 / 8;

/// Concrete Secp/Secq paper eVRF backend, feature-gated behind
/// `halo2curves-secp256k1`.
#[cfg(feature = "halo2curves-secp256k1")]
pub mod secp_secq {
    use super::*;

    use crate::proof_stream::{
        decode_point, CycleCurve, IdentityPolicy, Observe, ProofStreamCurve, ProverProofStream,
        VerifierProofStream,
    };
    use bulletproofs_cycle::{
        cycle::random_scalar,
        generators::{BulletproofGens, PedersenGens},
        r1cs::{Prover, Verifier},
        ConstraintSystem, Cycle, LinearCombination, R1CSError, R1CSProof, Variable,
        VerificationEquation,
    };
    use ff::{Field, PrimeField};
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use group::{Curve, Group};
    use halo2curves::secp256k1::{Fp, Fq, Secp256k1};
    use halo2curves::secq256k1::Secq256k1;
    use halo2curves::{Coordinates, CurveAffine, CurveExt};
    use merlin::Transcript;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[cfg(test)]
    use golden_core::{DealerMessageNonce, EvrfStatement};
    #[cfg(test)]
    use golden_halo2curves::golden_group::{
        Secp256k1Element, Secp256k1GoldenGroup, Secp256k1Scalar,
    };

    /// R1CS field: `Fp` (Secp256k1 base field = Secq256k1 scalar field).
    pub type R1csField = Fp;
    /// R1CS commitment group: `Secq256k1` (`G_out`).
    pub type R1csCycle = Secq256k1Cycle;
    /// `G_in` group: `Secp256k1`.
    pub type Gin = Secp256k1;
    /// `G_in` scalar field: `Fq`.
    pub type GinScalar = Fq;
    /// `G_out` commitment group: `Secq256k1`. Exposed so integration tests can
    /// construct random `R_j` points without re-deriving the cycle alias.
    pub type Gout = Secq256k1;
    /// `G_out` compressed point.
    pub type GoutCompressed = <R1csCycle as Cycle>::Compressed;

    /// Public statement for the one-receiver paper eVRF relation.
    #[derive(Clone, Debug)]
    pub struct SecpSecqEvrfStatement {
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
        pub r_point: Secq256k1,
        /// Public coefficient `beta` in `Fp`.
        pub beta: R1csField,
    }

    /// Witness for the one-receiver paper eVRF relation.
    #[derive(Clone)]
    pub struct SecpSecqEvrfWitness {
        /// Dealer identity secret `sk_1` in `Fq`.
        pub sk1: GinScalar,
    }

    impl core::fmt::Debug for SecpSecqEvrfWitness {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SecpSecqEvrfWitness")
                .field("sk1", &"<redacted>")
                .finish()
        }
    }

    /// Versioned proof-stream grammar for the standalone one-receiver relation.
    const ONE_RECEIVER_PROOF_ID: &[u8] = b"golden-paper-evrf-one-receiver-v2";
    /// Proof protocol identifier for the batched dealer relation and v2 stream grammar.
    const BATCHED_PROOF_ID: &[u8] = b"golden-paper-evrf-batched-v2";

    type GinStreamCurve = CycleCurve<Secp256k1Cycle>;
    type GoutStreamCurve = CycleCurve<R1csCycle>;

    /// Observe the complete standalone public statement in one canonical order.
    fn observe_one_receiver_statement(
        stream: &mut impl Observe,
        statement: &SecpSecqEvrfStatement,
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
        stream.observe_point::<GinStreamCurve>(
            b"statement.s",
            &statement.s,
            IdentityPolicy::Reject,
        )?;
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
    //
    // One dealer message covers all non-self receivers in a single R1CS
    // relation. The dealer identity secret `sk_1` and public key `PK_1` are
    // shared across the batch; per-receiver eVRF intermediates, pads, and
    // shares stay private witnesses.
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
        /// Published DH commitment `PK_j^pad_j` in the dealer broadcast.
        pub dh_commitment: Gin,
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
    ///
    /// Setup derives the exact multiplier count from the DKG threshold and
    /// receiver count, then expands the deterministic Bulletproof generators
    /// once. The same value can be shared by every dealer proof with that
    /// shape. With the `serde` feature, serialized parameters contain the
    /// prepared bases and must be authenticated before loading; deserialization
    /// validates encodings and dimensions but does not rederive every base.
    pub struct BatchedEvrfPublicParams {
        threshold: usize,
        receiver_count: usize,
        multiplier_count: usize,
        pc_gens: PedersenGens<R1csCycle>,
        bp_gens: BulletproofGens<R1csCycle>,
    }

    #[cfg(feature = "serde")]
    impl serde::Serialize for BatchedEvrfPublicParams {
        fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            #[derive(serde::Serialize)]
            struct Repr<'a> {
                threshold: usize,
                receiver_count: usize,
                bp_gens: &'a BulletproofGens<R1csCycle>,
            }

            Repr {
                threshold: self.threshold,
                receiver_count: self.receiver_count,
                bp_gens: &self.bp_gens,
            }
            .serialize(serializer)
        }
    }

    #[cfg(feature = "serde")]
    impl<'de> serde::Deserialize<'de> for BatchedEvrfPublicParams {
        fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            #[derive(serde::Deserialize)]
            struct Repr {
                threshold: usize,
                receiver_count: usize,
                bp_gens: BulletproofGens<R1csCycle>,
            }

            let repr = Repr::deserialize(deserializer)?;
            let multiplier_count = batched_multiplier_count(repr.threshold, repr.receiver_count)
                .map_err(|_| D::Error::custom("invalid batched public parameter shape"))?;
            let gens_capacity = multiplier_count
                .checked_next_power_of_two()
                .ok_or_else(|| D::Error::custom("batched public parameter capacity overflow"))?;
            if repr.bp_gens.gens_capacity != gens_capacity || repr.bp_gens.party_capacity != 1 {
                return Err(D::Error::custom(
                    "generator capacity does not match the batched circuit shape",
                ));
            }

            Ok(Self {
                threshold: repr.threshold,
                receiver_count: repr.receiver_count,
                multiplier_count,
                pc_gens: PedersenGens::default(),
                bp_gens: repr.bp_gens,
            })
        }
    }

    impl BatchedEvrfPublicParams {
        /// Build transparent parameters for a DKG threshold and receiver count.
        pub fn setup(threshold: usize, receiver_count: usize) -> Result<Self> {
            let multiplier_count = batched_multiplier_count(threshold, receiver_count)?;
            let gens_capacity = multiplier_count
                .checked_next_power_of_two()
                .ok_or(Error::ProofVerificationFailed)?;
            Ok(Self {
                threshold,
                receiver_count,
                multiplier_count,
                pc_gens: PedersenGens::default(),
                bp_gens: BulletproofGens::new(gens_capacity, 1),
            })
        }

        /// Return process-wide shared parameters for one exact circuit shape.
        pub fn shared(threshold: usize, receiver_count: usize) -> Result<std::sync::Arc<Self>> {
            type Cache = std::sync::Mutex<
                std::collections::HashMap<(usize, usize), std::sync::Arc<BatchedEvrfPublicParams>>,
            >;
            static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();

            let cache =
                CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
            let mut cache = cache.lock().map_err(|_| Error::ProofVerificationFailed)?;
            if let Some(params) = cache.get(&(threshold, receiver_count)) {
                return Ok(std::sync::Arc::clone(params));
            }

            let params = std::sync::Arc::new(Self::setup(threshold, receiver_count)?);
            cache.insert((threshold, receiver_count), std::sync::Arc::clone(&params));
            Ok(params)
        }

        /// DKG threshold used to size these parameters.
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

        fn validate_statement(&self, statement: &BatchedEvrfStatement) -> Result<()> {
            if self.threshold != statement.threshold
                || self.receiver_count != statement.receivers.len()
            {
                return Err(Error::ProofVerificationFailed);
            }
            Ok(())
        }
    }

    /// Witness for the batched dealer proof.
    #[derive(Clone)]
    pub struct BatchedEvrfWitness {
        /// Dealer identity secret `sk_1` in `Fq` (shared across the batch).
        pub sk1: GinScalar,
        /// Dealer polynomial coefficients in ascending degree order.
        pub coefficient_scalars: Vec<GinScalar>,
        /// Receiver shares in the same order as the public statement.
        pub shares: Vec<GinScalar>,
    }

    impl core::fmt::Debug for BatchedEvrfWitness {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("BatchedEvrfWitness")
                .field("sk1", &"<redacted>")
                .field("coefficient_scalars", &"<redacted>")
                .field("shares", &"<redacted>")
                .finish()
        }
    }

    /// Extract affine `(x, y)` coordinates of a non-identity `G_in` point.
    fn affine(point: &Gin) -> Result<(Fp, Fp)> {
        let aff = point.to_affine();
        let coords = aff.coordinates();
        let opt: Option<Coordinates<halo2curves::secp256k1::Secp256k1Affine>> =
            Option::from(coords);
        opt.map(|c| (*c.x(), *c.y()))
            .ok_or(Error::ProofVerificationFailed)
    }

    fn is_identity(point: &Gin) -> bool {
        *point == Gin::identity()
    }

    /// Bit length used for the `k = int(S.x)` decomposition. The Secp256k1
    /// base field modulus fits in 256 bits, so 256 bits cover every canonical
    /// `Fp` element.
    const K_BITS: usize = 256;

    /// Secp256k1 base-field modulus `p`, encoded little-endian.
    const SECP256K1_BASE_MODULUS_LE: [u8; 32] = [
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// Secp256k1 scalar-field modulus `q`, encoded little-endian.
    const SECP256K1_SCALAR_MODULUS_LE: [u8; 32] = [
        0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae,
        0xba, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// Difference between the Secp256k1 base-field modulus `p` and scalar
    /// modulus `q`, encoded little-endian.
    const SECP256K1_P_MINUS_Q_LE: [u8; 32] = [
        0xee, 0xba, 0xc9, 0x2f, 0x72, 0xa1, 0x2d, 0x40, 0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51,
        0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn modulus_bit(modulus_le: &[u8; 32], j: usize) -> bool {
        let byte_idx = j / 8;
        let bit_idx = j % 8;
        byte_idx < modulus_le.len() && (modulus_le[byte_idx] >> bit_idx) & 1 == 1
    }

    // ------------------------------------------------------------------
    // Chord-rule exponentiation gadget (paper Section 4.3, Boneh et al.
    // 2024/397 Appendix C.2.1).
    //
    // For a base point X in G_in and exponent k = Σ_{j=0}^{λ} k_j · 2^j, the
    // gadget computes L_λ = k · X via the recurrence
    //   L_0 = Δ_0,  L_i = L_{i-1} + Δ_i  for i = 1..λ
    // where Δ_j = k_j · P_j + C_j, P_j = 2^j · X, C_j = c_j · G_S.
    //
    // The correction scalars c_j satisfy Σ c_j = 0 mod |G_in| so that
    // L_λ = k · X + (Σ c_j) · G_S = k · X.  Following Boneh et al.:
    //   c_0 = 1,  c_1 = ... = c_{λ-1} = 2,  c_λ = s - (2λ - 1)
    // where s = |G_in| = Fq modulus.  Each Δ_j is a public linear function
    // of the bit k_j: x_{Δ_j} = k_j · (x_{D_j} - x_{C_j}) + x_{C_j}, where
    // D_j = P_j + C_j.  The verifier precomputes x_{C_j}, y_{C_j}, x_{D_j},
    // y_{D_j} (all in Fp) outside the R1CS.
    // ------------------------------------------------------------------

    /// Correction scalar `c_j` in `Fq` (the `G_in` scalar field), following
    /// Boneh et al. 2024/397: `c_0 = 1`, `c_1 = ... = c_{λ-1} = 2`,
    /// `c_λ = s - (2λ - 1)` where `s = |G_in|`.  Since `s ≡ 0` in `Fq`, this
    /// simplifies to `c_λ = 1 - 2λ`.
    fn chord_cj(j: usize, lambda: usize) -> Fq {
        if j == 0 {
            Fq::ONE
        } else if j < lambda {
            Fq::from(2)
        } else {
            // s - (2λ - 1) ≡ -(2λ - 1) = 1 - 2λ  (mod s, since s ≡ 0 in Fq)
            Fq::ONE - Fq::from((2 * lambda) as u64)
        }
    }

    /// Precomputed `Fp` coordinates for one chord-rule exponentiation.  Index
    /// `j` ranges over `0..=lambda`.  `c` holds coordinates of `C_j = c_j · G_S`
    /// and `d` holds coordinates of `D_j = P_j + C_j` where `P_j = 2^j · X`.
    /// The R1CS computes `x_{Δ_j} = k_j · (d.x - c.x) + c.x` and the
    /// corresponding `y` as a linear function of the witness bit `k_j`.
    #[derive(Clone, Debug)]
    struct ChordPrecomp {
        /// `(x, y)` coordinates of `C_j = c_j · G_S` for `j = 0..=lambda`.
        c: Vec<(Fp, Fp)>,
        /// `(x, y)` coordinates of `D_j = P_j + C_j` for `j = 0..=lambda`.
        d: Vec<(Fp, Fp)>,
    }

    /// Precompute the `C_j` and `D_j` coordinates for a chord-rule
    /// exponentiation of base `X` with `lambda + 1` bits.  The correction
    /// generator `G_S(X)` is derived from `X`, so each base gets independent
    /// correction points.  All coordinates are native `Fp` elements.
    fn precompute_chord(X: &Gin, lambda: usize) -> Result<ChordPrecomp> {
        let g_s = chord_correction_generator(X);
        let mut c = Vec::with_capacity(lambda + 1);
        let mut d = Vec::with_capacity(lambda + 1);
        let mut p_j = *X; // P_0 = 2^0 · X = X
        for j in 0..=lambda {
            let cj = chord_cj(j, lambda);
            let c_j_point = g_s * cj; // C_j = c_j · G_S(X)
            let d_j_point = p_j + c_j_point; // D_j = P_j + C_j
            c.push(affine(&c_j_point)?);
            d.push(affine(&d_j_point)?);
            p_j = p_j.double(); // P_{j+1} = 2 · P_j
        }
        Ok(ChordPrecomp { c, d })
    }

    /// Evaluate the chord-rule exponentiation using actual elliptic curve
    /// point arithmetic (the prover's witness generation path).  Given the
    /// bits `k_0..k_λ`, computes `L_λ = k · X` by incrementally applying
    /// `L_i = L_{i-1} + Δ_i` with `Δ_j = k_j · P_j + C_j` where
    /// `P_j = 2^j · X` and `C_j = c_j · G_S`.  Returns the affine coordinates
    /// of `L_λ`.  Used to generate the `L_i` witness coordinates for the R1CS
    /// and to verify correctness in tests.
    #[cfg(test)]
    fn chord_evaluate(bits: &[bool], X: &Gin, lambda: usize) -> Result<(Fp, Fp)> {
        chord_evaluate_point(bits, X, lambda).and_then(|p| affine(&p))
    }

    /// Evaluate the chord-rule exponentiation and return the `G_in` point
    /// `L_λ = k · X` (with `c_j` corrections reducing `k` mod `|G_in|`).
    fn chord_evaluate_point(bits: &[bool], X: &Gin, lambda: usize) -> Result<Gin> {
        if bits.len() != lambda + 1 {
            return Err(Error::ProofVerificationFailed);
        }
        let g_s = chord_correction_generator(X);
        let mut p_j = *X;
        let mut l = Gin::identity();
        for (j, &bit) in bits.iter().enumerate().take(lambda + 1) {
            let cj = chord_cj(j, lambda);
            let c_j_point = g_s * cj;
            let delta = if bit { p_j + c_j_point } else { c_j_point };
            l = if j == 0 { delta } else { l + delta };
            p_j = p_j.double();
        }
        Ok(l)
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

    /// Bit-decomposition gadget (paper Section 4.2). Given a committed
    /// variable `k_var` holding `k ∈ Fp` and `λ+1` bit assignments, constrains:
    /// - `k_j · (1 - k_j) = 0` for each `j` (each `k_j` is binary)
    /// - `k = Σ_{j=0}^{λ} 2^j · k_j` (the bits reconstruct `k`)
    /// - `Σ 2^j · k_j < p`, where `p` is the Secp256k1 base-field modulus
    ///
    /// Returns the allocated bit variables `k_0, ..., k_λ`. The range check is
    /// necessary because reconstruction is otherwise only modular in `Fp`;
    /// bits encoding `k + p` would reconstruct the same field element while
    /// producing a different scalar after reduction modulo the `G_in` scalar
    /// field.
    fn bit_decompose<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        k_var: Variable<R1csField>,
        bit_assignments: &[Option<R1csField>],
    ) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
        bit_decompose_bounded(cs, k_var, bit_assignments, &SECP256K1_BASE_MODULUS_LE)
    }

    fn bit_decompose_q<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        k_var: Variable<R1csField>,
        bit_assignments: &[Option<R1csField>],
    ) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
        bit_decompose_bounded(cs, k_var, bit_assignments, &SECP256K1_SCALAR_MODULUS_LE)
    }

    fn bit_decompose_bounded<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        k_var: Variable<R1csField>,
        bit_assignments: &[Option<R1csField>],
        modulus_le: &[u8; 32],
    ) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
        if bit_assignments.len() != K_BITS + 1 {
            return Err(R1CSError::FormatError);
        }
        let mut bit_vars = Vec::with_capacity(K_BITS + 1);
        let mut k_lc = LinearCombination::default();

        for (j, &bit) in bit_assignments.iter().enumerate() {
            // One multiplier gate: left = k_j, right = 1 - k_j, out = k_j*(1-k_j).
            let (left, right, out) =
                cs.allocate_multiplier(bit.map(|bit| (bit, R1csField::ONE - bit)))?;
            // Constrain right = 1 - left so that out = left*(1-left).
            cs.constrain(right - (LinearCombination::from(R1csField::ONE) - left));
            // k_j * (1 - k_j) = 0  ⟹  k_j is binary.
            cs.constrain(out.into());
            bit_vars.push(left);

            k_lc = k_lc + left * power_of_two(j);
        }

        // k = Σ 2^j * k_j
        cs.constrain(k_lc - k_var);

        // Canonical integer range check: bits must encode a value strictly
        // below the Secp256k1 base modulus p. We scan from MSB to LSB and keep
        // a linear-combination flag `prefix_equal` that is 1 exactly while all
        // higher bits still match p. If p_j is 0, setting bit j while the
        // prefix is equal would make the value greater than p, so constrain
        // `prefix_equal * k_j = 0`. If p_j is 1, `prefix_equal * k_j` carries
        // equality to the next bit. The final equality flag is constrained to
        // 0, rejecting the value p itself.
        let mut prefix_equal = LinearCombination::from(R1csField::ONE);
        let mut prefix_equal_assignment = Some(R1csField::ONE);
        for j in (0..=K_BITS).rev() {
            let bit_assignment = bit_assignments[j];
            let product_assignment = match (prefix_equal_assignment, bit_assignment) {
                (Some(eq), Some(bit)) => Some((eq, bit)),
                _ => None,
            };
            let (left, right, out) = cs.allocate_multiplier(product_assignment)?;
            cs.constrain(left - prefix_equal.clone());
            cs.constrain(right - bit_vars[j]);

            let product_lc: LinearCombination<R1csField> = out.into();
            if modulus_bit(modulus_le, j) {
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

    fn constrain_bits_lt_bound_when<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        bit_vars: &[Variable<R1csField>],
        bit_assignments: &[Option<R1csField>],
        bound_le: &[u8; 32],
        condition_var: Variable<R1csField>,
    ) -> core::result::Result<(), R1CSError> {
        if bit_vars.len() != K_BITS + 1 || bit_assignments.len() != K_BITS + 1 {
            return Err(R1CSError::FormatError);
        }

        let condition_lc = LinearCombination::from(condition_var);
        let mut prefix_equal = LinearCombination::from(R1csField::ONE);
        let mut prefix_equal_assignment = Some(R1csField::ONE);
        for j in (0..=K_BITS).rev() {
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

    // ------------------------------------------------------------------
    // Chord-rule R1CS exponentiation gadget (paper Section 4.3).
    // ------------------------------------------------------------------

    /// Witness values for one chord-rule exponentiation: all intermediate
    /// `L_i` coordinates and slopes `s_i` needed by the R1CS gadget.
    #[derive(Clone, Debug)]
    struct ChordWitness {
        /// `(x_{L_i}, y_{L_i})` for `i = 0..=lambda`.
        l_coords: Vec<(R1csField, R1csField)>,
        /// `s_i` for `i = 1..=lambda` (slope of the chord between
        /// `L_{i-1}` and `Δ_i`).
        slopes: Vec<R1csField>,
        /// `(x_{L_{i-1}} - x_{Δ_i})^{-1}` for `i = 1..=lambda`.
        denom_delta_inverses: Vec<R1csField>,
    }

    /// Compute the full chord-rule witness: all intermediate `L_i` points and
    /// slopes `s_i`.  Uses actual elliptic curve point arithmetic in `G_in`
    /// and field inversion in `Fp` for the slopes.
    fn chord_compute_witness(bits: &[bool], X: &Gin, lambda: usize) -> Result<ChordWitness> {
        if bits.len() != lambda + 1 {
            return Err(Error::ProofVerificationFailed);
        }

        let mut l_coords = Vec::with_capacity(lambda + 1);
        let mut slopes = Vec::with_capacity(lambda);
        let mut denom_delta_inverses = Vec::with_capacity(lambda);

        let g_s = chord_correction_generator(X);
        let mut p_j = *X;
        let mut l = Gin::identity();

        for (j, &bit) in bits.iter().enumerate().take(lambda + 1) {
            let cj = chord_cj(j, lambda);
            let c_j_point = g_s * cj;
            let delta = if bit { p_j + c_j_point } else { c_j_point };

            if j == 0 {
                l = delta;
            } else {
                // Compute slope s_j = (y_{L_{j-1}} - y_{Δ_j}) / (x_{L_{j-1}} - x_{Δ_j})
                let (x_prev, y_prev) = *l_coords.last().expect("L_{j-1} exists");
                let (x_delta, y_delta) = affine(&delta)?;

                let dx: R1csField = x_prev - x_delta;
                let dy: R1csField = y_prev - y_delta;
                let dx_inv = match Option::from(dx.invert()) {
                    Some(inv) => inv,
                    None => return Err(Error::ProofVerificationFailed),
                };
                let s_j = dy * dx_inv;
                slopes.push(s_j);
                denom_delta_inverses.push(dx_inv);

                l += delta;
            }

            let coords = affine(&l)?;
            l_coords.push(coords);
            p_j = p_j.double();
        }

        Ok(ChordWitness {
            l_coords,
            slopes,
            denom_delta_inverses,
        })
    }

    /// Build the linear combination for `x_{Δ_j}` = `k_j * (x_{D_j} - x_{C_j})
    /// + x_{C_j}`, expressed in terms of the bit variable `k_j_var`.
    fn delta_x_lc(
        k_j_var: Variable<R1csField>,
        precomp: &ChordPrecomp,
        j: usize,
    ) -> LinearCombination<R1csField> {
        let (cx, _) = precomp.c[j];
        let (dx, _) = precomp.d[j];
        LinearCombination::from(cx) + k_j_var * (dx - cx)
    }

    /// Build the linear combination for `y_{Δ_j}`.
    fn delta_y_lc(
        k_j_var: Variable<R1csField>,
        precomp: &ChordPrecomp,
        j: usize,
    ) -> LinearCombination<R1csField> {
        let (_, cy) = precomp.c[j];
        let (_, dy) = precomp.d[j];
        LinearCombination::from(cy) + k_j_var * (dy - cy)
    }

    /// Chord-rule exponentiation R1CS gadget (paper Section 4.3). Given the
    /// bit variables from [`bit_decompose`], the precomputed `C_j`/`D_j`
    /// coordinates, and an optional public result point `(result_x, result_y)`,
    /// constrains:
    /// - `L_0 = Δ_0` (base case, 2 linear constraints)
    /// - `L_i = L_{i-1} + Δ_i` for `i = 1..λ` (3 multiplication gates per
    ///   iteration via the chord-rule formulas)
    /// - when `result` is present, `L_λ = (result_x, result_y)` (final
    ///   full-point binding, 2 linear constraints)
    ///
    /// The full-point binding (both x and y) is critical for soundness: an
    /// x-only check cannot distinguish `L_λ` from `-L_λ`, which would allow
    /// non-canonical bit aliases (see [`bit_decompose`] doc).
    ///
    /// Returns the `(x_{L_λ}, y_{L_λ})` variables.  Uses `3λ` multiplication
    /// gates plus linear constraints.
    fn chord_exponentiate_r1cs_with_result<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        bit_vars: &[Variable<R1csField>],
        precomp: &ChordPrecomp,
        result: Option<(R1csField, R1csField)>,
        witness: Option<&ChordWitness>,
    ) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
        // The chord-rule gadget consumes bit_vars[0..=λ], precomp.{c,d}[0..=λ],
        // and witness.l_coords[0..=λ]/slopes[0..λ].  Reject mismatches before
        // building the circuit so a caller mistake surfaces as a format error
        // rather than a truncated exponentiation that silently binds L_λ.
        let lambda_plus_one = bit_vars.len();
        if lambda_plus_one < 2
            || precomp.c.len() != lambda_plus_one
            || precomp.d.len() != lambda_plus_one
        {
            return Err(R1CSError::FormatError);
        }
        if let Some(w) = witness {
            if w.l_coords.len() != lambda_plus_one
                || w.slopes.len() != lambda_plus_one - 1
                || w.denom_delta_inverses.len() != lambda_plus_one - 1
            {
                return Err(R1CSError::FormatError);
            }
        }

        // --- Base case: L_0 = Δ_0 ---
        let (x_l0_assign, y_l0_assign) = witness.map(|w| w.l_coords[0]).unzip();
        let x_l0 = cs.allocate(x_l0_assign)?;
        let y_l0 = cs.allocate(y_l0_assign)?;

        // x_{L_0} = x_{Δ_0}, y_{L_0} = y_{Δ_0}
        cs.constrain(x_l0 - delta_x_lc(bit_vars[0], precomp, 0));
        cs.constrain(y_l0 - delta_y_lc(bit_vars[0], precomp, 0));

        let mut x_prev = x_l0;
        let mut y_prev = y_l0;

        for (i, &bit_var) in bit_vars.iter().enumerate().skip(1) {
            // Slope s_i and L_i coordinates (witness values).
            let s_assign = witness.map(|w| w.slopes[i - 1]);
            let denom_delta_inv_assign = witness.map(|w| w.denom_delta_inverses[i - 1]);
            let (x_l_assign, y_l_assign) = witness.map(|w| w.l_coords[i]).unzip();

            let s_var = cs.allocate(s_assign)?;
            let denom_delta_inv = cs.allocate(denom_delta_inv_assign)?;
            let x_l = cs.allocate(x_l_assign)?;
            let y_l = cs.allocate(y_l_assign)?;

            // Linear combinations for Δ_i in terms of k_i_var.
            let dx_i = delta_x_lc(bit_var, precomp, i);
            let dy_i = delta_y_lc(bit_var, precomp, i);
            let denom_delta = x_prev - dx_i.clone();
            let denom_result = x_prev - x_l;

            let (_, _, delta_nonzero) = cs.multiply(denom_delta_inv.into(), denom_delta.clone());
            cs.constrain(delta_nonzero - R1csField::ONE);

            // Constraint 1: s_i * (x_{L_{i-1}} - x_{Δ_i}) = y_{L_{i-1}} - y_{Δ_i}
            let (_, _, out1) = cs.multiply(s_var.into(), denom_delta);
            cs.constrain(out1 - (y_prev - dy_i.clone()));

            // Constraint 2: s_i^2 = x_{L_{i-1}} + x_{L_i} + x_{Δ_i}
            let (_, _, out2) = cs.multiply(s_var.into(), s_var.into());
            cs.constrain(out2 - (x_prev + x_l + dx_i.clone()));

            // Constraint 3: s_i * (x_{L_{i-1}} - x_{L_i}) = y_{L_{i-1}} + y_{L_i}
            let (_, _, out3) = cs.multiply(s_var.into(), denom_result);
            cs.constrain(out3 - (y_prev + y_l));

            x_prev = x_l;
            y_prev = y_l;
        }

        if let Some((result_x, result_y)) = result {
            // Final full-point binding: L_λ = (result_x, result_y).
            cs.constrain(x_prev - result_x);
            cs.constrain(y_prev - result_y);
        }

        Ok((x_prev, y_prev))
    }

    fn chord_exponentiate_r1cs<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        bit_vars: &[Variable<R1csField>],
        precomp: &ChordPrecomp,
        result_x: R1csField,
        result_y: R1csField,
        witness: Option<&ChordWitness>,
    ) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
        chord_exponentiate_r1cs_with_result(
            cs,
            bit_vars,
            precomp,
            Some((result_x, result_y)),
            witness,
        )
    }

    // ------------------------------------------------------------------
    // Chaum-Pedersen proof (paper steps 0 and 1, outside R1CS).
    //
    // Proves log_{g_in}(PK_1) = log_{PK_2}(S) = sk_1 using a Fiat-Shamir
    // Schnorr-style proof of equal discrete logs.
    // ------------------------------------------------------------------

    fn random_nonzero_scalar<C: Cycle>(rng: &mut impl CryptoRngCore) -> C::Scalar {
        loop {
            let scalar = random_scalar::<C>(rng);
            if !bool::from(scalar.is_zero()) {
                return scalar;
            }
        }
    }

    fn stream_challenge_scalar<C: Cycle>(
        stream: &mut impl Observe,
        label: &'static [u8],
    ) -> C::Scalar {
        let mut bytes = [0u8; 64];
        stream.challenge(label, &mut bytes);
        C::scalar_from_wide(&bytes)
    }

    /// Send a Chaum-Pedersen proof of `log_{g_in}(PK_1) = log_{PK_2}(S)`.
    ///
    /// The prover chooses a nonce `r`, commits `R_1 = g_in^r` and
    /// `R_2 = PK_2^r`, extracts challenge `c` from the shared proof stream,
    /// and responds with `z = r + c * sk_1`.
    fn chaum_pedersen_prove(
        stream: &mut ProverProofStream,
        g_in: &Gin,
        pk2: &Gin,
        sk1: &GinScalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let nonce = random_nonzero_scalar::<Secp256k1Cycle>(rng);
        let r1 = *g_in * nonce;
        let r2 = *pk2 * nonce;
        stream.send_point::<GinStreamCurve>(b"cp.r1", &r1, IdentityPolicy::Reject)?;
        stream.send_point::<GinStreamCurve>(b"cp.r2", &r2, IdentityPolicy::Reject)?;
        let challenge = stream_challenge_scalar::<Secp256k1Cycle>(stream, b"cp.challenge");
        let response = nonce + challenge * *sk1;
        stream.send_scalar::<GinStreamCurve>(b"cp.z", &response)
    }

    /// Receive and verify a Chaum-Pedersen proof of
    /// `log_{g_in}(PK_1) = log_{PK_2}(S)`.
    ///
    /// Recomputes the shared-stream challenge and checks:
    /// - `g_in^z = R_1 * PK_1^c`
    /// - `PK_2^z = R_2 * S^c`
    fn chaum_pedersen_verify(
        stream: &mut VerifierProofStream<'_>,
        g_in: &Gin,
        pk1: &Gin,
        pk2: &Gin,
        s: &Gin,
    ) -> Result<()> {
        let r1 = stream.receive_point::<GinStreamCurve>(b"cp.r1", IdentityPolicy::Reject)?;
        let r2 = stream.receive_point::<GinStreamCurve>(b"cp.r2", IdentityPolicy::Reject)?;
        let challenge = stream_challenge_scalar::<Secp256k1Cycle>(stream, b"cp.challenge");
        let response = stream.receive_scalar::<GinStreamCurve>(b"cp.z")?;

        // g_in^z = R_1 * PK_1^c
        let first_equation_holds = *g_in * response == r1 + *pk1 * challenge;
        // PK_2^z = R_2 * S^c
        let second_equation_holds = *pk2 * response == r2 + *s * challenge;
        if !first_equation_holds || !second_equation_holds {
            return Err(Error::ProofVerificationFailed);
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Discrete-log proof of knowledge for step 9 (R = g_out^r).
    //
    // The R1CS commits to the eVRF output randomness `r` (an `Fp` element,
    // since `Fp` is the Secq256k1 scalar field) with a FIXED blinding of 1,
    // yielding the Pedersen prefix `V_r = r * g_out + 1 * g_out,1 = R + g_out,1`.
    // The verifier checks `V_r == R + g_out,1` outside the R1CS, which binds the
    // committed `r` to the public `R` (since `R = r * g_out` follows from the
    // link check).  The Schnorr PoK below proves the dealer actually KNOWS `r`
    // such that `R = g_out^r`, which the link check alone does not establish
    // (a malicious dealer could commit to a fake `r` without knowing the dlog
    // of `R` if the R1CS did not also constrain `r`).  The transcript binds the
    // proof to `R` and `V_r` so it cannot be replayed against a different R1CS
    // instance.
    // ------------------------------------------------------------------

    /// Send a Schnorr proof of knowledge of `r` such that `R = r * g_out`.
    ///
    /// The prover chooses nonce `rho`, commits `A = rho * g_out`, extracts
    /// challenge `c` from the shared transcript, and responds
    /// `t = rho + c * r`.
    fn dlog_prove(
        stream: &mut ProverProofStream,
        g_out: &Secq256k1,
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
    ///
    /// Checks `t * g_out = A + c * R`. The caller separately checks the
    /// Pedersen prefix link `V_r == R + g_out,1` while consuming the preceding
    /// nested R1CS phase.
    fn dlog_verify(
        stream: &mut VerifierProofStream<'_>,
        g_out: &Secq256k1,
        r_point: &Secq256k1,
    ) -> Result<()> {
        let a = stream.receive_point::<GoutStreamCurve>(b"dlog.a", IdentityPolicy::Reject)?;
        let challenge = stream_challenge_scalar::<R1csCycle>(stream, b"dlog.challenge");
        let response = stream.receive_scalar::<GoutStreamCurve>(b"dlog.t")?;

        // t * g_out = A + c * R
        if *g_out * response != a + *r_point * challenge {
            return Err(Error::ProofVerificationFailed);
        }

        Ok(())
    }

    /// Check the Pedersen prefix link: `V_r == R + g_out,1`, where `g_out,1` is
    /// the Bulletproofs blinding base `B_blinding` of `PedersenGens::<R1csCycle>`.
    /// This binds the `r` committed in the R1CS (with fixed blinding 1) to the
    /// public `R`, proving `R = r * g_out` for the committed `r`.
    fn pedersen_prefix_link(
        g_out_blinding: &Secq256k1,
        r_point: &Secq256k1,
        v_r: &GoutCompressed,
    ) -> Result<()> {
        let expected = *r_point + *g_out_blinding;
        let expected_compressed = R1csCycle::point_compress(&expected);
        if expected_compressed.as_ref() != v_r.as_ref() {
            return Err(Error::ProofVerificationFailed);
        }
        Ok(())
    }

    /// Parse a canonical R1CS proof with no trailing or non-canonical bytes.
    fn parse_canonical_r1cs_proof(bytes: &[u8]) -> Result<R1CSProof<R1csCycle>> {
        let proof = R1CSProof::<R1csCycle>::from_bytes(bytes)
            .map_err(|_| Error::ProofVerificationFailed)?;
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
    //   2: k = int(S.x)  (public input constraint tying committed k to S.x)
    //   3: k = Σ 2^j * k_j  (bit-decomposition)
    //   4: T_1 = H_{G_in,1}(msg)^k  (chord-rule exponentiation)
    //   5: T_2 = H_{G_in,2}(msg)^k  (chord-rule exponentiation)
    //   8: r = beta * r_1 + r_2  (linear, r_1 = T_1.x, r_2 = T_2.x)
    // Steps 6, 7 (r_i = int(T_i.x)) are free: r_i is the x-coordinate
    // variable from the chord-rule gadget.
    // Steps 0, 1 (Chaum-Pedersen) and 9 (DLOG PoK + prefix link) are
    // outside the R1CS.
    // ------------------------------------------------------------------

    /// Bulletproofs generator capacity for the one-receiver relation.
    /// Bit-decomp uses 257 multiplier gates; each chord-rule uses 4*256 = 1024.
    /// Total 2305, padded to 8192 for the inner-product layer.
    const R1CS_GENS_CAPACITY: usize = 8192;

    /// Process-wide cache for the single-receiver `BulletproofGens`.
    ///
    /// Construction is 16 384 SHAKE256→Secq256k1 hash-to-curves (~7.5 s on a
    /// fast machine, longer on CI) and is deterministic in the cycle type, so
    /// it is computed once per process via `OnceLock` and shared across every
    /// `evrf_prove` / `evrf_verify` call. Batched paths with a different
    /// capacity still construct their own gens.
    fn shared_bp_gens() -> &'static BulletproofGens<R1csCycle> {
        static GEN: std::sync::OnceLock<BulletproofGens<R1csCycle>> = std::sync::OnceLock::new();
        GEN.get_or_init(|| BulletproofGens::new(R1CS_GENS_CAPACITY, 1))
    }

    /// Process-wide cache for the single-receiver `PedersenGens`.
    ///
    /// Cheap to build (two points) but constructed identically on every call,
    /// so it is cached for uniformity with [`shared_bp_gens`].
    fn shared_pc_gens() -> &'static PedersenGens<R1csCycle> {
        static GEN: std::sync::OnceLock<PedersenGens<R1csCycle>> = std::sync::OnceLock::new();
        GEN.get_or_init(PedersenGens::default)
    }

    /// Random-oracle domain tag for `H_{G_in,1}`.
    const H_GIN_1_DOMAIN: &str = "golden-paper-evrf-H-Gin-1-v1";
    /// Random-oracle domain tag for `H_{G_in,2}`.
    const H_GIN_2_DOMAIN: &str = "golden-paper-evrf-H-Gin-2-v1";
    /// Random-oracle domain tag for per-base chord-rule correction generators.
    const CHORD_CORRECTION_DOMAIN: &str = "golden-paper-evrf-chord-correction-v1";

    /// Compute `H_{G_in,1}(msg)` as a `G_in` point derived from `msg` via
    /// `hash_to_curve` under the `H_GIN_1_DOMAIN` tag.  Used by both prover and
    /// verifier so the hash bases are bound to the message, not trusted from
    /// the public statement.
    fn h_gin_1(msg: &[u8; MESSAGE_BYTES]) -> Gin {
        let mut buf = [0u8; 64];
        buf[..MESSAGE_BYTES].copy_from_slice(msg);
        <Secp256k1 as CurveExt>::hash_to_curve(H_GIN_1_DOMAIN)(&buf[..])
    }

    /// Compute `H_{G_in,2}(msg)` as a `G_in` point derived from `msg` via
    /// `hash_to_curve` under the `H_GIN_2_DOMAIN` tag.  Used by both prover and
    /// verifier so the hash bases are bound to the message.
    fn h_gin_2(msg: &[u8; MESSAGE_BYTES]) -> Gin {
        let mut buf = [0u8; 64];
        buf[..MESSAGE_BYTES].copy_from_slice(msg);
        <Secp256k1 as CurveExt>::hash_to_curve(H_GIN_2_DOMAIN)(&buf[..])
    }

    /// Derive `G_S(X)` for the chord-rule correction terms used with base `X`.
    fn chord_correction_generator(X: &Gin) -> Gin {
        let compressed = Secp256k1Cycle::point_compress(X);
        <Secp256k1 as CurveExt>::hash_to_curve(CHORD_CORRECTION_DOMAIN)(compressed.as_ref())
    }

    /// Decompose an `Fp` element into little-endian bits via its canonical
    /// byte representation.  Produces exactly `K_BITS + 1` bits (the extra bit
    /// catches non-canonical aliases, which the chord-rule full-point binding
    /// rejects).
    fn decompose_k_fp(k: &R1csField, bits: &mut [bool]) {
        let repr = k.to_repr();
        let bytes: &[u8] = repr.as_ref();
        for (i, b) in bits.iter_mut().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            *b = byte_idx < bytes.len() && (bytes[byte_idx] >> bit_idx) & 1 == 1;
        }
    }

    /// Build the R1CS constraints for the one-receiver relation on the given
    /// prover or verifier.  The caller commits to `k` and `r` separately (the
    /// prover with witness + blinding, the verifier with the proof's compressed
    /// commitments) and passes the resulting variables.  The prover passes
    /// witness assignments for the chord-rule gadgets; the verifier passes
    /// `None`.
    #[allow(clippy::too_many_arguments)]
    fn build_one_receiver_r1cs<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        var_k: Variable<R1csField>,
        var_r: Variable<R1csField>,
        s_x: R1csField,
        h1: &Gin,
        h2: &Gin,
        t1_x: R1csField,
        t1_y: R1csField,
        t2_x: R1csField,
        t2_y: R1csField,
        beta: R1csField,
        bit_assignments: &[Option<R1csField>],
        witness1: Option<&ChordWitness>,
        witness2: Option<&ChordWitness>,
    ) -> core::result::Result<(), R1CSError> {
        // Step 2: bind the committed k to the public int(S.x).  Without this
        // constraint, a malicious prover could commit to an arbitrary exponent
        // unrelated to S.x and still satisfy the chord-rule constraints.
        cs.constrain(var_k - s_x);

        let bit_vars = bit_decompose(cs, var_k, bit_assignments)?;

        let precomp1 = precompute_chord(h1, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        let precomp2 = precompute_chord(h2, K_BITS).map_err(|_| R1CSError::VerificationError)?;

        let (x_t1, _) = chord_exponentiate_r1cs(cs, &bit_vars, &precomp1, t1_x, t1_y, witness1)?;
        let (x_t2, _) = chord_exponentiate_r1cs(cs, &bit_vars, &precomp2, t2_x, t2_y, witness2)?;

        // Step 8: r = beta * r_1 + r_2  (r_1 = T_1.x, r_2 = T_2.x)
        cs.constrain(var_r - (x_t1 * beta + x_t2));

        Ok(())
    }

    /// Generate the full one-receiver paper eVRF proof.
    pub fn evrf_prove(
        statement: &SecpSecqEvrfStatement,
        witness: &SecpSecqEvrfWitness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let g_in = Gin::generator();
        let mut stream = ProverProofStream::new(ONE_RECEIVER_PROOF_ID)?;
        observe_one_receiver_statement(&mut stream, statement)?;

        // Step 1: S = PK_2^sk_1.  Verify the witness is consistent with the
        // public S before proving.
        let s_computed = statement.pk2 * witness.sk1;
        if Secp256k1Cycle::point_compress(&s_computed).as_ref()
            != Secp256k1Cycle::point_compress(&statement.s).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }

        // Step 2: k = int(S.x)
        let (s_x, _) = affine(&statement.s)?;
        let k = s_x;

        // Derive H_{G_in,1}(msg), H_{G_in,2}(msg) from the message so the hash
        // bases are bound to msg, not trusted from the statement.  Reject a
        // statement whose h1/h2 do not match the derived values.
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);
        if Secp256k1Cycle::point_compress(&h1).as_ref()
            != Secp256k1Cycle::point_compress(&statement.h1).as_ref()
            || Secp256k1Cycle::point_compress(&h2).as_ref()
                != Secp256k1Cycle::point_compress(&statement.h2).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }

        // Bit-decompose k (step 3 witness).
        let mut bits = [false; K_BITS + 1];
        decompose_k_fp(&k, &mut bits);
        let bit_assignments: Vec<Option<R1csField>> = bits
            .iter()
            .map(|&b| {
                if b {
                    Some(R1csField::ONE)
                } else {
                    Some(R1csField::ZERO)
                }
            })
            .collect();

        // Steps 4, 5: compute chord-rule witnesses for T_1, T_2.
        let witness1 = chord_compute_witness(&bits, &h1, K_BITS)?;
        let witness2 = chord_compute_witness(&bits, &h2, K_BITS)?;

        // Public T_1, T_2 coordinates.
        let (t1_x, t1_y) = affine(&statement.t1)?;
        let (t2_x, t2_y) = affine(&statement.t2)?;

        // Steps 6, 7, 8: r_1 = T_1.x, r_2 = T_2.x, r = beta * r_1 + r_2.
        let r = statement.beta * t1_x + t2_x;

        // Step 9: R = g_out^r.  Verify the public R matches.
        let g_out = Secq256k1::generator();
        let r_computed = g_out * r;
        if R1csCycle::point_compress(&r_computed).as_ref()
            != R1csCycle::point_compress(&statement.r_point).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }

        // Steps 0, 1: stream the Chaum-Pedersen proof first, so every later
        // challenge binds both nonce commitments and the CP challenge/response.
        chaum_pedersen_prove(&mut stream, &g_in, &statement.pk2, &witness.sk1, rng)?;

        // Build the current typed R1CS proof as one nested child over the same
        // transcript. The commitment prefixes are framed in the child payload
        // for verifier reconstruction, but are observed only by R1CS commit.
        let pc_gens = shared_pc_gens();
        let bp_gens = shared_bp_gens();
        stream.send_nested(|transcript| {
            let k_blinding = random_scalar::<R1csCycle>(rng);
            let r_blinding = R1csField::ONE; // fixed for prefix link
            let mut prover = Prover::<R1csCycle, _>::new(pc_gens, transcript);
            let (v_k, var_k) = prover.commit(k, k_blinding);
            let (v_r, var_r) = prover.commit(r, r_blinding);
            build_one_receiver_r1cs(
                &mut prover,
                var_k,
                var_r,
                s_x,
                &h1,
                &h2,
                t1_x,
                t1_y,
                t2_x,
                t2_y,
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

        // Step 9: the DLOG PoK continues from the complete CP + R1CS prefix.
        dlog_prove(&mut stream, &g_out, &r, rng)?;

        Ok(stream.finish())
    }

    /// Verify the full one-receiver paper eVRF proof.
    pub fn evrf_verify(
        statement: &SecpSecqEvrfStatement,
        proof: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let g_in = Gin::generator();
        let g_out = Secq256k1::generator();
        let pc_gens = shared_pc_gens();
        let bp_gens = shared_bp_gens();
        let mut stream = VerifierProofStream::new(ONE_RECEIVER_PROOF_ID, proof)?;
        observe_one_receiver_statement(&mut stream, statement)?;

        // Steps 0, 1: verify the Chaum-Pedersen proof before entering R1CS.
        chaum_pedersen_verify(
            &mut stream,
            &g_in,
            &statement.pk1,
            &statement.pk2,
            &statement.s,
        )?;

        // Step 2: k = int(S.x) is public.  The R1CS constrains the committed k
        // to equal s_x, binding the exponent to the public S.x.
        let (s_x, _) = affine(&statement.s)?;

        // Derive H_{G_in,1}(msg), H_{G_in,2}(msg) from the message so the hash
        // bases are bound to msg, not trusted from the statement.  Reject a
        // statement whose h1/h2 do not match the derived values.
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);
        if Secp256k1Cycle::point_compress(&h1).as_ref()
            != Secp256k1Cycle::point_compress(&statement.h1).as_ref()
            || Secp256k1Cycle::point_compress(&h2).as_ref()
                != Secp256k1Cycle::point_compress(&statement.h2).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }

        // Public T_1, T_2 coordinates.
        let (t1_x, t1_y) = affine(&statement.t1)?;
        let (t2_x, t2_y) = affine(&statement.t2)?;

        // Parse the commitment prefixes and current typed R1CS proof from one
        // borrowed child frame. The R1CS verifier receives the same transcript;
        // the parent does not observe the raw child length or payload.
        stream.receive_nested(|transcript, payload| {
            // R1CS commitments can be identity encodings in the current engine;
            // their relation-specific policy is therefore explicitly `Allow`.
            let (v_k, cursor) = parse_nested_commitment(payload, 0, IdentityPolicy::Allow)?;
            let (v_r, cursor) = parse_nested_commitment(payload, cursor, IdentityPolicy::Allow)?;
            let r1cs_bytes = payload
                .get(cursor..)
                .ok_or(Error::ProofVerificationFailed)?;
            let r1cs_proof = parse_canonical_r1cs_proof(r1cs_bytes)?;

            // Step 9 prefix link: V_r == R + g_out,1.
            pedersen_prefix_link(&pc_gens.B_blinding, &statement.r_point, &v_r)?;

            // Build the verifier-side R1CS and verify. The verifier commits
            // using the nested proof's canonical compressed commitments.
            let mut verifier = Verifier::<R1csCycle, _>::new(transcript);
            let var_k = verifier.commit(v_k);
            let var_r = verifier.commit(v_r);
            let verifier_bits = vec![None; K_BITS + 1];
            build_one_receiver_r1cs(
                &mut verifier,
                var_k,
                var_r,
                s_x,
                &h1,
                &h2,
                t1_x,
                t1_y,
                t2_x,
                t2_y,
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

        // Step 9: verify the DLOG PoK after the complete CP + R1CS prefix.
        dlog_verify(&mut stream, &g_out, &statement.r_point)?;

        stream.finish()
    }

    // ------------------------------------------------------------------
    // Batched statement validation and transcript binding.
    // ------------------------------------------------------------------

    fn validate_batched_public_relations(statement: &BatchedEvrfStatement) -> Result<()> {
        if statement.receivers.is_empty()
            || statement.commitment_coefficients.is_empty()
            || statement.commitment_coefficients.len() != statement.threshold
            || statement.statement_roots.len() != statement.receivers.len()
            || is_identity(&statement.pk1)
        {
            return Err(Error::ProofVerificationFailed);
        }
        for rec in &statement.receivers {
            if is_identity(&rec.pkj)
                || is_identity(&rec.share_commitment)
                || is_identity(&rec.pad_commitment)
                || is_identity(&rec.dh_commitment)
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
        }
        Ok(())
    }

    fn feldman_share_commitment(coefficients: &[Gin], receiver: ParticipantIndex) -> Gin {
        let x = Fq::from(u64::from(receiver.get()));
        let mut x_pow = Fq::ONE;
        let mut result = Gin::identity();
        for coefficient in coefficients {
            result += *coefficient * x_pow;
            x_pow *= x;
        }
        result
    }

    /// Observe the complete batched dealer statement in its existing canonical order.
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
            stream.observe_point::<GinStreamCurve>(
                b"dh-commitment",
                &rec.dh_commitment,
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
    /// canonical bit decomposition and the `g^sk = PK_1` exponentiation.
    const BATCHED_SHARED_MULTIPLIERS: usize = 2_051;
    /// Multipliers added by one non-identity Feldman coefficient opening.
    const BATCHED_COEFFICIENT_MULTIPLIERS: usize = 2_052;
    /// Multipliers added by one receiver relation.
    const BATCHED_RECEIVER_MULTIPLIERS: usize = 11_219;

    /// Count multipliers from the exact public circuit shape.
    fn batched_multiplier_count(threshold: usize, receiver_count: usize) -> Result<usize> {
        if threshold == 0 || receiver_count == 0 {
            return Err(Error::ProofVerificationFailed);
        }
        let coefficients = threshold
            .checked_mul(BATCHED_COEFFICIENT_MULTIPLIERS)
            .ok_or(Error::ProofVerificationFailed)?;
        let receivers = receiver_count
            .checked_mul(BATCHED_RECEIVER_MULTIPLIERS)
            .ok_or(Error::ProofVerificationFailed)?;
        BATCHED_SHARED_MULTIPLIERS
            .checked_add(coefficients)
            .and_then(|count| count.checked_add(receivers))
            .ok_or(Error::ProofVerificationFailed)
    }

    fn bit_options(bits: &[bool]) -> Vec<Option<R1csField>> {
        bits.iter()
            .map(|&b| {
                if b {
                    Some(R1csField::ONE)
                } else {
                    Some(R1csField::ZERO)
                }
            })
            .collect()
    }

    #[derive(Clone, Debug)]
    struct HiddenReceiverWitness {
        /// Chord witness for `S_j = PK_j^sk_1`.
        sk_pkj: ChordWitness,
        /// Bits of `k_j = int(S_j.x)`.
        k_bits: Vec<Option<R1csField>>,
        /// Chord witness for `T_{1,j} = H1(msg)^k_j`.
        t1: ChordWitness,
        /// Chord witness for `T_{2,j} = H2(msg)^k_j`.
        t2: ChordWitness,
        /// Boolean `reduce_q` selecting whether `r_j` reduced by `q`.
        reduce_q: R1csField,
        /// `pad_j = beta * T_{1,j}.x + T_{2,j}.x mod q`.
        pad: R1csField,
        /// Bits of `pad_j`.
        pad_bits: Vec<Option<R1csField>>,
        /// Private dealer share `s_j`.
        share: R1csField,
        /// Bits of `s_j`.
        share_bits: Vec<Option<R1csField>>,
        /// Chord witness for `g_in^s_j`.
        share_commitment: ChordWitness,
        /// Chord witness for `g_in^pad_j`.
        pad_commitment: ChordWitness,
        /// Chord witness for `PK_j^pad_j`.
        dh_commitment: ChordWitness,
    }

    fn prove_feldman_coefficients<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        coefficients: &[Gin],
        coefficient_scalars: Option<&[GinScalar]>,
        g_in: &Gin,
    ) -> core::result::Result<(), R1CSError> {
        let precomp = precompute_chord(g_in, K_BITS).map_err(|_| R1CSError::VerificationError)?;

        for (i, coefficient) in coefficients.iter().enumerate() {
            let scalar_fp = coefficient_scalars.map(|scalars| fq_to_fp(&scalars[i]));
            let scalar_bits = if let Some(scalar_fp) = scalar_fp.as_ref() {
                let mut bits = [false; K_BITS + 1];
                decompose_k_fp(scalar_fp, &mut bits);
                bit_options(&bits)
            } else {
                vec![None; K_BITS + 1]
            };
            let scalar_var = cs.allocate(scalar_fp)?;
            let scalar_bit_vars = bit_decompose_q(cs, scalar_var, &scalar_bits)?;
            if is_identity(coefficient) {
                for &bit_var in &scalar_bit_vars {
                    cs.constrain(bit_var.into());
                }
            } else {
                let (coefficient_x, coefficient_y) =
                    affine(coefficient).map_err(|_| R1CSError::VerificationError)?;
                let witness = if let Some(scalar_fp) = scalar_fp.as_ref() {
                    let mut bits = [false; K_BITS + 1];
                    decompose_k_fp(scalar_fp, &mut bits);
                    Some(
                        chord_compute_witness(&bits, g_in, K_BITS)
                            .map_err(|_| R1CSError::VerificationError)?,
                    )
                } else {
                    None
                };
                chord_exponentiate_r1cs_with_result(
                    cs,
                    &scalar_bit_vars,
                    &precomp,
                    Some((coefficient_x, coefficient_y)),
                    witness.as_ref(),
                )?;
            }
        }

        Ok(())
    }

    fn ensure_feldman_coefficient_openings(
        coefficients: &[Gin],
        coefficient_scalars: &[GinScalar],
    ) -> Result<()> {
        if coefficients.len() != coefficient_scalars.len() {
            return Err(Error::ProofVerificationFailed);
        }

        let g_in = Gin::generator();
        for (coefficient, scalar) in coefficients.iter().zip(coefficient_scalars.iter()) {
            let opened = g_in * *scalar;
            if Secp256k1Cycle::point_compress(&opened).as_ref()
                != Secp256k1Cycle::point_compress(coefficient).as_ref()
            {
                return Err(Error::ProofVerificationFailed);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_hidden_receiver_slot<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        rec: &BatchedReceiverStatement,
        sk_bit_vars: &[Variable<R1csField>],
        h1: &Gin,
        h2: &Gin,
        beta: R1csField,
        g_in: &Gin,
        witness: Option<&HiddenReceiverWitness>,
    ) -> core::result::Result<(), R1CSError> {
        let precomp_s =
            precompute_chord(&rec.pkj, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        let (s_x, _) = chord_exponentiate_r1cs_with_result(
            cs,
            sk_bit_vars,
            &precomp_s,
            None,
            witness.map(|w| &w.sk_pkj),
        )?;

        let verifier_k_bits = vec![None; K_BITS + 1];
        let k_bits = witness.map_or(verifier_k_bits.as_slice(), |w| w.k_bits.as_slice());
        let k_bit_vars = bit_decompose(cs, s_x, k_bits)?;

        let precomp1 = precompute_chord(h1, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        let precomp2 = precompute_chord(h2, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        let (x_t1, _) = chord_exponentiate_r1cs_with_result(
            cs,
            &k_bit_vars,
            &precomp1,
            None,
            witness.map(|w| &w.t1),
        )?;
        let (x_t2, _) = chord_exponentiate_r1cs_with_result(
            cs,
            &k_bit_vars,
            &precomp2,
            None,
            witness.map(|w| &w.t2),
        )?;

        let r_lc = x_t1 * beta + x_t2;
        let pad_var = cs.allocate(witness.map(|w| w.pad))?;

        let reduce_assignment = witness.map(|w| w.reduce_q);
        let (reduce, reduce_right, reduce_out) =
            cs.allocate_multiplier(reduce_assignment.map(|bit| (bit, R1csField::ONE - bit)))?;
        cs.constrain(reduce_right - (LinearCombination::from(R1csField::ONE) - reduce));
        cs.constrain(reduce_out.into());
        cs.constrain(pad_var - (r_lc - reduce * Q_AS_FP));

        let verifier_pad_bits = vec![None; K_BITS + 1];
        let pad_bits = witness.map_or(verifier_pad_bits.as_slice(), |w| w.pad_bits.as_slice());
        let pad_bit_vars = bit_decompose_q(cs, pad_var, pad_bits)?;
        constrain_bits_lt_bound_when(cs, &pad_bit_vars, pad_bits, &SECP256K1_P_MINUS_Q_LE, reduce)?;

        let (pad_commitment_x, pad_commitment_y) =
            affine(&rec.pad_commitment).map_err(|_| R1CSError::VerificationError)?;
        let precomp_pad =
            precompute_chord(g_in, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        chord_exponentiate_r1cs_with_result(
            cs,
            &pad_bit_vars,
            &precomp_pad,
            Some((pad_commitment_x, pad_commitment_y)),
            witness.map(|w| &w.pad_commitment),
        )?;

        let share_var = cs.allocate(witness.map(|w| w.share))?;
        let verifier_share_bits = vec![None; K_BITS + 1];
        let share_bits =
            witness.map_or(verifier_share_bits.as_slice(), |w| w.share_bits.as_slice());
        let share_bit_vars = bit_decompose_q(cs, share_var, share_bits)?;
        let (share_commitment_x, share_commitment_y) =
            affine(&rec.share_commitment).map_err(|_| R1CSError::VerificationError)?;
        let precomp_share =
            precompute_chord(g_in, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        chord_exponentiate_r1cs_with_result(
            cs,
            &share_bit_vars,
            &precomp_share,
            Some((share_commitment_x, share_commitment_y)),
            witness.map(|w| &w.share_commitment),
        )?;

        let (dh_commitment_x, dh_commitment_y) =
            affine(&rec.dh_commitment).map_err(|_| R1CSError::VerificationError)?;
        let precomp_dh =
            precompute_chord(&rec.pkj, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        chord_exponentiate_r1cs_with_result(
            cs,
            &pad_bit_vars,
            &precomp_dh,
            Some((dh_commitment_x, dh_commitment_y)),
            witness.map(|w| &w.dh_commitment),
        )?;

        Ok(())
    }

    fn compute_hidden_receiver_witness(
        msg: &[u8; MESSAGE_BYTES],
        sk1: &Fq,
        share: &Fq,
        rec: &BatchedReceiverStatement,
        beta: &Fp,
    ) -> Result<HiddenReceiverWitness> {
        let g_in = Gin::generator();
        let h1 = h_gin_1(msg);
        let h2 = h_gin_2(msg);
        let sj = rec.pkj * *sk1;
        let (s_x, _) = affine(&sj)?;
        let mut k_bool_bits = [false; K_BITS + 1];
        decompose_k_fp(&s_x, &mut k_bool_bits);
        let k_bits = bit_options(&k_bool_bits);
        let t1 = chord_evaluate_point(&k_bool_bits, &h1, K_BITS)?;
        let t2 = chord_evaluate_point(&k_bool_bits, &h2, K_BITS)?;
        let (t1_x, _) = affine(&t1)?;
        let (t2_x, _) = affine(&t2)?;
        let r = *beta * t1_x + t2_x;
        let pad_fq = fp_to_fq(&r);
        let pad = fq_to_fp(&pad_fq);
        let reduce_q = if pad == r {
            R1csField::ZERO
        } else {
            R1csField::ONE
        };

        let pad_commitment = g_in * pad_fq;
        if Secp256k1Cycle::point_compress(&pad_commitment).as_ref()
            != Secp256k1Cycle::point_compress(&rec.pad_commitment).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }
        let dh_commitment = rec.pkj * pad_fq;
        if Secp256k1Cycle::point_compress(&dh_commitment).as_ref()
            != Secp256k1Cycle::point_compress(&rec.dh_commitment).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }

        let share_commitment = g_in * *share;
        if Secp256k1Cycle::point_compress(&share_commitment).as_ref()
            != Secp256k1Cycle::point_compress(&rec.share_commitment).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }
        if g_in * rec.encrypted_share != share_commitment + pad_commitment {
            return Err(Error::ProofVerificationFailed);
        }

        let mut sk_bits = [false; K_BITS + 1];
        decompose_k_fp(&fq_to_fp(sk1), &mut sk_bits);
        let mut pad_bool_bits = [false; K_BITS + 1];
        decompose_k_fp(&pad, &mut pad_bool_bits);
        let share_fp = fq_to_fp(share);
        let mut share_bool_bits = [false; K_BITS + 1];
        decompose_k_fp(&share_fp, &mut share_bool_bits);

        Ok(HiddenReceiverWitness {
            sk_pkj: chord_compute_witness(&sk_bits, &rec.pkj, K_BITS)?,
            k_bits,
            t1: chord_compute_witness(&k_bool_bits, &h1, K_BITS)?,
            t2: chord_compute_witness(&k_bool_bits, &h2, K_BITS)?,
            reduce_q,
            pad,
            pad_bits: bit_options(&pad_bool_bits),
            share: share_fp,
            share_bits: bit_options(&share_bool_bits),
            share_commitment: chord_compute_witness(&share_bool_bits, &g_in, K_BITS)?,
            pad_commitment: chord_compute_witness(&pad_bool_bits, &g_in, K_BITS)?,
            dh_commitment: chord_compute_witness(&pad_bool_bits, &rec.pkj, K_BITS)?,
        })
    }

    fn prove_batched_r1cs(
        params: &BatchedEvrfPublicParams,
        statement: &BatchedEvrfStatement,
        witness: &BatchedEvrfWitness,
        rng: &mut impl CryptoRngCore,
        transcript: &mut Transcript,
    ) -> Result<Vec<u8>> {
        if witness.shares.len() != statement.receivers.len()
            || witness.coefficient_scalars.len() != statement.commitment_coefficients.len()
        {
            return Err(Error::ProofVerificationFailed);
        }
        let g_in = Gin::generator();

        ensure_feldman_coefficient_openings(
            &statement.commitment_coefficients,
            &witness.coefficient_scalars,
        )?;

        // Verify PK_1 = g_in^sk_1.
        let pk1_computed = g_in * witness.sk1;
        if Secp256k1Cycle::point_compress(&pk1_computed).as_ref()
            != Secp256k1Cycle::point_compress(&statement.pk1).as_ref()
        {
            return Err(Error::ProofVerificationFailed);
        }
        // Derive h1, h2 from msg and reject a statement whose h1/h2 would not
        // match (the statement does not carry h1/h2; the R1CS uses the derived
        // values directly).
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);

        let mut prover = Prover::<R1csCycle, _>::new(&params.pc_gens, transcript);
        let sk_fp = fq_to_fp(&witness.sk1);
        let mut sk_bool_bits = [false; K_BITS + 1];
        decompose_k_fp(&sk_fp, &mut sk_bool_bits);
        let sk_bit_assignments = bit_options(&sk_bool_bits);
        let sk_var = prover
            .allocate(Some(sk_fp))
            .map_err(|_| Error::ProofVerificationFailed)?;
        let sk_bit_vars = bit_decompose_q(&mut prover, sk_var, &sk_bit_assignments)
            .map_err(|_| Error::ProofVerificationFailed)?;

        let pk1_witness = chord_compute_witness(&sk_bool_bits, &g_in, K_BITS)?;
        let pk1_precomp =
            precompute_chord(&g_in, K_BITS).map_err(|_| Error::ProofVerificationFailed)?;
        let (pk1_x, pk1_y) = affine(&statement.pk1)?;
        chord_exponentiate_r1cs_with_result(
            &mut prover,
            &sk_bit_vars,
            &pk1_precomp,
            Some((pk1_x, pk1_y)),
            Some(&pk1_witness),
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        prove_feldman_coefficients(
            &mut prover,
            &statement.commitment_coefficients,
            Some(&witness.coefficient_scalars),
            &g_in,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        for (rec, share) in statement.receivers.iter().zip(witness.shares.iter()) {
            let rec_witness = compute_hidden_receiver_witness(
                &statement.msg,
                &witness.sk1,
                share,
                rec,
                &statement.beta,
            )?;
            build_hidden_receiver_slot(
                &mut prover,
                rec,
                &sk_bit_vars,
                &h1,
                &h2,
                statement.beta,
                &g_in,
                Some(&rec_witness),
            )
            .map_err(|_| Error::ProofVerificationFailed)?;
        }

        let r1cs_proof = prover
            .prove(&params.bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        Ok(r1cs_proof.to_bytes())
    }

    /// Generate a Batched Dealer Proof as a Proof Stream containing one nested R1CS proof.
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
        Ok(stream.finish())
    }

    fn prepare_batched_r1cs(
        params: &BatchedEvrfPublicParams,
        statement: &BatchedEvrfStatement,
        proof: &R1CSProof<R1csCycle>,
        rng: &mut impl CryptoRngCore,
        transcript: &mut Transcript,
    ) -> Result<VerificationEquation<R1csCycle>> {
        let g_in = Gin::generator();
        // Derive h1, h2 from msg.
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);

        let mut verifier = Verifier::<R1csCycle, _>::new(transcript);
        let sk_var = verifier
            .allocate(None)
            .map_err(|_| Error::ProofVerificationFailed)?;
        let verifier_sk_bits = vec![None; K_BITS + 1];
        let sk_bit_vars = bit_decompose_q(&mut verifier, sk_var, &verifier_sk_bits)
            .map_err(|_| Error::ProofVerificationFailed)?;

        let pk1_precomp =
            precompute_chord(&g_in, K_BITS).map_err(|_| Error::ProofVerificationFailed)?;
        let (pk1_x, pk1_y) = affine(&statement.pk1)?;
        chord_exponentiate_r1cs_with_result(
            &mut verifier,
            &sk_bit_vars,
            &pk1_precomp,
            Some((pk1_x, pk1_y)),
            None,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        prove_feldman_coefficients(
            &mut verifier,
            &statement.commitment_coefficients,
            None,
            &g_in,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        for rec in &statement.receivers {
            build_hidden_receiver_slot(
                &mut verifier,
                rec,
                &sk_bit_vars,
                &h1,
                &h2,
                statement.beta,
                &g_in,
                None,
            )
            .map_err(|_| Error::ProofVerificationFailed)?;
        }

        verifier
            .verification_equation(proof, &params.pc_gens, &params.bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)
    }

    fn parse_batched_proof_stream(
        statement: &BatchedEvrfStatement,
        proof: &[u8],
    ) -> Result<(R1CSProof<R1csCycle>, Transcript)> {
        let mut stream = VerifierProofStream::new(BATCHED_PROOF_ID, proof)?;
        observe_batched_statement(&mut stream, statement)?;
        let parsed = stream.receive_nested(|transcript, payload| {
            Ok((parse_canonical_r1cs_proof(payload)?, transcript.clone()))
        })?;
        stream.finish()?;
        Ok(parsed)
    }

    /// Verify a Batched Dealer Proof represented as a Proof Stream with one nested R1CS proof.
    pub fn evrf_batched_verify(
        params: &BatchedEvrfPublicParams,
        statement: &BatchedEvrfStatement,
        proof: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        params.validate_statement(statement)?;
        validate_batched_public_relations(statement)?;
        let (r1cs_proof, mut transcript) = parse_batched_proof_stream(statement, proof)?;
        let equation = prepare_batched_r1cs(params, statement, &r1cs_proof, rng, &mut transcript)?;
        equation
            .verify()
            .map_err(|_| Error::ProofVerificationFailed)
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
        let parsed_proofs = instances
            .iter()
            .map(|(statement, proof)| parse_batched_proof_stream(statement, proof))
            .collect::<Result<Vec<_>>>()?;

        // Derive the batching entropy from the complete ordered statements and
        // proof bytes. The lower layer samples a fresh nonzero coefficient for
        // each equation from this transcript-derived RNG.
        let mut batch_transcript = Transcript::new(b"golden-paper-evrf-proof-batch-v1");
        batch_transcript.append_u64(b"batch-len", instances.len() as u64);
        for (index, (statement, proof)) in instances.iter().enumerate() {
            batch_transcript.append_u64(b"proof-index", index as u64);
            observe_batched_statement(&mut batch_transcript, statement)?;
            batch_transcript.append_u64(b"proof-len", proof.len() as u64);
            batch_transcript.append_message(b"proof", proof);
        }
        let mut seed = [0u8; 32];
        batch_transcript.challenge_bytes(b"batch-rng", &mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);

        let mut equations = Vec::with_capacity(instances.len());
        for ((statement, _), (r1cs_proof, mut transcript)) in instances.iter().zip(parsed_proofs) {
            let equation =
                prepare_batched_r1cs(params, statement, &r1cs_proof, &mut rng, &mut transcript)?;
            equations.push(equation);
        }

        VerificationEquation::verify_batch(equations, &mut rng)
            .map_err(|_| Error::ProofVerificationFailed)
    }

    // ------------------------------------------------------------------
    // Scalar representation helpers shared by the circuit and DKG adapter.
    // ------------------------------------------------------------------

    /// Convert an `Fp` element to `Fq` by reinterpreting its canonical LE bytes
    /// as a raw integer and reducing mod `q`. Needed because `p > q` for
    /// Secp256k1, so `Fq::from_repr` would reject Fp values in `[q, p)`.
    fn fp_to_fq(fp: &Fp) -> Fq {
        let bytes: [u8; 32] = *fp.to_repr().inner();
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(
                bytes[i * 8..i * 8 + 8]
                    .try_into()
                    .expect("32-byte canonical repr yields 4 u64 limbs"),
            );
        }
        Fq::from_raw(limbs)
    }

    /// Convert an `Fq` element to `Fp` by reinterpreting its canonical LE
    /// bytes. Always succeeds because `q < p` for Secp256k1, so every canonical
    /// `Fq` value is a valid `Fp` element.
    fn fq_to_fp(fq: &Fq) -> Fp {
        let bytes: [u8; 32] = *fq.to_repr().inner();
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(
                bytes[i * 8..i * 8 + 8]
                    .try_into()
                    .expect("32-byte canonical repr yields 4 u64 limbs"),
            );
        }
        Fp::from_raw(limbs)
    }

    /// The Secp256k1 scalar-field modulus `q` as an `Fp` element. Used to check
    /// the two possible values of `r_j` (`pad` or `pad + q`) that reduce to the
    /// same `Fq` pad.
    const Q_AS_FP: Fp = Fp::from_raw([
        0xbfd2_5e8c_d036_4141,
        0xbaae_dce6_af48_a03b,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
    ]);

    /// Compare two `Fp` elements by their canonical integer value. Returns true
    /// iff `a < b` as integers in `[0, p)`. Used to detect whether `pad + q`
    /// wrapped mod `p`, so the `pad + q` case is only accepted when it is a
    /// canonical representative strictly less than `p`.
    #[cfg(test)]
    fn fp_canonical_lt(a: &Fp, b: &Fp) -> bool {
        let a_repr = a.to_repr();
        let b_repr = b.to_repr();
        let a_bytes: &[u8] = a_repr.as_ref();
        let b_bytes: &[u8] = b_repr.as_ref();
        for i in (0..a_bytes.len()).rev() {
            if a_bytes[i] != b_bytes[i] {
                return a_bytes[i] < b_bytes[i];
            }
        }
        false
    }

    mod dkg_backend;

    pub use dkg_backend::SecpSecqBackend;

    /// Test-only helpers exposed so integration tests under `tests/` can
    /// build honest statements without re-implementing the protocol's
    /// chord-rule derivation. Marked `#[doc(hidden)]` because these exist
    /// purely for the crate's own test suite.
    #[doc(hidden)]
    pub mod testing {
        use super::*;

        /// Build a valid `(statement, witness)` pair for the one-receiver
        /// relation, deriving all public values from `sk1`, `pk2`, `msg`,
        /// and `beta`. Mirrors the steps the prover runs internally.
        pub fn build_statement_witness(
            msg: &[u8; MESSAGE_BYTES],
            sk1: GinScalar,
            pk2: Gin,
            beta: R1csField,
        ) -> (SecpSecqEvrfStatement, SecpSecqEvrfWitness) {
            let g_in = Gin::generator();

            let pk1 = g_in * sk1;
            let s = pk2 * sk1;
            let (k, _) = affine(&s).expect("S affine");

            let h1 = h_gin_1(msg);
            let h2 = h_gin_2(msg);

            let mut bits = [false; K_BITS + 1];
            decompose_k_fp(&k, &mut bits);
            let t1 = chord_evaluate_point(&bits, &h1, K_BITS).expect("T1");
            let t2 = chord_evaluate_point(&bits, &h2, K_BITS).expect("T2");

            let (t1_x, _) = affine(&t1).expect("T1 affine");
            let (t2_x, _) = affine(&t2).expect("T2 affine");
            let r = beta * t1_x + t2_x;

            let g_out = Secq256k1::generator();
            let r_point = g_out * r;

            let statement = SecpSecqEvrfStatement {
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
            let witness = SecpSecqEvrfWitness { sk1 };
            (statement, witness)
        }

        /// Build a valid batched `(statement, witness)` pair for `n`
        /// receivers (one per `pkj`), deriving all public values from
        /// `sk1` and the receiver public keys.
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
            let coefficient_scalars = vec![GinScalar::from(10u64), GinScalar::ONE];
            let commitment_coefficients = coefficient_scalars
                .iter()
                .map(|coefficient| g_in * *coefficient)
                .collect::<Vec<_>>();

            let mut shares = Vec::with_capacity(pkjs.len());
            let receivers: Vec<BatchedReceiverStatement> = pkjs
                .iter()
                .enumerate()
                .map(|(j, &pkj)| {
                    let sj = pkj * sk1;
                    let (k, _) = affine(&sj).expect("S affine");
                    let mut bits = [false; K_BITS + 1];
                    decompose_k_fp(&k, &mut bits);
                    let t1j = chord_evaluate_point(&bits, &h1, K_BITS).expect("T1");
                    let t2j = chord_evaluate_point(&bits, &h2, K_BITS).expect("T2");
                    let (t1_x, _) = affine(&t1j).expect("T1 affine");
                    let (t2_x, _) = affine(&t2j).expect("T2 affine");
                    let r = beta * t1_x + t2_x;
                    let pad = fp_to_fq(&r);
                    let receiver =
                        ParticipantIndex::new((j as u32) + 1).expect("nonzero receiver index");
                    let share = GinScalar::from((j as u64) + 11);
                    shares.push(share);
                    BatchedReceiverStatement {
                        receiver,
                        pkj,
                        share_commitment: g_in * share,
                        pad_commitment: g_in * pad,
                        dh_commitment: pkj * pad,
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
                coefficient_scalars,
                shares,
            };
            (statement, witness)
        }
    }

    #[cfg(test)]
    mod chord_tests {
        use super::*;
        use ff::PrimeField;

        /// Decompose `k` into little-endian bits via its canonical
        /// little-endian byte representation.  Bits beyond the field's
        /// canonical byte length are zero.
        fn decompose(k: &Fq, bits: &mut [bool]) {
            let repr = k.to_repr();
            let bytes: &[u8] = repr.as_ref();
            for (i, b) in bits.iter_mut().enumerate() {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                *b = byte_idx < bytes.len() && (bytes[byte_idx] >> bit_idx) & 1 == 1;
            }
        }

        #[test]
        fn correction_scalars_sum_to_zero() {
            let mut sum = Fq::ZERO;
            for j in 0..=K_BITS {
                sum += chord_cj(j, K_BITS);
            }
            // Σ c_j = 0 mod |G_in|, and |G_in| ≡ 0 in Fq, so the sum is 0.
            assert!(
                bool::from(sum.is_zero()),
                "correction scalars must sum to 0 in Fq, got {sum:?}"
            );
        }

        #[test]
        fn chord_evaluate_matches_direct_scalar_mul() {
            let X = Gin::generator() * Fq::from(42u64);
            let k = Fq::from_raw([
                0xDEADBEEFCAFEBABE,
                0x0123456789ABCDEF,
                0xFEDCBA9876543210,
                0x0000000000000001,
            ]);
            let mut bits = [false; K_BITS + 1];
            decompose(&k, &mut bits);

            let (lx, ly) = chord_evaluate(&bits, &X, K_BITS).expect("eval");
            let expected = X * k;
            let (ex, ey) = affine(&expected).expect("affine");
            assert_eq!(lx, ex, "L_λ x-coordinate mismatch");
            assert_eq!(ly, ey, "L_λ y-coordinate mismatch");
        }

        #[test]
        fn chord_evaluate_small_exponent() {
            let X = Gin::generator() * Fq::from(99u64);
            let k = Fq::from(5u64);
            let mut bits = [false; K_BITS + 1];
            decompose(&k, &mut bits);

            let (lx, ly) = chord_evaluate(&bits, &X, K_BITS).expect("eval");
            let expected = X * k;
            let (ex, ey) = affine(&expected).expect("affine");
            assert_eq!(lx, ex);
            assert_eq!(ly, ey);
        }

        #[test]
        fn precompute_chord_coordinates_are_correct() {
            let X = Gin::generator() * Fq::from(123u64);
            let g_s = chord_correction_generator(&X);
            let precomp = precompute_chord(&X, K_BITS).expect("precompute");

            assert_eq!(precomp.c.len(), K_BITS + 1, "c vector length");
            assert_eq!(precomp.d.len(), K_BITS + 1, "d vector length");

            // Independently recompute C_j = c_j · G_S and D_j = 2^j · X + C_j
            // for a representative sample of indices (first, middle, last, and
            // a few in between) and verify the precomputed coordinates match.
            let mut p_j = X;
            for j in 0..=K_BITS {
                let cj = chord_cj(j, K_BITS);
                let c_j_point = g_s * cj;
                let d_j_point = p_j + c_j_point;
                let (cx, cy) = affine(&c_j_point).expect("C_j affine");
                let (dx, dy) = affine(&d_j_point).expect("D_j affine");
                assert_eq!(precomp.c[j], (cx, cy), "C_{j} coordinate mismatch");
                assert_eq!(precomp.d[j], (dx, dy), "D_{j} coordinate mismatch");
                p_j = p_j.double();
            }
        }

        #[test]
        fn chord_correction_generator_is_base_bound() {
            let x1 = Gin::generator() * Fq::from(123u64);
            let x2 = Gin::generator() * Fq::from(456u64);
            assert_ne!(
                Secp256k1Cycle::point_compress(&chord_correction_generator(&x1)).as_ref(),
                Secp256k1Cycle::point_compress(&chord_correction_generator(&x2)).as_ref(),
                "different chord bases should derive different correction generators"
            );
        }
    }

    #[cfg(test)]
    mod r1cs_tests {
        use super::*;
        use bulletproofs_cycle::{
            generators::{BulletproofGens, PedersenGens},
            random_scalar, Prover, Verifier,
        };
        use ff::PrimeField;
        use merlin::Transcript;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        const R1CS_TEST_DOMAIN: &[u8] = b"golden-paper-evrf-r1cs-test";

        #[test]
        fn batched_parameter_setup_uses_exact_circuit_shape() {
            for (receivers, multipliers, capacity) in [
                (1, 17_374, 32_768),
                (4, 51_031, 65_536),
                (9, 107_126, 131_072),
            ] {
                let count = batched_multiplier_count(2, receivers).expect("valid shape");
                assert_eq!(count, multipliers, "receiver count {receivers}");
                assert_eq!(
                    count.next_power_of_two(),
                    capacity,
                    "receiver count {receivers}"
                );
            }
            assert_ne!(
                batched_multiplier_count(1, 1).expect("valid shape"),
                batched_multiplier_count(2, 1).expect("valid shape"),
                "threshold must be part of the parameter shape"
            );
        }

        /// Build a canonical bit decomposition of `k` (little-endian).
        fn decompose_k(k: &R1csField, bits: &mut [Option<R1csField>]) {
            let repr = k.to_repr();
            let bytes: &[u8] = repr.as_ref();
            for (i, b) in bits.iter_mut().enumerate() {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                let val = if byte_idx < bytes.len() && (bytes[byte_idx] >> bit_idx) & 1 == 1 {
                    R1csField::ONE
                } else {
                    R1csField::ZERO
                };
                *b = Some(val);
            }
        }

        fn decompose_le_bytes(bytes: &[u8], bits: &mut [Option<R1csField>]) {
            for (i, b) in bits.iter_mut().enumerate() {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                let val = if byte_idx < bytes.len() && (bytes[byte_idx] >> bit_idx) & 1 == 1 {
                    R1csField::ONE
                } else {
                    R1csField::ZERO
                };
                *b = Some(val);
            }
        }

        /// Helper: prove and verify a bit-decomposition of `k` with the given
        /// bit assignments.  Returns `Ok(())` if the verifier accepts.
        fn run_bit_decompose(
            k: R1csField,
            bit_assignments: &[Option<R1csField>],
        ) -> core::result::Result<(), R1CSError> {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let bp_gens = BulletproofGens::<R1csCycle>::new(1024, 1);
            let mut rng = ChaCha20Rng::seed_from_u64(0xA1B2C3D4);

            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let (v_k, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            bit_decompose(&mut prover, var_k, bit_assignments)?;
            let proof = prover.prove(&bp_gens, &mut rng).expect("prove");

            let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(R1CS_TEST_DOMAIN));
            let v_k_var = verifier.commit(v_k);
            let verifier_bits = vec![None; K_BITS + 1];
            bit_decompose(&mut verifier, v_k_var, &verifier_bits)?;
            verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)
        }

        fn run_conditional_pad_bound(
            pad: R1csField,
            reduce: R1csField,
        ) -> core::result::Result<(), R1CSError> {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let bp_gens = BulletproofGens::<R1csCycle>::new(2048, 1);
            let mut rng = ChaCha20Rng::seed_from_u64(0xC0DEC0DE);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&pad, &mut bits);

            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let (v_pad, var_pad) = prover.commit(pad, random_scalar::<R1csCycle>(&mut rng));
            let (v_reduce, var_reduce) =
                prover.commit(reduce, random_scalar::<R1csCycle>(&mut rng));
            let (_, _, reduce_boolean) = prover.multiply(
                var_reduce.into(),
                LinearCombination::from(R1csField::ONE) - var_reduce,
            );
            prover.constrain(reduce_boolean.into());
            let bit_vars = bit_decompose_q(&mut prover, var_pad, &bits)?;
            constrain_bits_lt_bound_when(
                &mut prover,
                &bit_vars,
                &bits,
                &SECP256K1_P_MINUS_Q_LE,
                var_reduce,
            )?;
            let proof = prover.prove(&bp_gens, &mut rng).expect("prove");

            let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(R1CS_TEST_DOMAIN));
            let var_pad = verifier.commit(v_pad);
            let var_reduce = verifier.commit(v_reduce);
            let (_, _, reduce_boolean) = verifier.multiply(
                var_reduce.into(),
                LinearCombination::from(R1csField::ONE) - var_reduce,
            );
            verifier.constrain(reduce_boolean.into());
            let verifier_bits = vec![None; K_BITS + 1];
            let bit_vars = bit_decompose_q(&mut verifier, var_pad, &verifier_bits)?;
            constrain_bits_lt_bound_when(
                &mut verifier,
                &bit_vars,
                &verifier_bits,
                &SECP256K1_P_MINUS_Q_LE,
                var_reduce,
            )?;
            verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)
        }

        #[test]
        fn bit_decompose_honest_proof_verifies() {
            let k = R1csField::from(0xDEADBEEFu64);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bits);
            run_bit_decompose(k, &bits).expect("honest proof verifies");
        }

        #[test]
        fn bit_decompose_random_k_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xF1E2D3C4);
            let k = R1csField::random(&mut rng);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bits);
            run_bit_decompose(k, &bits).expect("honest proof verifies");
        }

        #[test]
        fn bit_decompose_rejects_nonbinary_bit() {
            let k = R1csField::from(5u64);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bits);
            // Corrupt: set bit 1 to 2 (non-binary).
            bits[1] = Some(R1csField::from(2u64));
            assert!(
                run_bit_decompose(k, &bits).is_err(),
                "verifier must reject a non-binary bit"
            );
        }

        #[test]
        fn bit_decompose_rejects_wrong_reconstruction() {
            let k = R1csField::from(5u64);
            // Bits for k=4 instead of k=5.
            let wrong_k = R1csField::from(4u64);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&wrong_k, &mut bits);
            assert!(
                run_bit_decompose(k, &bits).is_err(),
                "verifier must reject bits that don't reconstruct k"
            );
        }

        #[test]
        fn bit_decompose_accepts_p_minus_one_boundary() {
            let k = R1csField::ZERO - R1csField::ONE;
            let mut p_minus_one = SECP256K1_BASE_MODULUS_LE;
            p_minus_one[0] -= 1;
            let mut bits = vec![None; K_BITS + 1];
            decompose_le_bytes(&p_minus_one, &mut bits);

            run_bit_decompose(k, &bits).expect("p - 1 is canonical");
        }

        #[test]
        fn bit_decompose_rejects_p_boundary() {
            let mut bits = vec![None; K_BITS + 1];
            decompose_le_bytes(&SECP256K1_BASE_MODULUS_LE, &mut bits);

            assert!(
                run_bit_decompose(R1csField::ZERO, &bits).is_err(),
                "canonical range check must reject p itself"
            );
        }

        #[test]
        fn conditional_pad_bound_rejects_reduce_wrap() {
            let wrapped_pad = R1csField::ZERO - Q_AS_FP;
            run_conditional_pad_bound(wrapped_pad, R1csField::ZERO)
                .expect("condition is disabled when reduce is zero");
            assert!(
                run_conditional_pad_bound(wrapped_pad, R1csField::ONE).is_err(),
                "reduce=1 must reject pad values where pad + q wraps modulo p"
            );
        }

        #[test]
        #[ignore = "slow: builds a full batched-dealer R1CS proof"]
        fn batched_receiver_slot_rejects_share_not_opening_commitment() {
            let mut rng = ChaCha20Rng::seed_from_u64(0x5A11_0F00);
            let sk1 = GinScalar::from(3u64);
            let pkj = Gin::generator() * GinScalar::from(5u64);
            let msg = [0x42u8; MESSAGE_BYTES];
            let beta = R1csField::from(7u64);
            let (statement, witness) = testing::build_batched(&msg, sk1, &[pkj], beta);
            let rec = &statement.receivers[0];
            let g_in = Gin::generator();
            let h1 = h_gin_1(&statement.msg);
            let h2 = h_gin_2(&statement.msg);

            let mut rec_witness = compute_hidden_receiver_witness(
                &statement.msg,
                &witness.sk1,
                &witness.shares[0],
                rec,
                &statement.beta,
            )
            .expect("honest hidden receiver witness");

            let wrong_share = witness.shares[0] + GinScalar::ONE;
            let wrong_share_fp = fq_to_fp(&wrong_share);
            let mut wrong_share_bits = [false; K_BITS + 1];
            decompose_k_fp(&wrong_share_fp, &mut wrong_share_bits);
            rec_witness.share = wrong_share_fp;
            rec_witness.share_bits = bit_options(&wrong_share_bits);
            rec_witness.share_commitment = chord_compute_witness(&wrong_share_bits, &g_in, K_BITS)
                .expect("wrong share commitment witness");

            let params = BatchedEvrfPublicParams::setup(1, 1).expect("public parameter setup");
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut prover_stream = ProverProofStream::new(BATCHED_PROOF_ID).expect("stream");
            observe_batched_statement(&mut prover_stream, &statement).expect("statement");
            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, prover_stream.transcript_mut());
            let sk_fp = fq_to_fp(&witness.sk1);
            let mut sk_bits = [false; K_BITS + 1];
            decompose_k_fp(&sk_fp, &mut sk_bits);
            let sk_var = prover.allocate(Some(sk_fp)).expect("allocate sk");
            let sk_bit_vars = bit_decompose_q(&mut prover, sk_var, &bit_options(&sk_bits))
                .expect("sk bit decomposition");

            let pk1_precomp = precompute_chord(&g_in, K_BITS).expect("PK1 precompute");
            let (pk1_x, pk1_y) = affine(&statement.pk1).expect("PK1 affine");
            chord_exponentiate_r1cs_with_result(
                &mut prover,
                &sk_bit_vars,
                &pk1_precomp,
                Some((pk1_x, pk1_y)),
                Some(&chord_compute_witness(&sk_bits, &g_in, K_BITS).expect("PK1 witness")),
            )
            .expect("PK1 constraint");
            build_hidden_receiver_slot(
                &mut prover,
                rec,
                &sk_bit_vars,
                &h1,
                &h2,
                statement.beta,
                &g_in,
                Some(&rec_witness),
            )
            .expect("receiver slot");

            let proof = prover.prove(&params.bp_gens, &mut rng).expect("prove");
            let mut verifier_stream = ProverProofStream::new(BATCHED_PROOF_ID).expect("stream");
            observe_batched_statement(&mut verifier_stream, &statement).expect("statement");
            let mut verifier = Verifier::<R1csCycle, _>::new(verifier_stream.transcript_mut());
            let sk_var = verifier.allocate(None).expect("allocate verifier sk");
            let verifier_sk_bits = vec![None; K_BITS + 1];
            let sk_bit_vars = bit_decompose_q(&mut verifier, sk_var, &verifier_sk_bits)
                .expect("verifier sk bit decomposition");
            chord_exponentiate_r1cs_with_result(
                &mut verifier,
                &sk_bit_vars,
                &pk1_precomp,
                Some((pk1_x, pk1_y)),
                None,
            )
            .expect("verifier PK1 constraint");
            build_hidden_receiver_slot(
                &mut verifier,
                rec,
                &sk_bit_vars,
                &h1,
                &h2,
                statement.beta,
                &g_in,
                None,
            )
            .expect("verifier receiver slot");

            assert!(
                verifier
                    .verify(&proof, &pc_gens, &params.bp_gens, &mut rng)
                    .is_err(),
                "R1CS must reject a hidden share that does not open share_commitment"
            );
        }

        #[test]
        fn bit_decompose_uses_exact_gate_count() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0x12345678);
            let k = R1csField::from(0xABCDu64);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bits);
            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            let _ = bit_decompose(&mut prover, var_k, &bits).expect("gadget");

            // One multiplier gate per bit for bitness, plus one per bit for
            // the canonical `< p` range check.
            let metrics = prover.metrics();
            assert_eq!(
                metrics.multipliers,
                2 * (K_BITS + 1),
                "expected exactly 2*(K_BITS + 1) multiplier gates, got {}",
                metrics.multipliers
            );
        }

        #[test]
        fn bit_decompose_rejects_short_bit_assignments() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0001);
            let k = R1csField::from(0xABCDu64);
            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            // Only K_BITS bits supplied instead of K_BITS + 1: gadget must
            // refuse to build a truncated circuit.
            let short_bits = vec![None; K_BITS];
            let result = bit_decompose(&mut prover, var_k, &short_bits);
            assert!(
                result.is_err(),
                "bit_decompose must reject bit_assignments.len() != K_BITS + 1"
            );
        }

        #[test]
        fn chord_exp_rejects_mismatched_witness_length() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0002);

            let X = Gin::generator() * GinScalar::from(12345u64);
            let precomp = precompute_chord(&X, K_BITS).expect("precompute");

            // bit_vars and precomp agree on λ+1 = 257 entries; build a witness
            // whose l_coords is one short so the length check fires before any
            // circuit construction.
            let truncated_witness = ChordWitness {
                l_coords: vec![(R1csField::ZERO, R1csField::ZERO); K_BITS],
                slopes: vec![R1csField::ZERO; K_BITS],
                denom_delta_inverses: vec![R1csField::ZERO; K_BITS],
            };

            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let k = R1csField::ZERO;
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            let mut bit_assignments = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bit_assignments);
            let bit_vars = bit_decompose(&mut prover, var_k, &bit_assignments).expect("bit_decomp");
            let result = chord_exponentiate_r1cs(
                &mut prover,
                &bit_vars,
                &precomp,
                R1csField::ZERO,
                R1csField::ZERO,
                Some(&truncated_witness),
            );
            assert!(
                result.is_err(),
                "chord_exponentiate_r1cs must reject witness whose l_coords length != λ+1"
            );
        }

        /// A non-canonical bit pattern encoding `k + p` satisfies modular
        /// reconstruction, so the gadget must reject it with an explicit
        /// integer `< p` range check.
        #[test]
        fn bit_decompose_rejects_modular_alias() {
            // 2^256 mod p is a known Fp constant.  We build bits encoding
            // k' = 2^256 (a 257-bit integer) and commit to k = 2^256 mod p.
            // The reconstruction Σ 2^j * k'_j = 2^256 ≡ (2^256 mod p) (mod p),
            // so only the canonical range check rejects the witness.
            let two_pow_256_mod_p = {
                let mut v = R1csField::ONE;
                for _ in 0..256 {
                    v = v.double();
                }
                v
            };

            // Bits encoding the integer 2^256: only bit 256 is set.
            let mut bits = vec![None; K_BITS + 1];
            for b in bits.iter_mut() {
                *b = Some(R1csField::ZERO);
            }
            bits[K_BITS] = Some(R1csField::ONE);

            assert!(
                run_bit_decompose(two_pow_256_mod_p, &bits).is_err(),
                "canonical range check must reject 2^256 as a non-canonical alias"
            );
        }

        // ----------------------------------------------------------------
        // Chord-rule R1CS exponentiation tests
        // ----------------------------------------------------------------

        /// Helper: build a chord-rule exponentiation proof and verify it.
        /// `k_val` is a small exponent (fits in u64) used as both an `Fp`
        /// element (for the R1CS) and an `Fq` scalar (for `T = k · X`).
        /// Returns `Ok(())` if the verifier accepts.
        fn run_chord_exp(
            k_val: u64,
            X: &Gin,
            result_override: Option<(Fp, Fp)>,
        ) -> core::result::Result<(), R1CSError> {
            run_chord_exp_with_witness(k_val, X, result_override, |_| {})
        }

        fn run_chord_exp_with_witness(
            k_val: u64,
            X: &Gin,
            result_override: Option<(Fp, Fp)>,
            mutate_witness: impl FnOnce(&mut ChordWitness),
        ) -> core::result::Result<(), R1CSError> {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            // bit_decompose: 257 gates, chord_exp: ~1024+ gates.  Pad to 4096.
            let bp_gens = BulletproofGens::<R1csCycle>::new(4096, 1);
            let mut rng = ChaCha20Rng::seed_from_u64(0x5CA1E000);

            let k_fp = R1csField::from(k_val);
            let k_fq = Fq::from(k_val);

            // Decompose k into bits (little-endian).  k_val fits in 64 bits,
            // so bits beyond index 63 are zero.
            let mut bits = [false; K_BITS + 1];
            for (i, b) in bits.iter_mut().enumerate() {
                *b = if i < 64 { (k_val >> i) & 1 == 1 } else { false };
            }

            // Precompute C_j/D_j for base X.
            let precomp = precompute_chord(X, K_BITS).expect("precompute");

            // Compute witness: all intermediate L_i and s_i.
            let mut witness = chord_compute_witness(&bits, X, K_BITS).expect("witness");
            mutate_witness(&mut witness);

            // Expected result: T = k * X.
            let t_point = X * k_fq;
            let (tx, ty) = affine(&t_point).expect("T affine");
            let (result_x, result_y) = result_override.unwrap_or((tx, ty));

            // Bit assignments for the R1CS.
            let bit_assignments: Vec<Option<R1csField>> = bits
                .iter()
                .map(|&b| {
                    if b {
                        Some(R1csField::ONE)
                    } else {
                        Some(R1csField::ZERO)
                    }
                })
                .collect();

            // Prover
            let mut prover =
                Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(R1CS_TEST_DOMAIN));
            let (v_k, var_k) = prover.commit(k_fp, random_scalar::<R1csCycle>(&mut rng));
            let bit_vars = bit_decompose(&mut prover, var_k, &bit_assignments).expect("bit_decomp");
            chord_exponentiate_r1cs(
                &mut prover,
                &bit_vars,
                &precomp,
                result_x,
                result_y,
                Some(&witness),
            )
            .expect("chord_exp");
            let proof = prover.prove(&bp_gens, &mut rng)?;

            // Verifier
            let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(R1CS_TEST_DOMAIN));
            let v_k_var = verifier.commit(v_k);
            let verifier_bits = vec![None; K_BITS + 1];
            let bit_vars =
                bit_decompose(&mut verifier, v_k_var, &verifier_bits).expect("bit_decomp");
            chord_exponentiate_r1cs(&mut verifier, &bit_vars, &precomp, result_x, result_y, None)
                .expect("chord_exp");
            verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)
        }

        #[test]
        fn chord_exp_honest_proof_verifies() {
            let X = Gin::generator() * Fq::from(42u64);
            run_chord_exp(0xDEADBEEFu64, &X, None).expect("honest proof verifies");
        }

        #[test]
        fn chord_exp_small_exponent_verifies() {
            let X = Gin::generator() * Fq::from(7u64);
            run_chord_exp(3u64, &X, None).expect("honest proof verifies");
        }

        #[test]
        fn chord_exp_rejects_wrong_result_x() {
            let X = Gin::generator() * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            let wrong_x = tx + R1csField::ONE;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, Some((wrong_x, ty))).is_err(),
                "verifier must reject wrong result x"
            );
        }

        #[test]
        fn chord_exp_rejects_wrong_result_y() {
            let X = Gin::generator() * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            let wrong_y = ty + R1csField::ONE;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, Some((tx, wrong_y))).is_err(),
                "verifier must reject wrong result y"
            );
        }

        #[test]
        fn chord_exp_rejects_negated_result_y() {
            let X = Gin::generator() * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            // -T has the same x but negated y.  The full-point binding
            // (x AND y) must reject this, unlike an x-only check.
            let neg_y = -ty;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, Some((tx, neg_y))).is_err(),
                "verifier must reject -T (same x, negated y)"
            );
        }

        #[test]
        fn chord_exp_rejects_wrong_delta_denominator_inverse() {
            let X = Gin::generator() * Fq::from(42u64);
            assert!(
                run_chord_exp_with_witness(0xDEADBEEFu64, &X, None, |w| {
                    w.denom_delta_inverses[0] += R1csField::ONE;
                })
                .is_err(),
                "verifier must reject a wrong inverse for x_L_prev - x_Delta"
            );
        }
    }

    #[cfg(test)]
    mod cp_tests {
        use super::*;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        const CP_TEST_PROOF_ID: &[u8] = b"golden-paper-evrf-cp-tests-v2";

        fn prove(g_in: &Gin, pk2: &Gin, sk1: &GinScalar, rng: &mut impl CryptoRngCore) -> Vec<u8> {
            let mut stream = ProverProofStream::new(CP_TEST_PROOF_ID).expect("stream");
            chaum_pedersen_prove(&mut stream, g_in, pk2, sk1, rng).expect("prove");
            stream.finish()
        }

        fn verify(proof: &[u8], g_in: &Gin, pk1: &Gin, pk2: &Gin, s: &Gin) -> Result<()> {
            let mut stream = VerifierProofStream::new(CP_TEST_PROOF_ID, proof)?;
            chaum_pedersen_verify(&mut stream, g_in, pk1, pk2, s)?;
            stream.finish()
        }

        #[test]
        fn chaum_pedersen_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
            let g_in = Gin::generator();
            let sk1 = GinScalar::random(&mut rng);
            let pk1 = g_in * sk1;
            let pk2 = g_in * GinScalar::random(&mut rng);
            let s = pk2 * sk1;

            let proof = prove(&g_in, &pk2, &sk1, &mut rng);
            verify(&proof, &g_in, &pk1, &pk2, &s).expect("verify");
        }

        #[test]
        fn chaum_pedersen_rejects_wrong_sk1() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBADF00D);
            let g_in = Gin::generator();
            let sk1 = GinScalar::random(&mut rng);
            let pk1 = g_in * sk1;
            let pk2 = g_in * GinScalar::random(&mut rng);
            let s = pk2 * sk1;

            // Prove with the wrong sk1.
            let wrong_sk1 = GinScalar::random(&mut rng);
            let proof = prove(&g_in, &pk2, &wrong_sk1, &mut rng);
            assert!(
                verify(&proof, &g_in, &pk1, &pk2, &s).is_err(),
                "verifier must reject wrong sk1"
            );
        }

        #[test]
        fn chaum_pedersen_rejects_wrong_s() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAD5_BAD5);
            let g_in = Gin::generator();
            let sk1 = GinScalar::random(&mut rng);
            let pk1 = g_in * sk1;
            let pk2 = g_in * GinScalar::random(&mut rng);

            let proof = prove(&g_in, &pk2, &sk1, &mut rng);

            // Verify with a wrong S (different DH point).
            let wrong_s = pk2 * GinScalar::random(&mut rng);
            assert!(
                verify(&proof, &g_in, &pk1, &pk2, &wrong_s).is_err(),
                "verifier must reject wrong S"
            );
        }

        #[test]
        fn chaum_pedersen_rejects_wrong_pk2() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA4D12);
            let g_in = Gin::generator();
            let sk1 = GinScalar::random(&mut rng);
            let pk1 = g_in * sk1;
            let pk2 = g_in * GinScalar::random(&mut rng);
            let s = pk2 * sk1;

            let proof = prove(&g_in, &pk2, &sk1, &mut rng);

            // Verify with a wrong PK_2.
            let wrong_pk2 = g_in * GinScalar::random(&mut rng);
            assert!(
                verify(&proof, &g_in, &pk1, &wrong_pk2, &s).is_err(),
                "verifier must reject wrong PK_2"
            );
        }
    }

    #[cfg(test)]
    mod dlog_tests {
        use super::*;
        use bulletproofs_cycle::generators::PedersenGens;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        const DLOG_TEST_PROOF_ID: &[u8] = b"golden-paper-evrf-dlog-tests-v2";

        /// Build a Pedersen commitment to `r` with fixed blinding 1 and return
        /// `(V_r compressed, g_out, g_out,1)` matching the step-9 prefix link.
        fn prefix_commit(r: R1csField) -> (GoutCompressed, Secq256k1, Secq256k1) {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let v_r_point = pc_gens.commit(r, R1csField::ONE);
            let v_r = R1csCycle::point_compress(&v_r_point);
            (v_r, pc_gens.B, pc_gens.B_blinding)
        }

        fn observe_prior_context(
            stream: &mut impl Observe,
            r_point: &Secq256k1,
            v_r: &GoutCompressed,
        ) -> Result<()> {
            stream.observe_point::<GoutStreamCurve>(
                b"statement.r",
                r_point,
                IdentityPolicy::Reject,
            )?;
            // In the full proof, `V_r` is observed by the preceding R1CS
            // verifier commitment rather than by this DLOG phase itself.
            stream.observe_bytes(b"test.r1cs-v-r", R1csCycle::compressed_as_bytes(v_r));
            Ok(())
        }

        fn prove(
            g_out: &Secq256k1,
            r_point: &Secq256k1,
            v_r: &GoutCompressed,
            r: &R1csField,
            rng: &mut impl CryptoRngCore,
        ) -> Vec<u8> {
            let mut stream = ProverProofStream::new(DLOG_TEST_PROOF_ID).expect("stream");
            observe_prior_context(&mut stream, r_point, v_r).expect("context");
            dlog_prove(&mut stream, g_out, r, rng).expect("prove");
            stream.finish()
        }

        fn verify(
            proof: &[u8],
            g_out: &Secq256k1,
            r_point: &Secq256k1,
            v_r: &GoutCompressed,
        ) -> Result<()> {
            let mut stream = VerifierProofStream::new(DLOG_TEST_PROOF_ID, proof)?;
            observe_prior_context(&mut stream, r_point, v_r)?;
            dlog_verify(&mut stream, g_out, r_point)?;
            stream.finish()
        }

        #[test]
        fn dlog_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C0);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, g_out_blinding) = prefix_commit(r);
            let r_point = g_out * r;

            pedersen_prefix_link(&g_out_blinding, &r_point, &v_r).expect("prefix link");
            let proof = prove(&g_out, &r_point, &v_r, &r, &mut rng);
            verify(&proof, &g_out, &r_point, &v_r).expect("verify");
        }

        #[test]
        fn dlog_rejects_wrong_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C1);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _g_out_blinding) = prefix_commit(r);
            let r_point = g_out * r;

            // Prove with the wrong r (the dealer does not know the dlog of R).
            let wrong_r = R1csField::random(&mut rng);
            let proof = prove(&g_out, &r_point, &v_r, &wrong_r, &mut rng);
            assert!(
                verify(&proof, &g_out, &r_point, &v_r).is_err(),
                "verifier must reject wrong r"
            );
        }

        #[test]
        fn dlog_rejects_wrong_r_point() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C2);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _) = prefix_commit(r);
            let r_point = g_out * r;

            let proof = prove(&g_out, &r_point, &v_r, &r, &mut rng);

            // Verify against a different R (not r * g_out).
            let wrong_r_point = g_out * R1csField::random(&mut rng);
            assert!(
                verify(&proof, &g_out, &wrong_r_point, &v_r).is_err(),
                "verifier must reject wrong R"
            );
        }

        #[test]
        fn dlog_rejects_wrong_v_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C3);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _) = prefix_commit(r);
            let r_point = g_out * r;

            let proof = prove(&g_out, &r_point, &v_r, &r, &mut rng);

            // Verify against a V_r from a different r (transcript mismatch).
            let wrong_r = R1csField::random(&mut rng);
            let (wrong_v_r, _, _) = prefix_commit(wrong_r);
            assert!(
                verify(&proof, &g_out, &r_point, &wrong_v_r).is_err(),
                "verifier must reject wrong V_r (transcript binding)"
            );
        }

        #[test]
        fn pedersen_prefix_link_rejects_mismatch() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C4);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, g_out_blinding) = prefix_commit(r);
            let r_point = g_out * r;

            // Honest link holds.
            pedersen_prefix_link(&g_out_blinding, &r_point, &v_r).expect("honest link");

            // A V_r from a different r fails the link.
            let wrong_r = R1csField::random(&mut rng);
            let (wrong_v_r, _, _) = prefix_commit(wrong_r);
            assert!(
                pedersen_prefix_link(&g_out_blinding, &r_point, &wrong_v_r).is_err(),
                "prefix link must reject V_r not matching R + g_out,1"
            );
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod dkg_unit_tests {
        use super::*;

        use golden_core::GoldenGroup;
        use halo2curves::secp256k1::Fp;

        #[test]
        fn fp_canonical_lt_detects_pad_plus_q_wrap() {
            use super::{fp_canonical_lt, Q_AS_FP};
            use ff::Field;
            // Small pad: pad + q < p, no wrap. sum > pad.
            let small = Fp::from(1u64);
            let sum = small + Q_AS_FP;
            assert!(fp_canonical_lt(&small, &sum));
            assert!(!fp_canonical_lt(&sum, &small));

            // pad = p - 1 (largest Fp element): pad + q wraps to q - 1 < pad.
            let p_minus_1 = Fp::ZERO - Fp::ONE;
            let wrapped = p_minus_1 + Q_AS_FP;
            assert!(fp_canonical_lt(&wrapped, &p_minus_1));
            assert!(!fp_canonical_lt(&p_minus_1, &wrapped));
        }

        fn context_statement() -> BatchedEvrfStatement {
            let g_in = Gin::generator();
            let pk1 = g_in * GinScalar::from(3u64);
            let pkj = g_in * GinScalar::from(5u64);
            let share = GinScalar::from(13u64);
            let pad = GinScalar::from(7u64);

            BatchedEvrfStatement {
                msg: [9u8; MESSAGE_BYTES],
                pk1,
                beta: R1csField::from(17u64),
                threshold: 1,
                commitment_coefficients: vec![g_in * share],
                statement_roots: vec![[1u8; 32]],
                receivers: vec![BatchedReceiverStatement {
                    receiver: ParticipantIndex::new(1).unwrap(),
                    pkj,
                    share_commitment: g_in * share,
                    pad_commitment: g_in * pad,
                    dh_commitment: pkj * pad,
                    encrypted_share: share + pad,
                }],
            }
        }

        fn evrf_statement() -> EvrfStatement<Secp256k1GoldenGroup> {
            let statement = context_statement();
            let rec = &statement.receivers[0];
            EvrfStatement {
                protocol_version: golden_core::PROTOCOL_VERSION,
                backend_id: <Secp256k1GoldenGroup as GoldenGroup>::BACKEND_ID,
                session_id: golden_core::SessionId([3u8; 32]),
                registry_root: [4u8; 32],
                threshold: statement.threshold,
                dealer: ParticipantIndex::new(2).unwrap(),
                receiver: rec.receiver,
                msg_i: DealerMessageNonce(statement.msg),
                beta: Secp256k1Scalar(GinScalar::from(17u64)),
                dealer_public_key: Secp256k1Element(statement.pk1),
                receiver_public_key: Secp256k1Element(rec.pkj),
                commitment_coefficients: statement
                    .commitment_coefficients
                    .iter()
                    .copied()
                    .map(Secp256k1Element)
                    .collect(),
                share_commitment: Secp256k1Element(rec.share_commitment),
                pad_commitment: Secp256k1Element(rec.pad_commitment),
                dh_commitment: Secp256k1Element(rec.dh_commitment),
                encrypted_share: Secp256k1Scalar(rec.encrypted_share),
                transcript_root: [5u8; 32],
            }
        }

        #[test]
        fn batched_stream_pins_statement_boundary_checkpoint() {
            let statement = context_statement();
            let mut changed = statement.clone();
            changed.statement_roots[0][0] ^= 0x80;

            let mut stream = ProverProofStream::new(BATCHED_PROOF_ID).expect("stream");
            observe_batched_statement(&mut stream, &statement).expect("statement");
            let mut checkpoint = [0u8; 64];
            stream.challenge(b"r1cs-boundary", &mut checkpoint);
            assert_eq!(
                checkpoint,
                [
                    247, 25, 213, 42, 121, 243, 204, 120, 70, 68, 75, 51, 206, 117, 113, 102, 226,
                    129, 74, 188, 184, 249, 56, 36, 91, 132, 27, 123, 113, 156, 110, 121, 116, 185,
                    133, 17, 40, 166, 105, 171, 8, 145, 175, 175, 189, 164, 99, 107, 127, 11, 148,
                    198, 242, 109, 210, 14, 250, 163, 209, 209, 85, 22, 50, 20,
                ]
            );

            let mut changed_stream = ProverProofStream::new(BATCHED_PROOF_ID).expect("stream");
            observe_batched_statement(&mut changed_stream, &changed).expect("statement");
            let mut changed_checkpoint = [0u8; 64];
            changed_stream.challenge(b"r1cs-boundary", &mut changed_checkpoint);
            assert_ne!(changed_checkpoint, checkpoint);
        }

        #[test]
        fn batched_statement_rejects_root_count_mismatch() {
            let mut statement = context_statement();
            statement.statement_roots.clear();
            assert_eq!(
                validate_batched_public_relations(&statement).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        #[test]
        fn public_batched_verifiers_reject_root_count_mismatch() {
            let mut statement = context_statement();
            let params =
                BatchedEvrfPublicParams::setup(statement.threshold, statement.receivers.len())
                    .expect("public parameter setup");
            statement.statement_roots.clear();
            let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

            assert_eq!(
                evrf_batched_verify(&params, &statement, &[], &mut rng).unwrap_err(),
                Error::ProofVerificationFailed
            );
            assert_eq!(
                evrf_batched_verify_many(&params, &[(&statement, &[])]).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        #[test]
        fn batched_statement_rejects_wrong_feldman_commitment() {
            let g_in = Gin::generator();
            let mut statement = context_statement();
            statement.commitment_coefficients[0] += g_in;
            assert_eq!(
                validate_batched_public_relations(&statement).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        #[test]
        fn batched_statement_rejects_threshold_commitment_mismatch() {
            let mut statement = context_statement();
            statement.threshold += 1;
            assert_eq!(
                validate_batched_public_relations(&statement).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        #[test]
        fn batched_statement_rejects_wrong_encrypted_share_relation() {
            let mut statement = context_statement();
            statement.receivers[0].encrypted_share += GinScalar::ONE;
            assert_eq!(
                validate_batched_public_relations(&statement).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        fn assert_batched_statement_rejects_identity(
            mutate: impl FnOnce(&mut BatchedEvrfStatement),
        ) {
            let mut statement = context_statement();
            mutate(&mut statement);
            assert_eq!(
                validate_batched_public_relations(&statement).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }

        #[test]
        fn batched_statement_rejects_identity_pk1() {
            assert_batched_statement_rejects_identity(|statement| {
                statement.pk1 = Gin::identity();
            });
        }

        #[test]
        fn batched_statement_rejects_identity_receiver_pk() {
            assert_batched_statement_rejects_identity(|statement| {
                statement.receivers[0].pkj = Gin::identity();
            });
        }

        #[test]
        fn batched_statement_rejects_identity_share_commitment() {
            assert_batched_statement_rejects_identity(|statement| {
                statement.receivers[0].share_commitment = Gin::identity();
            });
        }

        #[test]
        fn batched_statement_rejects_identity_pad_commitment() {
            assert_batched_statement_rejects_identity(|statement| {
                statement.receivers[0].pad_commitment = Gin::identity();
            });
        }

        #[test]
        fn batched_statement_rejects_identity_dh_commitment() {
            assert_batched_statement_rejects_identity(|statement| {
                statement.receivers[0].dh_commitment = Gin::identity();
            });
        }

        #[test]
        fn batch_context_rejects_shared_field_mismatch() {
            let first = evrf_statement();
            let mut changed = first.clone();
            changed.msg_i.0[0] ^= 0x80;
            assert_eq!(
                dkg_backend::ensure_same_batch_context(&changed, &first).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }
}
