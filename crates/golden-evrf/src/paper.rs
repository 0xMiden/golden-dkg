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

#[cfg(all(feature = "halo2curves-secp256k1", test))]
use golden_core::GoldenGroup;
#[cfg(feature = "halo2curves-secp256k1")]
use golden_core::{Error, EvrfStatement, EvrfWitness, Result};
#[cfg(feature = "halo2curves-secp256k1")]
use rand_core::CryptoRngCore;

/// Byte length of the paper `msg_i` nonce (256-bit security parameter).
pub const MESSAGE_BYTES: usize = 256 / 8;

/// Concrete Secp/Secq paper eVRF backend, feature-gated behind
/// `halo2curves-secp256k1`.
#[cfg(feature = "halo2curves-secp256k1")]
pub mod secp_secq {
    use super::*;

    use bulletproofs_cycle::{
        cycle::random_scalar,
        generators::{BulletproofGens, PedersenGens},
        r1cs::{Prover, Verifier},
        transcript::{append_point, challenge_scalar},
        ConstraintSystem, Cycle, LinearCombination, R1CSError, R1CSProof, Variable,
    };
    use ff::{Field, PrimeField};
    use golden_halo2curves::{Secp256k1Cycle, Secq256k1Cycle};
    use group::{Curve, Group};
    use halo2curves::secp256k1::{Fp, Fq, Secp256k1};
    use halo2curves::secq256k1::Secq256k1;
    use halo2curves::{Coordinates, CurveAffine, CurveExt};
    use merlin::Transcript;

    /// R1CS field: `Fp` (Secp256k1 base field = Secq256k1 scalar field).
    pub type R1csField = Fp;
    /// R1CS commitment group: `Secq256k1` (`G_out`).
    type R1csCycle = Secq256k1Cycle;
    /// `G_in` group: `Secp256k1`.
    type Gin = Secp256k1;
    /// `G_in` scalar field: `Fq`.
    type GinScalar = Fq;
    /// `G_out` compressed point.
    type GoutCompressed = <R1csCycle as Cycle>::Compressed;

    /// Transcript domain label for the paper eVRF proof.
    pub const PROOF_DOMAIN: &[u8] = b"golden-paper-evrf-v1";

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

    /// Chaum-Pedersen proof of `log_{g_in}(PK_1) = log_{PK_2}(S) = sk_1`.
    #[derive(Clone, Copy, Debug)]
    pub struct ChaumPedersenProof {
        /// Nonce commitment `R_1 = g_in^r`.
        pub r1: Gin,
        /// Nonce commitment `R_2 = PK_2^r`.
        pub r2: Gin,
        /// Response `z = r + c * sk_1`.
        pub z: GinScalar,
    }

    /// Discrete-log proof of knowledge for `R = g_out^r`.
    #[derive(Clone, Copy, Debug)]
    pub struct DlogProof {
        /// Nonce commitment `A = g_out^rho`.
        pub a: Secq256k1,
        /// Response `t = rho + c * r`.
        pub t: R1csField,
    }

    /// Proof envelope carrying the R1CS proof and the two outside-R1CS proofs.
    #[derive(Clone, Debug)]
    pub struct EvrfProofEnvelope {
        /// Bulletproofs R1CS proof for steps 3, 4, 5, 8.
        pub r1cs: R1CSProof<R1csCycle>,
        /// Pedersen commitment to `k = int(S.x)` in `G_out` (random blinding).
        pub k_commitment: GoutCompressed,
        /// Pedersen commitment to `r` in `G_out` (the R1CS prefix `theta`).
        pub r_commitment: GoutCompressed,
        /// Chaum-Pedersen proof for steps 0 and 1.
        pub cp: ChaumPedersenProof,
        /// Discrete-log proof for step 9.
        pub dlog: DlogProof,
    }

    // ------------------------------------------------------------------
    // Batched dealer proof (paper Section 4, batched across receivers).
    //
    // One dealer message covers all non-self receivers in a single R1CS
    // relation. The dealer identity secret `sk_1` and public key `PK_1` are
    // shared across the batch; each receiver has its own `PK_j`, `S_j`, `k_j`,
    // `T_{1,j}`, `T_{2,j}`, `r_j`, and `R_j`. Steps 0 and 1 use a batched
    // Chaum-Pedersen proof (one nonce, one response, per-receiver nonce
    // commitments). Step 9 uses a per-receiver DLOG PoK with prefix link.
    // ------------------------------------------------------------------

    /// Per-receiver public inputs for the batched dealer proof.
    #[derive(Clone, Debug)]
    pub struct BatchedReceiverStatement {
        /// Receiver identity public key `PK_j` in `G_in`.
        pub pkj: Gin,
        /// DH shared point `S_j = PK_j^sk_1` in `G_in`.
        pub sj: Gin,
        /// `T_{1,j} = H_{G_in,1}(msg)^{k_j}` in `G_in`.
        pub t1j: Gin,
        /// `T_{2,j} = H_{G_in,2}(msg)^{k_j}` in `G_in`.
        pub t2j: Gin,
        /// eVRF output commitment `R_j = g_out^{r_j}` in `G_out`.
        pub r_point_j: Secq256k1,
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
        /// Per-receiver statements, in the canonical ordered receiver list.
        pub receivers: Vec<BatchedReceiverStatement>,
    }

    /// Witness for the batched dealer proof. Only the shared dealer identity
    /// secret is needed; all per-receiver values are derived from it.
    #[derive(Clone)]
    pub struct BatchedEvrfWitness {
        /// Dealer identity secret `sk_1` in `Fq` (shared across the batch).
        pub sk1: GinScalar,
    }

    impl core::fmt::Debug for BatchedEvrfWitness {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("BatchedEvrfWitness")
                .field("sk1", &"<redacted>")
                .finish()
        }
    }

    /// Batched Chaum-Pedersen proof of `log_{g_in}(PK_1) = sk_1` and
    /// `log_{PK_j}(S_j) = sk_1` for every receiver `j`. One nonce `r`, one
    /// challenge `c`, one response `z = r + c * sk_1`.
    #[derive(Clone, Debug)]
    pub struct BatchedChaumPedersenProof {
        /// Nonce commitment `R_0 = g_in^r`.
        pub r0: Gin,
        /// Per-receiver nonce commitments `R_j = PK_j^r`.
        pub rjs: Vec<Gin>,
        /// Response `z = r + c * sk_1`.
        pub z: GinScalar,
    }

    /// Batched proof envelope carrying the combined R1CS proof, per-receiver
    /// commitments, the batched Chaum-Pedersen proof, and per-receiver DLOG
    /// proofs.
    #[derive(Clone, Debug)]
    pub struct BatchedEvrfProofEnvelope {
        /// Combined Bulletproofs R1CS proof for all receivers (steps 2-8).
        pub r1cs: R1CSProof<R1csCycle>,
        /// Per-receiver Pedersen commitments to `k_j = int(S_j.x)`.
        pub k_commitments: Vec<GoutCompressed>,
        /// Per-receiver Pedersen commitments to `r_j` (the R1CS prefix `theta_j`).
        pub r_commitments: Vec<GoutCompressed>,
        /// Batched Chaum-Pedersen proof for steps 0 and 1.
        pub cp: BatchedChaumPedersenProof,
        /// Per-receiver discrete-log proofs for step 9.
        pub dlogs: Vec<DlogProof>,
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

    /// Bit length used for the `k = int(S.x)` decomposition. The Secp256k1
    /// base field modulus fits in 256 bits, so 256 bits cover every canonical
    /// `Fp` element.
    const K_BITS: usize = 256;

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
    /// exponentiation of base `X` with `lambda + 1` bits, using `G_S` as the
    /// `G_in` generator.  All coordinates are native `Fp` elements.
    fn precompute_chord(X: &Gin, g_s: &Gin, lambda: usize) -> Result<ChordPrecomp> {
        let mut c = Vec::with_capacity(lambda + 1);
        let mut d = Vec::with_capacity(lambda + 1);
        let mut p_j = *X; // P_0 = 2^0 · X = X
        for j in 0..=lambda {
            let cj = chord_cj(j, lambda);
            let c_j_point = *g_s * cj; // C_j = c_j · G_S
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
    fn chord_evaluate(bits: &[bool], X: &Gin, g_s: &Gin, lambda: usize) -> Result<(Fp, Fp)> {
        chord_evaluate_point(bits, X, g_s, lambda).and_then(|p| affine(&p))
    }

    /// Evaluate the chord-rule exponentiation and return the `G_in` point
    /// `L_λ = k · X` (with `c_j` corrections reducing `k` mod `|G_in|`).
    #[cfg(test)]
    fn chord_evaluate_point(bits: &[bool], X: &Gin, g_s: &Gin, lambda: usize) -> Result<Gin> {
        if bits.len() != lambda + 1 {
            return Err(Error::ProofVerificationFailed);
        }
        let mut p_j = *X;
        let mut l = Gin::identity();
        for (j, &bit) in bits.iter().enumerate().take(lambda + 1) {
            let cj = chord_cj(j, lambda);
            let c_j_point = *g_s * cj;
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

    /// Bit-decomposition gadget (paper Section 4.2).  Given a committed
    /// variable `k_var` holding `k ∈ Fp` and `λ+1` bit assignments, constrains:
    /// - `k_j · (1 - k_j) = 0` for each `j` (each `k_j` is binary)
    /// - `k = Σ_{j=0}^{λ} 2^j · k_j` (the bits reconstruct `k`)
    ///
    /// Returns the allocated bit variables `k_0, ..., k_λ`.  Uses exactly
    /// `λ+1` multiplication gates (one per bit via `allocate_multiplier`) plus
    /// linear constraints (folded into one by the Bulletproofs verifier).
    ///
    /// The reconstruction constraint is modular: `Σ 2^j · k_j ≡ k (mod p)`.
    /// This allows non-canonical bit patterns (e.g. bits encoding `k + p`).
    /// In the full paper eVRF relation, the chord-rule gadget's final
    /// constraint binds the **full point** `L_λ = T` (both x and y
    /// coordinates), not just the x-coordinate.  An x-only check would be
    /// insufficient because `(k + p) · X = -k · X` shares the same
    /// x-coordinate as `k · X` when `2k + p ≡ 0 (mod |G_in|)`.  Binding y
    /// as well distinguishes `L_λ` from `-L_λ` and rejects all non-canonical
    /// aliases.  The bit-decomposition gadget is always composed with the
    /// chord-rule exponentiation, never used in isolation for the paper
    /// relation.
    fn bit_decompose<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        k_var: Variable<R1csField>,
        bit_assignments: &[Option<R1csField>],
        lambda: usize,
    ) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
        if bit_assignments.len() != lambda + 1 {
            return Err(R1CSError::FormatError);
        }
        let mut bit_vars = Vec::with_capacity(lambda + 1);
        let mut k_lc = LinearCombination::default();

        for (j, &bit) in bit_assignments.iter().enumerate().take(lambda + 1) {
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

        Ok(bit_vars)
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
    }

    /// Compute the full chord-rule witness: all intermediate `L_i` points and
    /// slopes `s_i`.  Uses actual elliptic curve point arithmetic in `G_in`
    /// and field inversion in `Fp` for the slopes.
    fn chord_compute_witness(
        bits: &[bool],
        X: &Gin,
        g_s: &Gin,
        lambda: usize,
    ) -> Result<ChordWitness> {
        if bits.len() != lambda + 1 {
            return Err(Error::ProofVerificationFailed);
        }

        let mut l_coords = Vec::with_capacity(lambda + 1);
        let mut slopes = Vec::with_capacity(lambda);

        let mut p_j = *X;
        let mut l = Gin::identity();

        for (j, &bit) in bits.iter().enumerate().take(lambda + 1) {
            let cj = chord_cj(j, lambda);
            let c_j_point = *g_s * cj;
            let delta = if bit { p_j + c_j_point } else { c_j_point };

            if j == 0 {
                l = delta;
            } else {
                // Compute slope s_j = (y_{L_{j-1}} - y_{Δ_j}) / (x_{L_{j-1}} - x_{Δ_j})
                let (x_prev, y_prev) = *l_coords.last().expect("L_{j-1} exists");
                let (x_delta, y_delta) = affine(&delta)?;

                let dx: R1csField = x_prev - x_delta;
                let dy: R1csField = y_prev - y_delta;
                // dx must be non-zero for the chord rule (guaranteed by the
                // c_j correction terms with overwhelming probability over a
                // random oracle H).  If dx == 0 we hit an exceptional case
                // (L_{j-1} = ±Δ_j) that the chord-rule gadget does not handle.
                // Return an error rather than fabricating a wrong slope.
                let dx_inv: Option<R1csField> = Option::from(dx.invert());
                let s_j = match dx_inv {
                    Some(inv) => dy * inv,
                    None => return Err(Error::ProofVerificationFailed),
                };
                slopes.push(s_j);

                l += delta;
            }

            let coords = affine(&l)?;
            l_coords.push(coords);
            p_j = p_j.double();
        }

        Ok(ChordWitness { l_coords, slopes })
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

    /// Chord-rule exponentiation R1CS gadget (paper Section 4.3).  Given the
    /// bit variables from [`bit_decompose`], the precomputed `C_j`/`D_j`
    /// coordinates, and the public result point `(result_x, result_y)`,
    /// constrains:
    /// - `L_0 = Δ_0` (base case, 2 linear constraints)
    /// - `L_i = L_{i-1} + Δ_i` for `i = 1..λ` (3 multiplication gates per
    ///   iteration via the chord-rule formulas)
    /// - `L_λ = (result_x, result_y)` (final full-point binding, 2 linear
    ///   constraints)
    ///
    /// The full-point binding (both x and y) is critical for soundness: an
    /// x-only check cannot distinguish `L_λ` from `-L_λ`, which would allow
    /// non-canonical bit aliases (see [`bit_decompose`] doc).
    ///
    /// Returns the `(x_{L_λ}, y_{L_λ})` variables.  Uses `3λ` multiplication
    /// gates plus linear constraints.
    fn chord_exponentiate_r1cs<CS: ConstraintSystem<R1csCycle>>(
        cs: &mut CS,
        bit_vars: &[Variable<R1csField>],
        precomp: &ChordPrecomp,
        result_x: R1csField,
        result_y: R1csField,
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
            if w.l_coords.len() != lambda_plus_one || w.slopes.len() != lambda_plus_one - 1 {
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
            let (x_l_assign, y_l_assign) = witness.map(|w| w.l_coords[i]).unzip();

            let s_var = cs.allocate(s_assign)?;
            let x_l = cs.allocate(x_l_assign)?;
            let y_l = cs.allocate(y_l_assign)?;

            // Linear combinations for Δ_i in terms of k_i_var.
            let dx_i = delta_x_lc(bit_var, precomp, i);
            let dy_i = delta_y_lc(bit_var, precomp, i);

            // Constraint 1: s_i * (x_{L_{i-1}} - x_{Δ_i}) = y_{L_{i-1}} - y_{Δ_i}
            let (_, _, out1) = cs.multiply(s_var.into(), x_prev - dx_i.clone());
            cs.constrain(out1 - (y_prev - dy_i.clone()));

            // Constraint 2: s_i^2 = x_{L_{i-1}} + x_{L_i} + x_{Δ_i}
            let (_, _, out2) = cs.multiply(s_var.into(), s_var.into());
            cs.constrain(out2 - (x_prev + x_l + dx_i.clone()));

            // Constraint 3: s_i * (x_{L_{i-1}} - x_{L_i}) = y_{L_{i-1}} + y_{L_i}
            let (_, _, out3) = cs.multiply(s_var.into(), x_prev - x_l);
            cs.constrain(out3 - (y_prev + y_l));

            x_prev = x_l;
            y_prev = y_l;
        }

        // Final full-point binding: L_λ = (result_x, result_y).
        cs.constrain(x_prev - result_x);
        cs.constrain(y_prev - result_y);

        Ok((x_prev, y_prev))
    }

    // ------------------------------------------------------------------
    // Chaum-Pedersen proof (paper steps 0 and 1, outside R1CS).
    //
    // Proves log_{g_in}(PK_1) = log_{PK_2}(S) = sk_1 using a Fiat-Shamir
    // Schnorr-style proof of equal discrete logs.
    // ------------------------------------------------------------------

    /// Transcript domain label for the Chaum-Pedersen sub-proof.
    const CP_DOMAIN: &[u8] = b"golden-paper-evrf-cp-v1";

    /// Build a Merlin transcript for the Chaum-Pedersen proof, binding all
    /// public inputs.
    fn cp_transcript(g_in: &Gin, pk1: &Gin, pk2: &Gin, s: &Gin) -> Transcript {
        let mut t = Transcript::new(CP_DOMAIN);
        append_point::<Secp256k1Cycle>(&mut t, b"g_in", &Secp256k1Cycle::point_compress(g_in));
        append_point::<Secp256k1Cycle>(&mut t, b"PK_1", &Secp256k1Cycle::point_compress(pk1));
        append_point::<Secp256k1Cycle>(&mut t, b"PK_2", &Secp256k1Cycle::point_compress(pk2));
        append_point::<Secp256k1Cycle>(&mut t, b"S", &Secp256k1Cycle::point_compress(s));
        t
    }

    /// Generate a Chaum-Pedersen proof of `log_{g_in}(PK_1) = log_{PK_2}(S)`.
    ///
    /// Prover chooses nonce `r`, commits `R_1 = g_in^r`, `R_2 = PK_2^r`,
    /// extracts challenge `c` from the transcript, and responds
    /// `z = r + c * sk_1`.
    fn chaum_pedersen_prove(
        g_in: &Gin,
        pk1: &Gin,
        pk2: &Gin,
        s: &Gin,
        sk1: &GinScalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ChaumPedersenProof> {
        let r = GinScalar::random(rng);
        let r1 = *g_in * r;
        let r2 = *pk2 * r;

        let mut transcript = cp_transcript(g_in, pk1, pk2, s);
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_1",
            &Secp256k1Cycle::point_compress(&r1),
        );
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_2",
            &Secp256k1Cycle::point_compress(&r2),
        );
        let c = challenge_scalar::<Secp256k1Cycle>(&mut transcript, b"c");

        let z = r + c * *sk1;

        Ok(ChaumPedersenProof { r1, r2, z })
    }

    /// Verify a Chaum-Pedersen proof of `log_{g_in}(PK_1) = log_{PK_2}(S)`.
    ///
    /// Recomputes the challenge and checks:
    /// - `g_in^z = R_1 * PK_1^c`
    /// - `PK_2^z = R_2 * S^c`
    fn chaum_pedersen_verify(
        g_in: &Gin,
        pk1: &Gin,
        pk2: &Gin,
        s: &Gin,
        proof: &ChaumPedersenProof,
    ) -> Result<()> {
        let mut transcript = cp_transcript(g_in, pk1, pk2, s);
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_1",
            &Secp256k1Cycle::point_compress(&proof.r1),
        );
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_2",
            &Secp256k1Cycle::point_compress(&proof.r2),
        );
        let c = challenge_scalar::<Secp256k1Cycle>(&mut transcript, b"c");

        // g_in^z = R_1 * PK_1^c
        let lhs1 = *g_in * proof.z;
        let rhs1 = proof.r1 + *pk1 * c;
        if lhs1 != rhs1 {
            return Err(Error::ProofVerificationFailed);
        }

        // PK_2^z = R_2 * S^c
        let lhs2 = *pk2 * proof.z;
        let rhs2 = proof.r2 + *s * c;
        if lhs2 != rhs2 {
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

    /// Transcript domain label for the step-9 discrete-log sub-proof.
    const DLOG_DOMAIN: &[u8] = b"golden-paper-evrf-dlog-v1";

    /// Build a Merlin transcript for the step-9 DLOG proof, binding `g_out`,
    /// the public `R`, and the R1CS commitment `V_r` so the proof is tied to the
    /// same R1CS instance.
    fn dlog_transcript(g_out: &Secq256k1, r_point: &Secq256k1, v_r: &GoutCompressed) -> Transcript {
        let mut t = Transcript::new(DLOG_DOMAIN);
        append_point::<R1csCycle>(&mut t, b"g_out", &R1csCycle::point_compress(g_out));
        append_point::<R1csCycle>(&mut t, b"R", &R1csCycle::point_compress(r_point));
        append_point::<R1csCycle>(&mut t, b"V_r", v_r);
        t
    }

    /// Generate a Schnorr proof of knowledge of `r` such that `R = r * g_out`.
    ///
    /// Prover chooses nonce `rho`, commits `A = rho * g_out`, extracts challenge
    /// `c` from the transcript, and responds `t = rho + c * r`.
    fn dlog_prove(
        g_out: &Secq256k1,
        r_point: &Secq256k1,
        v_r: &GoutCompressed,
        r: &R1csField,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DlogProof> {
        let rho = R1csField::random(rng);
        let a = *g_out * rho;

        let mut transcript = dlog_transcript(g_out, r_point, v_r);
        append_point::<R1csCycle>(&mut transcript, b"A", &R1csCycle::point_compress(&a));
        let c = challenge_scalar::<R1csCycle>(&mut transcript, b"c");

        let t = rho + c * *r;

        Ok(DlogProof { a, t })
    }

    /// Verify a Schnorr proof of knowledge of `r` such that `R = r * g_out`.
    ///
    /// Recomputes the challenge and checks `t * g_out = A + c * R`.  The caller
    /// must separately check the Pedersen prefix link `V_r == R + g_out,1`.
    fn dlog_verify(
        g_out: &Secq256k1,
        r_point: &Secq256k1,
        v_r: &GoutCompressed,
        proof: &DlogProof,
    ) -> Result<()> {
        let mut transcript = dlog_transcript(g_out, r_point, v_r);
        append_point::<R1csCycle>(&mut transcript, b"A", &R1csCycle::point_compress(&proof.a));
        let c = challenge_scalar::<R1csCycle>(&mut transcript, b"c");

        // t * g_out = A + c * R
        let lhs = *g_out * proof.t;
        let rhs = proof.a + *r_point * c;
        if lhs != rhs {
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
    /// Bit-decomp uses 257 multiplier gates; each chord-rule uses 3*256 = 768.
    /// Total 1793, padded to 8192 for the inner-product layer.
    const R1CS_GENS_CAPACITY: usize = 8192;

    /// Random-oracle domain tag for `H_{G_in,1}`.
    const H_GIN_1_DOMAIN: &str = "golden-paper-evrf-H-Gin-1-v1";
    /// Random-oracle domain tag for `H_{G_in,2}`.
    const H_GIN_2_DOMAIN: &str = "golden-paper-evrf-H-Gin-2-v1";

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
        g_s: &Gin,
    ) -> core::result::Result<(), R1CSError> {
        // Step 2: bind the committed k to the public int(S.x).  Without this
        // constraint, a malicious prover could commit to an arbitrary exponent
        // unrelated to S.x and still satisfy the chord-rule constraints.
        cs.constrain(var_k - s_x);

        let bit_vars = bit_decompose(cs, var_k, bit_assignments, K_BITS)?;

        let precomp1 =
            precompute_chord(h1, g_s, K_BITS).map_err(|_| R1CSError::VerificationError)?;
        let precomp2 =
            precompute_chord(h2, g_s, K_BITS).map_err(|_| R1CSError::VerificationError)?;

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
    ) -> Result<EvrfProofEnvelope> {
        let g_in = Gin::generator();
        let g_s = g_in;

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
        let witness1 = chord_compute_witness(&bits, &h1, &g_s, K_BITS)?;
        let witness2 = chord_compute_witness(&bits, &h2, &g_s, K_BITS)?;

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

        // Build the R1CS proof.
        let pc_gens = PedersenGens::<R1csCycle>::default();
        let bp_gens = BulletproofGens::<R1csCycle>::new(R1CS_GENS_CAPACITY, 1);
        let k_blinding = random_scalar::<R1csCycle>(rng);
        let r_blinding = R1csField::ONE; // fixed for prefix link

        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
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
            &g_s,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;
        let r1cs_proof = prover
            .prove(&bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        // Step 0, 1: Chaum-Pedersen proof.
        let cp = chaum_pedersen_prove(
            &g_in,
            &statement.pk1,
            &statement.pk2,
            &statement.s,
            &witness.sk1,
            rng,
        )?;

        // Step 9: DLOG PoK.
        let dlog = dlog_prove(&g_out, &statement.r_point, &v_r, &r, rng)?;

        Ok(EvrfProofEnvelope {
            r1cs: r1cs_proof,
            k_commitment: v_k,
            r_commitment: v_r,
            cp,
            dlog,
        })
    }

    /// Verify the full one-receiver paper eVRF proof.
    pub fn evrf_verify(
        statement: &SecpSecqEvrfStatement,
        proof: &EvrfProofEnvelope,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let g_in = Gin::generator();
        let g_s = g_in;
        let g_out = Secq256k1::generator();
        let pc_gens = PedersenGens::<R1csCycle>::default();
        let bp_gens = BulletproofGens::<R1csCycle>::new(R1CS_GENS_CAPACITY, 1);

        // Step 0, 1: verify Chaum-Pedersen proof.
        chaum_pedersen_verify(
            &g_in,
            &statement.pk1,
            &statement.pk2,
            &statement.s,
            &proof.cp,
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

        // Step 9 prefix link: V_r == R + g_out,1.
        pedersen_prefix_link(&pc_gens.B_blinding, &statement.r_point, &proof.r_commitment)?;

        // Build the verifier-side R1CS and verify.  The verifier commits using
        // the proof's compressed commitments.
        let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(PROOF_DOMAIN));
        let var_k = verifier.commit(proof.k_commitment);
        let var_r = verifier.commit(proof.r_commitment);
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
            &g_s,
        )
        .map_err(|_| Error::ProofVerificationFailed)?;

        verifier
            .verify(&proof.r1cs, &pc_gens, &bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        // Step 9: verify DLOG PoK.
        dlog_verify(&g_out, &statement.r_point, &proof.r_commitment, &proof.dlog)?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Batched Chaum-Pedersen proof (paper steps 0 and 1, batched).
    //
    // Proves `log_{g_in}(PK_1) = sk_1` and `log_{PK_j}(S_j) = sk_1` for every
    // receiver j with a single nonce r, single challenge c, and single
    // response z = r + c * sk_1.  The transcript binds msg, PK_1, and the full
    // ordered receiver list (PK_j, S_j) so the proof cannot be replayed against
    // a different dealer message, dealer key, receiver set, or receiver order.
    // ------------------------------------------------------------------

    /// Transcript domain label for the batched Chaum-Pedersen sub-proof.
    const BATCHED_CP_DOMAIN: &[u8] = b"golden-paper-evrf-batched-cp-v1";

    /// Build a Merlin transcript for the batched Chaum-Pedersen proof, binding
    /// `msg`, `g_in`, `PK_1`, and every `(PK_j, S_j)` in order.
    fn batched_cp_transcript(
        msg: &[u8; MESSAGE_BYTES],
        g_in: &Gin,
        pk1: &Gin,
        receivers: &[BatchedReceiverStatement],
    ) -> Transcript {
        let mut t = Transcript::new(BATCHED_CP_DOMAIN);
        t.append_message(b"msg", msg);
        append_point::<Secp256k1Cycle>(&mut t, b"g_in", &Secp256k1Cycle::point_compress(g_in));
        append_point::<Secp256k1Cycle>(&mut t, b"PK_1", &Secp256k1Cycle::point_compress(pk1));
        for (j, r) in receivers.iter().enumerate() {
            t.append_message(b"idx", &(j as u64).to_le_bytes());
            append_point::<Secp256k1Cycle>(
                &mut t,
                b"PK_j",
                &Secp256k1Cycle::point_compress(&r.pkj),
            );
            append_point::<Secp256k1Cycle>(&mut t, b"S_j", &Secp256k1Cycle::point_compress(&r.sj));
        }
        t
    }

    /// Generate a batched Chaum-Pedersen proof.
    fn batched_chaum_pedersen_prove(
        msg: &[u8; MESSAGE_BYTES],
        g_in: &Gin,
        pk1: &Gin,
        receivers: &[BatchedReceiverStatement],
        sk1: &GinScalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<BatchedChaumPedersenProof> {
        let r = GinScalar::random(rng);
        let r0 = *g_in * r;
        let rjs: Vec<Gin> = receivers.iter().map(|rec| rec.pkj * r).collect();

        let mut transcript = batched_cp_transcript(msg, g_in, pk1, receivers);
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_0",
            &Secp256k1Cycle::point_compress(&r0),
        );
        for (j, rj) in rjs.iter().enumerate() {
            t_append_idx(&mut transcript, j);
            append_point::<Secp256k1Cycle>(
                &mut transcript,
                b"R_j",
                &Secp256k1Cycle::point_compress(rj),
            );
        }
        let c = challenge_scalar::<Secp256k1Cycle>(&mut transcript, b"c");

        let z = r + c * *sk1;

        Ok(BatchedChaumPedersenProof { r0, rjs, z })
    }

    /// Append a receiver index to a transcript in a fixed encoding.
    fn t_append_idx(transcript: &mut Transcript, j: usize) {
        transcript.append_message(b"idx", &(j as u64).to_le_bytes());
    }

    /// Verify a batched Chaum-Pedersen proof.
    fn batched_chaum_pedersen_verify(
        msg: &[u8; MESSAGE_BYTES],
        g_in: &Gin,
        pk1: &Gin,
        receivers: &[BatchedReceiverStatement],
        proof: &BatchedChaumPedersenProof,
    ) -> Result<()> {
        if proof.rjs.len() != receivers.len() {
            return Err(Error::ProofVerificationFailed);
        }
        let mut transcript = batched_cp_transcript(msg, g_in, pk1, receivers);
        append_point::<Secp256k1Cycle>(
            &mut transcript,
            b"R_0",
            &Secp256k1Cycle::point_compress(&proof.r0),
        );
        for (j, rj) in proof.rjs.iter().enumerate() {
            t_append_idx(&mut transcript, j);
            append_point::<Secp256k1Cycle>(
                &mut transcript,
                b"R_j",
                &Secp256k1Cycle::point_compress(rj),
            );
        }
        let c = challenge_scalar::<Secp256k1Cycle>(&mut transcript, b"c");

        // g_in^z = R_0 * PK_1^c  (step 0)
        let lhs0 = *g_in * proof.z;
        let rhs0 = proof.r0 + *pk1 * c;
        if lhs0 != rhs0 {
            return Err(Error::ProofVerificationFailed);
        }

        // PK_j^z = R_j * S_j^c  (step 1, per receiver)
        for (j, rec) in receivers.iter().enumerate() {
            let lhs = rec.pkj * proof.z;
            let rhs = proof.rjs[j] + rec.sj * c;
            if lhs != rhs {
                return Err(Error::ProofVerificationFailed);
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Batched R1CS relation and prove/verify path.
    // ------------------------------------------------------------------

    /// Bulletproofs generator capacity for the batched relation.  Each
    /// receiver slot runs the full one-receiver relation, which fits in
    /// `R1CS_GENS_CAPACITY` (8192) generators.  `allocate` calls also consume
    /// multiplier slots in this backend, so the per-receiver count is much
    /// larger than the explicit `multiply` gate count.  Size from the
    /// one-receiver capacity times the receiver count, rounded up to a power
    /// of two.
    fn batched_gens_capacity(num_receivers: usize) -> usize {
        let total = R1CS_GENS_CAPACITY * num_receivers;
        let mut cap = R1CS_GENS_CAPACITY;
        while cap < total {
            cap *= 2;
        }
        cap
    }

    /// Build the R1CS constraints for one receiver slot in the batched
    /// relation.  Commits to `k_j` and `r_j` (caller-supplied variables) and
    /// adds the step-2, 3, 4, 5, 8 constraints for that receiver.
    #[allow(clippy::too_many_arguments)]
    fn build_one_receiver_slot<CS: ConstraintSystem<R1csCycle>>(
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
        g_s: &Gin,
    ) -> core::result::Result<(), R1CSError> {
        // Same as the one-receiver relation: step 2 binds k to S.x, steps 3-5
        // are bit-decomp + two chord-rules, step 8 is r = beta*r_1 + r_2.
        build_one_receiver_r1cs(
            cs,
            var_k,
            var_r,
            s_x,
            h1,
            h2,
            t1_x,
            t1_y,
            t2_x,
            t2_y,
            beta,
            bit_assignments,
            witness1,
            witness2,
            g_s,
        )
    }

    /// Generate the batched dealer proof.
    pub fn evrf_batched_prove(
        statement: &BatchedEvrfStatement,
        witness: &BatchedEvrfWitness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<BatchedEvrfProofEnvelope> {
        if statement.receivers.is_empty() {
            return Err(Error::ProofVerificationFailed);
        }
        let g_in = Gin::generator();
        let g_s = g_in;
        let g_out = Secq256k1::generator();

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

        let pc_gens = PedersenGens::<R1csCycle>::default();
        let bp_gens =
            BulletproofGens::<R1csCycle>::new(batched_gens_capacity(statement.receivers.len()), 1);

        let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
        let mut k_commitments = Vec::with_capacity(statement.receivers.len());
        let mut r_commitments = Vec::with_capacity(statement.receivers.len());
        let mut dlogs = Vec::with_capacity(statement.receivers.len());

        for rec in &statement.receivers {
            // Step 1: verify S_j = PK_j^sk_1.
            let sj_computed = rec.pkj * witness.sk1;
            if Secp256k1Cycle::point_compress(&sj_computed).as_ref()
                != Secp256k1Cycle::point_compress(&rec.sj).as_ref()
            {
                return Err(Error::ProofVerificationFailed);
            }

            // Step 2: k_j = int(S_j.x)
            let (s_x, _) = affine(&rec.sj)?;
            let k = s_x;

            // Bit-decompose k_j.
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

            // Steps 4, 5: chord-rule witnesses for T_{1,j}, T_{2,j}.
            let witness1 = chord_compute_witness(&bits, &h1, &g_s, K_BITS)?;
            let witness2 = chord_compute_witness(&bits, &h2, &g_s, K_BITS)?;

            // Public T_{1,j}, T_{2,j} coordinates.
            let (t1_x, t1_y) = affine(&rec.t1j)?;
            let (t2_x, t2_y) = affine(&rec.t2j)?;

            // Steps 6, 7, 8: r_j = beta * T_{1,j}.x + T_{2,j}.x
            let r = statement.beta * t1_x + t2_x;

            // Step 9: verify R_j = g_out^{r_j}.
            let r_computed = g_out * r;
            if R1csCycle::point_compress(&r_computed).as_ref()
                != R1csCycle::point_compress(&rec.r_point_j).as_ref()
            {
                return Err(Error::ProofVerificationFailed);
            }

            // Commit to k_j (random blinding) and r_j (fixed blinding 1).
            let k_blinding = random_scalar::<R1csCycle>(rng);
            let (v_k, var_k) = prover.commit(k, k_blinding);
            let (v_r, var_r) = prover.commit(r, R1csField::ONE);

            build_one_receiver_slot(
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
                &g_s,
            )
            .map_err(|_| Error::ProofVerificationFailed)?;

            // Step 9: DLOG PoK for this receiver.
            let dlog = dlog_prove(&g_out, &rec.r_point_j, &v_r, &r, rng)?;

            k_commitments.push(v_k);
            r_commitments.push(v_r);
            dlogs.push(dlog);
        }

        let r1cs_proof = prover
            .prove(&bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        // Steps 0, 1: batched Chaum-Pedersen proof.
        let cp = batched_chaum_pedersen_prove(
            &statement.msg,
            &g_in,
            &statement.pk1,
            &statement.receivers,
            &witness.sk1,
            rng,
        )?;

        Ok(BatchedEvrfProofEnvelope {
            r1cs: r1cs_proof,
            k_commitments,
            r_commitments,
            cp,
            dlogs,
        })
    }

    /// Verify the batched dealer proof.
    pub fn evrf_batched_verify(
        statement: &BatchedEvrfStatement,
        proof: &BatchedEvrfProofEnvelope,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if statement.receivers.is_empty()
            || proof.k_commitments.len() != statement.receivers.len()
            || proof.r_commitments.len() != statement.receivers.len()
            || proof.dlogs.len() != statement.receivers.len()
            || proof.cp.rjs.len() != statement.receivers.len()
        {
            return Err(Error::ProofVerificationFailed);
        }
        let g_in = Gin::generator();
        let g_s = g_in;
        let g_out = Secq256k1::generator();
        let pc_gens = PedersenGens::<R1csCycle>::default();
        let bp_gens =
            BulletproofGens::<R1csCycle>::new(batched_gens_capacity(statement.receivers.len()), 1);

        // Steps 0, 1: verify batched Chaum-Pedersen proof.
        batched_chaum_pedersen_verify(
            &statement.msg,
            &g_in,
            &statement.pk1,
            &statement.receivers,
            &proof.cp,
        )?;

        // Derive h1, h2 from msg.
        let h1 = h_gin_1(&statement.msg);
        let h2 = h_gin_2(&statement.msg);

        let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(PROOF_DOMAIN));

        for (j, rec) in statement.receivers.iter().enumerate() {
            // Step 2: k_j = int(S_j.x) (public).
            let (s_x, _) = affine(&rec.sj)?;

            // Public T_{1,j}, T_{2,j} coordinates.
            let (t1_x, t1_y) = affine(&rec.t1j)?;
            let (t2_x, t2_y) = affine(&rec.t2j)?;

            // Step 9 prefix link: V_{r,j} == R_j + g_out,1.
            pedersen_prefix_link(&pc_gens.B_blinding, &rec.r_point_j, &proof.r_commitments[j])?;

            // Commit using the proof's compressed commitments.
            let var_k = verifier.commit(proof.k_commitments[j]);
            let var_r = verifier.commit(proof.r_commitments[j]);
            let verifier_bits = vec![None; K_BITS + 1];
            build_one_receiver_slot(
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
                &g_s,
            )
            .map_err(|_| Error::ProofVerificationFailed)?;

            // Step 9: verify DLOG PoK for this receiver.
            dlog_verify(
                &g_out,
                &rec.r_point_j,
                &proof.r_commitments[j],
                &proof.dlogs[j],
            )?;
        }

        verifier
            .verify(&proof.r1cs, &pc_gens, &bp_gens, rng)
            .map_err(|_| Error::ProofVerificationFailed)?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // DKG bridge: SecpSecqBackend implements EvrfProofBackend over the
    // halo2curves Secp256k1 GoldenGroup adapter. The proof carries the paper
    // eVRF envelope plus the per-receiver public inputs (S_j, T_{1,j},
    // T_{2,j}, R_j) that the verifier needs but EvrfStatement does not hold.
    // ------------------------------------------------------------------

    use golden_core::{DealerMessageNonce, EvrfProofBackend, ParticipantIndex};
    use golden_halo2curves::golden_group::{
        scalar_to_r1cs_field, Secp256k1Element, Secp256k1GoldenGroup, Secp256k1Scalar,
    };
    use halo2curves::serde::Repr as SerdeRepr;

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

    /// Per-receiver public values carried alongside the proof envelope so the
    /// verifier can reconstruct the `BatchedEvrfStatement`. The `pad`
    /// field is the DKG pad scalar (`r_j mod q` as `Fq`); the verifier checks
    /// it opens the DKG pad/DH commitments and links to the eVRF output `R_j`.
    #[derive(Clone, Debug)]
    struct SecpSecqReceiverPublic {
        receiver: ParticipantIndex,
        sj: Gin,
        t1j: Gin,
        t2j: Gin,
        r_point_j: Secq256k1,
        pad: Fq,
    }

    /// Byte-serialized paper eVRF proof for the DKG. The inner bytes encode
    /// the `BatchedEvrfProofEnvelope` plus per-receiver public inputs.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SecpSecqProof(pub Vec<u8>);

    const SECP_COMPRESSED: usize = 33;
    const SECQ_COMPRESSED: usize = 33;
    const FP_BYTES: usize = 32;
    const FQ_BYTES: usize = 32;

    /// Encode a `Gin` (Secp256k1) point as its 33-byte compressed form.
    fn encode_gin(point: &Gin) -> [u8; SECP_COMPRESSED] {
        let bytes = Secp256k1Cycle::point_compress(point);
        let mut out = [0u8; SECP_COMPRESSED];
        out.copy_from_slice(bytes.as_ref());
        out
    }

    /// Decode a `Gin` (Secp256k1) point from 33 compressed bytes.
    fn decode_gin(bytes: &[u8]) -> Result<Gin> {
        if bytes.len() < SECP_COMPRESSED {
            return Err(Error::ProofVerificationFailed);
        }
        let mut arr = [0u8; SECP_COMPRESSED];
        arr.copy_from_slice(&bytes[..SECP_COMPRESSED]);
        let repr = SerdeRepr::<SECP_COMPRESSED>::from(arr);
        Secp256k1Cycle::compressed_decompress(&repr).ok_or(Error::ProofVerificationFailed)
    }

    /// Encode a `Secq256k1` point as its 33-byte compressed form.
    fn encode_gout(point: &Secq256k1) -> [u8; SECQ_COMPRESSED] {
        let bytes = R1csCycle::point_compress(point);
        let mut out = [0u8; SECQ_COMPRESSED];
        out.copy_from_slice(bytes.as_ref());
        out
    }

    /// Decode a `Secq256k1` point from 33 compressed bytes.
    fn decode_gout(bytes: &[u8]) -> Result<Secq256k1> {
        if bytes.len() < SECQ_COMPRESSED {
            return Err(Error::ProofVerificationFailed);
        }
        let mut arr = [0u8; SECQ_COMPRESSED];
        arr.copy_from_slice(&bytes[..SECQ_COMPRESSED]);
        let repr = SerdeRepr::<SECQ_COMPRESSED>::from(arr);
        R1csCycle::compressed_decompress(&repr).ok_or(Error::ProofVerificationFailed)
    }

    /// Encode a `GoutCompressed` (Repr<33>) as 33 raw bytes.
    fn encode_gout_compressed(c: &GoutCompressed) -> [u8; SECQ_COMPRESSED] {
        let mut out = [0u8; SECQ_COMPRESSED];
        out.copy_from_slice(c.as_ref());
        out
    }

    /// Encode an `Fp` scalar as 32 canonical LE bytes.
    fn encode_fp(s: &Fp) -> [u8; FP_BYTES] {
        *s.to_repr().inner()
    }

    /// Decode an `Fp` scalar from 32 canonical LE bytes.
    fn decode_fp(bytes: &[u8]) -> Result<Fp> {
        if bytes.len() < FP_BYTES {
            return Err(Error::ProofVerificationFailed);
        }
        let mut arr = [0u8; FP_BYTES];
        arr.copy_from_slice(&bytes[..FP_BYTES]);
        let repr = SerdeRepr::<FP_BYTES>::from(arr);
        Option::from(Fp::from_repr(repr)).ok_or(Error::ProofVerificationFailed)
    }

    /// Encode an `Fq` scalar as 32 canonical LE bytes.
    fn encode_fq(s: &Fq) -> [u8; FQ_BYTES] {
        *s.to_repr().inner()
    }

    /// Decode an `Fq` scalar from 32 canonical LE bytes.
    fn decode_fq(bytes: &[u8]) -> Result<Fq> {
        if bytes.len() < FQ_BYTES {
            return Err(Error::ProofVerificationFailed);
        }
        let mut arr = [0u8; FQ_BYTES];
        arr.copy_from_slice(&bytes[..FQ_BYTES]);
        let repr = SerdeRepr::<FQ_BYTES>::from(arr);
        Option::from(Fq::from_repr(repr)).ok_or(Error::ProofVerificationFailed)
    }

    /// Serialize the proof envelope and per-receiver publics into a flat byte
    /// vector.
    fn encode_proof(
        envelope: &BatchedEvrfProofEnvelope,
        publics: &[SecpSecqReceiverPublic],
    ) -> Result<Vec<u8>> {
        let n = publics.len();
        if envelope.k_commitments.len() != n
            || envelope.r_commitments.len() != n
            || envelope.dlogs.len() != n
            || envelope.cp.rjs.len() != n
        {
            return Err(Error::ProofVerificationFailed);
        }
        let r1cs_bytes = envelope.r1cs.to_bytes();

        let mut out = Vec::with_capacity(
            8 + r1cs_bytes.len()
                + SECP_COMPRESSED
                + FQ_BYTES
                + n * (4
                    + 4 * SECP_COMPRESSED
                    + SECQ_COMPRESSED
                    + 2 * SECQ_COMPRESSED
                    + FQ_BYTES
                    + FQ_BYTES),
        );
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out.extend_from_slice(&(r1cs_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&r1cs_bytes);
        out.extend_from_slice(&encode_gin(&envelope.cp.r0));
        out.extend_from_slice(&encode_fq(&envelope.cp.z));
        // `j` indexes five parallel slices (publics, k_commitments,
        // r_commitments, rjs, dlogs); enumerate on one would still need the
        // others by index.
        #[allow(clippy::needless_range_loop)]
        for j in 0..n {
            out.extend_from_slice(&publics[j].receiver.get().to_le_bytes());
            out.extend_from_slice(&encode_gin(&publics[j].sj));
            out.extend_from_slice(&encode_gin(&publics[j].t1j));
            out.extend_from_slice(&encode_gin(&publics[j].t2j));
            out.extend_from_slice(&encode_gout(&publics[j].r_point_j));
            out.extend_from_slice(&encode_fq(&publics[j].pad));
            out.extend_from_slice(&encode_gout_compressed(&envelope.k_commitments[j]));
            out.extend_from_slice(&encode_gout_compressed(&envelope.r_commitments[j]));
            out.extend_from_slice(&encode_gin(&envelope.cp.rjs[j]));
            out.extend_from_slice(&encode_gout(&envelope.dlogs[j].a));
            out.extend_from_slice(&encode_fp(&envelope.dlogs[j].t));
        }
        Ok(out)
    }

    /// Deserialize the proof envelope and per-receiver publics from a flat
    /// byte vector.
    fn decode_proof(
        bytes: &[u8],
    ) -> Result<(BatchedEvrfProofEnvelope, Vec<SecpSecqReceiverPublic>)> {
        if bytes.len() < 8 {
            return Err(Error::ProofVerificationFailed);
        }
        let n = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")) as usize;
        let r1cs_len = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;
        if bytes.len() < 8 + r1cs_len {
            return Err(Error::ProofVerificationFailed);
        }
        let r1cs = R1CSProof::<R1csCycle>::from_bytes(&bytes[8..8 + r1cs_len])
            .map_err(|_| Error::ProofVerificationFailed)?;

        let mut cursor = 8 + r1cs_len;
        if bytes.len() < cursor + SECP_COMPRESSED + FQ_BYTES {
            return Err(Error::ProofVerificationFailed);
        }
        let cp_r0 = decode_gin(&bytes[cursor..cursor + SECP_COMPRESSED])?;
        cursor += SECP_COMPRESSED;
        let cp_z = decode_fq(&bytes[cursor..cursor + FQ_BYTES])?;
        cursor += FQ_BYTES;

        let per_receiver_size = 4
            + 3 * SECP_COMPRESSED
            + SECQ_COMPRESSED
            + FQ_BYTES
            + 2 * SECQ_COMPRESSED
            + SECP_COMPRESSED
            + SECQ_COMPRESSED
            + FQ_BYTES;
        if bytes.len() < cursor + n * per_receiver_size {
            return Err(Error::ProofVerificationFailed);
        }

        let mut k_commitments = Vec::with_capacity(n);
        let mut r_commitments = Vec::with_capacity(n);
        let mut rjs = Vec::with_capacity(n);
        let mut dlogs = Vec::with_capacity(n);
        let mut publics = Vec::with_capacity(n);

        for _ in 0..n {
            let receiver = ParticipantIndex::new(u32::from_le_bytes(
                bytes[cursor..cursor + 4].try_into().expect("4 bytes"),
            ))
            .map_err(|_| Error::ProofVerificationFailed)?;
            cursor += 4;
            let sj = decode_gin(&bytes[cursor..cursor + SECP_COMPRESSED])?;
            cursor += SECP_COMPRESSED;
            let t1j = decode_gin(&bytes[cursor..cursor + SECP_COMPRESSED])?;
            cursor += SECP_COMPRESSED;
            let t2j = decode_gin(&bytes[cursor..cursor + SECP_COMPRESSED])?;
            cursor += SECP_COMPRESSED;
            let r_point_j = decode_gout(&bytes[cursor..cursor + SECQ_COMPRESSED])?;
            cursor += SECQ_COMPRESSED;
            let pad = decode_fq(&bytes[cursor..cursor + FQ_BYTES])?;
            cursor += FQ_BYTES;

            let mut kc = <GoutCompressed as Default>::default();
            kc.as_mut()
                .copy_from_slice(&bytes[cursor..cursor + SECQ_COMPRESSED]);
            k_commitments.push(kc);
            cursor += SECQ_COMPRESSED;

            let mut rc = <GoutCompressed as Default>::default();
            rc.as_mut()
                .copy_from_slice(&bytes[cursor..cursor + SECQ_COMPRESSED]);
            r_commitments.push(rc);
            cursor += SECQ_COMPRESSED;

            let rj = decode_gin(&bytes[cursor..cursor + SECP_COMPRESSED])?;
            rjs.push(rj);
            cursor += SECP_COMPRESSED;

            let dlog_a = decode_gout(&bytes[cursor..cursor + SECQ_COMPRESSED])?;
            cursor += SECQ_COMPRESSED;
            let dlog_t = decode_fp(&bytes[cursor..cursor + FP_BYTES])?;
            cursor += FP_BYTES;
            dlogs.push(DlogProof {
                a: dlog_a,
                t: dlog_t,
            });

            publics.push(SecpSecqReceiverPublic {
                receiver,
                sj,
                t1j,
                t2j,
                r_point_j,
                pad,
            });
        }

        let envelope = BatchedEvrfProofEnvelope {
            r1cs,
            k_commitments,
            r_commitments,
            cp: BatchedChaumPedersenProof {
                r0: cp_r0,
                rjs,
                z: cp_z,
            },
            dlogs,
        };
        Ok((envelope, publics))
    }

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

    /// Compute the per-receiver paper eVRF public values from the dealer
    /// identity secret and the receiver public key.
    fn compute_receiver_public(
        msg: &[u8; MESSAGE_BYTES],
        sk1: &Fq,
        pkj: &Gin,
        receiver: ParticipantIndex,
        beta: &Fp,
    ) -> Result<SecpSecqReceiverPublic> {
        let g_out = Secq256k1::generator();
        let sj = *pkj * sk1;
        let (s_x, _) = affine(&sj)?;
        let k_fq = fp_to_fq(&s_x);
        let h1 = h_gin_1(msg);
        let h2 = h_gin_2(msg);
        let t1j = h1 * k_fq;
        let t2j = h2 * k_fq;
        let r = compute_pad_fp(msg, sk1, pkj, beta)?;
        let r_point_j = g_out * r;
        let pad = fp_to_fq(&r);
        Ok(SecpSecqReceiverPublic {
            receiver,
            sj,
            t1j,
            t2j,
            r_point_j,
            pad,
        })
    }

    /// Concrete Secp/Secq paper eVRF backend for the DKG.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecpSecqBackend;

    impl EvrfProofBackend<Secp256k1GoldenGroup> for SecpSecqBackend {
        type Proof = SecpSecqProof;

        fn derive_pad(
            msg_i: DealerMessageNonce,
            beta: &Secp256k1Scalar,
            identity_secret: &Secp256k1Scalar,
            peer_public_key: &Secp256k1Element,
            _receiver_public_key: &Secp256k1Element,
        ) -> Result<Secp256k1Scalar> {
            let beta_fp = scalar_to_r1cs_field(beta).ok_or(Error::ProofVerificationFailed)?;
            let r = compute_pad_fp(&msg_i.0, &identity_secret.0, &peer_public_key.0, &beta_fp)?;
            Ok(Secp256k1Scalar(fp_to_fq(&r)))
        }

        fn prove_batch(
            statements: &[EvrfStatement<Secp256k1GoldenGroup>],
            witnesses: &[EvrfWitness<Secp256k1GoldenGroup>],
            rng: &mut impl CryptoRngCore,
        ) -> Result<Self::Proof> {
            if statements.is_empty() || statements.len() != witnesses.len() {
                return Err(Error::ProofVerificationFailed);
            }
            let msg = statements[0].msg_i.0;
            let pk1 = statements[0].dealer_public_key.0;
            let beta =
                scalar_to_r1cs_field(&statements[0].beta).ok_or(Error::ProofVerificationFailed)?;
            let sk1 = witnesses[0].identity_secret.0;

            let pk1_computed = Gin::generator() * sk1;
            if Secp256k1Cycle::point_compress(&pk1_computed).as_ref()
                != Secp256k1Cycle::point_compress(&pk1).as_ref()
            {
                return Err(Error::ProofVerificationFailed);
            }

            let mut receivers = Vec::with_capacity(statements.len());
            let mut publics = Vec::with_capacity(statements.len());
            for statement in statements {
                let pkj = statement.receiver_public_key.0;
                let public = compute_receiver_public(&msg, &sk1, &pkj, statement.receiver, &beta)?;
                receivers.push(BatchedReceiverStatement {
                    pkj,
                    sj: public.sj,
                    t1j: public.t1j,
                    t2j: public.t2j,
                    r_point_j: public.r_point_j,
                });
                publics.push(public);
            }

            let batched_statement = BatchedEvrfStatement {
                msg,
                pk1,
                beta,
                receivers,
            };
            let batched_witness = BatchedEvrfWitness { sk1 };
            let envelope = evrf_batched_prove(&batched_statement, &batched_witness, rng)?;
            let bytes = encode_proof(&envelope, &publics)?;
            Ok(SecpSecqProof(bytes))
        }

        fn verify_batch(
            statements: &[EvrfStatement<Secp256k1GoldenGroup>],
            proof: &Self::Proof,
        ) -> Result<()> {
            if statements.is_empty() {
                return Err(Error::ProofVerificationFailed);
            }
            let (envelope, publics) = decode_proof(&proof.0)?;
            if publics.len() != statements.len() {
                return Err(Error::ProofVerificationFailed);
            }
            let msg = statements[0].msg_i.0;
            let pk1 = statements[0].dealer_public_key.0;
            let beta =
                scalar_to_r1cs_field(&statements[0].beta).ok_or(Error::ProofVerificationFailed)?;
            let g_in = Gin::generator();
            let g_out = Secq256k1::generator();

            let mut receivers = Vec::with_capacity(statements.len());
            for (statement, public) in statements.iter().zip(publics.iter()) {
                if statement.receiver != public.receiver {
                    return Err(Error::ProofVerificationFailed);
                }

                // Bind the DKG pad/DH commitments to the eVRF pad. The pad
                // scalar (Fq) opens pad_commitment = g_in^pad and
                // dh_commitment = PK_j^pad. This prevents a dealer from
                // publishing valid eVRF proof for the real pad while using a
                // different pad for the DKG commitments.
                let pad_fq = public.pad;
                let pad_commitment_expected = g_in * pad_fq;
                if Secp256k1Cycle::point_compress(&pad_commitment_expected).as_ref()
                    != Secp256k1Cycle::point_compress(&statement.pad_commitment.0).as_ref()
                {
                    return Err(Error::ProofVerificationFailed);
                }
                let dh_commitment_expected = statement.receiver_public_key.0 * pad_fq;
                if Secp256k1Cycle::point_compress(&dh_commitment_expected).as_ref()
                    != Secp256k1Cycle::point_compress(&statement.dh_commitment.0).as_ref()
                {
                    return Err(Error::ProofVerificationFailed);
                }

                // Link the eVRF output R_j to the DKG pad. Since r_j is an Fp
                // element and pad = r_j mod q, and p < 2q for Secp256k1, r_j is
                // either pad or pad + q (as integers in [0, p)). When
                // pad + q >= p, the only canonical Fp representative reducing to
                // pad mod q is pad itself, so the `pad + q` case is only
                // accepted when `pad + q` does not wrap mod p. The no-wrap
                // condition is `(pad + q) mod p > pad`, detected by
                // `fp_canonical_lt(&pad_fp, &pad_plus_q)`.
                let pad_fp = fq_to_fp(&pad_fq);
                let r_case0 = g_out * pad_fp;
                let pad_plus_q = pad_fp + Q_AS_FP;
                let case1_canonical = fp_canonical_lt(&pad_fp, &pad_plus_q);
                let r_case1 = g_out * pad_plus_q;
                let r_ok = R1csCycle::point_compress(&r_case0).as_ref()
                    == R1csCycle::point_compress(&public.r_point_j).as_ref()
                    || (case1_canonical
                        && R1csCycle::point_compress(&r_case1).as_ref()
                            == R1csCycle::point_compress(&public.r_point_j).as_ref());
                if !r_ok {
                    return Err(Error::ProofVerificationFailed);
                }

                receivers.push(BatchedReceiverStatement {
                    pkj: statement.receiver_public_key.0,
                    sj: public.sj,
                    t1j: public.t1j,
                    t2j: public.t2j,
                    r_point_j: public.r_point_j,
                });
            }

            let batched_statement = BatchedEvrfStatement {
                msg,
                pk1,
                beta,
                receivers,
            };
            use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
            let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
            evrf_batched_verify(&batched_statement, &envelope, &mut rng)
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
            let g_s = Gin::generator();
            let X = g_s * Fq::from(42u64);
            let k = Fq::from_raw([
                0xDEADBEEFCAFEBABE,
                0x0123456789ABCDEF,
                0xFEDCBA9876543210,
                0x0000000000000001,
            ]);
            let mut bits = [false; K_BITS + 1];
            decompose(&k, &mut bits);

            let (lx, ly) = chord_evaluate(&bits, &X, &g_s, K_BITS).expect("eval");
            let expected = X * k;
            let (ex, ey) = affine(&expected).expect("affine");
            assert_eq!(lx, ex, "L_λ x-coordinate mismatch");
            assert_eq!(ly, ey, "L_λ y-coordinate mismatch");
        }

        #[test]
        fn chord_evaluate_small_exponent() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(99u64);
            let k = Fq::from(5u64);
            let mut bits = [false; K_BITS + 1];
            decompose(&k, &mut bits);

            let (lx, ly) = chord_evaluate(&bits, &X, &g_s, K_BITS).expect("eval");
            let expected = X * k;
            let (ex, ey) = affine(&expected).expect("affine");
            assert_eq!(lx, ex);
            assert_eq!(ly, ey);
        }

        #[test]
        fn precompute_chord_coordinates_are_correct() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(123u64);
            let precomp = precompute_chord(&X, &g_s, K_BITS).expect("precompute");

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
        fn chord_compute_witness_rejects_exceptional_addition() {
            // With X = g_s, k_0 = 1, k_1 = 0:
            //   L_0 = Delta_0 = 1*g_s + 1*g_s = 2*g_s
            //   Delta_1 = 0*P_1 + 2*g_s = 2*g_s
            //   x_{L_0} = x_{Delta_1}  ⟹  dx = 0 (exceptional case)
            // The witness computation must return an error, not fabricate
            // a zero slope.
            let g_s = Gin::generator();
            let X = g_s;
            let mut bits = [false; K_BITS + 1];
            bits[0] = true; // k_0 = 1
            bits[1] = false; // k_1 = 0

            let result = chord_compute_witness(&bits, &X, &g_s, K_BITS);
            assert!(
                result.is_err(),
                "chord_compute_witness must reject exceptional dx=0 case"
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

        /// Helper: prove and verify a bit-decomposition of `k` with the given
        /// bit assignments.  Returns `Ok(())` if the verifier accepts.
        fn run_bit_decompose(
            k: R1csField,
            bit_assignments: &[Option<R1csField>],
        ) -> core::result::Result<(), R1CSError> {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let bp_gens = BulletproofGens::<R1csCycle>::new(512, 1);
            let mut rng = ChaCha20Rng::seed_from_u64(0xA1B2C3D4);

            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
            let (v_k, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            bit_decompose(&mut prover, var_k, bit_assignments, K_BITS)?;
            let proof = prover.prove(&bp_gens, &mut rng).expect("prove");

            let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(PROOF_DOMAIN));
            let v_k_var = verifier.commit(v_k);
            let verifier_bits = vec![None; K_BITS + 1];
            bit_decompose(&mut verifier, v_k_var, &verifier_bits, K_BITS)?;
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
        fn bit_decompose_uses_exact_gate_count() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0x12345678);
            let k = R1csField::from(0xABCDu64);
            let mut bits = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bits);
            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            let _ = bit_decompose(&mut prover, var_k, &bits, K_BITS).expect("gadget");

            // One multiplier gate per bit (λ+1 = 257), no extra allocations.
            let metrics = prover.metrics();
            assert_eq!(
                metrics.multipliers,
                K_BITS + 1,
                "expected exactly λ+1 multiplier gates, got {}",
                metrics.multipliers
            );
        }

        #[test]
        fn bit_decompose_rejects_short_bit_assignments() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0001);
            let k = R1csField::from(0xABCDu64);
            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            // Only λ bits supplied instead of λ+1: gadget must refuse to build
            // a truncated circuit.
            let short_bits = vec![None; K_BITS];
            let result = bit_decompose(&mut prover, var_k, &short_bits, K_BITS);
            assert!(
                result.is_err(),
                "bit_decompose must reject bit_assignments.len() != lambda + 1"
            );
        }

        #[test]
        fn chord_exp_rejects_mismatched_witness_length() {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0002);

            let g_s = Gin::generator();
            let X = g_s * GinScalar::from(12345u64);
            let precomp = precompute_chord(&X, &g_s, K_BITS).expect("precompute");

            // bit_vars and precomp agree on λ+1 = 257 entries; build a witness
            // whose l_coords is one short so the length check fires before any
            // circuit construction.
            let truncated_witness = ChordWitness {
                l_coords: vec![(R1csField::ZERO, R1csField::ZERO); K_BITS],
                slopes: vec![R1csField::ZERO; K_BITS],
            };

            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
            let k = R1csField::ZERO;
            let (_, var_k) = prover.commit(k, random_scalar::<R1csCycle>(&mut rng));
            let mut bit_assignments = vec![None; K_BITS + 1];
            decompose_k(&k, &mut bit_assignments);
            let bit_vars =
                bit_decompose(&mut prover, var_k, &bit_assignments, K_BITS).expect("bit_decomp");
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

        /// The reconstruction constraint is modular (mod p), so a non-canonical
        /// bit pattern encoding `k + p` satisfies `Σ 2^j * k_j ≡ k (mod p)`.
        /// In isolation this proof verifies — the aliasing is caught by the
        /// chord-rule gadget's final **full-point** constraint (both x and y)
        /// in the full relation, not by the bit-decomp alone.  An x-only check
        /// would be insufficient because `(k+p)·X = -k·X` shares the same
        /// x-coordinate.  This test documents the isolation behavior.
        #[test]
        fn bit_decompose_modular_alias_passes_in_isolation() {
            // 2^256 mod p is a known Fp constant.  We build bits encoding
            // k' = 2^256 (a 257-bit integer) and commit to k = 2^256 mod p.
            // The reconstruction Σ 2^j * k'_j = 2^256 ≡ (2^256 mod p) (mod p),
            // so the constraint passes despite the non-canonical representation.
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

            // The proof verifies because 2^256 ≡ two_pow_256_mod_p (mod p).
            run_bit_decompose(two_pow_256_mod_p, &bits).expect("modular alias passes in isolation");
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
            g_s: &Gin,
            result_override: Option<(Fp, Fp)>,
        ) -> core::result::Result<(), R1CSError> {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            // bit_decompose: 257 gates, chord_exp: ~768+ gates.  Pad to 4096.
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
            let precomp = precompute_chord(X, g_s, K_BITS).expect("precompute");

            // Compute witness: all intermediate L_i and s_i.
            let witness = chord_compute_witness(&bits, X, g_s, K_BITS).expect("witness");

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
            let mut prover = Prover::<R1csCycle, _>::new(&pc_gens, Transcript::new(PROOF_DOMAIN));
            let (v_k, var_k) = prover.commit(k_fp, random_scalar::<R1csCycle>(&mut rng));
            let bit_vars =
                bit_decompose(&mut prover, var_k, &bit_assignments, K_BITS).expect("bit_decomp");
            chord_exponentiate_r1cs(
                &mut prover,
                &bit_vars,
                &precomp,
                result_x,
                result_y,
                Some(&witness),
            )
            .expect("chord_exp");
            let proof = prover.prove(&bp_gens, &mut rng).expect("prove");

            // Verifier
            let mut verifier = Verifier::<R1csCycle, _>::new(Transcript::new(PROOF_DOMAIN));
            let v_k_var = verifier.commit(v_k);
            let verifier_bits = vec![None; K_BITS + 1];
            let bit_vars =
                bit_decompose(&mut verifier, v_k_var, &verifier_bits, K_BITS).expect("bit_decomp");
            chord_exponentiate_r1cs(&mut verifier, &bit_vars, &precomp, result_x, result_y, None)
                .expect("chord_exp");
            verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)
        }

        #[test]
        fn chord_exp_honest_proof_verifies() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(42u64);
            run_chord_exp(0xDEADBEEFu64, &X, &g_s, None).expect("honest proof verifies");
        }

        #[test]
        fn chord_exp_small_exponent_verifies() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(7u64);
            run_chord_exp(3u64, &X, &g_s, None).expect("honest proof verifies");
        }

        #[test]
        fn chord_exp_rejects_wrong_result_x() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            let wrong_x = tx + R1csField::ONE;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, &g_s, Some((wrong_x, ty))).is_err(),
                "verifier must reject wrong result x"
            );
        }

        #[test]
        fn chord_exp_rejects_wrong_result_y() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            let wrong_y = ty + R1csField::ONE;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, &g_s, Some((tx, wrong_y))).is_err(),
                "verifier must reject wrong result y"
            );
        }

        #[test]
        fn chord_exp_rejects_negated_result_y() {
            let g_s = Gin::generator();
            let X = g_s * Fq::from(42u64);
            let t = X * Fq::from(0xDEADBEEFu64);
            let (tx, ty) = affine(&t).expect("T affine");
            // -T has the same x but negated y.  The full-point binding
            // (x AND y) must reject this, unlike an x-only check.
            let neg_y = -ty;
            assert!(
                run_chord_exp(0xDEADBEEFu64, &X, &g_s, Some((tx, neg_y))).is_err(),
                "verifier must reject -T (same x, negated y)"
            );
        }
    }

    #[cfg(test)]
    mod cp_tests {
        use super::*;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        #[test]
        fn chaum_pedersen_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
            let g_in = Gin::generator();
            let sk1 = GinScalar::random(&mut rng);
            let pk1 = g_in * sk1;
            let pk2 = g_in * GinScalar::random(&mut rng);
            let s = pk2 * sk1;

            let proof = chaum_pedersen_prove(&g_in, &pk1, &pk2, &s, &sk1, &mut rng).expect("prove");
            chaum_pedersen_verify(&g_in, &pk1, &pk2, &s, &proof).expect("verify");
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
            let proof =
                chaum_pedersen_prove(&g_in, &pk1, &pk2, &s, &wrong_sk1, &mut rng).expect("prove");
            assert!(
                chaum_pedersen_verify(&g_in, &pk1, &pk2, &s, &proof).is_err(),
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
            let s = pk2 * sk1;

            let proof = chaum_pedersen_prove(&g_in, &pk1, &pk2, &s, &sk1, &mut rng).expect("prove");

            // Verify with a wrong S (different DH point).
            let wrong_s = pk2 * GinScalar::random(&mut rng);
            assert!(
                chaum_pedersen_verify(&g_in, &pk1, &pk2, &wrong_s, &proof).is_err(),
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

            let proof = chaum_pedersen_prove(&g_in, &pk1, &pk2, &s, &sk1, &mut rng).expect("prove");

            // Verify with a wrong PK_2.
            let wrong_pk2 = g_in * GinScalar::random(&mut rng);
            assert!(
                chaum_pedersen_verify(&g_in, &pk1, &wrong_pk2, &s, &proof).is_err(),
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

        /// Build a Pedersen commitment to `r` with fixed blinding 1 and return
        /// `(V_r compressed, g_out, g_out,1)` matching the step-9 prefix link.
        fn prefix_commit(r: R1csField) -> (GoutCompressed, Secq256k1, Secq256k1) {
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let v_r_point = pc_gens.commit(r, R1csField::ONE);
            let v_r = R1csCycle::point_compress(&v_r_point);
            (v_r, pc_gens.B, pc_gens.B_blinding)
        }

        #[test]
        fn dlog_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C0);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, g_out_blinding) = prefix_commit(r);
            let r_point = g_out * r;

            pedersen_prefix_link(&g_out_blinding, &r_point, &v_r).expect("prefix link");
            let proof = dlog_prove(&g_out, &r_point, &v_r, &r, &mut rng).expect("prove");
            dlog_verify(&g_out, &r_point, &v_r, &proof).expect("verify");
        }

        #[test]
        fn dlog_rejects_wrong_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C1);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _g_out_blinding) = prefix_commit(r);
            let r_point = g_out * r;

            // Prove with the wrong r (the dealer does not know the dlog of R).
            let wrong_r = R1csField::random(&mut rng);
            let proof = dlog_prove(&g_out, &r_point, &v_r, &wrong_r, &mut rng).expect("prove");
            assert!(
                dlog_verify(&g_out, &r_point, &v_r, &proof).is_err(),
                "verifier must reject wrong r"
            );
        }

        #[test]
        fn dlog_rejects_wrong_r_point() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C2);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _) = prefix_commit(r);
            let r_point = g_out * r;

            let proof = dlog_prove(&g_out, &r_point, &v_r, &r, &mut rng).expect("prove");

            // Verify against a different R (not r * g_out).
            let wrong_r_point = g_out * R1csField::random(&mut rng);
            assert!(
                dlog_verify(&g_out, &wrong_r_point, &v_r, &proof).is_err(),
                "verifier must reject wrong R"
            );
        }

        #[test]
        fn dlog_rejects_wrong_v_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xD10C3);
            let r = R1csField::random(&mut rng);
            let (v_r, g_out, _) = prefix_commit(r);
            let r_point = g_out * r;

            let proof = dlog_prove(&g_out, &r_point, &v_r, &r, &mut rng).expect("prove");

            // Verify against a V_r from a different r (transcript mismatch).
            let wrong_r = R1csField::random(&mut rng);
            let (wrong_v_r, _, _) = prefix_commit(wrong_r);
            assert!(
                dlog_verify(&g_out, &r_point, &wrong_v_r, &proof).is_err(),
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
    mod one_receiver_tests {
        use super::*;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        /// Build a valid `(statement, witness)` pair for the one-receiver
        /// relation, deriving all public values from `sk1` and `msg`.
        fn build_statement_witness(
            msg: &[u8; MESSAGE_BYTES],
            sk1: GinScalar,
            pk2: Gin,
            beta: R1csField,
        ) -> (SecpSecqEvrfStatement, SecpSecqEvrfWitness) {
            let g_in = Gin::generator();

            // Step 0: PK_1 = g_in^sk_1
            let pk1 = g_in * sk1;
            // Step 1: S = PK_2^sk_1
            let s = pk2 * sk1;
            // Step 2: k = int(S.x)
            let (k, _) = affine(&s).expect("S affine");

            // H_{G_in,1}(msg), H_{G_in,2}(msg): derive from msg via the same
            // helpers the prover/verifier use, so the statement's h1/h2 match.
            let h1 = h_gin_1(msg);
            let h2 = h_gin_2(msg);

            // Steps 4, 5: T_1 = H_1^k, T_2 = H_2^k via chord-rule (handles
            // k mod |G_in| reduction since k is an Fp element).
            let mut bits = [false; K_BITS + 1];
            decompose_k_fp(&k, &mut bits);
            let t1 = chord_evaluate_point(&bits, &h1, &g_in, K_BITS).expect("T1");
            let t2 = chord_evaluate_point(&bits, &h2, &g_in, K_BITS).expect("T2");

            // Steps 6, 7, 8: r = beta * T_1.x + T_2.x
            let (t1_x, _) = affine(&t1).expect("T1 affine");
            let (t2_x, _) = affine(&t2).expect("T2 affine");
            let r = beta * t1_x + t2_x;

            // Step 9: R = g_out^r
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

        fn make_msg(seed: u64) -> [u8; MESSAGE_BYTES] {
            let mut msg = [0u8; MESSAGE_BYTES];
            msg[..8].copy_from_slice(&seed.to_le_bytes());
            msg
        }

        #[test]
        fn evrf_one_receiver_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xFEED);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(0xBEE_u64);
            let msg = make_msg(0xCAFEBABE);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            evrf_verify(&statement, &proof, &mut verify_rng).expect("verify");
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_pk2() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0001);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(42u64);
            let msg = make_msg(1);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            // Swap PK_2 for a different receiver.  The Chaum-Pedersen proof
            // (bound to the original PK_2) must fail.
            let wrong_pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let mut bad = statement.clone();
            bad.pk2 = wrong_pk2;
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject wrong receiver PK_2"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_beta() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_BEEF);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(7u64);
            let msg = make_msg(2);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            let mut bad = statement.clone();
            bad.beta = R1csField::from(99u64);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject wrong beta"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0002);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(3u64);
            let msg = make_msg(3);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            // Swap R for a random point.  The prefix link and DLOG PoK must fail.
            let g_out = Secq256k1::generator();
            let mut bad = statement.clone();
            bad.r_point = g_out * R1csField::random(&mut rng);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject wrong R"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_transcript_domain() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0003);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(5u64);
            let msg = make_msg(4);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            // Verify the R1CS proof under a wrong transcript domain by
            // re-running the verifier with a different PROOF_DOMAIN.  We can't
            // easily override the constant, so instead we verify that the proof
            // bytes are bound to the correct domain by checking that a proof
            // generated under one domain fails under another.  This is covered
            // by the r1cs_smoke test's wrong-domain check; here we verify the
            // envelope's R1CS proof rejects a swapped k_commitment, which is
            // the same class of transcript-binding failure.
            let mut bad_proof = proof.clone();
            // Corrupt the k_commitment so the verifier's commitment doesn't
            // match the proof's internal transcript.
            let wrong_k = R1csField::random(&mut rng);
            let pc_gens = PedersenGens::<R1csCycle>::default();
            let wrong_v_k = pc_gens.commit(wrong_k, R1csField::ONE);
            bad_proof.k_commitment = R1csCycle::point_compress(&wrong_v_k);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&statement, &bad_proof, &mut verify_rng).is_err(),
                "verifier must reject a proof whose k_commitment is swapped"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_sk1() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0004);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(11u64);
            let msg = make_msg(5);
            let (statement, _witness) = build_statement_witness(&msg, sk1, pk2, beta);

            // Prove with the wrong sk1 (inconsistent with S).
            let wrong_sk1 = GinScalar::random(&mut rng);
            let bad_witness = SecpSecqEvrfWitness { sk1: wrong_sk1 };
            assert!(
                evrf_prove(&statement, &bad_witness, &mut rng).is_err(),
                "prover must refuse to prove with a sk1 inconsistent with S"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_msg() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0005);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(13u64);
            let msg = make_msg(6);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            // Flip a bit in msg but keep h1/h2 from the original msg.  The
            // verifier recomputes h1/h2 from the mutated msg and must reject.
            let mut bad = statement.clone();
            bad.msg[0] ^= 0x01;
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a proof whose msg has been mutated"
            );
        }

        #[test]
        fn evrf_one_receiver_rejects_wrong_s() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBAAD_0006);
            let sk1 = GinScalar::random(&mut rng);
            let pk2 = Gin::generator() * GinScalar::random(&mut rng);
            let beta = R1csField::from(17u64);
            let msg = make_msg(7);
            let (statement, witness) = build_statement_witness(&msg, sk1, pk2, beta);

            let proof = evrf_prove(&statement, &witness, &mut rng).expect("prove");

            // Swap S for a different DH point.  The Chaum-Pedersen proof (bound
            // to the original S) and the var_k = int(S.x) constraint must fail.
            let wrong_s = pk2 * GinScalar::random(&mut rng);
            let mut bad = statement.clone();
            bad.s = wrong_s;
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a proof whose S has been swapped"
            );
        }
    }

    #[cfg(test)]
    mod batched_dealer_tests {
        use super::*;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        /// Build a valid batched `(statement, witness)` pair for `n` receivers.
        fn build_batched(
            msg: &[u8; MESSAGE_BYTES],
            sk1: GinScalar,
            pkjs: &[Gin],
            beta: R1csField,
        ) -> (BatchedEvrfStatement, BatchedEvrfWitness) {
            let g_in = Gin::generator();
            let pk1 = g_in * sk1;
            let h1 = h_gin_1(msg);
            let h2 = h_gin_2(msg);
            let g_out = Secq256k1::generator();

            let receivers: Vec<BatchedReceiverStatement> = pkjs
                .iter()
                .map(|&pkj| {
                    let sj = pkj * sk1;
                    let (k, _) = affine(&sj).expect("S affine");
                    let mut bits = [false; K_BITS + 1];
                    decompose_k_fp(&k, &mut bits);
                    let t1j = chord_evaluate_point(&bits, &h1, &g_in, K_BITS).expect("T1");
                    let t2j = chord_evaluate_point(&bits, &h2, &g_in, K_BITS).expect("T2");
                    let (t1_x, _) = affine(&t1j).expect("T1 affine");
                    let (t2_x, _) = affine(&t2j).expect("T2 affine");
                    let r = beta * t1_x + t2_x;
                    let r_point_j = g_out * r;
                    BatchedReceiverStatement {
                        pkj,
                        sj,
                        t1j,
                        t2j,
                        r_point_j,
                    }
                })
                .collect();

            let statement = BatchedEvrfStatement {
                msg: *msg,
                pk1,
                beta,
                receivers,
            };
            let witness = BatchedEvrfWitness { sk1 };
            (statement, witness)
        }

        fn make_msg(seed: u64) -> [u8; MESSAGE_BYTES] {
            let mut msg = [0u8; MESSAGE_BYTES];
            msg[..8].copy_from_slice(&seed.to_le_bytes());
            msg
        }

        fn make_pkjs(rng: &mut ChaCha20Rng, n: usize) -> Vec<Gin> {
            (0..n)
                .map(|_| Gin::generator() * GinScalar::random(&mut *rng))
                .collect()
        }

        #[test]
        fn evrf_batched_dealer_honest_proof_verifies() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C1);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(0xABCD);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            evrf_batched_verify(&statement, &proof, &mut verify_rng).expect("verify");
        }

        #[test]
        fn evrf_batched_dealer_rejects_wrong_receiver_pk() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C2);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(1);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Swap one receiver's PK_j.  The batched Chaum-Pedersen proof
            // (bound to the original PK_j) must fail.
            let mut bad = statement.clone();
            bad.receivers[0].pkj = Gin::generator() * GinScalar::random(&mut rng);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a swapped receiver PK_j"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_reordered_receivers() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C3);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 3);
            let beta = R1csField::from(7u64);
            let msg = make_msg(2);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Reorder the receiver list.  The batched CP transcript binds the
            // ordered (PK_j, S_j) list, so the reordered statement must fail.
            let mut bad = statement.clone();
            bad.receivers.reverse();
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a reordered receiver list"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_missing_receiver() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C4);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 3);
            let beta = R1csField::from(7u64);
            let msg = make_msg(3);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Drop one receiver.  The proof envelope length and the CP
            // transcript both bind the receiver count.
            let mut bad = statement.clone();
            bad.receivers.pop();
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a missing receiver"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_wrong_beta() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C5);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(4);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            let mut bad = statement.clone();
            bad.beta = R1csField::from(99u64);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject wrong beta"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_wrong_r() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C6);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(5);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Swap one receiver's R_j.  The prefix link and DLOG PoK must fail.
            let g_out = Secq256k1::generator();
            let mut bad = statement.clone();
            bad.receivers[1].r_point_j = g_out * R1csField::random(&mut rng);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a swapped R_j"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_wrong_msg() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C7);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(6);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Flip a bit in msg.  The verifier recomputes h1/h2 from the
            // mutated msg and the R1CS constraints must fail.
            let mut bad = statement.clone();
            bad.msg[0] ^= 0x01;
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a mutated msg"
            );
        }

        #[test]
        fn evrf_batched_dealer_rejects_proof_replay_across_dealer_keys() {
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C8);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 2);
            let beta = R1csField::from(7u64);
            let msg = make_msg(7);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");

            // Build a second statement with a different dealer key.  The
            // batched CP proof (bound to the original PK_1) must fail.
            let sk1_b = GinScalar::random(&mut rng);
            let (bad, _) = build_batched(&msg, sk1_b, &pkjs, beta);
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            assert!(
                evrf_batched_verify(&bad, &proof, &mut verify_rng).is_err(),
                "verifier must reject a proof replayed across dealer keys"
            );
        }

        #[test]
        fn evrf_batched_dealer_four_receivers_verifies() {
            // Regression for generator sizing: a 4-receiver batch needs more
            // than R1CS_GENS_CAPACITY generators, so the capacity helper must
            // round up to the next power of two above 4 * 8192 = 32768.
            let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C9);
            let sk1 = GinScalar::random(&mut rng);
            let pkjs = make_pkjs(&mut rng, 4);
            let beta = R1csField::from(7u64);
            let msg = make_msg(8);
            let (statement, witness) = build_batched(&msg, sk1, &pkjs, beta);

            let proof = evrf_batched_prove(&statement, &witness, &mut rng).expect("prove");
            let mut verify_rng = ChaCha20Rng::seed_from_u64(0xCAFE);
            evrf_batched_verify(&statement, &proof, &mut verify_rng).expect("verify");
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod dkg_integration_tests {
        use super::*;
        use golden_core::{
            complete, create_dealing, verify_dealing, DkgConfig, GoldenScalar, ParticipantIndex,
            ParticipantRegistry, SessionId,
        };
        use golden_halo2curves::golden_group::{Secp256k1GoldenGroup, Secp256k1Scalar};
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use std::collections::BTreeMap;

        fn idx(value: u32) -> ParticipantIndex {
            ParticipantIndex::new(value).unwrap()
        }

        fn identity_secret(participant: ParticipantIndex) -> Secp256k1Scalar {
            Secp256k1Scalar::from_u64(100 + u64::from(participant.get())).unwrap()
        }

        fn config() -> DkgConfig<Secp256k1GoldenGroup> {
            let participants = [idx(1), idx(2), idx(3)];
            let registry = ParticipantRegistry::new(
                participants
                    .iter()
                    .map(|p| {
                        (
                            *p,
                            Secp256k1GoldenGroup::mul_generator(&identity_secret(*p)),
                        )
                    })
                    .collect(),
            )
            .unwrap();
            DkgConfig::new(
                2,
                SessionId([42u8; 32]),
                Secp256k1Scalar::from_u64(77).unwrap(),
                registry,
            )
            .unwrap()
        }

        #[test]
        fn dkg_completes_with_batched_evrf_backend() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();

            let dealings: BTreeMap<_, _> = config
                .registry
                .indexes()
                .map(|dealer| {
                    (
                        dealer,
                        create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                            dealer,
                            &identity_secret(dealer),
                            &config,
                            &mut rng,
                        )
                        .unwrap(),
                    )
                })
                .collect();

            for dealing in dealings.values() {
                verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config)
                    .unwrap();
            }

            let receiver = idx(2);
            let own_dealing = dealings.get(&receiver).unwrap();
            let peer_dealings = dealings
                .iter()
                .filter_map(|(dealer, dealing)| {
                    if *dealer == receiver {
                        None
                    } else {
                        Some((*dealer, dealing.message.clone()))
                    }
                })
                .collect();
            let output = complete::<Secp256k1GoldenGroup, SecpSecqBackend>(
                receiver,
                &identity_secret(receiver),
                own_dealing,
                &peer_dealings,
                &config,
            )
            .unwrap();

            assert_eq!(
                output.public_key_shares[&receiver],
                Secp256k1GoldenGroup::mul_generator(&output.secret_share.value)
            );
            assert_eq!(output.public_key_shares.len(), 3);
        }

        /// Verify the wrap-detection helper used by the R_j link check. When
        /// `pad + q < p` the sum is canonical and greater than `pad`; when
        /// `pad + q >= p` the wrapped sum is less than `pad`. The link check
        /// accepts the `pad + q` case only in the first (no-wrap) situation.
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

        /// Tamper helper: a different group element (point + generator).
        fn tamper_element(
            point: &<Secp256k1GoldenGroup as GoldenGroup>::Element,
        ) -> <Secp256k1GoldenGroup as GoldenGroup>::Element {
            Secp256k1GoldenGroup::add(point, &Secp256k1GoldenGroup::generator())
        }

        /// Tamper helper: a different scalar (scalar + one).
        fn tamper_scalar(s: &Secp256k1Scalar) -> Secp256k1Scalar {
            Secp256k1Scalar::add(s, &Secp256k1Scalar::one())
        }

        /// Run `verify_dealing` against `config` for a single dealer after
        /// applying `tamper` to the freshly built dealer message.
        fn assert_dealing_rejected<F>(tamper: F)
        where
            F: FnOnce(&mut golden_core::DealerMessage<Secp256k1GoldenGroup, SecpSecqProof>),
        {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();
            let dealer = idx(1);
            let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            // Baseline: the honest dealing verifies.
            verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config)
                .unwrap();
            tamper(&mut dealing.message);
            let result =
                verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
            assert!(
                result.is_err(),
                "tampered dealing must be rejected, got {result:?}"
            );
        }

        /// Build the `EvrfStatement` list exactly as `verify_dealing` does, so
        /// the backend's `verify_batch` can be invoked directly with a tampered
        /// statement. `golden_core::statement_for_receiver` is private, so the
        /// statement is assembled field-by-field from the public config and
        /// dealing message.
        fn build_statements(
            dealing: &golden_core::DkgDealing<Secp256k1GoldenGroup, SecpSecqProof>,
            config: &DkgConfig<Secp256k1GoldenGroup>,
            dealer: ParticipantIndex,
        ) -> Vec<golden_core::EvrfStatement<Secp256k1GoldenGroup>> {
            use golden_core::{EvrfStatement, PROTOCOL_VERSION};
            let mut statements = Vec::new();
            for receiver in config.registry.indexes() {
                if receiver == dealer {
                    continue;
                }
                let share_commitment = dealing
                    .message
                    .commitment
                    .public_key_share(receiver)
                    .unwrap();
                let encrypted_share = dealing
                    .message
                    .encrypted_shares
                    .get(&receiver)
                    .cloned()
                    .unwrap();
                statements.push(EvrfStatement {
                    protocol_version: PROTOCOL_VERSION,
                    backend_id: <Secp256k1GoldenGroup as GoldenGroup>::BACKEND_ID,
                    session_id: config.session_id,
                    registry_root: config.registry.root(),
                    dealer,
                    receiver,
                    msg_i: dealing.message.msg_i,
                    beta: config.beta,
                    dealer_public_key: *config.registry.public_key(dealer).unwrap(),
                    receiver_public_key: *config.registry.public_key(receiver).unwrap(),
                    share_commitment,
                    pad_commitment: encrypted_share.pad_commitment,
                    dh_commitment: encrypted_share.dh_commitment,
                    encrypted_share: encrypted_share.encrypted_share,
                    transcript_root: dealing.message.transcript_root,
                });
            }
            statements
        }

        #[test]
        fn dkg_rejects_tampered_pad_commitment() {
            assert_dealing_rejected(|msg| {
                let receiver = idx(2);
                let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
                entry.pad_commitment = tamper_element(&entry.pad_commitment);
            });
        }

        #[test]
        fn dkg_rejects_tampered_dh_commitment() {
            assert_dealing_rejected(|msg| {
                let receiver = idx(2);
                let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
                entry.dh_commitment = tamper_element(&entry.dh_commitment);
            });
        }

        #[test]
        fn dkg_rejects_tampered_encrypted_share() {
            assert_dealing_rejected(|msg| {
                let receiver = idx(2);
                let entry = msg.encrypted_shares.get_mut(&receiver).unwrap();
                entry.encrypted_share = tamper_scalar(&entry.encrypted_share);
            });
        }

        #[test]
        fn dkg_rejects_tampered_share_commitment() {
            assert_dealing_rejected(|msg| {
                // Replace the Feldman commitment with one whose top coefficient
                // differs, so the derived share commitment for receivers changes.
                let mut coeffs = msg.commitment.coefficients().to_vec();
                let last = coeffs.last_mut().unwrap();
                *last = tamper_element(last);
                msg.commitment = golden_core::FeldmanCommitment::from_coefficients(coeffs).unwrap();
            });
        }

        #[test]
        fn dkg_rejects_tampered_transcript_root() {
            assert_dealing_rejected(|msg| {
                msg.transcript_root[0] ^= 0x01;
            });
        }

        #[test]
        fn dkg_rejects_tampered_proof_bytes() {
            assert_dealing_rejected(|msg| {
                if msg.proof.0.is_empty() {
                    msg.proof.0.push(0);
                }
                msg.proof.0[0] ^= 0x01;
            });
        }

        #[test]
        fn dkg_rejects_swapped_encrypted_shares() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();
            let dealer = idx(1);
            let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config)
                .unwrap();
            // Swap the encrypted shares for receivers idx(2) and idx(3). The
            // proof binds per-receiver statements by receiver index, so a swap
            // breaks either the commitment check or the backend verification.
            let a = dealing
                .message
                .encrypted_shares
                .get(&idx(2))
                .cloned()
                .unwrap();
            let b = dealing
                .message
                .encrypted_shares
                .get(&idx(3))
                .cloned()
                .unwrap();
            dealing.message.encrypted_shares.insert(idx(2), b);
            dealing.message.encrypted_shares.insert(idx(3), a);
            let result =
                verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
            assert!(
                result.is_err(),
                "swapped encrypted shares must be rejected, got {result:?}"
            );
        }

        #[test]
        fn dkg_rejects_missing_encrypted_share() {
            assert_dealing_rejected(|msg| {
                msg.encrypted_shares.remove(&idx(3));
            });
        }

        #[test]
        fn dkg_rejects_extra_self_receiver() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();
            let dealer = idx(1);
            let mut dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config)
                .unwrap();
            // Insert an encrypted share for the dealer itself, then recompute
            // the transcript root so the dealing-root check passes and
            // verification reaches `ensure_public_share_keys`, which rejects
            // the self-receiver entry.
            let placeholder = dealing
                .message
                .encrypted_shares
                .get(&idx(2))
                .cloned()
                .unwrap();
            dealing.message.encrypted_shares.insert(dealer, placeholder);
            dealing.message.transcript_root = dealing.message.recompute_transcript_root();
            let result =
                verify_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(&dealing.message, &config);
            assert!(
                matches!(result, Err(golden_core::Error::UnexpectedShare(d)) if d == dealer.get()),
                "self-receiver must be rejected with UnexpectedShare({}), got {result:?}",
                dealer.get()
            );
        }

        /// The backend binding check must reject a proof whose carried pad
        /// does not open the DKG `pad_commitment`. This bypasses the DKG
        /// transcript-root check by invoking the backend directly with a
        /// tampered statement, isolating the pad-commitment binding.
        #[test]
        fn backend_rejects_pad_commitment_not_opened_by_proof_pad() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();
            let dealer = idx(1);
            let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            let mut statements = build_statements(&dealing, &config, dealer);
            // Baseline: the backend accepts the honest statement list.
            SecpSecqBackend::verify_batch(&statements, &dealing.message.proof).unwrap();
            // Tamper with the first receiver's pad_commitment. The backend
            // checks pad_commitment == g_in^pad (pad from the proof), so this
            // must fail.
            statements[0].pad_commitment = tamper_element(&statements[0].pad_commitment);
            let result = SecpSecqBackend::verify_batch(&statements, &dealing.message.proof);
            assert!(
                result.is_err(),
                "backend must reject pad_commitment not opened by proof pad, got {result:?}"
            );
        }

        /// Symmetric to the above: tamper with `dh_commitment` so it no longer
        /// equals `PK_j^pad` for the proof's pad.
        #[test]
        fn backend_rejects_dh_commitment_not_opened_by_proof_pad() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let config = config();
            let dealer = idx(1);
            let dealing = create_dealing::<Secp256k1GoldenGroup, SecpSecqBackend>(
                dealer,
                &identity_secret(dealer),
                &config,
                &mut rng,
            )
            .unwrap();
            let mut statements = build_statements(&dealing, &config, dealer);
            SecpSecqBackend::verify_batch(&statements, &dealing.message.proof).unwrap();
            statements[0].dh_commitment = tamper_element(&statements[0].dh_commitment);
            let result = SecpSecqBackend::verify_batch(&statements, &dealing.message.proof);
            assert!(
                result.is_err(),
                "backend must reject dh_commitment not opened by proof pad, got {result:?}"
            );
        }

        /// Decoders that return `Result` must reject short input slices
        /// rather than panicking. Each of the four fixed-width decoders
        /// (`decode_gin`, `decode_gout`, `decode_fp`, `decode_fq`) is called
        /// with a slice one byte shorter than the fixed width; all must
        /// return `ProofVerificationFailed` (or whatever error the crate
        /// maps to) rather than abort the process.
        #[test]
        fn decoders_reject_short_inputs() {
            use super::{decode_fp, decode_fq, decode_gin, decode_gout};
            let short_secp = [0u8; SECP_COMPRESSED - 1];
            let short_secq = [0u8; SECQ_COMPRESSED - 1];
            let short_fp = [0u8; FP_BYTES - 1];
            let short_fq = [0u8; FQ_BYTES - 1];
            assert_eq!(
                decode_gin(&short_secp).unwrap_err(),
                Error::ProofVerificationFailed
            );
            assert_eq!(
                decode_gout(&short_secq).unwrap_err(),
                Error::ProofVerificationFailed
            );
            assert_eq!(
                decode_fp(&short_fp).unwrap_err(),
                Error::ProofVerificationFailed
            );
            assert_eq!(
                decode_fq(&short_fq).unwrap_err(),
                Error::ProofVerificationFailed
            );
        }
    }
}
