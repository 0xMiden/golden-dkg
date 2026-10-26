//! Private Secp circuits; policy/native evaluation remains in core.
#![allow(non_snake_case)]
use crate::{
    driver::{Backend, Slot},
    ec::{Affine, EcCurve, Engine, ScalarRef},
    outer::secp::SecqCycle,
};
#[cfg(test)]
use bulletproofs_cycle::Cycle;
use bulletproofs_cycle::{
    r1cs::RandomizableConstraintSystem, ConstraintSystem, LinearCombination, R1CSError, Variable,
};
use ff::{Field, PrimeField};
use golden_core::{DkgGroup, Error, Result};
use golden_curves::secp256k1::Secp256k1Group;
use group::{Curve, Group};
use halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
#[cfg(test)]
use halo2curves::CurveExt;
use halo2curves::{Coordinates, CurveAffine};
type R1csField = Fp;
type R1csCycle = SecqCycle;
type Gin = Secp256k1;
#[cfg(test)]
const CHORD_CORRECTION_DOMAIN: &str = "golden-paper-evrf-chord-correction-v1";
fn affine(point: &Gin) -> Result<(Fp, Fp)> {
    let aff = point.to_affine();
    let coords = aff.coordinates();
    let opt: Option<Coordinates<halo2curves::secp256k1::Secp256k1Affine>> = Option::from(coords);
    opt.map(|c| (*c.x(), *c.y())).ok_or(Error::InvalidProof)
}

/// Batch-convert `points` to affine `(x, y)` coordinates with a single
/// field inversion (Montgomery's trick via `group::Curve::batch_normalize`),
/// instead of one inversion per point via [`affine`].
fn batch_affine(points: &[Gin]) -> Result<Vec<(Fp, Fp)>> {
    let mut affines = vec![Secp256k1Affine::default(); points.len()];
    Gin::batch_normalize(points, &mut affines);
    affines
        .iter()
        .map(|aff| {
            let opt: Option<Coordinates<Secp256k1Affine>> = Option::from(aff.coordinates());
            opt.map(|c| (*c.x(), *c.y())).ok_or(Error::InvalidProof)
        })
        .collect()
}

/// Bit length used for the `k = int(S.x)` decomposition. The Secp256k1
/// base field modulus fits in 256 bits, so 256 bits cover every canonical
/// `Fp` element.
const K_BITS: usize = 256;

/// Secp256k1 scalar-field modulus `q`, encoded little-endian.
const SECP256K1_SCALAR_MODULUS_LE: [u8; 32] = [
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Difference between the Secp256k1 base-field modulus `p` and scalar
/// modulus `q`, encoded little-endian.
const SECP256K1_P_MINUS_Q_LE: [u8; 32] = [
    0xee, 0xba, 0xc9, 0x2f, 0x72, 0xa1, 0x2d, 0x40, 0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
#[cfg(test)]
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

/// Precomputed `Fp` coordinates for one chord-rule exponentiation,
/// grouped for 2-bit windowed selection. Bit `0` is the gadget's
/// unpaired base case; bits `1..=lambda` pair into `lambda / 2` windows,
/// window `w` (`w = 1..=lambda/2`) covering bits `(2w-1, 2w)`.
///
/// For window `w`, `windows[w-1]` holds the four combined candidate
/// points `Q_{b0,b1} = (b0 ? P_{2w-1} : 0) + (b1 ? P_{2w} : 0) + C_{2w-1}
/// + C_{2w}` (with `P_j = 2^j · X`, `C_j = c_j · G_S`), indexed
///   `[Q00, Q10, Q01, Q11]` for `(bit_{2w-1}, bit_{2w}) = (0,0), (1,0),
///   (0,1), (1,1)`. The R1CS selects `x_{Δ_w}` as the corresponding
///   linear combination of the two window bits and their product (see
///   [`window_delta_x_lc`]).
#[derive(Clone, Debug)]
#[cfg(test)]
struct ChordPrecomp {
    /// `(x, y)` of `C_0 = c_0 · G_S`, the base case's correction point.
    c0: (Fp, Fp),
    /// `(x, y)` of `D_0 = P_0 + C_0`, the base case's bit-set point.
    d0: (Fp, Fp),
    /// Combined window candidate points for `w = 1..=lambda/2`.
    windows: Vec<[(Fp, Fp); 4]>,
    /// Public doubling data shared by native witness generation.
    powers: Vec<Gin>,
    corrections: [Gin; 3],
}

/// Precompute the base-case and windowed candidate coordinates for a
/// chord-rule exponentiation of base `X` with `lambda + 1` bits (`lambda`
/// must be even). The correction generator `G_S(X)` is derived from `X`,
/// so each base gets independent correction points. All coordinates are
/// native `Fp` elements.
#[cfg(test)]
fn precompute_chord(X: &Gin, lambda: usize) -> Result<ChordPrecomp> {
    if lambda == 0 || !lambda.is_multiple_of(2) {
        return Err(Error::InvalidProof);
    }
    let g_s = chord_correction_generator(X);

    // chord_cj only ever returns one of three distinct scalars across
    // j = 0..=lambda (1, 2, and 1-2λ), so C_j = c_j * G_S collapses to
    // three distinct points; compute each once instead of once per j.
    let c_first = g_s;
    let c_mid = g_s * Fq::from(2);
    let c_last = g_s * chord_cj(lambda, lambda);

    // Raw per-bit C_j and D_j = P_j + C_j (still projective), j = 0..=lambda.
    let mut c_points = Vec::with_capacity(lambda + 1);
    let mut d_points = Vec::with_capacity(lambda + 1);
    let mut powers = Vec::with_capacity(lambda + 1);
    let mut p_j = *X; // P_0 = 2^0 · X = X
    for j in 0..=lambda {
        let c_j_point = if j == 0 {
            c_first
        } else if j < lambda {
            c_mid
        } else {
            c_last
        };
        powers.push(p_j);
        c_points.push(c_j_point);
        d_points.push(p_j + c_j_point);
        p_j = p_j.double(); // P_{j+1} = 2 · P_j
    }

    let num_windows = lambda / 2;
    let mut points = Vec::with_capacity(2 + 4 * num_windows);
    points.push(c_points[0]);
    points.push(d_points[0]);
    for w in 1..=num_windows {
        let (j1, j2) = (2 * w - 1, 2 * w);
        let (c1, d1) = (c_points[j1], d_points[j1]);
        let (c2, d2) = (c_points[j2], d_points[j2]);
        points.push(c1 + c2); // Q00 = C_j1 + C_j2
        points.push(d1 + c2); // Q10 = P_j1 + C_j1 + C_j2
        points.push(c1 + d2); // Q01 = C_j1 + P_j2 + C_j2
        points.push(d1 + d2); // Q11 = P_j1 + P_j2 + C_j1 + C_j2
    }

    // Batch-normalize every point with a single field inversion.
    let affines = batch_affine(&points)?;
    let (base, window_coords) = affines.split_at(2);
    let windows = window_coords.as_chunks::<4>().0.to_vec();
    Ok(ChordPrecomp {
        c0: base[0],
        d0: base[1],
        windows,
        powers,
        corrections: [c_first, c_mid, c_last],
    })
}

// ------------------------------------------------------------------
// R1CS gadgets
// ------------------------------------------------------------------

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

    let mut coefficient = R1csField::ONE;
    for &bit in bit_assignments {
        // One multiplier gate: left = k_j, right = 1 - k_j, out = k_j*(1-k_j).
        let (left, right, out) =
            cs.allocate_multiplier(bit.map(|bit| (bit, R1csField::ONE - bit)))?;
        // Constrain right = 1 - left so that out = left*(1-left).
        cs.constrain(right - (LinearCombination::from(R1csField::ONE) - left));
        // k_j * (1 - k_j) = 0  ⟹  k_j is binary.
        cs.constrain(out.into());
        bit_vars.push(left);

        k_lc = k_lc + left * coefficient;
        coefficient = coefficient.double();
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
    // The caller already constrained every bit to 0/1. Their sum is
    // below the field characteristic, so it is zero iff all high bits
    // are zero. Gate the sum once instead of chaining each leading zero.
    let lower_bits_start = (0..=K_BITS)
        .rev()
        .find(|&j| modulus_bit(bound_le, j))
        .map_or(0, |msb| msb + 1);
    if lower_bits_start < bit_vars.len() {
        let high_sum = bit_vars[lower_bits_start..]
            .iter()
            .fold(LinearCombination::default(), |lc, &bit| lc + bit);
        let (_, _, violation) = cs.multiply(condition_lc.clone(), high_sum);
        cs.constrain(violation.into());
    }
    // When the condition holds, the omitted high prefix is all zero.
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

// ------------------------------------------------------------------
// Chord-rule R1CS exponentiation gadget (paper Section 4.3).
// ------------------------------------------------------------------

/// Witness values for one chord-rule exponentiation: `L_w` at every
/// checkpoint boundary (see [`chord_is_checkpoint_window`]) and the
/// window addition slopes `s_w` needed by the R1CS gadget.
#[cfg(test)]
struct ChordWitness {
    /// `(x_{L_w}, y_{L_w})` for each checkpoint window `w`, in
    /// increasing order. The gadget only ever reads the running point at
    /// checkpoint boundaries (every intermediate window's coordinates
    /// are consumed immediately as a linear combination, not read back
    /// from the witness), so only those boundary points are retained.
    checkpoint_coords: Vec<(R1csField, R1csField)>,
    /// `s_w` for `w = 1..=lambda/2` (slope of the chord between
    /// `L_{w-1}` and the windowed `Δ_w`).
    slopes: Vec<R1csField>,
    /// The corresponding `x_prev - x_delta`, before batch inversion.
    denominators: Vec<R1csField>,
    /// Batch-computed inverses used by the in-circuit nonzero guards.
    inverses: Vec<R1csField>,
}

#[cfg(test)]
fn chord_compute_witness_precomputed(
    bits: &[bool],
    precomp: &ChordPrecomp,
) -> Result<ChordWitness> {
    let lambda = precomp.powers.len() - 1;
    if bits.len() != lambda + 1 {
        return Err(Error::InvalidProof);
    }
    let num_windows = lambda / 2;
    let p_points = &precomp.powers;
    let correction = |j| {
        precomp.corrections[if j == 0 {
            0
        } else if j < lambda {
            1
        } else {
            2
        }]
    };

    // Pass 1: accumulate L_w via native curve addition (no field
    // inversions), one window at a time, recording every combined Δ_w
    // (w >= 1) needed for a slope so every point can be normalized to
    // affine coordinates together, in a single batched inversion below.
    let mut l_points = Vec::with_capacity(num_windows + 1);
    let mut delta_points = Vec::with_capacity(num_windows); // Δ_1..Δ_{num_windows}

    // Base case: L_0 = Δ_0 = (bit_0 ? P_0 : 0) + C_0.
    let mut l = if bits[0] {
        p_points[0] + correction(0)
    } else {
        correction(0)
    };
    l_points.push(l);

    for w in 1..=num_windows {
        let (j1, j2) = (2 * w - 1, 2 * w);
        let mut delta = correction(j1) + correction(j2);
        if bits[j1] {
            delta += p_points[j1];
        }
        if bits[j2] {
            delta += p_points[j2];
        }
        delta_points.push(delta);
        l += delta;
        l_points.push(l);
    }

    // Batch-normalize every L_w and Δ_w (w >= 1) with a single inversion.
    let mut points = l_points;
    points.extend_from_slice(&delta_points);
    let affines = batch_affine(&points)?;
    let (l_coords, delta_coords) = affines.split_at(num_windows + 1);

    // Pass 2: slopes s_w = (y_{L_{w-1}} - y_{Δ_w}) / (x_{L_{w-1}} - x_{Δ_w}),
    // batching the num_windows field inversions into one.
    let mut dxs = Vec::with_capacity(num_windows);
    let mut dys = Vec::with_capacity(num_windows);
    for w in 1..=num_windows {
        let (x_prev, y_prev) = l_coords[w - 1];
        let (x_delta, y_delta) = delta_coords[w - 1];
        let dx: R1csField = x_prev - x_delta;
        let dy: R1csField = y_prev - y_delta;
        if bool::from(dx.is_zero()) {
            return Err(Error::InvalidProof);
        }
        dxs.push(dx);
        dys.push(dy);
    }
    let denominators = dxs.clone();
    R1csCycle::scalar_batch_invert(&mut dxs);
    let slopes: Vec<R1csField> = dys
        .iter()
        .zip(dxs.iter())
        .map(|(dy, dx_inv)| *dy * dx_inv)
        .collect();

    let checkpoint_coords = (1..=num_windows)
        .filter(|&w| chord_is_checkpoint_window(w, num_windows))
        .map(|w| l_coords[w])
        .collect();

    Ok(ChordWitness {
        checkpoint_coords,
        slopes,
        denominators,
        inverses: dxs,
    })
}

/// Build the linear combination for `x_{Δ_0}` = `k_0 * (x_{D_0} - x_{C_0})
/// + x_{C_0}`, the gadget's unpaired base-case bit.
#[cfg(test)]
fn delta0_x_lc(
    k0_var: Variable<R1csField>,
    precomp: &ChordPrecomp,
) -> LinearCombination<R1csField> {
    let (cx, _) = precomp.c0;
    let (dx, _) = precomp.d0;
    LinearCombination::from(cx) + k0_var * (dx - cx)
}

/// Build the linear combination for `y_{Δ_0}`.
#[cfg(test)]
fn delta0_y_lc(
    k0_var: Variable<R1csField>,
    precomp: &ChordPrecomp,
) -> LinearCombination<R1csField> {
    let (_, cy) = precomp.c0;
    let (_, dy) = precomp.d0;
    LinearCombination::from(cy) + k0_var * (dy - cy)
}

/// Build the linear combination for `x_{Δ_w}`, the x-coordinate of the
/// combined 2-bit-window candidate selected by `(s0, s1) = (k_{2w-1},
/// k_{2w})`, given their shared product `and_var = s0 * s1`:
/// `x_{Δ_w} = Q00.x + s0*(Q10.x-Q00.x) + s1*(Q01.x-Q00.x) +
/// and_var*(Q11.x-Q10.x-Q01.x+Q00.x)`. A pure linear combination once
/// `and_var` is known, so window selection costs no multiplier gate of
/// its own beyond the one shared `and_var` product.
#[cfg(test)]
fn window_delta_x_lc(
    s0_var: Variable<R1csField>,
    s1_var: Variable<R1csField>,
    and_var: Variable<R1csField>,
    window: &[(Fp, Fp); 4],
) -> LinearCombination<R1csField> {
    let (q00x, _) = window[0];
    let (q10x, _) = window[1];
    let (q01x, _) = window[2];
    let (q11x, _) = window[3];
    LinearCombination::from(q00x)
        + s0_var * (q10x - q00x)
        + s1_var * (q01x - q00x)
        + and_var * (q11x - q10x - q01x + q00x)
}

/// Build the linear combination for `y_{Δ_w}`, the y-coordinate
/// analogue of [`window_delta_x_lc`].
#[cfg(test)]
fn window_delta_y_lc(
    s0_var: Variable<R1csField>,
    s1_var: Variable<R1csField>,
    and_var: Variable<R1csField>,
    window: &[(Fp, Fp); 4],
) -> LinearCombination<R1csField> {
    let (_, q00y) = window[0];
    let (_, q10y) = window[1];
    let (_, q01y) = window[2];
    let (_, q11y) = window[3];
    LinearCombination::from(q00y)
        + s0_var * (q10y - q00y)
        + s1_var * (q01y - q00y)
        + and_var * (q11y - q10y - q01y + q00y)
}

/// Compute the shared 2-bit-window AND products `k_{2w-1} * k_{2w}` for
/// `w = 1..=(bit_vars.len()-1)/2` (`bit_vars.len()` must be odd; bit `0`
/// is the chord-rule gadget's unpaired base case and is excluded).
/// Callable once per distinct bit vector and shared as `window_products`
/// across every [`chord_exponentiate_r1cs_with_result`] call that reuses
/// those bits, so the shared product is paid for once rather than once
/// per chord.
#[cfg(test)]
fn chord_window_products<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    bit_vars: &[Variable<R1csField>],
) -> core::result::Result<Vec<Variable<R1csField>>, R1CSError> {
    if bit_vars.len() < 3 || bit_vars.len().is_multiple_of(2) {
        return Err(R1CSError::FormatError);
    }
    let num_windows = (bit_vars.len() - 1) / 2;
    let mut products = Vec::with_capacity(num_windows);
    for w in 1..=num_windows {
        let (_, _, and_var) = cs.multiply(bit_vars[2 * w - 1].into(), bit_vars[2 * w].into());
        products.push(and_var);
    }
    Ok(products)
}

/// Interval, in loop iterations, at which the chord-rule gadget
/// re-materializes its running point as a fresh allocated variable pair
/// instead of an ever-growing linear combination. Bounds the per-step
/// evaluation cost of the running point at the cost of one multiplier
/// gate (an allocated pair) per interval.
#[cfg(test)]
const CHORD_CHECKPOINT_INTERVAL: usize = 16;

/// Whether window `w` (`w = 1..=num_windows`) is a checkpoint boundary:
/// the chord-rule gadget re-materializes its running point here, and
/// [`chord_compute_witness_precomputed`] retains only these boundary coordinates in
/// [`ChordWitness::checkpoint_coords`]. The final window is always a
/// checkpoint so the gadget has a concrete result to return.
#[cfg(test)]
fn chord_is_checkpoint_window(w: usize, num_windows: usize) -> bool {
    w.is_multiple_of(CHORD_CHECKPOINT_INTERVAL) || w == num_windows
}

/// Number of checkpoint windows in `1..=num_windows` (the length
/// [`ChordWitness::checkpoint_coords`] must have for a given chord).
#[cfg(test)]
fn chord_checkpoint_count(num_windows: usize) -> usize {
    let full_intervals = num_windows / CHORD_CHECKPOINT_INTERVAL;
    if num_windows.is_multiple_of(CHORD_CHECKPOINT_INTERVAL) {
        full_intervals
    } else {
        full_intervals + 1
    }
}

/// Chord-rule exponentiation R1CS gadget (paper Section 4.3), using 2-bit
/// windowed selection (Boneh et al. 2024/397, Remark 1 / Section 6.3:
/// the recurrence can process two key bits per iteration). Given the
/// bit variables from [`bit_decompose_q`],
/// the windowed precomputed coordinates, the shared window AND products
/// from [`chord_window_products`], and an optional public result point
/// `(result_x, result_y)`, constrains:
/// - `L_0 = Δ_0` (base case, expressed directly as a linear combination
///   of `bit_vars[0]`, no allocation)
/// - `L_w = L_{w-1} + Δ_w` for each window `w = 1..=lambda/2` (3
///   multiplication gates for the chord formulas and one inverse guard, plus
///   the shared `and_var` product amortized across every gadget call
///   that reuses `window_products`; `x_{L_w}`/`y_{L_w}` are themselves
///   linear combinations of the gate outputs rather than separately
///   allocated and constrained), where `Δ_w` is the windowed selection
///   of one of four precomputed candidates by `(bit_{2w-1}, bit_{2w})`
///   (see [`window_delta_x_lc`])
/// - when `result` is present, `L_λ = (result_x, result_y)` (final
///   full-point binding, 2 linear constraints)
///
/// The full-point binding (both x and y) is critical for soundness: an
/// x-only check cannot distinguish `L_λ` from `-L_λ`, which would allow
/// non-canonical bit aliases (see [`bit_decompose_q`] doc).
///
/// Every chord denominator `x_{L_{w-1}} - x_{Δ_w}` has an inverse
/// constraint, so exceptional additions fail closed. Completeness still
/// relies on the hash-derived correction generator avoiding those cases;
/// rejecting them does not supply a completeness or composition proof.
///
/// The running point is re-materialized as an allocated variable pair
/// every [`CHORD_CHECKPOINT_INTERVAL`] windows (see that constant), so
/// the gadget bounds running linear-combination size without materializing
/// every intermediate point. Each denominator also has an inverse guard;
/// preparation counts the resulting exact allocation layout.
///
/// Returns the `(x_{L_λ}, y_{L_λ})` variables.
#[cfg(test)]
fn chord_exponentiate_r1cs_with_result<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    bit_vars: &[Variable<R1csField>],
    precomp: &ChordPrecomp,
    window_products: &[Variable<R1csField>],
    result: Option<(R1csField, R1csField)>,
    witness: Option<&ChordWitness>,
) -> core::result::Result<(Variable<R1csField>, Variable<R1csField>), R1CSError> {
    // The chord-rule gadget consumes bit_vars[0..=λ] (λ even, so bits
    // 1..=λ pair into λ/2 windows), precomp.windows[0..λ/2],
    // window_products[0..λ/2], and witness.checkpoint_coords/
    // slopes[0..λ/2]. Reject mismatches before building the circuit so a
    // caller mistake surfaces as a format error rather than a truncated
    // exponentiation that silently binds L_λ.
    let lambda_plus_one = bit_vars.len();
    if lambda_plus_one < 3 || lambda_plus_one.is_multiple_of(2) {
        return Err(R1CSError::FormatError);
    }
    let num_windows = (lambda_plus_one - 1) / 2;
    if precomp.windows.len() != num_windows || window_products.len() != num_windows {
        return Err(R1CSError::FormatError);
    }
    if let Some(w) = witness {
        if w.checkpoint_coords.len() != chord_checkpoint_count(num_windows)
            || w.slopes.len() != num_windows
            || w.denominators.len() != num_windows
            || w.inverses.len() != num_windows
        {
            return Err(R1CSError::FormatError);
        }
    }

    // --- Base case: L_0 = Δ_0, expressed directly as a linear
    // combination of the bit variable rather than an allocated pair
    // constrained equal to it.
    let mut x_prev = delta0_x_lc(bit_vars[0], precomp);
    let mut y_prev = delta0_y_lc(bit_vars[0], precomp);
    let mut checkpoint: Option<(Variable<R1csField>, Variable<R1csField>)> = None;
    let mut checkpoint_idx = 0;

    for w in 1..=num_windows {
        let s0_var = bit_vars[2 * w - 1];
        let s1_var = bit_vars[2 * w];
        let and_var = window_products[w - 1];
        let window = &precomp.windows[w - 1];

        // Windowed selection of Δ_w in terms of the two window bits and
        // their shared product.
        let dx_w = window_delta_x_lc(s0_var, s1_var, and_var, window);
        let dy_w = window_delta_y_lc(s0_var, s1_var, and_var, window);
        let denom_delta = x_prev.clone() - dx_w.clone();

        // Constraint 1: s_w * (x_{L_{w-1}} - x_{Δ_w}) = y_{L_{w-1}} - y_{Δ_w}
        // Allocate the slope in the multiplication itself. Both other
        // wires remain bound to the same denominator/numerator LCs.
        let assignment = witness.map(|wit| (wit.slopes[w - 1], wit.denominators[w - 1]));
        let (s_var, denominator, out1) = cs.allocate_multiplier(assignment)?;
        cs.constrain(denominator - denom_delta);
        cs.constrain(out1 - (y_prev.clone() - dy_w));
        // Exclude coincident/opposite exceptional points inside the circuit,
        // rather than relying only on honest witness generation to reject dx=0.
        let inverse_assignment = witness.map(|wit| wit.inverses[w - 1]);
        let inverse = cs.allocate(inverse_assignment)?;
        let (_, _, inverse_product) = cs.multiply(denominator.into(), inverse.into());
        cs.constrain(inverse_product - Fp::ONE);

        // Constraint 2 defines x_{L_w} directly as a linear combination
        // of the gate output, rather than allocating x_{L_w} and
        // constraining it equal to this same expression:
        // x_{L_w} = s_w^2 - x_{L_{w-1}} - x_{Δ_w}
        let (_, _, out2) = cs.multiply(s_var.into(), s_var.into());
        let mut x_l = out2 - x_prev.clone() - dx_w;

        // Constraint 3 defines y_{L_w} the same way:
        // y_{L_w} = s_w * (x_{L_{w-1}} - x_{L_w}) - y_{L_{w-1}}
        let denom_result = x_prev - x_l.clone();
        let (_, _, out3) = cs.multiply(s_var.into(), denom_result);
        let mut y_l = out3 - y_prev;

        // An un-checkpointed running point grows the term count of
        // x_l/y_l by a constant amount every window, since each
        // window's definition embeds the previous one. Left unchecked
        // over the full 128-window chain this makes every subsequent
        // `multiply()` evaluation (and the final flattened constraint)
        // increasingly expensive. Every `CHORD_CHECKPOINT_INTERVAL`
        // windows, and unconditionally on the last window (so the
        // gadget always has a `Variable` pair to return), materialize
        // the running point as a fresh allocated pair and resume
        // accumulating from that 1-term LC.
        if chord_is_checkpoint_window(w, num_windows) {
            let (x_ck_assign, y_ck_assign) = witness
                .map(|wit| wit.checkpoint_coords[checkpoint_idx])
                .unzip();
            let x_ck = cs.allocate(x_ck_assign)?;
            let y_ck = cs.allocate(y_ck_assign)?;
            cs.constrain(x_l - x_ck);
            cs.constrain(y_l - y_ck);
            x_l = x_ck.into();
            y_l = y_ck.into();
            checkpoint = Some((x_ck, y_ck));
            checkpoint_idx += 1;
        }

        x_prev = x_l;
        y_prev = y_l;
    }

    // The loop always visits `w == num_windows` on its last iteration,
    // which unconditionally checkpoints, so `checkpoint` is always
    // populated here (num_windows >= 1 is guaranteed by the length
    // check above).
    let (x_final, y_final) =
        checkpoint.expect("final loop iteration always checkpoints the running point");

    if let Some((result_x, result_y)) = result {
        // Final full-point binding: L_λ = (result_x, result_y).
        cs.constrain(x_final - result_x);
        cs.constrain(y_final - result_y);
    }

    Ok((x_final, y_final))
}

/// Process-wide cache for `g_in`'s chord-rule precompute table.
///
/// `g_in = Gin::generator()` is a compile-time constant, so
/// `precompute_chord` produces the same table on every call. PK_1 and every
/// receiver's pad commitment exponentiate against `g_in`, so this is
/// computed once per process instead of repeatedly per proof.
#[cfg(test)]
fn shared_g_in_chord_precomp() -> &'static ChordPrecomp {
    static PRECOMP: std::sync::OnceLock<ChordPrecomp> = std::sync::OnceLock::new();
    PRECOMP.get_or_init(|| {
        precompute_chord(&Gin::generator(), K_BITS)
            .expect("chord precompute for the fixed G_in generator must succeed")
    })
}
/// Derive `G_S(X)` for the chord-rule correction terms used with base `X`.
#[cfg(test)]
fn chord_correction_generator(X: &Gin) -> Gin {
    let compressed = group::GroupEncoding::to_bytes(X);
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

fn scalar_to_base(value: &Fq) -> Fp {
    let bytes = Secp256k1Group::encode_scalar(value);
    Fp::from_raw(core::array::from_fn(|i| {
        u64::from_le_bytes(core::array::from_fn(|j| bytes[8 * i + j]))
    }))
}
const Q_AS_FP: Fp = Fp::from_raw([
    0xbfd2_5e8c_d036_4141,
    0xbaae_dce6_af48_a03b,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
]);

/// Enforce integer reduction, not merely field equality. For quotient 1 the
/// remainder is additionally below p-q, so quotient*q+remainder cannot wrap p.
fn reduce_scalar_r1cs<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    value: LinearCombination<Fp>,
    witness: Option<(Fp, Fp)>,
) -> core::result::Result<(Variable<Fp>, Vec<Variable<Fp>>), R1CSError> {
    let remainder = cs.allocate(witness.map(|w| w.0))?;
    let (quotient, right, product) =
        cs.allocate_multiplier(witness.map(|w| (w.1, Fp::ONE - w.1)))?;
    cs.constrain(right - (LinearCombination::from(Fp::ONE) - quotient));
    cs.constrain(product.into());
    cs.constrain(remainder - (value - quotient * Q_AS_FP));
    let mut bools = [false; K_BITS + 1];
    if let Some((value, _)) = witness {
        decompose_k_fp(&value, &mut bools);
    }
    let assignments = bools
        .iter()
        .map(|&b| witness.map(|_| if b { Fp::ONE } else { Fp::ZERO }))
        .collect::<Vec<_>>();
    let bits = bit_decompose_q(cs, remainder, &assignments)?;
    constrain_bits_lt_bound_when(cs, &bits, &assignments, &SECP256K1_P_MINUS_Q_LE, quotient)?;
    Ok((remainder, bits))
}
#[cfg(test)]
struct SecretPrefix {
    bits: Vec<Variable<Fp>>,
    products: Vec<Variable<Fp>>,
}
#[cfg(test)]
fn prefix<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    pk: &Gin,
    secret: Option<&Fq>,
) -> Result<SecretPrefix> {
    let value = secret.map(scalar_to_base);
    let mut bools = [false; K_BITS + 1];
    if let Some(value) = value {
        decompose_k_fp(&value, &mut bools);
    }
    let assignments = bools
        .iter()
        .map(|&b| secret.map(|_| if b { Fp::ONE } else { Fp::ZERO }))
        .collect::<Vec<_>>();
    let variable = cs.allocate(value).map_err(|_| Error::InvalidProof)?;
    let bits = bit_decompose_q(cs, variable, &assignments).map_err(|_| Error::InvalidProof)?;
    let products = chord_window_products(cs, &bits).map_err(|_| Error::InvalidProof)?;
    let table = shared_g_in_chord_precomp();
    let witness = secret
        .map(|_| chord_compute_witness_precomputed(&bools, table))
        .transpose()?;
    chord_exponentiate_r1cs_with_result(
        cs,
        &bits,
        table,
        &products,
        Some(affine(pk)?),
        witness.as_ref(),
    )
    .map_err(|_| Error::InvalidProof)?;
    Ok(SecretPrefix { bits, products })
}
/// DH and its canonical exponent are independent of the sharing message.
#[cfg(test)]
struct ReceiverPrefix {
    bits: Vec<Variable<Fp>>,
    products: Vec<Variable<Fp>>,
    scalar: Option<Fq>,
}
fn reduction_witness(value: &Fp) -> (Fp, Fp) {
    let reduced = scalar_to_base(&Secp256k1Group::reduce_base_field(value));
    (reduced, if reduced == *value { Fp::ZERO } else { Fp::ONE })
}
fn scalar_bit_witness(value: Option<Fp>) -> Option<Vec<bool>> {
    value.map(|value| {
        let mut bits = vec![false; K_BITS + 1];
        decompose_k_fp(&value, &mut bits);
        bits
    })
}
#[cfg(test)]
fn receiver_prefix<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    peer_point: &Gin,
    prefix: &SecretPrefix,
    secret: Option<&Fq>,
    peer: &ChordPrecomp,
) -> Result<ReceiverPrefix> {
    let native = secret
        .map(|secret| affine(&(peer_point * *secret)))
        .transpose()?
        .map(|(x, _)| reduction_witness(&x));
    let secret_bits = scalar_bit_witness(secret.map(scalar_to_base));
    let dh = secret_bits
        .as_ref()
        .map(|bits| chord_compute_witness_precomputed(bits, peer))
        .transpose()?;
    let (dh_x, _) = chord_exponentiate_r1cs_with_result(
        cs,
        &prefix.bits,
        peer,
        &prefix.products,
        None,
        dh.as_ref(),
    )
    .map_err(|_| Error::InvalidProof)?;
    let (k, bits) = reduce_scalar_r1cs(cs, dh_x.into(), native).map_err(|_| Error::InvalidProof)?;
    let inverse = native
        .map(|(k, _)| Option::<Fp>::from(k.invert()).ok_or(Error::InvalidProof))
        .transpose()?;
    let inverse = cs.allocate(inverse).map_err(|_| Error::InvalidProof)?;
    let (_, _, product) = cs.multiply(k.into(), inverse.into());
    cs.constrain(product - Fp::ONE);
    let products = chord_window_products(cs, &bits).map_err(|_| Error::InvalidProof)?;
    Ok(ReceiverPrefix {
        bits,
        products,
        scalar: native.map(|(k, _)| Secp256k1Group::reduce_base_field(&k)),
    })
}
#[cfg(test)]
struct SlotWitness {
    t1: ChordWitness,
    t2: ChordWitness,
    pad: Fp,
    pad_quotient: Fp,
    pad_point: ChordWitness,
}
#[cfg(test)]
fn slot_witness(
    scalar: &Fq,
    beta: Fp,
    h1: &ChordPrecomp,
    h2: &ChordPrecomp,
) -> Result<SlotWitness> {
    let mut k_bits = [false; K_BITS + 1];
    decompose_k_fp(&scalar_to_base(scalar), &mut k_bits);
    let t1 = chord_compute_witness_precomputed(&k_bits, h1)?;
    let t2 = chord_compute_witness_precomputed(&k_bits, h2)?;
    let t1_x = t1.checkpoint_coords.last().ok_or(Error::InvalidProof)?.0;
    let t2_x = t2.checkpoint_coords.last().ok_or(Error::InvalidProof)?.0;
    let (pad, pad_quotient) = reduction_witness(&(beta * t1_x + t2_x));
    let mut pad_bits = [false; K_BITS + 1];
    decompose_k_fp(&pad, &mut pad_bits);
    Ok(SlotWitness {
        t1,
        t2,
        pad,
        pad_quotient,
        pad_point: chord_compute_witness_precomputed(&pad_bits, shared_g_in_chord_precomp())?,
    })
}
#[cfg(test)]
fn receiver_slot<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    slot: &Slot<Secp256k1Group>,
    prefix: &ReceiverPrefix,
    beta: Fp,
    h1: &ChordPrecomp,
    h2: &ChordPrecomp,
) -> Result<()> {
    let witness = prefix
        .scalar
        .as_ref()
        .map(|scalar| slot_witness(scalar, beta, h1, h2))
        .transpose()?;
    let (t1_x, _) = chord_exponentiate_r1cs_with_result(
        cs,
        &prefix.bits,
        h1,
        &prefix.products,
        None,
        witness.as_ref().map(|w| &w.t1),
    )
    .map_err(|_| Error::InvalidProof)?;
    let (t2_x, _) = chord_exponentiate_r1cs_with_result(
        cs,
        &prefix.bits,
        h2,
        &prefix.products,
        None,
        witness.as_ref().map(|w| &w.t2),
    )
    .map_err(|_| Error::InvalidProof)?;
    let (_, pad_bits) = reduce_scalar_r1cs(
        cs,
        t1_x * beta + t2_x,
        witness.as_ref().map(|w| (w.pad, w.pad_quotient)),
    )
    .map_err(|_| Error::InvalidProof)?;
    let products = chord_window_products(cs, &pad_bits).map_err(|_| Error::InvalidProof)?;
    chord_exponentiate_r1cs_with_result(
        cs,
        &pad_bits,
        shared_g_in_chord_precomp(),
        &products,
        Some(affine(&slot.pad)?),
        witness.as_ref().map(|w| &w.pad_point),
    )
    .map_err(|_| Error::InvalidProof)?;
    Ok(())
}

impl EcCurve for SecqCycle {
    fn a() -> Fp {
        Fp::ZERO
    }
    fn b() -> Fp {
        Fp::from(7)
    }
    fn affine(point: &Gin) -> Result<Affine<Fp>> {
        let (x, y) = affine(point)?;
        Ok(Affine { x, y })
    }
    fn batch_affine(points: &[Gin]) -> Result<Vec<Affine<Fp>>> {
        batch_affine(points)
            .map(|points| points.into_iter().map(|(x, y)| Affine { x, y }).collect())
    }
    fn native_x<CS: ConstraintSystem<Self>>(
        _: &mut CS,
        point: (Variable<Fp>, Variable<Fp>),
        _: Option<&Gin>,
    ) -> Result<Variable<Fp>> {
        Ok(point.0)
    }
}

/// Register every EC relation before the common commitment/challenge boundary.
fn build_deferred<CS: RandomizableConstraintSystem<SecqCycle>>(
    cs: &mut CS,
    pk: &Gin,
    slots: &[Slot<Secp256k1Group>],
    secret: Option<&Fq>,
    beta: Fp,
) -> Result<()> {
    let mut engine = Engine::<SecqCycle>::new();
    let value = secret.map(scalar_to_base);
    let bools = scalar_bit_witness(value);
    let assignments = (0..=K_BITS)
        .map(|i| {
            bools
                .as_ref()
                .map(|bits| if bits[i] { Fp::ONE } else { Fp::ZERO })
        })
        .collect::<Vec<_>>();
    let variable = cs.allocate(value).map_err(|_| Error::InvalidProof)?;
    let bits = bit_decompose_q(cs, variable, &assignments).map_err(|_| Error::InvalidProof)?;
    let dealer = engine.scalar(bits, bools)?;
    let anchor = engine.mul(cs, &Gin::generator(), dealer)?;
    engine.assert_equal(anchor, pk)?;

    // Instance-major slots revisit each receiver. Reuse the certified DH point,
    // exact reduction, nonzero check and window selectors across those visits.
    let mut receivers = std::collections::BTreeMap::<Vec<u8>, (ScalarRef, Option<Fq>)>::new();
    for slot in slots {
        for point in [&slot.peer, &slot.h1, &slot.h2, &slot.pad] {
            if bool::from(point.is_identity()) {
                return Err(Error::InvalidProof);
            }
        }
        let key = Secp256k1Group::encode_point(&slot.peer);
        let (scalar, native) = match receivers.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let point = engine.mul(cs, &slot.peer, dealer)?;
                let x = engine.point_x(cs, point)?;
                let native = secret
                    .map(|secret| affine(&(slot.peer * *secret)))
                    .transpose()?
                    .map(|(x, _)| reduction_witness(&x));
                let (k, bits) =
                    reduce_scalar_r1cs(cs, x.into(), native).map_err(|_| Error::InvalidProof)?;
                let inverse = native
                    .map(|(k, _)| Option::<Fp>::from(k.invert()).ok_or(Error::InvalidProof))
                    .transpose()?;
                let inverse = cs.allocate(inverse).map_err(|_| Error::InvalidProof)?;
                let (_, _, product) = cs.multiply(k.into(), inverse.into());
                cs.constrain(product - Fp::ONE);
                let scalar = engine.scalar(bits, scalar_bit_witness(native.map(|(k, _)| k)))?;
                let native = native.map(|(k, _)| Secp256k1Group::reduce_base_field(&k));
                *entry.insert((scalar, native))
            }
        };
        let t1 = engine.mul(cs, &slot.h1, scalar)?;
        let t2 = engine.mul(cs, &slot.h2, scalar)?;
        let t1_x = engine.point_x(cs, t1)?;
        let t2_x = engine.point_x(cs, t2)?;
        let native = native
            .map(|k| -> Result<(Fp, Fp)> {
                let (x1, _) = affine(&(slot.h1 * k))?;
                let (x2, _) = affine(&(slot.h2 * k))?;
                Ok(reduction_witness(&(beta * x1 + x2)))
            })
            .transpose()?;
        let (_, bits) =
            reduce_scalar_r1cs(cs, t1_x * beta + t2_x, native).map_err(|_| Error::InvalidProof)?;
        let pad = engine.scalar(bits, scalar_bit_witness(native.map(|(pad, _)| pad)))?;
        let point = engine.mul(cs, &Gin::generator(), pad)?;
        engine.assert_equal(point, &slot.pad)?;
    }
    engine.finalize(cs)
}

impl Backend for SecqCycle {
    type Dkg = Secp256k1Group;
    const PROOF_ID: &'static [u8] = b"golden-dkg/main-golden/secp-secq-bp/v2";
    const CIRCUIT_COSTS: crate::shape::CircuitCosts = crate::shape::CircuitCosts {
        secret_multipliers: 514,
        reduction_multipliers: 713,
        reduction_allocations: 1,
        native_x_multipliers: 0,
        native_x_allocations: 0,
    };
    const CYCLE_ID: &'static str = "secq256k1";
    fn build<CS: RandomizableConstraintSystem<Self>>(
        cs: &mut CS,
        pk: &Gin,
        slots: &[Slot<Secp256k1Group>],
        secret: Option<&Fq>,
        beta: Fp,
    ) -> Result<()> {
        build_deferred(cs, pk, slots, secret, beta)
    }
    #[cfg(test)]
    fn build_ladder<CS: ConstraintSystem<Self>>(
        cs: &mut CS,
        pk: &Gin,
        slots: &[Slot<Secp256k1Group>],
        secret: Option<&Fq>,
        beta: Fp,
    ) -> Result<()> {
        let mut tables = std::collections::BTreeMap::new();
        for slot in slots {
            for point in [&slot.peer, &slot.h1, &slot.h2, &slot.pad] {
                if bool::from(point.is_identity()) {
                    return Err(Error::InvalidProof);
                }
            }
            for point in [&slot.peer, &slot.h1, &slot.h2] {
                let key = Secp256k1Group::encode_point(point);
                if let std::collections::btree_map::Entry::Vacant(entry) = tables.entry(key) {
                    entry.insert(precompute_chord(point, K_BITS)?);
                }
            }
        }
        // One allocation/decomposition, one generator relation and one set of
        // dealer-secret window products serve every instance-major receiver slot.
        let shared = prefix(cs, pk, secret)?;
        let mut receivers = std::collections::BTreeMap::new();
        for slot in slots {
            let peer = tables
                .get(&Secp256k1Group::encode_point(&slot.peer))
                .ok_or(Error::ProofOperationFailed)?;
            let h1 = tables
                .get(&Secp256k1Group::encode_point(&slot.h1))
                .ok_or(Error::ProofOperationFailed)?;
            let h2 = tables
                .get(&Secp256k1Group::encode_point(&slot.h2))
                .ok_or(Error::ProofOperationFailed)?;
            let key = Secp256k1Group::encode_point(&slot.peer);
            let receiver = match receivers.entry(key) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(receiver_prefix(cs, &slot.peer, &shared, secret, peer)?)
                }
            };
            receiver_slot(cs, slot, receiver, beta, h1, h2)?;
        }
        Ok(())
    }
}
crate::prepared::concrete_system!(
    SecpSecqPrepared,
    SecpSecqBulletproofs,
    SecqCycle,
    Secp256k1Group
);

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs_cycle::{
        generators::{BulletproofGens, PedersenGens},
        r1cs::{Prover, Verifier},
    };
    use merlin::Transcript;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    #[test]
    fn shared_prefix_capacity_matches_real_layout() {
        crate::shape::check_counted_layout::<SecqCycle>();
    }
    #[test]
    fn integer_reduction_rejects_field_wrap_alias() {
        let pc = PedersenGens::<SecqCycle>::default();
        let mut sizing = Verifier::<SecqCycle, _>::new(Transcript::new(b"reduction-sizing"));
        reduce_scalar_r1cs(&mut sizing, Fp::ZERO.into(), None).unwrap();
        let bp =
            BulletproofGens::<SecqCycle>::new(sizing.metrics().multipliers.next_power_of_two(), 1);
        let mut rng = ChaCha20Rng::from_seed([73; 32]);
        let p_minus_one = -Fp::ONE;
        let mut cases = vec![
            (Fp::ZERO, Fp::ZERO, Fp::ZERO, true),
            (Q_AS_FP - Fp::ONE, Q_AS_FP - Fp::ONE, Fp::ZERO, true),
            (Q_AS_FP, Fp::ZERO, Fp::ONE, true),
        ];
        let (remainder, quotient) = reduction_witness(&p_minus_one);
        cases.push((p_minus_one, remainder, quotient, true));
        // 0 = (p-q) + q mod p is a false integer reduction. The strict
        // remainder < p-q gate must reject the equality-boundary alias.
        cases.push((Fp::ZERO, -Q_AS_FP, Fp::ONE, false));
        for (value, remainder, quotient, accepted) in cases {
            let mut prover =
                Prover::<SecqCycle, _>::new(&pc, Transcript::new(b"reduction-boundary"));
            reduce_scalar_r1cs(&mut prover, value.into(), Some((remainder, quotient))).unwrap();
            let proof = prover.prove(&bp, &mut rng).unwrap();
            let mut verifier =
                Verifier::<SecqCycle, _>::new(Transcript::new(b"reduction-boundary"));
            reduce_scalar_r1cs(&mut verifier, value.into(), None).unwrap();
            let verdict = verifier
                .verification_equation(&proof, &pc, &bp, &mut rng)
                .and_then(|equation| equation.verify());
            assert_eq!(verdict.is_ok(), accepted);
        }
    }
}
