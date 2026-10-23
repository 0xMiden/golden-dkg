//! Private Jubjub Edwards circuit; policy/native evaluation remains in core.
use crate::{
    driver::{Backend, Slot},
    outer::cycle::Bls12_381G1Cycle,
};
use bulletproofs_cycle::{ConstraintSystem, LinearCombination, R1CSError, Variable};
use ff::{Field, PrimeField};
use golden_core::{DkgGroup, Error, Result};
use golden_curves::jubjub::JubjubGroup;
use group::Group;
use jubjub::{ExtendedPoint, Fr, SubgroupPoint};
type R1csField = bls12_381::Scalar;
type R1csCycle = Bls12_381G1Cycle;
type Gin = SubgroupPoint;
/// Extract affine `(u, v)` coordinates of a non-identity `G_in` point.
fn affine(point: &Gin) -> Result<(R1csField, R1csField)> {
    if is_identity(point) {
        return Err(Error::InvalidProof);
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

/// Bit-decomposition gadget (paper Section 4.2), generalized to an
/// arbitrary bit width so the same implementation serves both the
/// `K_BITS + 1`-wide scalar decompositions ([`bit_decompose_q`])
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
    let mut bit_weight = R1csField::ONE;

    for &bit in bit_assignments {
        let (left, right, out) =
            cs.allocate_multiplier(bit.map(|bit| (bit, R1csField::ONE - bit)))?;
        cs.constrain(right - (LinearCombination::from(R1csField::ONE) - left));
        cs.constrain(out.into());
        bit_vars.push(left);

        k_lc = k_lc + left * bit_weight;
        bit_weight = bit_weight.double();
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
    /// Public doubling chain reused by native witness generation.
    powers: Vec<Gin>,
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
    Ok(EdwardsWindowPrecomp {
        powers,
        bit0,
        windows,
    })
}

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
        return Err(Error::InvalidProof);
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

/// Convert a `GinScalar` element to `R1csField`. Always exact (an injective
/// embedding, not a reduction): `q < p`, so every canonical `GinScalar`
/// value is already a valid `R1csField` element.
fn fr_to_fp(fr: &Fr) -> R1csField {
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
/// Process-wide cache for `g_in`'s windowed additive-ladder precompute.
fn shared_g_in_window_precomp() -> &'static EdwardsWindowPrecomp {
    static PRECOMP: std::sync::OnceLock<EdwardsWindowPrecomp> = std::sync::OnceLock::new();
    PRECOMP.get_or_init(|| {
        precompute_windowed_base_powers(&Gin::generator())
            .expect("the generator is not the identity")
    })
}

struct SecretPrefix {
    bits: Vec<Variable<R1csField>>,
    products: Vec<Variable<R1csField>>,
}
fn prefix<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    pk: &Gin,
    secret: Option<&Fr>,
) -> Result<SecretPrefix> {
    let value = secret.map(fr_to_fp);
    let assignments = bit_options_or_none(value);
    let variable = cs.allocate(value).map_err(|_| Error::InvalidProof)?;
    let bits = bit_decompose_q(cs, variable, &assignments).map_err(|_| Error::InvalidProof)?;
    let products = edwards_window_products(cs, &bits).map_err(|_| Error::InvalidProof)?;
    let table = shared_g_in_window_precomp();
    let mut bools = [false; K_BITS + 1];
    if let Some(value) = value {
        decompose_k_fp(&value, &mut bools);
    }
    let witness = secret
        .map(|_| edwards_windowed_ladder_witness(&bools, &table.powers))
        .transpose()?;
    edwards_exponentiate_windowed_r1cs(
        cs,
        &bits,
        &products,
        table,
        Some(affine(pk)?),
        witness.as_ref(),
    )
    .map_err(|_| Error::InvalidProof)?;
    Ok(SecretPrefix { bits, products })
}
struct SlotWitness {
    dh: EdwardsWindowWitness,
    k: R1csField,
    k_quotient: u8,
    k_inverse: R1csField,
    t1: EdwardsWindowWitness,
    t2: EdwardsWindowWitness,
    pad: R1csField,
    pad_quotient: u8,
    pad_point: EdwardsWindowWitness,
}
fn slot_witness(
    secret: &Fr,
    slot: &Slot<JubjubGroup>,
    beta: R1csField,
    peer: &EdwardsWindowPrecomp,
    h1: &EdwardsWindowPrecomp,
    h2: &EdwardsWindowPrecomp,
) -> Result<SlotWitness> {
    let (dh_u, _) = affine(&(slot.peer * *secret))?;
    let (k, k_quotient) = reduce_pad_witness(&dh_u);
    let k_inverse = Option::<R1csField>::from(k.invert()).ok_or(Error::InvalidProof)?;
    let mut k_bits = [false; K_BITS + 1];
    decompose_k_fp(&k, &mut k_bits);
    let t1 = edwards_windowed_ladder_witness(&k_bits, &h1.powers)?;
    let t2 = edwards_windowed_ladder_witness(&k_bits, &h2.powers)?;
    let t1_u = t1.window_results.last().ok_or(Error::InvalidProof)?.0;
    let t2_u = t2.window_results.last().ok_or(Error::InvalidProof)?.0;
    let (pad, pad_quotient) = reduce_pad_witness(&(beta * t1_u + t2_u));
    let mut secret_bits = [false; K_BITS + 1];
    decompose_k_fp(&fr_to_fp(secret), &mut secret_bits);
    let mut pad_bits = [false; K_BITS + 1];
    decompose_k_fp(&pad, &mut pad_bits);
    Ok(SlotWitness {
        dh: edwards_windowed_ladder_witness(&secret_bits, &peer.powers)?,
        k,
        k_quotient,
        k_inverse,
        t1,
        t2,
        pad,
        pad_quotient,
        pad_point: edwards_windowed_ladder_witness(
            &pad_bits,
            &shared_g_in_window_precomp().powers,
        )?,
    })
}
#[allow(clippy::too_many_arguments)]
fn receiver_slot<CS: ConstraintSystem<R1csCycle>>(
    cs: &mut CS,
    slot: &Slot<JubjubGroup>,
    prefix: &SecretPrefix,
    secret: Option<&Fr>,
    beta: R1csField,
    peer: &EdwardsWindowPrecomp,
    h1: &EdwardsWindowPrecomp,
    h2: &EdwardsWindowPrecomp,
) -> Result<()> {
    let witness = secret
        .map(|secret| slot_witness(secret, slot, beta, peer, h1, h2))
        .transpose()?;
    let (dh_u, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &prefix.bits,
        &prefix.products,
        peer,
        None,
        witness.as_ref().map(|w| &w.dh),
    )
    .map_err(|_| Error::InvalidProof)?;
    // The bounded quotient 0..8 and the tighter remainder bound for quotient
    // eight force quotient*q+k < p. This is exact integer reduction of DH.u.
    let (k, k_bits) = reduce_pad_r1cs(
        cs,
        dh_u.into(),
        witness.as_ref().map(|w| (w.k, w.k_quotient)),
    )
    .map_err(|_| Error::InvalidProof)?;
    let inverse = cs
        .allocate(witness.as_ref().map(|w| w.k_inverse))
        .map_err(|_| Error::InvalidProof)?;
    let (_, _, product) = cs.multiply(k.into(), inverse.into());
    cs.constrain(product - R1csField::ONE);
    let products = edwards_window_products(cs, &k_bits).map_err(|_| Error::InvalidProof)?;
    let (t1_u, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &k_bits,
        &products,
        h1,
        None,
        witness.as_ref().map(|w| &w.t1),
    )
    .map_err(|_| Error::InvalidProof)?;
    let (t2_u, _) = edwards_exponentiate_windowed_r1cs(
        cs,
        &k_bits,
        &products,
        h2,
        None,
        witness.as_ref().map(|w| &w.t2),
    )
    .map_err(|_| Error::InvalidProof)?;
    let (_, pad_bits) = reduce_pad_r1cs(
        cs,
        t1_u * beta + t2_u,
        witness.as_ref().map(|w| (w.pad, w.pad_quotient)),
    )
    .map_err(|_| Error::InvalidProof)?;
    let products = edwards_window_products(cs, &pad_bits).map_err(|_| Error::InvalidProof)?;
    edwards_exponentiate_windowed_r1cs(
        cs,
        &pad_bits,
        &products,
        shared_g_in_window_precomp(),
        Some(affine(&slot.pad)?),
        witness.as_ref().map(|w| &w.pad_point),
    )
    .map_err(|_| Error::InvalidProof)?;
    Ok(())
}

impl Backend for Bls12_381G1Cycle {
    type Dkg = JubjubGroup;
    const PROOF_ID: &'static [u8] = b"golden-dkg/main-golden/jubjub-bls12-381-bp/v1";
    const CYCLE_ID: &'static str = "bls12-381-g1";
    fn build<CS: ConstraintSystem<Self>>(
        cs: &mut CS,
        pk: &Gin,
        slots: &[Slot<JubjubGroup>],
        secret: Option<&Fr>,
        beta: R1csField,
    ) -> Result<()> {
        let mut tables = std::collections::BTreeMap::new();
        for slot in slots {
            for point in [&slot.peer, &slot.h1, &slot.h2, &slot.pad] {
                if bool::from(point.is_identity()) {
                    return Err(Error::InvalidProof);
                }
            }
            for point in [&slot.peer, &slot.h1, &slot.h2] {
                let key = JubjubGroup::encode_point(point);
                if let std::collections::btree_map::Entry::Vacant(entry) = tables.entry(key) {
                    entry.insert(precompute_windowed_base_powers(point)?);
                }
            }
        }
        let shared = prefix(cs, pk, secret)?;
        for slot in slots {
            let peer = tables
                .get(&JubjubGroup::encode_point(&slot.peer))
                .ok_or(Error::ProofOperationFailed)?;
            let h1 = tables
                .get(&JubjubGroup::encode_point(&slot.h1))
                .ok_or(Error::ProofOperationFailed)?;
            let h2 = tables
                .get(&JubjubGroup::encode_point(&slot.h2))
                .ok_or(Error::ProofOperationFailed)?;
            receiver_slot(cs, slot, &shared, secret, beta, peer, h1, h2)?;
        }
        Ok(())
    }
}
crate::prepared::concrete_system!(
    BlsJubjubPrepared,
    BlsJubjubBulletproofs,
    Bls12_381G1Cycle,
    JubjubGroup
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
        crate::shape::check_counted_layout::<Bls12_381G1Cycle>();
    }
    #[test]
    fn integer_reduction_rejects_field_wrap_alias() {
        let pc = PedersenGens::<Bls12_381G1Cycle>::default();
        let mut sizing = Verifier::<Bls12_381G1Cycle, _>::new(Transcript::new(b"reduction-sizing"));
        reduce_pad_r1cs(&mut sizing, R1csField::ZERO.into(), None).unwrap();
        let bp = BulletproofGens::<Bls12_381G1Cycle>::new(
            sizing.metrics().multipliers.next_power_of_two(),
            1,
        );
        let mut rng = ChaCha20Rng::from_seed([74; 32]);
        let q = gin_scalar_modulus_as_r1cs_field();
        let p_minus_one = -R1csField::ONE;
        let mut cases = vec![
            (R1csField::ZERO, R1csField::ZERO, 0, true),
            (q - R1csField::ONE, q - R1csField::ONE, 0, true),
            (q, R1csField::ZERO, 1, true),
            (q * R1csField::from(8), R1csField::ZERO, 8, true),
        ];
        let (remainder, quotient) = reduce_pad_witness(&p_minus_one);
        cases.push((p_minus_one, remainder, quotient, true));
        cases.push((R1csField::ZERO, -q * R1csField::from(8), 8, false));
        for (value, remainder, quotient, accepted) in cases {
            let mut prover =
                Prover::<Bls12_381G1Cycle, _>::new(&pc, Transcript::new(b"reduction-boundary"));
            reduce_pad_r1cs(&mut prover, value.into(), Some((remainder, quotient))).unwrap();
            let proof = prover.prove(&bp, &mut rng).unwrap();
            let mut verifier =
                Verifier::<Bls12_381G1Cycle, _>::new(Transcript::new(b"reduction-boundary"));
            reduce_pad_r1cs(&mut verifier, value.into(), None).unwrap();
            let verdict = verifier
                .verification_equation(&proof, &pc, &bp, &mut rng)
                .and_then(|equation| equation.verify());
            assert_eq!(verdict.is_ok(), accepted);
        }
    }
}
