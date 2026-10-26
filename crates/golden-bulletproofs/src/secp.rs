//! Private Secp circuits; policy/native evaluation remains in core.
use crate::{
    driver::{Backend, Slot},
    ec::{Affine, EcCurve, Engine, ScalarRef},
    outer::secp::SecqCycle,
};
use bulletproofs_cycle::{
    r1cs::RandomizableConstraintSystem, ConstraintSystem, LinearCombination, R1CSError, Variable,
};
use ff::{Field, PrimeField};
use golden_core::{DkgGroup, Error, Result};
use golden_curves::secp256k1::Secp256k1Group;
use group::{Curve, Group};
use halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2curves::{Coordinates, CurveAffine};
type R1csField = Fp;
type R1csCycle = SecqCycle;
type Gin = Secp256k1;
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
    // below the supplied modulus. Scan from MSB to LSB and keep a flag
    // `prefix_equal` that is 1 while higher bits match the bound. At a
    // zero bound bit, `prefix_equal * k_j = 0` prevents exceeding it.
    // At a one bound bit, the product carries equality to the next bit.
    // Reject final equality as well.
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

/// Decompose an `Fp` element into little-endian bits via its canonical
/// byte representation. Produces exactly `K_BITS + 1` bits; the canonical
/// range constraint forces the extra high bit to zero.
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
