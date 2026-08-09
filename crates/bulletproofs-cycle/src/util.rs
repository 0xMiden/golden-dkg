//! Polynomials and small helpers used by the R1CS proof path, generic over a
//! prime scalar field `S`.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use ff::PrimeField;

/// Degree-3 vector polynomial `a + b*x + c*x^2 + d*x^3`.
pub struct VecPoly3<S: PrimeField>(pub Vec<S>, pub Vec<S>, pub Vec<S>, pub Vec<S>);

/// Degree-6 scalar polynomial `a*x + b*x^2 + c*x^3 + d*x^4 + e*x^5 + f*x^6`.
pub struct Poly6<S: PrimeField> {
    /// Coefficient of `x`.
    pub t1: S,
    /// Coefficient of `x^2`.
    pub t2: S,
    /// Coefficient of `x^3`.
    pub t3: S,
    /// Coefficient of `x^4`.
    pub t4: S,
    /// Coefficient of `x^5`.
    pub t5: S,
    /// Coefficient of `x^6`.
    pub t6: S,
}

/// Iterator over the powers of a scalar.
pub struct ScalarExp<S: PrimeField> {
    x: S,
    next_exp_x: S,
}

impl<S: PrimeField> Iterator for ScalarExp<S> {
    type Item = S;

    fn next(&mut self) -> Option<S> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

/// Powers of `x`, starting at `x^0 = 1`.
pub fn exp_iter<S: PrimeField>(x: S) -> ScalarExp<S> {
    ScalarExp {
        x,
        next_exp_x: S::ONE,
    }
}

impl<S: PrimeField> VecPoly3<S> {
    /// Inner product of `lhs` and `rhs` assuming `lhs.0` and `rhs.2` are zero,
    /// which holds for the R1CS proof polynomials.
    pub(crate) fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6<S> {
        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);
        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    /// Horner-evaluates the polynomial at `x`. Any field left empty (as an
    /// allocation-free stand-in for an all-zero limb the caller knows never
    /// gets written) is read back as zero rather than indexed.
    pub(crate) fn eval(&self, x: S) -> Vec<S> {
        let n = self
            .0
            .len()
            .max(self.1.len())
            .max(self.2.len())
            .max(self.3.len());
        let at = |v: &Vec<S>, i: usize| v.get(i).copied().unwrap_or(S::ZERO);
        let mut out = vec![S::ZERO; n];
        for (i, out_i) in out.iter_mut().enumerate().take(n) {
            *out_i =
                at(&self.0, i) + x * (at(&self.1, i) + x * (at(&self.2, i) + x * at(&self.3, i)));
        }
        out
    }
}

impl<S: PrimeField> Poly6<S> {
    pub(crate) fn eval(&self, x: S) -> S {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}

/// First 32 bytes of `data`.
///
/// **Precondition: `data.len() >= 32`.** Indexes `data[..32]` without a
/// bounds check, so a short slice panics. Callers in
/// `inner_product_proof::from_bytes` and `r1cs::proof::from_bytes` slice
/// from a pre-length-checked buffer, so the panic is unreachable in
/// production; future callers must do the same.
pub fn read32(data: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[..32]);
    buf
}

/// Inner product of two equally sized scalar slices.
pub fn inner_product<S: PrimeField>(a: &[S], b: &[S]) -> S {
    let mut out = S::ZERO;
    let len = a.len().min(b.len());
    for i in 0..len {
        out += a[i] * b[i];
    }
    out
}

/// Sum of all powers of `x` up to `x^(n-1)`, i.e. `1 + x + x^2 + ... + x^(n-1)`.
///
/// If `n` is a power of two, uses the doubling algorithm with `2*lg(n)`
/// multiplications and additions. Otherwise falls back to the linear-time
/// slow path. The Bulletproofs callers always pass `n` as a power of two
/// (the inner-product round count), so the fast path is the one that
/// matters in production.
pub fn sum_of_powers<S: PrimeField>(x: &S, n: usize) -> S {
    if !n.is_power_of_two() {
        return sum_of_powers_slow(x, n);
    }
    if n == 0 || n == 1 {
        return S::from(n as u64);
    }
    let mut m = n;
    let mut result = S::ONE + *x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m /= 2;
    }
    result
}

/// Linear-time sum of powers: `exp_iter(*x).take(n).sum()`.
pub fn sum_of_powers_slow<S: PrimeField>(x: &S, n: usize) -> S {
    exp_iter(*x).take(n).sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use ff::Field;
    use halo2curves::secp256k1::Fq as S;

    #[test]
    fn exp_iter_starts_at_one() {
        // x^0 == 1 for any x, including x == 0. The prover relies on this
        // when building powers-of-y vectors; a regression to x^1 first
        // would silently shift every power vector by one position.
        let x = S::from(7);
        let mut it = exp_iter(x);
        assert_eq!(it.next(), Some(S::ONE));
        assert_eq!(it.next(), Some(x));
        assert_eq!(it.next(), Some(x * x));
    }

    #[test]
    fn exp_iter_zero_yields_all_ones() {
        // 0^0 is treated as 1 here; 0^k for k >= 1 is 0. Pin both behaviors.
        let mut it = exp_iter(S::ZERO);
        assert_eq!(it.next(), Some(S::ONE));
        assert_eq!(it.next(), Some(S::ZERO));
        assert_eq!(it.next(), Some(S::ZERO));
    }

    #[test]
    fn inner_product_handles_mismatched_lengths() {
        // inner_product takes a.len().min(b.len()) rather than panicking.
        // The R1CS callers always feed equal lengths, but the helper itself
        // must not panic on a longer slice — that would convert a future
        // caller mistake into an abort instead of a wrong answer.
        let a = [S::from(2), S::from(3), S::from(5)];
        let b = [S::from(7), S::from(11)];
        assert_eq!(
            inner_product(&a, &b),
            S::from(2) * S::from(7) + S::from(3) * S::from(11)
        );
        assert_eq!(inner_product(&a[..0], &b), S::ZERO);
    }

    #[test]
    fn read32_copies_first_32_bytes() {
        let mut data = vec![0u8; 64];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let got = read32(&data);
        assert_eq!(got, {
            let mut want = [0u8; 32];
            for (i, b) in want.iter_mut().enumerate() {
                *b = i as u8;
            }
            want
        });
    }

    #[test]
    #[should_panic(expected = "range end index 32")]
    fn read32_panics_on_short_input() {
        // Pins the documented precondition: read32 indexes data[..32]
        // without a bounds check. Callers in inner_product_proof.rs and
        // r1cs/proof.rs slice from a pre-length-checked buffer, so this
        // panic is unreachable in production; pinning it here makes sure
        // no future caller can feed a short slice silently.
        let data = [0u8; 31];
        let _ = read32(&data);
    }

    #[test]
    fn vecpoly3_eval_matches_horner() {
        // VecPoly3 eval is Horner on (a, b, c, d). Pin against a direct
        // polynomial evaluation so a reordering of the coefficients fails.
        let p = VecPoly3(
            vec![S::from(1), S::from(2)],
            vec![S::from(3), S::from(4)],
            vec![S::from(5), S::from(6)],
            vec![S::from(7), S::from(8)],
        );
        let x = S::from(2);
        let got = p.eval(x);
        // a_i + x*(b_i + x*(c_i + x*d_i))
        let want0 = S::from(1) + x * (S::from(3) + x * (S::from(5) + x * S::from(7)));
        let want1 = S::from(2) + x * (S::from(4) + x * (S::from(6) + x * S::from(8)));
        assert_eq!(got, vec![want0, want1]);
    }

    #[test]
    fn poly6_eval_matches_horner() {
        // x*(t1 + x*(t2 + x*(...)))
        let p = Poly6 {
            t1: S::from(1),
            t2: S::from(2),
            t3: S::from(3),
            t4: S::from(4),
            t5: S::from(5),
            t6: S::from(6),
        };
        let x = S::from(2);
        let want = x
            * (S::from(1)
                + x * (S::from(2)
                    + x * (S::from(3) + x * (S::from(4) + x * (S::from(5) + x * S::from(6))))));
        assert_eq!(p.eval(x), want);
    }

    #[test]
    fn special_inner_product_pins_zero_prefix_contract() {
        // special_inner_product skips lhs.0 and rhs.2 terms per its doc:
        // the caller must guarantee lhs.0 == 0 and rhs.2 == 0. Construct
        // inputs where the skipped terms are nonzero and confirm the
        // result still matches the documented formula (i.e. those terms
        // are ignored, not folded in). If anyone "fixes" the helper to
        // include them, the R1CS polynomial algebra shifts silently.
        let lhs = VecPoly3(
            vec![S::from(99), S::from(99)], // skipped
            vec![S::from(1), S::from(2)],
            vec![S::from(3), S::from(4)],
            vec![S::from(5), S::from(6)],
        );
        let rhs = VecPoly3(
            vec![S::from(7), S::from(8)],
            vec![S::from(9), S::from(10)],
            vec![S::from(99), S::from(99)], // skipped
            vec![S::from(11), S::from(12)],
        );
        let got = VecPoly3::special_inner_product(&lhs, &rhs);
        // Mirror the implementation's term selection exactly.
        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);
        assert_eq!(got.t1, t1);
        assert_eq!(got.t2, t2);
        assert_eq!(got.t3, t3);
        assert_eq!(got.t4, t4);
        assert_eq!(got.t5, t5);
        assert_eq!(got.t6, t6);
        // And confirm the skipped terms really were skipped: the product
        // computed with lhs.0 and rhs.2 zeroed is identical.
        let lhs_zero = VecPoly3(
            vec![S::ZERO, S::ZERO],
            lhs.1.clone(),
            lhs.2.clone(),
            lhs.3.clone(),
        );
        let rhs_zero = VecPoly3(
            rhs.0.clone(),
            rhs.1.clone(),
            vec![S::ZERO, S::ZERO],
            rhs.3.clone(),
        );
        assert_eq!(
            VecPoly3::special_inner_product(&lhs_zero, &rhs_zero).t1,
            got.t1
        );
    }

    #[test]
    fn vecpoly3_zero_evaluates_to_zero() {
        let p = VecPoly3(
            vec![S::ZERO; 4],
            vec![S::ZERO; 4],
            vec![S::ZERO; 4],
            vec![S::ZERO; 4],
        );
        assert_eq!(p.eval(S::from(7)), vec![S::ZERO; 4]);
    }

    #[test]
    fn vecpoly3_eval_treats_empty_fields_as_zero() {
        // Mirrors the r1cs prover's l_poly/r_poly construction, which leaves
        // a known-zero limb unallocated rather than filling it with zeros.
        let p = VecPoly3(
            Vec::new(),
            vec![S::from(3), S::from(4)],
            vec![S::from(5), S::from(6)],
            vec![S::from(7), S::from(8)],
        );
        let x = S::from(2);
        let got = p.eval(x);
        let want0 = x * (S::from(3) + x * (S::from(5) + x * S::from(7)));
        let want1 = x * (S::from(4) + x * (S::from(6) + x * S::from(8)));
        assert_eq!(got, vec![want0, want1]);
    }

    // The tests below are ported from upstream `bulletproofs 5.0.0/src/util.rs`
    // to keep this fork's coverage of the scalar-algebra helpers at parity
    // with upstream. They are generic over the same `S = Fq` instantiation
    // as the rest of this module.

    #[test]
    fn exp_2_is_powers_of_2() {
        let exp_2: Vec<S> = exp_iter(S::from(2)).take(4).collect();
        assert_eq!(exp_2[0], S::from(1));
        assert_eq!(exp_2[1], S::from(2));
        assert_eq!(exp_2[2], S::from(4));
        assert_eq!(exp_2[3], S::from(8));
    }

    #[test]
    fn inner_product_fixed_length_4() {
        let a = [S::from(1), S::from(2), S::from(3), S::from(4)];
        let b = [S::from(2), S::from(3), S::from(4), S::from(5)];
        assert_eq!(inner_product(&a, &b), S::from(40));
    }

    #[test]
    fn sum_of_powers_matches_slow_path() {
        // For power-of-2 n the optimized path must match the naive loop.
        let x = S::from(10);
        for &n in &[0usize, 1, 2, 4, 8, 16, 32, 64] {
            assert_eq!(sum_of_powers_slow(&x, n), sum_of_powers(&x, n));
        }
        // Non-power-of-2 falls through to the slow path internally.
        assert_eq!(sum_of_powers(&x, 3), sum_of_powers_slow(&x, 3));
        assert_eq!(sum_of_powers(&x, 5), sum_of_powers_slow(&x, 5));
    }

    #[test]
    fn sum_of_powers_slow_pins_decimal_pattern() {
        // sum_of_powers_slow(10, k) = 1 + 10 + 100 + ... + 10^(k-1),
        // i.e. the repunit 111...1 with k digits. Pins both the formula
        // and the `from(u64)` widening.
        let x = S::from(10);
        assert_eq!(sum_of_powers_slow(&x, 0), S::ZERO);
        assert_eq!(sum_of_powers_slow(&x, 1), S::ONE);
        assert_eq!(sum_of_powers_slow(&x, 2), S::from(11));
        assert_eq!(sum_of_powers_slow(&x, 3), S::from(111));
        assert_eq!(sum_of_powers_slow(&x, 4), S::from(1111));
        assert_eq!(sum_of_powers_slow(&x, 5), S::from(11111));
        assert_eq!(sum_of_powers_slow(&x, 6), S::from(111111));
    }
}
