//! Native witnesses for the windowed divisor certificate.
//!
//! The ordered basis has weights `0, 2, 3, ..., degree` and is
//! `1, x, -y, x², -xy, ...` on `y² = x³ + a*x + b`. A monic function of
//! weighted degree N has N coefficients in this basis. Interpolation fixes
//! the final coefficient to one and imposes every root with its multiplicity.
//!
//! The native constructor multiplies chord functions and cancels their known
//! vertical factors, keeping a polynomial throughout. This is the incremental
//! divisor construction of Eagen, §3.1.1 (https://eprint.iacr.org/2022/596),
//! specialized to adding one point at a time. It takes quadratic field work
//! and linear storage; a Gaussian implementation remains a test oracle.

use ff::PrimeField;
use golden_core::{Error, Result};

use super::Affine;

const MAX_DEGREE: usize = 258;

fn valid_degree<F: PrimeField>(degree: usize) -> bool {
    (1..=MAX_DEGREE).contains(&degree)
        // The real backends have large prime fields. Also reject dimensions
        // reaching the characteristic when this helper is used with a small
        // test field: multiplicities must remain exact integers.
        && (F::NUM_BITS > 9 || (1..=degree).all(|n| F::from(n as u64) != F::ZERO))
}

/// Basis values and derivatives with respect to x along the curve.
pub(super) fn basis<F: PrimeField>(
    point: Affine<F>,
    degree: usize,
    a: F,
) -> Result<(Vec<F>, Vec<F>)> {
    if !valid_degree::<F>(degree) {
        return Err(Error::InvalidProof);
    }
    let inverse_2y = Option::<F>::from(point.y.double().invert()).ok_or(Error::InvalidProof)?;
    let derivative_y = (F::from(3) * point.x.square() + a) * inverse_2y;
    let mut powers = vec![F::ONE; degree / 2 + 1];
    for power in 1..powers.len() {
        powers[power] = powers[power - 1] * point.x;
    }
    let mut values = Vec::with_capacity(degree);
    let mut derivatives = Vec::with_capacity(degree);
    values.push(F::ONE);
    derivatives.push(F::ZERO);
    for weight in 2..=degree {
        let has_y = weight % 2 != 0;
        let power = if has_y { (weight - 3) / 2 } else { weight / 2 };
        let derivative_x = if power == 0 {
            F::ZERO
        } else {
            F::from(power as u64) * powers[power - 1]
        };
        let (value, derivative) = if has_y {
            (
                -point.y * powers[power],
                -derivative_y * powers[power] - point.y * derivative_x,
            )
        } else {
            (powers[power], derivative_x)
        };
        values.push(value);
        derivatives.push(derivative);
    }
    Ok((values, derivatives))
}

fn curve_b<F: PrimeField>(roots: &[Affine<F>], a: F) -> Result<F> {
    let degree = roots.len();
    if degree < 3 || !valid_degree::<F>(degree) || F::from(6) == F::ZERO {
        return Err(Error::InvalidProof);
    }
    // The length check above establishes that the first root exists.
    let first = roots[0];
    let b = first.y.square() - first.x.square() * first.x - a * first.x;
    if F::from(4) * a.square() * a + F::from(27) * b.square() == F::ZERO {
        return Err(Error::InvalidProof);
    }
    for &root in roots {
        if root.y == F::ZERO || root.y.square() != root.x.square() * root.x + a * root.x + b {
            return Err(Error::InvalidProof);
        }
    }
    Ok(b)
}

fn trim<F: PrimeField>(polynomial: &mut Vec<F>) {
    while polynomial
        .last()
        .is_some_and(|coefficient| *coefficient == F::ZERO)
    {
        polynomial.pop();
    }
}

/// Multiply ascending polynomial coefficients by `constant + slope*x`.
fn multiply_linear<F: PrimeField>(polynomial: &[F], constant: F, slope: F) -> Vec<F> {
    if polynomial.is_empty() {
        return Vec::new();
    }
    let mut product = vec![F::ZERO; polynomial.len() + 1];
    for (index, &coefficient) in polynomial.iter().enumerate() {
        product[index] += coefficient * constant;
        product[index + 1] += coefficient * slope;
    }
    trim(&mut product);
    product
}

/// Divide by `x-root`, rejecting a nonzero remainder rather than dropping it.
fn divide_linear<F: PrimeField>(polynomial: &[F], root: F) -> Result<Vec<F>> {
    if polynomial.is_empty() {
        return Ok(Vec::new());
    }
    let degree = polynomial.len() - 1;
    if degree == 0 {
        return Err(Error::InvalidProof);
    }
    let mut quotient = vec![F::ZERO; degree];
    let mut carry = polynomial[degree];
    quotient[degree - 1] = carry;
    for index in (1..degree).rev() {
        carry = polynomial[index] + root * carry;
        quotient[index - 1] = carry;
    }
    if polynomial[0] + root * carry != F::ZERO {
        return Err(Error::InvalidProof);
    }
    trim(&mut quotient);
    Ok(quotient)
}

/// Construct the monic divisor through finite roots on one nonsingular curve.
///
/// After processing i roots with sum S, the maintained polynomial g has divisor
/// `sum(roots) + (-S) - (i+1)O` if S is finite, or `sum(roots) - iO` if S=O.
/// Adding P multiplies g by the chord through S and P, then divides by x-x(S).
/// Its two vertical roots cancel exactly, including tangent multiplicities.
/// Identity partial sums and opposite points have explicit vertical-line cases.
/// Each step is linear in i, so total field work is quadratic and storage linear.
pub(super) fn interpolate<F: PrimeField>(roots: &[Affine<F>], a: F) -> Result<Vec<F>> {
    let b = curve_b(roots, a)?;
    let mut sum: Option<Affine<F>> = None;
    // The coordinate-ring polynomial is even(x) - y*odd(x).
    let mut even = vec![F::ONE];
    let mut odd = Vec::new();
    for &point in roots {
        let Some(previous) = sum else {
            even = multiply_linear(&even, -point.x, F::ONE);
            odd = multiply_linear(&odd, -point.x, F::ONE);
            sum = Some(point);
            continue;
        };
        if previous.x == point.x && previous.y == -point.y {
            // The new root is exactly the closing root already present in g.
            sum = None;
            continue;
        }
        let (numerator, denominator) = if previous.x == point.x {
            if previous.y != point.y {
                return Err(Error::InvalidProof);
            }
            (F::from(3) * previous.x.square() + a, previous.y.double())
        } else {
            (point.y - previous.y, point.x - previous.x)
        };
        let slope =
            numerator * Option::<F>::from(denominator.invert()).ok_or(Error::InvalidProof)?;
        let constant = previous.y - slope * previous.x;

        // (even-y*odd)*(constant+slope*x-y), reduced by y²=x³+a*x+b.
        let mut next_even = multiply_linear(&even, constant, slope);
        if !odd.is_empty() {
            next_even.resize(next_even.len().max(odd.len() + 3), F::ZERO);
            for (index, &coefficient) in odd.iter().enumerate() {
                next_even[index] += b * coefficient;
                next_even[index + 1] += a * coefficient;
                next_even[index + 3] += coefficient;
            }
        }
        let mut next_odd = multiply_linear(&odd, constant, slope);
        next_odd.resize(next_odd.len().max(even.len()), F::ZERO);
        for (entry, &coefficient) in next_odd.iter_mut().zip(&even) {
            *entry += coefficient;
        }
        trim(&mut next_even);
        trim(&mut next_odd);
        even = divide_linear(&next_even, previous.x)?;
        odd = divide_linear(&next_odd, previous.x)?;
        let x = slope.square() - previous.x - point.x;
        sum = Some(Affine {
            x,
            y: slope * (previous.x - x) - previous.y,
        });
    }
    if sum.is_some() {
        return Err(Error::InvalidProof);
    }
    let degree = roots.len();
    let mut coefficients = vec![F::ZERO; degree];
    for (index, &coefficient) in even.iter().enumerate() {
        let weight = 2 * index;
        if weight > degree {
            return Err(Error::InvalidProof);
        }
        coefficients[weight.saturating_sub(1)] = coefficient;
    }
    for (index, &coefficient) in odd.iter().enumerate() {
        let weight = 2 * index + 3;
        if weight > degree {
            return Err(Error::InvalidProof);
        }
        coefficients[weight - 1] = coefficient;
    }
    let leading = coefficients[degree - 1];
    if leading != F::ONE {
        let inverse = Option::<F>::from(leading.invert()).ok_or(Error::InvalidProof)?;
        for coefficient in &mut coefficients {
            *coefficient *= inverse;
        }
    }
    Ok(coefficients)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expand the basis in the local parameter `t = x - point.x`.
    ///
    /// Coefficients of `t^j` impose order of vanishing without dividing by j!,
    /// so repeated roots retain their full multiplicity.
    fn local_rows<F: PrimeField>(
        point: Affine<F>,
        multiplicity: usize,
        degree: usize,
        a: F,
    ) -> Result<Vec<Vec<F>>> {
        let inverse_2y = Option::<F>::from(point.y.double().invert()).ok_or(Error::InvalidProof)?;
        let mut ys = vec![F::ZERO; multiplicity];
        ys[0] = point.y;
        for order in 1..multiplicity {
            let curve_coefficient = match order {
                1 => F::from(3) * point.x.square() + a,
                2 => F::from(3) * point.x,
                3 => F::ONE,
                _ => F::ZERO,
            };
            let cross = (1..order)
                .map(|j| ys[j] * ys[order - j])
                .fold(F::ZERO, |sum, term| sum + term);
            ys[order] = (curve_coefficient - cross) * inverse_2y;
        }
        let mut powers = vec![vec![F::ZERO; multiplicity]; degree / 2 + 1];
        powers[0][0] = F::ONE;
        for power in 1..powers.len() {
            for order in 0..multiplicity {
                powers[power][order] = powers[power - 1][order] * point.x
                    + if order == 0 {
                        F::ZERO
                    } else {
                        powers[power - 1][order - 1]
                    };
            }
        }
        let mut rows = Vec::with_capacity(multiplicity);
        for order in 0..multiplicity {
            let mut row = Vec::with_capacity(degree);
            row.push(if order == 0 { F::ONE } else { F::ZERO });
            for weight in 2..=degree {
                if weight % 2 == 0 {
                    row.push(powers[weight / 2][order]);
                } else {
                    let power = (weight - 3) / 2;
                    row.push(
                        -(0..=order)
                            .map(|j| ys[j] * powers[power][order - j])
                            .fold(F::ZERO, |sum, term| sum + term),
                    );
                }
            }
            rows.push(row);
        }
        Ok(rows)
    }

    /// Independent Hermite interpolation oracle for native constructor tests.
    fn interpolate_gaussian<F: PrimeField>(roots: &[Affine<F>], a: F) -> Result<Vec<F>> {
        curve_b(roots, a)?;
        let degree = roots.len();
        let mut groups: Vec<(Affine<F>, usize)> = Vec::with_capacity(degree);
        for &root in roots {
            if let Some((_, count)) = groups.iter_mut().find(|(point, _)| *point == root) {
                *count += 1;
            } else {
                groups.push((root, 1));
            }
        }
        let unknowns = degree - 1;
        let mut matrix = Vec::with_capacity(degree);
        for (root, multiplicity) in groups {
            for mut row in local_rows(root, multiplicity, degree, a)? {
                // Move the monic leading term to the right-hand side.
                row[unknowns] = -row[unknowns];
                matrix.push(row);
            }
        }
        // Forward elimination keeps work below each pivot; back substitution
        // avoids the redundant eliminations of Gauss-Jordan interpolation.
        for column in 0..unknowns {
            let pivot = (column..degree)
                .find(|&row| matrix[row][column] != F::ZERO)
                .ok_or(Error::InvalidProof)?;
            matrix.swap(column, pivot);
            let inverse =
                Option::<F>::from(matrix[column][column].invert()).ok_or(Error::InvalidProof)?;
            for value in &mut matrix[column][column..] {
                *value *= inverse;
            }
            let (processed, remaining) = matrix.split_at_mut(column + 1);
            let pivot_values = &processed[column][column..];
            for row in remaining {
                let factor = row[column];
                for (value, pivot_value) in row[column..].iter_mut().zip(pivot_values) {
                    *value -= factor * pivot_value;
                }
            }
        }
        if matrix[unknowns..]
            .iter()
            .flatten()
            .any(|value| *value != F::ZERO)
        {
            return Err(Error::InvalidProof);
        }
        let mut coefficients = vec![F::ZERO; degree];
        coefficients[unknowns] = F::ONE;
        for row in (0..unknowns).rev() {
            let mut value = matrix[row][unknowns];
            for (coefficient, entry) in coefficients[row + 1..unknowns]
                .iter()
                .zip(&matrix[row][row + 1..unknowns])
            {
                value -= *coefficient * entry;
            }
            coefficients[row] = value;
        }
        Ok(coefficients)
    }

    fn with_oracle<F: PrimeField>(roots: &[Affine<F>], a: F) -> Result<Vec<F>> {
        let result = interpolate(roots, a);
        assert_eq!(result, interpolate_gaussian(roots, a));
        result
    }

    fn dot<F: PrimeField>(left: &[F], right: &[F]) -> F {
        assert_eq!(left.len(), right.len());
        left.iter()
            .zip(right)
            .fold(F::ZERO, |sum, (a, b)| sum + *a * b)
    }

    fn add<F: PrimeField>(left: Affine<F>, right: Affine<F>, a: F) -> Affine<F> {
        let slope = if left == right {
            (F::from(3) * left.x.square() + a)
                * Option::<F>::from(left.y.double().invert()).unwrap()
        } else {
            (right.y - left.y) * Option::<F>::from((right.x - left.x).invert()).unwrap()
        };
        let x = slope.square() - left.x - right.x;
        Affine {
            x,
            y: slope * (left.x - x) - left.y,
        }
    }

    fn native_cases<F: PrimeField>() {
        let p = Affine {
            x: F::ZERO,
            y: F::ONE,
        };
        // P is a flex on y²=x³+1, so 3P=O. This exercises repeated
        // multiplicities above three, including mixed x/y basis terms.
        for multiplicity in [3, 6, 12] {
            let roots = vec![p; multiplicity];
            let coefficients = with_oracle(&roots, F::ZERO).unwrap();
            assert_eq!(coefficients.len(), multiplicity);
            assert_eq!(coefficients.last(), Some(&F::ONE));
            for row in local_rows(p, multiplicity, multiplicity, F::ZERO).unwrap() {
                assert_eq!(dot(&coefficients, &row), F::ZERO);
            }
        }
        assert_eq!(
            with_oracle(&[p; 3], F::ZERO).unwrap(),
            vec![F::ONE, F::ZERO, F::ONE]
        );
        assert_eq!(
            with_oracle(&[p; 6], F::ZERO).unwrap(),
            vec![F::from(2), F::ZERO, F::from(2), F::ZERO, F::ZERO, F::ONE],
        );
        let negative_p = Affine { x: p.x, y: -p.y };
        assert_eq!(
            with_oracle(&[p, negative_p, p, negative_p], F::ZERO).unwrap(),
            vec![F::ZERO, F::ZERO, F::ZERO, F::ONE],
        );
        assert_eq!(
            with_oracle(&[p, p, negative_p, negative_p], F::ZERO).unwrap(),
            vec![F::ZERO, F::ZERO, F::ZERO, F::ONE],
        );

        // Use a!=0 and close native point sums to test arbitrary finite
        // root multisets independently from the interpolation equations.
        let a = F::ONE;
        let twice_p = add(p, p, a);
        let minus_twice_p = Affine {
            x: twice_p.x,
            y: -twice_p.y,
        };
        let tangent = with_oracle(&[p, p, minus_twice_p], a).unwrap();
        assert_eq!(
            tangent,
            vec![
                F::ONE,
                Option::<F>::from(F::from(2).invert()).unwrap(),
                F::ONE
            ]
        );
        let (values, derivatives) = basis(p, tangent.len(), a).unwrap();
        assert_eq!(dot(&tangent, &values), F::ZERO);
        assert_eq!(dot(&tangent, &derivatives), F::ZERO);
        for count in (2..12).chain([32, 64]) {
            let mut roots = vec![p, twice_p];
            let mut sum = add(p, twice_p, a);
            let mut next = twice_p;
            for _ in 2..count {
                next = add(next, p, a);
                sum = add(sum, next, a);
                roots.push(next);
            }
            roots.push(Affine {
                x: sum.x,
                y: -sum.y,
            });
            let coefficients = with_oracle(&roots, a).unwrap();
            // A different processing order must produce the same canonical
            // polynomial, including when intermediate sums become identity.
            roots.reverse();
            assert_eq!(with_oracle(&roots, a).unwrap(), coefficients);
            for root in roots {
                let (values, _) = basis(root, coefficients.len(), a).unwrap();
                assert_eq!(dot(&coefficients, &values), F::ZERO);
            }
        }

        // Valid points whose sum is not zero cannot supply the certificate.
        assert!(with_oracle(&[p, p, twice_p], a).is_err());
        assert!(with_oracle(&[p; 3], a).is_err());
        // Malformed dimensions and incompatible curve geometry are rejected.
        assert!(with_oracle::<F>(&[], a).is_err());
        assert!(with_oracle(&[p; 2], a).is_err());
        assert!(with_oracle(&[p; MAX_DEGREE + 1], a).is_err());
        assert!(with_oracle(
            &[
                p,
                p,
                Affine {
                    x: p.x,
                    y: F::from(2)
                }
            ],
            a
        )
        .is_err());
        assert!(with_oracle(
            &[Affine {
                x: F::ZERO,
                y: F::ZERO
            }; 3],
            a
        )
        .is_err());
        assert!(with_oracle(
            &[Affine {
                x: F::ONE,
                y: F::ONE
            }; 3],
            F::ZERO
        )
        .is_err());
        assert!(basis(p, 0, a).is_err());
        assert!(basis(p, MAX_DEGREE + 1, a).is_err());
        assert!(basis(
            Affine {
                x: F::ZERO,
                y: F::ZERO
            },
            3,
            a
        )
        .is_err());
    }

    #[test]
    #[cfg(feature = "secp-secq")]
    fn secp_divisor_native_equivalence_and_rejections() {
        native_cases::<halo2curves::secp256k1::Fp>();
    }

    #[test]
    #[cfg(feature = "jubjub-bls12-381")]
    fn bls_divisor_native_equivalence_and_rejections() {
        native_cases::<bls12_381::Scalar>();
    }
}
