//! Deferred public-base multiplications, bound to their committed scalar bits.
//!
//! Every point is allocated in phase one. Finalization allocates selectors and
//! monic divisors, then registers one callback after Bulletproofs commits that
//! entire witness. Each multiplication has its own divisor equation: sharing
//! selectors never folds the dealer anchor, DH or hash-base obligations.
mod divisor;

use crate::driver::Backend;
use bulletproofs_cycle::{
    r1cs::{RandomizableConstraintSystem, RandomizedConstraintSystem},
    ConstraintSystem, Cycle, LinearCombination, R1CSError, Variable,
};
use ff::{Field, PrimeField};
use golden_core::{DkgGroup, Error, Result};
use group::Group;
use p3_maybe_rayon::prelude::*;
use std::{collections::BTreeMap, sync::Arc};

type Point<C> = <<C as Backend>::Dkg as DkgGroup>::Point;
type Lc<C> = LinearCombination<<C as Cycle>::Scalar>;
type Var<C> = Variable<<C as Cycle>::Scalar>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Affine<F: PrimeField> {
    pub x: F,
    pub y: F,
}

/// The coordinate adapter is the only curve-specific part of certification.
pub(crate) trait EcCurve: Backend {
    fn a() -> Self::Scalar;
    fn b() -> Self::Scalar;
    fn affine(point: &Point<Self>) -> Result<Affine<Self::Scalar>>;
    fn batch_affine(points: &[Point<Self>]) -> Result<Vec<Affine<Self::Scalar>>>;
    fn native_x<CS: ConstraintSystem<Self>>(
        cs: &mut CS,
        point: (Var<Self>, Var<Self>),
        witness: Option<&Point<Self>>,
    ) -> Result<Var<Self>>;
}

#[derive(Clone, Copy)]
pub(crate) struct ScalarRef(usize);
#[derive(Clone, Copy)]
pub(crate) struct PointRef(usize);

struct Scalar<C: EcCurve> {
    bits: Vec<Var<C>>,
    witness: Option<Vec<bool>>,
}
struct Operation<C: EcCurve> {
    base: Point<C>,
    scalar: ScalarRef,
    coordinates: (Var<C>, Var<C>),
    witness: Option<Point<C>>,
    native_x: Option<Var<C>>,
    expected: Vec<Point<C>>,
}

/// Collection and materialization cannot discharge an obligation. Only the
/// consuming `finalize` installs all multiplication certificates and equalities.
#[must_use = "finalize the engine to constrain its registered multiplications"]
pub(crate) struct Engine<C: EcCurve> {
    scalars: Vec<Scalar<C>>,
    operations: Vec<Operation<C>>,
}
impl<C: EcCurve> Engine<C> {
    pub fn new() -> Self {
        Self {
            scalars: Vec::new(),
            operations: Vec::new(),
        }
    }
    /// The caller supplies bits already constrained to a canonical scalar.
    pub fn scalar(&mut self, bits: Vec<Var<C>>, witness: Option<Vec<bool>>) -> Result<ScalarRef> {
        if bits.is_empty()
            || bits.len() > 257
            || witness
                .as_ref()
                .is_some_and(|values| values.len() != bits.len())
        {
            return Err(Error::InvalidProof);
        }
        let reference = ScalarRef(self.scalars.len());
        self.scalars.push(Scalar { bits, witness });
        Ok(reference)
    }
    pub fn mul<CS: ConstraintSystem<C>>(
        &mut self,
        cs: &mut CS,
        base: &Point<C>,
        scalar: ScalarRef,
    ) -> Result<PointRef> {
        let scalar_data = self.scalars.get(scalar.0).ok_or(Error::InvalidProof)?;
        if bool::from(base.is_identity()) {
            return Err(Error::InvalidProof);
        }
        let witness = scalar_data.witness.as_ref().map(|bits| {
            let value = bits
                .iter()
                .rev()
                .fold(<C::Dkg as DkgGroup>::Scalar::ZERO, |value, &bit| {
                    value.double() + <C::Dkg as DkgGroup>::Scalar::from(u64::from(bit))
                });
            *base * value
        });
        let affine = witness.as_ref().map(C::affine).transpose()?;
        let coordinates = allocate_point::<C, CS>(cs, affine).map_err(|_| Error::InvalidProof)?;
        let reference = PointRef(self.operations.len());
        self.operations.push(Operation {
            base: *base,
            scalar,
            coordinates,
            witness,
            native_x: None,
            expected: Vec::new(),
        });
        Ok(reference)
    }
    pub fn point_x<CS: ConstraintSystem<C>>(
        &mut self,
        cs: &mut CS,
        point: PointRef,
    ) -> Result<Var<C>> {
        let operation = self
            .operations
            .get_mut(point.0)
            .ok_or(Error::InvalidProof)?;
        if let Some(x) = operation.native_x {
            return Ok(x);
        }
        let x = C::native_x(cs, operation.coordinates, operation.witness.as_ref())?;
        operation.native_x = Some(x);
        Ok(x)
    }
    pub fn assert_equal(&mut self, point: PointRef, expected: &Point<C>) -> Result<()> {
        C::affine(expected)?;
        self.operations
            .get_mut(point.0)
            .ok_or(Error::InvalidProof)?
            .expected
            .push(*expected);
        Ok(())
    }
    pub fn finalize<CS: RandomizableConstraintSystem<C>>(self, cs: &mut CS) -> Result<()> {
        self.finalize_with_tables(cs, true)
    }
    fn finalize_with_tables<CS: RandomizableConstraintSystem<C>>(
        self,
        cs: &mut CS,
        parallel_tables: bool,
    ) -> Result<()> {
        let mut uses = vec![0usize; self.scalars.len()];
        for operation in &self.operations {
            uses[operation.scalar.0] += 1;
        }
        let widths = self
            .scalars
            .iter()
            .zip(&uses)
            .map(|(scalar, &count)| choose_width(scalar.bits.len(), count))
            .collect::<Vec<_>>();
        cs.transcript()
            .append_message(b"ec-engine", b"windowed-divisor/v1");
        cs.transcript()
            .append_u64(b"ec-scalars", self.scalars.len() as u64);
        cs.transcript()
            .append_u64(b"ec-operations", self.operations.len() as u64);
        let mut selections = Vec::with_capacity(self.scalars.len());
        for (scalar, &width) in self.scalars.iter().zip(&widths) {
            cs.transcript()
                .append_u64(b"ec-scalar-bits", scalar.bits.len() as u64);
            cs.transcript().append_u64(b"ec-window-width", width as u64);
            selections.push(selectors::<C, CS>(cs, &scalar.bits, width));
        }
        let mut prepared_tables =
            prepare_public_tables::<C>(&self.operations, &self.scalars, &widths, parallel_tables);
        let mut tables = BTreeMap::new();
        let mut relations = Vec::with_capacity(self.operations.len());
        for operation in self.operations {
            let scalar = &self.scalars[operation.scalar.0];
            let width = widths[operation.scalar.0];
            let key = (
                <C::Dkg as DkgGroup>::encode_point(&operation.base),
                scalar.bits.len(),
                width,
            );
            cs.transcript().append_message(b"ec-base", &key.0);
            cs.transcript()
                .append_u64(b"ec-scalar", operation.scalar.0 as u64);
            for expected in operation.expected {
                let expected = C::affine(&expected)?;
                cs.constrain(operation.coordinates.0 - expected.x);
                cs.constrain(operation.coordinates.1 - expected.y);
            }
            // Tiny scalars use a direct lookup, whose full cost is below ECIP.
            if scalar.bits.len() <= 4 {
                let mut candidates = Vec::with_capacity(1 << scalar.bits.len());
                // Zero is identity and has no affine encoding. The production
                // relation already rules it out; explicitly exclude this digit.
                let lookup = &selections[operation.scalar.0][0];
                cs.constrain(lookup[0].clone());
                for digit in 1..1u64 << scalar.bits.len() {
                    candidates.push(C::affine(
                        &(operation.base * <C::Dkg as DkgGroup>::Scalar::from(digit)),
                    )?);
                }
                for (coordinate, axis) in [
                    (operation.coordinates.0, false),
                    (operation.coordinates.1, true),
                ] {
                    let expected = candidates.iter().zip(&lookup[1..]).fold(
                        Lc::<C>::default(),
                        |sum, (point, select)| {
                            sum + select.clone() * if axis { point.y } else { point.x }
                        },
                    );
                    cs.constrain(coordinate - expected);
                }
                continue;
            }
            let table = match tables.entry(key) {
                std::collections::btree_map::Entry::Occupied(entry) => Arc::clone(entry.get()),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    // Consume results where the original lazy construction ran.
                    // Earlier assertions/witness failures retain precedence over
                    // failures of tables prepared for later operations.
                    let table = prepared_tables
                        .remove(entry.key())
                        .ok_or(Error::ProofOperationFailed)??;
                    Arc::clone(entry.insert(table))
                }
            };
            let witness = scalar
                .witness
                .as_ref()
                .zip(operation.witness.as_ref())
                .map(|(bits, output)| {
                    let mut roots = selected(&table, bits)?;
                    let output = C::affine(output)?;
                    roots.push(Affine {
                        x: output.x,
                        y: -output.y,
                    });
                    divisor::interpolate(&roots, C::a())
                })
                .transpose()?;
            let mut coefficients = Vec::with_capacity(table.windows.len() + 1);
            for index in 0..table.windows.len() {
                coefficients.push(Lc::<C>::from(
                    cs.allocate(witness.as_ref().map(|v| v[index]))
                        .map_err(|_| Error::InvalidProof)?,
                ));
            }
            coefficients.push(C::Scalar::ONE.into());
            relations.push(Relation {
                table,
                scalar: operation.scalar,
                coefficients,
                witness,
                coordinates: operation.coordinates,
                point: operation.witness.as_ref().map(C::affine).transpose()?,
            });
        }
        if relations.is_empty() {
            return Ok(());
        }
        cs.specify_randomized_constraints(move |cs| {
            let challenge = challenge::<C, _>(cs, &relations)?;
            for relation in relations {
                certify::<C, _>(cs, relation, &selections, &challenge)?;
            }
            Ok(())
        })
        .map_err(|_| Error::InvalidProof)
    }
}

type TableKey = (Vec<u8>, usize, usize);

/// Prepare each used public table once. Native work can run concurrently, but
/// result consumption, circuit allocations and proof transcript writes remain
/// in operation order. In particular, never short-circuit the parallel collect.
fn prepare_public_tables<C: EcCurve>(
    operations: &[Operation<C>],
    scalars: &[Scalar<C>],
    widths: &[usize],
    parallel: bool,
) -> BTreeMap<TableKey, Result<Arc<Table<C::Scalar>>>> {
    let mut seen = BTreeMap::new();
    let mut tasks = Vec::new();
    for operation in operations {
        let bits = scalars[operation.scalar.0].bits.len();
        if bits <= 4 {
            continue;
        }
        let key = (
            <C::Dkg as DkgGroup>::encode_point(&operation.base),
            bits,
            widths[operation.scalar.0],
        );
        if let std::collections::btree_map::Entry::Vacant(entry) = seen.entry(key) {
            tasks.push((entry.key().clone(), operation.base));
            entry.insert(());
        }
    }
    let prepare =
        |(key, base): &(TableKey, Point<C>)| prepare_table::<C>(base, key.1, key.2).map(Arc::new);
    let results = if parallel {
        tasks.par_iter().map(prepare).collect::<Vec<_>>()
    } else {
        tasks.iter().map(prepare).collect::<Vec<_>>()
    };
    tasks.into_iter().map(|(key, _)| key).zip(results).collect()
}

fn allocate_point<C: EcCurve, CS: ConstraintSystem<C>>(
    cs: &mut CS,
    point: Option<Affine<C::Scalar>>,
) -> core::result::Result<(Var<C>, Var<C>), R1CSError> {
    let (x, copy_x, x2) = cs.allocate_multiplier(point.map(|p| (p.x, p.x)))?;
    let (y, copy_y, y2) = cs.allocate_multiplier(point.map(|p| (p.y, p.y)))?;
    cs.constrain(x - copy_x);
    cs.constrain(y - copy_y);
    let x3 = cs.multiply(x.into(), x2.into()).2;
    cs.constrain(y2 - x3 - x * C::a() - C::b());
    Ok((x, y))
}

/// Scalar-group selector multipliers and divisor coefficient allocations per
/// operation, sharing the exact width choice used by circuit finalization.
pub(crate) fn scalar_cost(bits: usize, uses: usize) -> (usize, usize) {
    let width = choose_width(bits, uses);
    (selector_cost(bits, width), bits.div_ceil(width))
}

fn selector_cost(bits: usize, width: usize) -> usize {
    let complete = bits / width;
    let remainder = bits % width;
    complete
        .saturating_mul((1usize << width) - width - 1)
        .saturating_add((1usize << remainder) - remainder - 1)
}

/// Minimize selectors plus divisor-coefficient allocations over the complete
/// public scalar-use group. Canonical bit/reduction costs are common to all plans.
fn choose_width(bits: usize, operations: usize) -> usize {
    if bits <= 4 {
        return bits.max(1);
    }
    (2usize..=4)
        .min_by_key(|&width| {
            selector_cost(bits, width)
                .saturating_add(operations.saturating_mul(bits.div_ceil(width).div_ceil(2)))
        })
        .unwrap_or(2)
}
fn selectors<C: EcCurve, CS: ConstraintSystem<C>>(
    cs: &mut CS,
    bits: &[Var<C>],
    width: usize,
) -> Vec<Vec<Lc<C>>> {
    bits.chunks(width)
        .map(|chunk| {
            let count = 1usize << chunk.len();
            let mut monomials = vec![Lc::<C>::from(C::Scalar::ONE)];
            for mask in 1usize..count {
                let bit = mask.trailing_zeros() as usize;
                let rest = mask ^ (1 << bit);
                monomials.push(if rest == 0 {
                    chunk[bit].into()
                } else {
                    cs.multiply(chunk[bit].into(), monomials[rest].clone())
                        .2
                        .into()
                });
            }
            (0..count)
                .map(|digit| {
                    let mut subset = (count - 1) ^ digit;
                    let mut value = Lc::<C>::default();
                    loop {
                        let sign = if subset.count_ones().is_multiple_of(2) {
                            C::Scalar::ONE
                        } else {
                            -C::Scalar::ONE
                        };
                        value = value + monomials[digit | subset].clone() * sign;
                        if subset == 0 {
                            break;
                        }
                        subset = (subset - 1) & ((count - 1) ^ digit);
                    }
                    value
                })
                .collect()
        })
        .collect()
}
struct Table<F: PrimeField> {
    windows: Vec<Vec<Affine<F>>>,
    widths: Vec<usize>,
}
fn prepare_table<C: EcCurve>(
    base: &Point<C>,
    bits: usize,
    width: usize,
) -> Result<Table<C::Scalar>> {
    let widths = (0..bits)
        .step_by(width)
        .map(|start| width.min(bits - start))
        .collect::<Vec<_>>();
    for attempt in 0..16u64 {
        let mut transcript = merlin::Transcript::new(b"golden-dkg/ec-window-offset/v1");
        transcript.append_message(b"group", <C::Dkg as DkgGroup>::GROUP_ID.as_bytes());
        transcript.append_message(b"base", &<C::Dkg as DkgGroup>::encode_point(base));
        transcript.append_u64(b"bits", bits as u64);
        transcript.append_u64(b"width", width as u64);
        transcript.append_u64(b"attempt", attempt);
        let mut offsets = Vec::with_capacity(widths.len());
        let mut sum = Point::<C>::identity();
        let mut seed = [0u8; 64];
        transcript.challenge_bytes(b"offset-generator", &mut seed);
        let mut offset =
            <C::Dkg as DkgGroup>::hash_to_point(b"golden-dkg/ec-window-offset/v1", &seed)?;
        // ECIP needs finite candidates and a zero total shift, rather than
        // independent offsets. Doubling one hashed point avoids a hash per
        // window; repeated roots remain covered by exact multiplicities.
        for _ in 0..widths.len() - 1 {
            offsets.push(offset);
            sum += offset;
            offset = offset.double();
        }
        offsets.push(-sum);
        let mut power = *base;
        let mut candidates = Vec::new();
        let mut finite = true;
        for (&len, offset) in widths.iter().zip(offsets) {
            let mut point = offset;
            for _ in 0..1usize << len {
                if bool::from(point.is_identity()) {
                    finite = false;
                    break;
                }
                candidates.push(point);
                point += power;
            }
            for _ in 0..len {
                power = power.double();
            }
        }
        if finite {
            let mut coordinates = C::batch_affine(&candidates)?.into_iter();
            let windows = widths
                .iter()
                .map(|&len| coordinates.by_ref().take(1 << len).collect())
                .collect();
            return Ok(Table { windows, widths });
        }
    }
    Err(Error::ProofOperationFailed)
}
fn selected<F: PrimeField>(table: &Table<F>, bits: &[bool]) -> Result<Vec<Affine<F>>> {
    if bits.len() != table.widths.iter().sum::<usize>() {
        return Err(Error::InvalidProof);
    }
    let mut position = 0;
    Ok(table
        .windows
        .iter()
        .zip(&table.widths)
        .map(|(window, &len)| {
            let digit = (0..len)
                .map(|bit| usize::from(bits[position + bit]) << bit)
                .sum::<usize>();
            position += len;
            window[digit]
        })
        .collect())
}
struct Relation<C: EcCurve> {
    table: Arc<Table<C::Scalar>>,
    scalar: ScalarRef,
    coefficients: Vec<Lc<C>>,
    witness: Option<Vec<C::Scalar>>,
    coordinates: (Var<C>, Var<C>),
    point: Option<Affine<C::Scalar>>,
}
struct Challenge<F: PrimeField> {
    points: [Affine<F>; 3],
    alpha: [F; 3],
    lambda: F,
    mu: F,
}
fn challenge<C: EcCurve, CS: RandomizedConstraintSystem<C>>(
    cs: &mut CS,
    relations: &[Relation<C>],
) -> core::result::Result<Challenge<C::Scalar>, R1CSError> {
    for _ in 0..16 {
        let mut seed = [0u8; 64];
        cs.transcript()
            .challenge_bytes(b"ecip-line-point-0", &mut seed);
        let first = <C::Dkg as DkgGroup>::hash_to_point(b"golden-dkg/ecip-evaluation/v1", &seed)
            .map_err(|_| R1CSError::FormatError)?;
        cs.transcript()
            .challenge_bytes(b"ecip-line-point-1", &mut seed);
        let second = <C::Dkg as DkgGroup>::hash_to_point(b"golden-dkg/ecip-evaluation/v1", &seed)
            .map_err(|_| R1CSError::FormatError)?;
        let points = [
            C::affine(&first),
            C::affine(&second),
            C::affine(&(-(first + second))),
        ];
        let [Ok(first), Ok(second), Ok(third)] = points else {
            continue;
        };
        let Some(inverse) = Option::<C::Scalar>::from((second.x - first.x).invert()) else {
            continue;
        };
        let lambda = (second.y - first.y) * inverse;
        let mu = first.y - lambda * first.x;
        let points = [first, second, third];
        let denominators = points.map(|point| {
            C::Scalar::from(3) * point.x.square() + C::a() - lambda * point.y.double()
        });
        if denominators.iter().any(|v| bool::from(v.is_zero()))
            || points.iter().any(|p| bool::from(p.y.is_zero()))
            || relations.iter().any(|relation| {
                relation
                    .table
                    .windows
                    .iter()
                    .flatten()
                    .any(|p| bool::from((p.y - lambda * p.x - mu).is_zero()))
            })
        {
            continue;
        }
        let alpha = core::array::from_fn(|i| {
            points[i].y.double()
                * Option::<C::Scalar>::from(denominators[i].invert()).unwrap_or(C::Scalar::ZERO)
        });
        return Ok(Challenge {
            points,
            alpha,
            lambda,
            mu,
        });
    }
    Err(R1CSError::FormatError)
}
fn certify<C: EcCurve, CS: ConstraintSystem<C>>(
    cs: &mut CS,
    relation: Relation<C>,
    selections: &[Vec<Vec<Lc<C>>>],
    challenge: &Challenge<C::Scalar>,
) -> core::result::Result<(), R1CSError> {
    let mut equation = Lc::<C>::default();
    for index in 0..3 {
        let (values, derivatives) =
            divisor::basis(challenge.points[index], relation.coefficients.len(), C::a())
                .map_err(|_| R1CSError::FormatError)?;
        let value = relation
            .coefficients
            .iter()
            .zip(&values)
            .fold(Lc::<C>::default(), |sum, (c, v)| sum + c.clone() * *v);
        let derivative = relation
            .coefficients
            .iter()
            .zip(&derivatives)
            .fold(Lc::<C>::default(), |sum, (c, v)| sum + c.clone() * *v);
        let witness = relation
            .witness
            .as_ref()
            .map(|coefficients| {
                let value = coefficients
                    .iter()
                    .zip(&values)
                    .fold(C::Scalar::ZERO, |sum, (c, v)| sum + *c * v);
                let derivative = coefficients
                    .iter()
                    .zip(&derivatives)
                    .fold(C::Scalar::ZERO, |sum, (c, v)| sum + *c * v);
                Option::<C::Scalar>::from(value.invert())
                    .map(|inverse| (value, inverse, derivative))
                    .ok_or(R1CSError::FormatError)
            })
            .transpose()?;
        let (denominator, inverse, one) =
            cs.allocate_multiplier(witness.map(|(value, inverse, _)| (value, inverse)))?;
        cs.constrain(denominator - value);
        cs.constrain(one - C::Scalar::ONE);
        let ratio = cs.multiply(derivative, inverse.into()).2;
        equation = equation + ratio * challenge.alpha[index];
    }
    let denominator = -Lc::<C>::from(relation.coordinates.1)
        - relation.coordinates.0 * challenge.lambda
        - challenge.mu;
    let witness = relation
        .point
        .map(|point| {
            let denominator = -point.y - challenge.lambda * point.x - challenge.mu;
            Option::<C::Scalar>::from(denominator.invert())
                .map(|inverse| (-inverse, denominator))
                .ok_or(R1CSError::FormatError)
        })
        .transpose()?;
    let (reciprocal, den, minus_one) = cs.allocate_multiplier(witness)?;
    cs.constrain(den - denominator);
    cs.constrain(minus_one + C::Scalar::ONE);
    equation = equation - reciprocal;
    let mut reciprocals = relation
        .table
        .windows
        .iter()
        .flatten()
        .map(|point| point.y - challenge.lambda * point.x - challenge.mu)
        .collect::<Vec<_>>();
    C::scalar_batch_invert(&mut reciprocals);
    let mut position = 0;
    for (window, selection) in relation
        .table
        .windows
        .iter()
        .zip(&selections[relation.scalar.0])
    {
        for (_, selector) in window.iter().zip(selection) {
            equation = equation + selector.clone() * reciprocals[position];
            position += 1;
        }
    }
    cs.constrain(equation);
    Ok(())
}

#[cfg(test)]
mod tests;
