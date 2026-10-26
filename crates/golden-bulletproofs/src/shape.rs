//! Checked public-shape arithmetic, pinned against concrete circuit synthesis in tests.
use crate::{driver::Backend, ec};
use golden_core::{DkgConfig, DkgGroup, Error, Result};

/// Fixed costs of the curve-specific canonical scalar and coordinate gadgets.
#[derive(Clone, Copy)]
pub(crate) struct CircuitCosts {
    pub secret_multipliers: usize,
    pub reduction_multipliers: usize,
    pub reduction_allocations: usize,
    pub native_x_multipliers: usize,
    pub native_x_allocations: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub phase_one: usize,
    pub total: usize,
}

fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or(Error::ProofOperationFailed)
}
fn mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right).ok_or(Error::ProofOperationFailed)
}
fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0, add)
}

/// Count only the public plan: no curve arithmetic, tables or constraints.
/// Scalar groups share selectors, while each multiplication owns its divisor.
pub(crate) fn layout<C: Backend>(receivers: usize, sharings: usize) -> Result<Layout> {
    if sharings == 0 {
        return Err(Error::ProofOperationFailed);
    }
    if receivers == 0 {
        return Ok(Layout {
            phase_one: 0,
            total: 0,
        });
    }
    let costs = C::CIRCUIT_COSTS;
    let pads = mul(receivers, sharings)?;
    let hashes = mul(2, pads)?;
    let dealer_uses = add(receivers, 1)?;
    let operations = add(dealer_uses, mul(3, pads)?)?;
    let coordinates = add(receivers, hashes)?;
    let reductions = add(receivers, pads)?;
    let (dealer_selectors, dealer_windows) = ec::scalar_cost(257, dealer_uses);
    let (exponent_selectors, exponent_windows) = ec::scalar_cost(257, mul(2, sharings)?);
    let (pad_selectors, pad_windows) = ec::scalar_cost(257, 1);
    let coefficients = sum([
        mul(dealer_uses, dealer_windows)?,
        mul(hashes, exponent_windows)?,
        mul(pads, pad_windows)?,
    ])?;
    let selectors = sum([
        dealer_selectors,
        mul(receivers, exponent_selectors)?,
        mul(pads, pad_selectors)?,
    ])?;
    // Every EC point costs three multipliers. Each receiver also needs its
    // own nonzero-exponent multiplication, independently of the sharing count.
    let fixed = sum([
        costs.secret_multipliers,
        mul(3, operations)?,
        mul(costs.reduction_multipliers, reductions)?,
        receivers,
        mul(costs.native_x_multipliers, coordinates)?,
    ])?;
    // Unpaired allocations share multiplier halves across the entire first
    // phase, including divisor coefficients. The commitment flushes the last
    // half before each operation's seven randomized multipliers are allocated.
    let allocations = sum([
        1,
        mul(costs.reduction_allocations, reductions)?,
        receivers,
        mul(costs.native_x_allocations, coordinates)?,
        coefficients,
    ])?;
    let phase_one = sum([fixed, selectors, allocations.div_ceil(2)])?;
    Ok(Layout {
        phase_one,
        total: add(phase_one, mul(7, operations)?)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Shape {
    pub receivers: usize,
    pub sharings: usize,
}
impl Shape {
    pub fn of<G: DkgGroup>(config: &DkgConfig<G>) -> Self {
        Self {
            receivers: config.registry().len() - 1,
            sharings: config.instances().len(),
        }
    }
    pub fn layout<C: Backend>(self) -> Result<Layout> {
        layout::<C>(self.receivers, self.sharings)
    }
}
impl Layout {
    pub fn capacity(self) -> Result<usize> {
        if self.total == 0 {
            return Ok(0);
        }
        self.total
            .checked_next_power_of_two()
            .ok_or(Error::ProofOperationFailed)
    }
}

#[cfg(test)]
pub(crate) fn check_counted_layout<C: Backend>() {
    tests::check_counted_layout::<C>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::Slot;
    use bulletproofs_cycle::{
        r1cs::{Metrics, RandomizableConstraintSystem, RandomizedConstraintSystem},
        ConstraintSystem, Cycle, LinearCombination, R1CSError, Variable,
    };
    use ff::Field;
    use group::Group;
    use merlin::Transcript;

    struct Counter<C: Cycle> {
        transcript: Transcript,
        multipliers: usize,
        constraints: usize,
        pending: Option<usize>,
        phase_one: Option<usize>,
        marker: core::marker::PhantomData<C>,
    }
    impl<C: Cycle> Counter<C> {
        fn new() -> Self {
            Self {
                transcript: Transcript::new(b"golden-dkg/layout-counter/v1"),
                multipliers: 0,
                constraints: 0,
                pending: None,
                phase_one: None,
                marker: core::marker::PhantomData,
            }
        }
    }
    impl<C: Cycle> ConstraintSystem<C> for Counter<C> {
        fn transcript(&mut self) -> &mut Transcript {
            &mut self.transcript
        }
        fn multiply(
            &mut self,
            _: LinearCombination<C::Scalar>,
            _: LinearCombination<C::Scalar>,
        ) -> (
            Variable<C::Scalar>,
            Variable<C::Scalar>,
            Variable<C::Scalar>,
        ) {
            self.constraints += 2;
            let i = self.multipliers;
            self.multipliers += 1;
            (
                Variable::multiplier_left(i),
                Variable::multiplier_right(i),
                Variable::multiplier_output(i),
            )
        }
        fn allocate(
            &mut self,
            _: Option<C::Scalar>,
        ) -> core::result::Result<Variable<C::Scalar>, R1CSError> {
            Ok(match self.pending.take() {
                Some(i) => Variable::multiplier_right(i),
                None => {
                    let i = self.multipliers;
                    self.multipliers += 1;
                    self.pending = Some(i);
                    Variable::multiplier_left(i)
                }
            })
        }
        fn allocate_multiplier(
            &mut self,
            _: Option<(C::Scalar, C::Scalar)>,
        ) -> core::result::Result<
            (
                Variable<C::Scalar>,
                Variable<C::Scalar>,
                Variable<C::Scalar>,
            ),
            R1CSError,
        > {
            let i = self.multipliers;
            self.multipliers += 1;
            Ok((
                Variable::multiplier_left(i),
                Variable::multiplier_right(i),
                Variable::multiplier_output(i),
            ))
        }
        fn metrics(&self) -> Metrics {
            Metrics {
                multipliers: self.multipliers,
                constraints: self.constraints,
                phase_one_constraints: self.constraints,
                phase_two_constraints: 0,
            }
        }
        fn constrain(&mut self, _: LinearCombination<C::Scalar>) {
            self.constraints += 1;
        }
    }

    impl<C: Cycle> RandomizableConstraintSystem<C> for Counter<C> {
        type RandomizedCS = Self;
        fn specify_randomized_constraints<F>(
            &mut self,
            callback: F,
        ) -> core::result::Result<(), R1CSError>
        where
            F: 'static + FnOnce(&mut Self) -> core::result::Result<(), R1CSError>,
        {
            self.phase_one = Some(self.multipliers);
            // Match both production constraint systems at the commitment boundary.
            self.pending = None;
            callback(self)
        }
    }
    impl<C: Cycle> RandomizedConstraintSystem<C> for Counter<C> {
        fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar {
            let mut bytes = [0u8; 64];
            self.transcript.challenge_bytes(label, &mut bytes);
            bytes.iter().rev().fold(C::Scalar::ZERO, |value, &byte| {
                value * C::Scalar::from(256) + C::Scalar::from(u64::from(byte))
            })
        }
    }

    fn synthesized_layout<C: Backend>(receivers: usize, sharings: usize) -> Layout {
        let generator = <C::Dkg as DkgGroup>::Point::generator();
        let mut slots = Vec::new();
        for _ in 0..sharings {
            for receiver in 0..receivers {
                slots.push(Slot::<C::Dkg> {
                    peer: generator * <C::Dkg as DkgGroup>::Scalar::from((receiver + 2) as u64),
                    h1: generator,
                    h2: generator,
                    pad: generator,
                });
            }
        }
        let mut counter = Counter::<C>::new();
        C::build(&mut counter, &generator, &slots, None, C::Scalar::ONE).unwrap();
        Layout {
            phase_one: counter.phase_one.unwrap_or(counter.multipliers),
            total: counter.multipliers,
        }
    }

    pub(super) fn check_counted_layout<C: Backend>() {
        // Bracket dealer-width changes at 9 and 36 receivers, and exponent-
        // width changes at five and nineteen sharings. The counter executes
        // both phases of the real circuit without retaining its equations.
        for receivers in [1, 2, 3, 8, 9, 35, 36, 49, 99] {
            for sharings in [1, 2] {
                assert_eq!(
                    layout::<C>(receivers, sharings).unwrap(),
                    synthesized_layout::<C>(receivers, sharings),
                    "layout mismatch for {receivers} receivers and {sharings} sharings",
                );
            }
        }
        for sharings in [5, 19] {
            assert_eq!(
                layout::<C>(1, sharings).unwrap(),
                synthesized_layout::<C>(1, sharings),
                "layout mismatch for one receiver and {sharings} sharings",
            );
        }
        let singleton = layout::<C>(0, 1).unwrap();
        assert_eq!(
            singleton,
            Layout {
                phase_one: 0,
                total: 0
            }
        );
        assert_eq!(singleton.capacity().unwrap(), 0);
        for (receivers, sharings) in [
            (1, 0),
            (usize::MAX, 1),
            (1, usize::MAX),
            (usize::MAX / 2, 3),
        ] {
            assert_eq!(
                layout::<C>(receivers, sharings),
                Err(Error::ProofOperationFailed)
            );
        }
        assert_eq!(
            Layout {
                phase_one: usize::MAX,
                total: usize::MAX
            }
            .capacity(),
            Err(Error::ProofOperationFailed),
        );
        assert!(layout::<C>(2, 2).unwrap().total < 2 * layout::<C>(2, 1).unwrap().total);
    }
}
