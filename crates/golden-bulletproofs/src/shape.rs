//! Count the actual deterministic constraint layout without retaining equations.
use crate::driver::{Backend, Slot};
use bulletproofs_cycle::{
    r1cs::Metrics, ConstraintSystem, Cycle, LinearCombination, R1CSError, Variable,
};
use ff::Field;
use golden_core::{DkgConfig, DkgGroup, Error, Result};
use group::Group;
use merlin::Transcript;

struct Counter<C: Cycle> {
    transcript: Transcript,
    multipliers: usize,
    constraints: usize,
    pending: Option<usize>,
    marker: core::marker::PhantomData<C>,
}
impl<C: Cycle> Counter<C> {
    fn new() -> Self {
        Self {
            transcript: Transcript::new(b"golden-dkg/layout-counter/v1"),
            multipliers: 0,
            constraints: 0,
            pending: None,
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

/// The only state carried between slots is an optional half multiplier. Therefore
/// allocation counts repeat after every two slots, including prefix/slot pairing.
pub(crate) fn multiplier_count<C: Backend>(slot_count: usize) -> Result<usize> {
    let generator = <C::Dkg as DkgGroup>::Point::generator();
    let slot = Slot::<C::Dkg> {
        peer: generator,
        h1: generator,
        h2: generator,
        pad: generator,
    };
    let mut counts = [0usize; 3];
    for (n, count) in counts.iter_mut().enumerate() {
        let mut counter = Counter::<C>::new();
        let slots = (0..n)
            .map(|_| Slot::<C::Dkg> {
                peer: slot.peer,
                h1: slot.h1,
                h2: slot.h2,
                pad: slot.pad,
            })
            .collect::<Vec<_>>();
        C::build(&mut counter, &generator, &slots, None, C::Scalar::ONE)?;
        *count = counter.metrics().multipliers;
    }
    let pair = counts[2]
        .checked_sub(counts[0])
        .ok_or(Error::ProofOperationFailed)?;
    let odd = counts[1]
        .checked_sub(counts[0])
        .ok_or(Error::ProofOperationFailed)?;
    counts[0]
        .checked_add(
            (slot_count / 2)
                .checked_mul(pair)
                .ok_or(Error::ProofOperationFailed)?,
        )
        .and_then(|n| n.checked_add(if slot_count % 2 == 1 { odd } else { 0 }))
        .ok_or(Error::ProofOperationFailed)
}

pub(crate) fn required_capacity<C: Backend>(config: &DkgConfig<C::Dkg>) -> Result<usize> {
    let receivers = config
        .registry()
        .len()
        .checked_sub(1)
        .ok_or(Error::ProofOperationFailed)?;
    if receivers == 0 {
        return Ok(0);
    }
    let slots = config
        .instances()
        .len()
        .checked_mul(receivers)
        .ok_or(Error::ProofOperationFailed)?;
    multiplier_count::<C>(slots)?
        .checked_next_power_of_two()
        .ok_or(Error::ProofOperationFailed)
}

#[cfg(test)]
pub(crate) fn check_counted_layout<C: Backend>() {
    use bulletproofs_cycle::r1cs::Verifier;
    let generator = <C::Dkg as DkgGroup>::Point::generator();
    for slots in 0..=5 {
        let data = (0..slots)
            .map(|_| Slot::<C::Dkg> {
                peer: generator,
                h1: generator,
                h2: generator,
                pad: generator,
            })
            .collect::<Vec<_>>();
        let mut transcript = Transcript::new(b"golden-dkg/layout-parity-test/v1");
        let mut verifier = Verifier::<C, _>::new(&mut transcript);
        C::build(&mut verifier, &generator, &data, None, C::Scalar::ONE).unwrap();
        assert_eq!(
            multiplier_count::<C>(slots).unwrap(),
            verifier.metrics().multipliers
        );
    }
    assert!(multiplier_count::<C>(2).unwrap() < 2 * multiplier_count::<C>(1).unwrap());
}
