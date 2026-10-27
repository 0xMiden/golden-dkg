//! Checked shape arithmetic, pinned against the concrete circuits in tests.
use crate::driver::Backend;
use golden_core::{DkgConfig, Error, Result};

/// The only state carried between slots is an optional half multiplier. Therefore
/// allocation counts repeat after every two slots, including prefix/slot pairing.
pub(crate) fn multiplier_count<C: Backend>(slot_count: usize) -> Result<usize> {
    let counts = C::MULTIPLIER_COUNTS;
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
    let receivers = config.receiver_count();
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
    use crate::driver::Slot;
    use bulletproofs_cycle::{r1cs::Verifier, ConstraintSystem};
    use ff::Field;
    use golden_core::DkgGroup;
    use group::Group;
    use merlin::Transcript;

    let generator = <C::Dkg as DkgGroup>::Point::generator();
    for slots in [0, 1, 2, 3, 4, 5, 9, 18] {
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
    assert!(matches!(
        multiplier_count::<C>(usize::MAX),
        Err(Error::ProofOperationFailed)
    ));
}
