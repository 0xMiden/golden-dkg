//! Small real-proof tests exercise the engine without the native dealer checker.
use super::*;
use bulletproofs_cycle::{BulletproofGens, PedersenGens, Prover, Verifier};
use merlin::Transcript;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

const BITS: usize = 8;
const VALUE: u64 = 181;

fn bit_values(value: u64) -> Vec<bool> {
    (0..BITS).map(|bit| (value >> bit) & 1 != 0).collect()
}

/// Fix a small canonical scalar while retaining the production boolean wires.
fn scalar_bits<C: EcCurve, CS: ConstraintSystem<C>>(cs: &mut CS, prover: bool) -> Vec<Var<C>> {
    bit_values(VALUE)
        .into_iter()
        .map(|bit| {
            let value = C::Scalar::from(u64::from(bit));
            let (left, right, product) = cs
                .allocate_multiplier(prover.then_some((value, C::Scalar::ONE - value)))
                .unwrap();
            cs.constrain(right - (Lc::<C>::from(C::Scalar::ONE) - left));
            cs.constrain(product.into());
            cs.constrain(left - value);
            left
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlanAttack {
    Honest,
    OmitFinalize,
    OmitOperation,
    OmitAssertion,
    InconsistentBits,
    UnobservedInconsistentBits,
}

fn engine_plan<C: EcCurve, CS: RandomizableConstraintSystem<C>>(
    cs: &mut CS,
    prover: bool,
    attack: PlanAttack,
) -> Result<()> {
    let bits = scalar_bits::<C, _>(cs, prover);
    let mut engine = Engine::<C>::new();
    // In this case both public targets agree with the false native witness.
    // Only linkage to the original committed scalar bits can reject it.
    let native_value = if matches!(
        attack,
        PlanAttack::InconsistentBits | PlanAttack::UnobservedInconsistentBits
    ) {
        VALUE - 1
    } else {
        VALUE
    };
    let scalar = engine.scalar(bits, prover.then(|| bit_values(native_value)))?;
    let generator = Point::<C>::generator();
    let second = <C::Dkg as DkgGroup>::hash_to_point(b"ec-engine-test-base", b"second")?;
    for (index, base) in [generator, second].into_iter().enumerate() {
        if prover && attack == PlanAttack::OmitOperation && index == 1 {
            continue;
        }
        let expected = base * <C::Dkg as DkgGroup>::Scalar::from(native_value);
        let point = engine.mul(cs, &base, scalar)?;
        if attack == PlanAttack::UnobservedInconsistentBits {
            continue;
        }
        let x = engine.point_x(cs, point)?;
        let before = cs.metrics();
        assert_eq!(x, engine.point_x(cs, point)?);
        assert_eq!(before.multipliers, cs.metrics().multipliers);
        assert_eq!(before.constraints, cs.metrics().constraints);
        cs.constrain(x - <C::Dkg as DkgGroup>::affine_x(&expected)?);
        let target = if attack == PlanAttack::OmitAssertion && index == 0 {
            expected + base
        } else {
            expected
        };
        if !(prover && attack == PlanAttack::OmitAssertion && index == 0) {
            engine.assert_equal(point, &target)?;
        }
    }
    if prover && attack == PlanAttack::OmitFinalize {
        drop(engine);
        Ok(())
    } else {
        engine.finalize(cs)
    }
}

fn check_engine_plans<C: EcCurve>() {
    let pc = PedersenGens::<C>::default();
    let bp = BulletproofGens::<C>::new(256, 1);
    let mut rng = ChaCha20Rng::from_seed([72; 32]);
    for attack in [
        PlanAttack::Honest,
        PlanAttack::OmitFinalize,
        PlanAttack::OmitOperation,
        PlanAttack::OmitAssertion,
        PlanAttack::InconsistentBits,
        PlanAttack::UnobservedInconsistentBits,
    ] {
        let mut prover = Prover::<C, _>::new(&pc, Transcript::new(b"engine-plan"));
        engine_plan::<C, _>(&mut prover, true, attack).unwrap();
        let proof = prover.prove(&bp, &mut rng).unwrap();
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"engine-plan"));
        engine_plan::<C, _>(&mut verifier, false, attack).unwrap();
        let verdict = verifier
            .verification_equation(&proof, &pc, &bp, &mut rng)
            .and_then(|equation| equation.verify());
        assert_eq!(verdict.is_ok(), attack == PlanAttack::Honest, "{attack:?}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WitnessAttack {
    Honest,
    DivisorCoefficient,
    SubstituteX,
    NegateY,
}

/// Build one certificate directly so malicious assignments reach the verifier
/// instead of being rejected by honest native interpolation in `finalize`.
fn certificate<C: EcCurve, CS: RandomizableConstraintSystem<C>>(
    cs: &mut CS,
    prover: bool,
    attack: WitnessAttack,
) -> Result<()> {
    let bits = scalar_bits::<C, _>(cs, prover);
    let base = Point::<C>::generator();
    let width = choose_width(BITS, 1);
    let table = Arc::new(prepare_table::<C>(&base, BITS, width)?);
    let selections = vec![selectors::<C, _>(cs, &bits, width)];
    let product = C::affine(&(base * <C::Dkg as DkgGroup>::Scalar::from(VALUE)))?;
    let assigned = match attack {
        WitnessAttack::SubstituteX => Affine {
            x: product.x + C::Scalar::ONE,
            y: product.y,
        },
        WitnessAttack::NegateY => Affine {
            x: product.x,
            y: -product.y,
        },
        _ => product,
    };
    if attack == WitnessAttack::NegateY {
        // This attack preserves the curve equation and must fail the ECIP
        // output relation, independently of the on-curve allocation gadget.
        assert_eq!(
            assigned.y.square(),
            assigned.x.square() * assigned.x + assigned.x * C::a() + C::b()
        );
    }
    let coordinates =
        allocate_point::<C, _>(cs, prover.then_some(assigned)).map_err(|_| Error::InvalidProof)?;
    let witness = if prover {
        let mut roots = selected(&table, &bit_values(VALUE))?;
        roots.push(Affine {
            x: product.x,
            y: -product.y,
        });
        let mut coefficients = divisor::interpolate(&roots, C::a())?;
        if attack == WitnessAttack::DivisorCoefficient {
            coefficients[0] += C::Scalar::ONE;
        }
        Some(coefficients)
    } else {
        None
    };
    let mut coefficients = Vec::with_capacity(table.windows.len() + 1);
    for index in 0..table.windows.len() {
        coefficients.push(Lc::<C>::from(
            cs.allocate(witness.as_ref().map(|values| values[index]))
                .map_err(|_| Error::InvalidProof)?,
        ));
    }
    coefficients.push(C::Scalar::ONE.into());
    let relation = Relation::<C> {
        table,
        scalar: ScalarRef(0),
        coefficients,
        witness,
        coordinates,
        point: prover.then_some(assigned),
    };
    cs.specify_randomized_constraints(move |cs| {
        let evaluation = challenge::<C, _>(cs, core::slice::from_ref(&relation))?;
        certify::<C, _>(cs, relation, &selections, &evaluation)
    })
    .map_err(|_| Error::InvalidProof)
}

fn check_certificate_witnesses<C: EcCurve>() {
    let pc = PedersenGens::<C>::default();
    let bp = BulletproofGens::<C>::new(256, 1);
    let mut rng = ChaCha20Rng::from_seed([73; 32]);
    for attack in [
        WitnessAttack::Honest,
        WitnessAttack::DivisorCoefficient,
        WitnessAttack::SubstituteX,
        WitnessAttack::NegateY,
    ] {
        let mut prover = Prover::<C, _>::new(&pc, Transcript::new(b"certificate-witness"));
        certificate::<C, _>(&mut prover, true, attack).unwrap();
        let proof = prover.prove(&bp, &mut rng).unwrap();
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"certificate-witness"));
        certificate::<C, _>(&mut verifier, false, attack).unwrap();
        let verdict = verifier
            .verification_equation(&proof, &pc, &bp, &mut rng)
            .and_then(|equation| equation.verify());
        assert_eq!(
            verdict.is_ok(),
            attack == WitnessAttack::Honest,
            "{attack:?}"
        );
    }
}

#[cfg(feature = "secp-secq")]
#[test]
fn secp_shared_scalar_and_plan_obligations() {
    check_engine_plans::<crate::outer::secp::SecqCycle>();
}

#[cfg(feature = "secp-secq")]
#[test]
fn secp_rejects_malformed_certificate_witnesses() {
    check_certificate_witnesses::<crate::outer::secp::SecqCycle>();
}

#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn jubjub_shared_scalar_and_plan_obligations() {
    check_engine_plans::<crate::outer::cycle::Bls12_381G1Cycle>();
}

#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn jubjub_rejects_malformed_certificate_witnesses() {
    check_certificate_witnesses::<crate::outer::cycle::Bls12_381G1Cycle>();
}

/// Exercise duplicated public tables, shared selectors and the direct tiny-
/// scalar path together. The same seeded proof must cross-verify in both modes.
fn check_table_preparation_equivalence<C: EcCurve>() {
    fn plan<C: EcCurve, CS: RandomizableConstraintSystem<C>>(
        cs: &mut CS,
        prover: bool,
        parallel: bool,
    ) {
        let bits = scalar_bits::<C, _>(cs, prover);
        let mut engine = Engine::<C>::new();
        let tiny = engine
            .scalar(
                bits[..3].to_vec(),
                prover.then(|| bit_values(VALUE)[..3].to_vec()),
            )
            .unwrap();
        let scalar = engine
            .scalar(bits, prover.then(|| bit_values(VALUE)))
            .unwrap();
        let generator = Point::<C>::generator();
        let second =
            <C::Dkg as DkgGroup>::hash_to_point(b"ec-table-equivalence", b"second").unwrap();
        for base in [generator, second, generator] {
            let point = engine.mul(cs, &base, scalar).unwrap();
            let expected = base * <C::Dkg as DkgGroup>::Scalar::from(VALUE);
            engine.assert_equal(point, &expected).unwrap();
        }
        let point = engine.mul(cs, &generator, tiny).unwrap();
        engine
            .assert_equal(
                point,
                &(generator * <C::Dkg as DkgGroup>::Scalar::from(VALUE & 7)),
            )
            .unwrap();
        engine.finalize_with_tables(cs, parallel).unwrap();
    }
    let pc = PedersenGens::<C>::default();
    let bp = BulletproofGens::<C>::new(256, 1);
    let mut reference = None;
    for parallel in [false, true] {
        let mut rng = ChaCha20Rng::from_seed([74; 32]);
        let mut prover =
            Prover::<C, _>::new(&pc, Transcript::new(b"table-preparation-equivalence"));
        plan::<C, _>(&mut prover, true, parallel);
        let proof = prover.prove(&bp, &mut rng).unwrap();
        let encoded = proof.to_bytes();
        if let Some(reference) = &reference {
            assert_eq!(reference, &encoded);
        } else {
            reference = Some(encoded);
        }
        let mut verifier = Verifier::<C, _>::new(Transcript::new(b"table-preparation-equivalence"));
        plan::<C, _>(&mut verifier, false, !parallel);
        verifier
            .verification_equation(&proof, &pc, &bp, &mut rng)
            .unwrap()
            .verify()
            .unwrap();
    }
}

#[cfg(feature = "secp-secq")]
#[test]
fn secp_parallel_table_preparation_preserves_proof_bytes() {
    check_table_preparation_equivalence::<crate::outer::secp::SecqCycle>();
}

#[cfg(feature = "jubjub-bls12-381")]
#[test]
fn jubjub_parallel_table_preparation_preserves_proof_bytes() {
    check_table_preparation_equivalence::<crate::outer::cycle::Bls12_381G1Cycle>();
}
