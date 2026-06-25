//! Verifier constraint system, generic over a [`Cycle`].

#![allow(non_snake_case)]

use core::borrow::BorrowMut;
use core::iter;

use ff::Field;
use group::Group;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use super::linear_combination::VariableKind;
use super::{
    ConstraintSystem, LinearCombination, Metrics, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};
use crate::cycle::Cycle;
use crate::errors::R1CSError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::transcript::{
    append_point, append_scalar, challenge_scalar, validate_and_append_point, R1csDomain,
};
use crate::util::{exp_iter, inner_product};

/// Verifier constraint system.
pub struct Verifier<C: Cycle, T: BorrowMut<Transcript>> {
    transcript: T,
    constraints: Vec<LinearCombination<C::Scalar>>,
    num_vars: usize,
    V: Vec<C::Compressed>,
    deferred_constraints:
        Vec<Box<dyn FnOnce(&mut RandomizingVerifier<C, T>) -> Result<(), R1CSError>>>,
    pending_multiplier: Option<usize>,
}

/// Verifier in the randomization phase.
pub struct RandomizingVerifier<C: Cycle, T: BorrowMut<Transcript>> {
    verifier: Verifier<C, T>,
}

impl<C: Cycle, T: BorrowMut<Transcript>> ConstraintSystem<C> for Verifier<C, T> {
    fn transcript(&mut self) -> &mut Transcript {
        self.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        mut left: LinearCombination<C::Scalar>,
        mut right: LinearCombination<C::Scalar>,
    ) -> (
        Variable<C::Scalar>,
        Variable<C::Scalar>,
        Variable<C::Scalar>,
    ) {
        let var = self.num_vars;
        self.num_vars += 1;

        let l_var = Variable::multiplier_left(var);
        let r_var = Variable::multiplier_right(var);
        let o_var = Variable::multiplier_output(var);

        left.terms.push((l_var, -C::Scalar::ONE));
        right.terms.push((r_var, -C::Scalar::ONE));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(&mut self, _: Option<C::Scalar>) -> Result<Variable<C::Scalar>, R1CSError> {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Ok(Variable::multiplier_left(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                Ok(Variable::multiplier_right(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        _: Option<(C::Scalar, C::Scalar)>,
    ) -> Result<
        (
            Variable<C::Scalar>,
            Variable<C::Scalar>,
            Variable<C::Scalar>,
        ),
        R1CSError,
    > {
        let var = self.num_vars;
        self.num_vars += 1;
        Ok((
            Variable::multiplier_left(var),
            Variable::multiplier_right(var),
            Variable::multiplier_output(var),
        ))
    }

    fn metrics(&self) -> Metrics {
        Metrics {
            multipliers: self.num_vars,
            constraints: self.constraints.len() + self.deferred_constraints.len(),
            phase_one_constraints: self.constraints.len(),
            phase_two_constraints: self.deferred_constraints.len(),
        }
    }

    fn constrain(&mut self, lc: LinearCombination<C::Scalar>) {
        self.constraints.push(lc);
    }
}

impl<C: Cycle, T: BorrowMut<Transcript>> RandomizableConstraintSystem<C> for Verifier<C, T> {
    type RandomizedCS = RandomizingVerifier<C, T>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + FnOnce(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<C: Cycle, T: BorrowMut<Transcript>> ConstraintSystem<C> for RandomizingVerifier<C, T> {
    fn transcript(&mut self) -> &mut Transcript {
        self.verifier.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        left: LinearCombination<C::Scalar>,
        right: LinearCombination<C::Scalar>,
    ) -> (
        Variable<C::Scalar>,
        Variable<C::Scalar>,
        Variable<C::Scalar>,
    ) {
        self.verifier.multiply(left, right)
    }

    fn allocate(
        &mut self,
        assignment: Option<C::Scalar>,
    ) -> Result<Variable<C::Scalar>, R1CSError> {
        self.verifier.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(C::Scalar, C::Scalar)>,
    ) -> Result<
        (
            Variable<C::Scalar>,
            Variable<C::Scalar>,
            Variable<C::Scalar>,
        ),
        R1CSError,
    > {
        self.verifier.allocate_multiplier(input_assignments)
    }

    fn metrics(&self) -> Metrics {
        self.verifier.metrics()
    }

    fn constrain(&mut self, lc: LinearCombination<C::Scalar>) {
        self.verifier.constrain(lc)
    }
}

impl<C: Cycle, T: BorrowMut<Transcript>> RandomizedConstraintSystem<C>
    for RandomizingVerifier<C, T>
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar {
        challenge_scalar::<C>(self.verifier.transcript.borrow_mut(), label)
    }
}

impl<C: Cycle, T: BorrowMut<Transcript>> Verifier<C, T> {
    /// Construct a new verifier constraint system.
    pub fn new(mut transcript: T) -> Self {
        transcript.borrow_mut().r1cs_domain_sep();
        Verifier {
            transcript,
            num_vars: 0,
            V: Vec::new(),
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Commit to a high-level variable by supplying its Pedersen commitment.
    pub fn commit(&mut self, commitment: C::Compressed) -> Variable<C::Scalar> {
        let i = self.V.len();
        self.V.push(commitment.clone());
        append_point::<C>(self.transcript.borrow_mut(), b"V", &commitment);
        Variable::committed(i)
    }

    fn flattened_constraints(
        &self,
        z: &C::Scalar,
    ) -> (
        Vec<C::Scalar>,
        Vec<C::Scalar>,
        Vec<C::Scalar>,
        Vec<C::Scalar>,
        C::Scalar,
    ) {
        let n = self.num_vars;
        let m = self.V.len();

        let mut wL = vec![C::Scalar::ZERO; n];
        let mut wR = vec![C::Scalar::ZERO; n];
        let mut wO = vec![C::Scalar::ZERO; n];
        let mut wV = vec![C::Scalar::ZERO; m];
        let mut wc = C::Scalar::ZERO;

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var.kind {
                    VariableKind::MultiplierLeft(i) => wL[i] += exp_z * coeff,
                    VariableKind::MultiplierRight(i) => wR[i] += exp_z * coeff,
                    VariableKind::MultiplierOutput(i) => wO[i] += exp_z * coeff,
                    VariableKind::Committed(i) => wV[i] -= exp_z * coeff,
                    VariableKind::One => wc -= exp_z * coeff,
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV, wc)
    }

    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        self.pending_multiplier = None;
        if self.deferred_constraints.is_empty() {
            self.transcript.borrow_mut().r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.borrow_mut().r1cs_2phase_domain_sep();
            let mut callbacks = std::mem::take(&mut self.deferred_constraints);
            let mut wrapped = RandomizingVerifier { verifier: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped)?;
            }
            Ok(wrapped.verifier)
        }
    }

    /// Consume the verifier and check the proof.
    pub fn verify(
        self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), R1CSError> {
        self.verify_and_return_transcript(proof, pc_gens, bp_gens, rng)
            .map(|_| ())
    }

    /// Same as [`Verifier::verify`] but returns the transcript.
    pub fn verify_and_return_transcript(
        mut self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<T, R1CSError> {
        let transcript = self.transcript.borrow_mut();
        transcript.append_u64(b"m", self.V.len() as u64);

        // `n1` is the phase-1 multiplier count: the number of left/right
        // variable slots the prover allocated before its first call to
        // `specify_randomized_constraints`. Phase-2 multipliers (allocated
        // inside randomized callbacks) are appended after A_I1/A_O1/S1 are
        // bound to the transcript, so n2 = n - n1 below counts phase-2 slots.
        let n1 = self.num_vars;
        validate_and_append_point::<C>(transcript, b"A_I1", &proof.A_I1)?;
        validate_and_append_point::<C>(transcript, b"A_O1", &proof.A_O1)?;
        validate_and_append_point::<C>(transcript, b"S1", &proof.S1)?;

        self = self.create_randomized_constraints()?;

        // `n` is the total multiplier count after phase-2 callbacks have run.
        // The verifier's phase split is:
        //   n1 = phase-1 slots (committed in A_I1/A_O1/S1)
        //   n2 = phase-2 slots (committed in A_I2/A_O2/S2)
        //   pad = zero rows added so the IPP shape is a power of two
        // The IPP polynomials pad all three groups to `padded_n` with zeros;
        // `u_for_g` below marks phase-2 and pad rows with the IPP challenge
        // `u` so the verifier weights phase-1 vs phase-2 rows correctly.
        let n = self.num_vars;
        let n2 = n - n1;
        let padded_n = self.num_vars.next_power_of_two();
        let pad = padded_n - n;

        if bp_gens.gens_capacity < padded_n {
            return Err(R1CSError::InvalidGeneratorsLength);
        }
        let gens = bp_gens.share(0);

        {
            let transcript = self.transcript.borrow_mut();
            append_point::<C>(transcript, b"A_I2", &proof.A_I2);
            append_point::<C>(transcript, b"A_O2", &proof.A_O2);
            append_point::<C>(transcript, b"S2", &proof.S2);
        }

        let y = challenge_scalar::<C>(self.transcript.borrow_mut(), b"y");
        let z = challenge_scalar::<C>(self.transcript.borrow_mut(), b"z");

        {
            let transcript = self.transcript.borrow_mut();
            validate_and_append_point::<C>(transcript, b"T_1", &proof.T_1)?;
            validate_and_append_point::<C>(transcript, b"T_3", &proof.T_3)?;
            validate_and_append_point::<C>(transcript, b"T_4", &proof.T_4)?;
            validate_and_append_point::<C>(transcript, b"T_5", &proof.T_5)?;
            validate_and_append_point::<C>(transcript, b"T_6", &proof.T_6)?;
        }

        let u = challenge_scalar::<C>(self.transcript.borrow_mut(), b"u");
        let x = challenge_scalar::<C>(self.transcript.borrow_mut(), b"x");

        {
            let transcript = self.transcript.borrow_mut();
            append_scalar::<C>(transcript, b"t_x", &proof.t_x);
            append_scalar::<C>(transcript, b"t_x_blinding", &proof.t_x_blinding);
            append_scalar::<C>(transcript, b"e_blinding", &proof.e_blinding);
        }

        let w = challenge_scalar::<C>(self.transcript.borrow_mut(), b"w");

        let (wL, wR, wO, wV, wc) = self.flattened_constraints(&z);

        let (u_sq, u_inv_sq, s) = proof
            .ipp_proof
            .verification_scalars(padded_n, self.transcript.borrow_mut())
            .map_err(|_| R1CSError::VerificationError)?;

        let a = proof.ipp_proof.a;
        let b = proof.ipp_proof.b;

        let y_inv = C::scalar_invert(&y);
        let y_inv_vec: Vec<C::Scalar> = exp_iter(y_inv).take(padded_n).collect();
        let yneg_wR: Vec<C::Scalar> = wR
            .iter()
            .zip(y_inv_vec.iter())
            .map(|(wRi, ey)| *wRi * *ey)
            .chain(std::iter::repeat_n(C::Scalar::ZERO, pad))
            .collect();

        let delta = inner_product(&yneg_wR[0..n], &wL);

        // Phase-1 rows get weight 1, phase-2 and pad rows get weight `u`.
        // The pad rows are zero in `yneg_wR` and `s_owned`, so weighting them
        // by `u` is harmless; it just keeps the vector shape aligned with the
        // IPP generators.
        let u_for_g: Vec<C::Scalar> = std::iter::repeat_n(C::Scalar::ONE, n1)
            .chain(std::iter::repeat_n(u, n2 + pad))
            .collect();
        let u_for_h = u_for_g.clone();

        let s_owned: Vec<C::Scalar> = s.iter().take(padded_n).copied().collect();
        let s_rev: Vec<C::Scalar> = s.iter().rev().take(padded_n).copied().collect();

        let g_scalars: Vec<C::Scalar> = yneg_wR
            .iter()
            .zip(u_for_g.iter())
            .zip(s_owned.iter())
            .map(|((yneg_wRi, u_or_1), s_i)| *u_or_1 * (x * yneg_wRi - a * s_i))
            .collect();

        let wL_pad: Vec<C::Scalar> = wL
            .iter()
            .chain(std::iter::repeat_n(&C::Scalar::ZERO, pad))
            .copied()
            .collect();
        let wO_pad: Vec<C::Scalar> = wO
            .iter()
            .chain(std::iter::repeat_n(&C::Scalar::ZERO, pad))
            .copied()
            .collect();

        let h_scalars: Vec<C::Scalar> = y_inv_vec
            .iter()
            .zip(u_for_h.iter())
            .zip(s_rev.iter())
            .zip(wL_pad.iter())
            .zip(wO_pad.iter())
            .map(|((((y_inv_i, u_or_1), s_i_inv), wLi), wOi)| {
                *u_or_1 * (*y_inv_i * (x * wLi + wOi - b * s_i_inv) - C::Scalar::ONE)
            })
            .collect();

        let builder = self.transcript.borrow_mut().build_rng();
        let mut rng = builder.finalize(rng);
        let r = C::Scalar::random(&mut rng);

        let xx = x * x;
        let rxx = r * xx;
        let xxx = x * xx;

        let T_scalars = [r * x, rxx * x, rxx * xx, rxx * xxx, rxx * xx * xx];
        let T_points = [
            proof.T_1.clone(),
            proof.T_3.clone(),
            proof.T_4.clone(),
            proof.T_5.clone(),
            proof.T_6.clone(),
        ];

        let mega_scalars: Vec<C::Scalar> = iter::once(x)
            .chain(iter::once(xx))
            .chain(iter::once(xxx))
            .chain(iter::once(u * x))
            .chain(iter::once(u * xx))
            .chain(iter::once(u * xxx))
            .chain(wV.iter().map(|wVi| *wVi * rxx))
            .chain(T_scalars.iter().copied())
            .chain(iter::once(
                w * (proof.t_x - a * b) + r * (xx * (wc + delta) - proof.t_x),
            ))
            .chain(iter::once(-proof.e_blinding - r * proof.t_x_blinding))
            .chain(g_scalars.iter().copied())
            .chain(h_scalars.iter().copied())
            .chain(u_sq.iter().copied())
            .chain(u_inv_sq.iter().copied())
            .collect();

        let mega_points: Vec<Option<C::Point>> = iter::once(C::compressed_decompress(&proof.A_I1))
            .chain(iter::once(C::compressed_decompress(&proof.A_O1)))
            .chain(iter::once(C::compressed_decompress(&proof.S1)))
            .chain(iter::once(C::compressed_decompress(&proof.A_I2)))
            .chain(iter::once(C::compressed_decompress(&proof.A_O2)))
            .chain(iter::once(C::compressed_decompress(&proof.S2)))
            .chain(self.V.iter().map(C::compressed_decompress))
            .chain(T_points.iter().map(C::compressed_decompress))
            .chain(iter::once(Some(pc_gens.B)))
            .chain(iter::once(Some(pc_gens.B_blinding)))
            .chain(gens.G(padded_n).map(|p| Some(*p)))
            .chain(gens.H(padded_n).map(|p| Some(*p)))
            .chain(proof.ipp_proof.L_vec.iter().map(C::compressed_decompress))
            .chain(proof.ipp_proof.R_vec.iter().map(C::compressed_decompress))
            .collect();

        let mega_check = C::vartime_msm_optional(&mega_scalars, &mega_points)
            .ok_or(R1CSError::VerificationError)?;

        if !bool::from(mega_check.is_identity()) {
            return Err(R1CSError::VerificationError);
        }

        Ok(self.transcript)
    }
}
