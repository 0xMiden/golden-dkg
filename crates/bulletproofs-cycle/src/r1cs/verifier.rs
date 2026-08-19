//! Verifier constraint system, generic over a [`Cycle`].

#![allow(non_snake_case)]

use core::borrow::BorrowMut;
use core::iter;

use alloc::sync::Arc;
use ff::Field;
use group::Group;
use merlin::Transcript;
use p3_maybe_rayon::prelude::*;
use rand_core::CryptoRngCore;

use super::linear_combination::{scaled_by_coefficient, VariableKind};
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

/// A fully prepared R1CS verification equation.
///
/// The Bulletproof and Pedersen generators are split from proof-specific
/// points so multiple equations over the same generators can share one MSM.
pub struct VerificationEquation<C: Cycle> {
    pedersen_scalars: [C::Scalar; 2],
    pedersen_points: [C::Point; 2],
    g_scalars: Vec<C::Scalar>,
    g_points: Arc<Vec<C::Affine>>,
    h_scalars: Vec<C::Scalar>,
    h_points: Arc<Vec<C::Affine>>,
    proof_scalars: Vec<C::Scalar>,
    proof_points: Vec<Option<C::Point>>,
}

impl<C: Cycle> VerificationEquation<C> {
    /// Check one prepared verification equation.
    pub fn verify(self) -> Result<(), R1CSError> {
        let g_len = self.g_scalars.len();
        let h_len = self.h_scalars.len();
        let scalars: Vec<C::Scalar> = self
            .pedersen_scalars
            .into_iter()
            .chain(self.proof_scalars)
            .collect();
        let points: Vec<Option<C::Point>> = self
            .pedersen_points
            .into_iter()
            .map(Some)
            .chain(self.proof_points)
            .collect();
        let mut check =
            C::vartime_msm_optional(&scalars, &points).ok_or(R1CSError::VerificationError)?;
        check += C::vartime_msm_affine(&self.g_scalars, &self.g_points[..g_len]);
        check += C::vartime_msm_affine(&self.h_scalars, &self.h_points[..h_len]);
        if !bool::from(check.is_identity()) {
            return Err(R1CSError::VerificationError);
        }
        Ok(())
    }

    /// Check several prepared equations with one MSM.
    ///
    /// `rng` supplies the nonzero coefficient for each equation. It must be
    /// seeded with fresh verifier entropy or from a domain-separated transcript
    /// that binds the complete ordered batch. Fixed, input-independent
    /// coefficients do not provide sound batch verification.
    pub fn verify_batch(
        equations: Vec<Self>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), R1CSError> {
        let first = equations.first().ok_or(R1CSError::VerificationError)?;
        let pedersen_points = first.pedersen_points;
        let mut pedersen_scalars = [C::Scalar::ZERO; 2];
        let mut g_scalars = Vec::new();
        let mut g_points = Arc::clone(&first.g_points);
        let mut h_scalars = Vec::new();
        let mut h_points = Arc::clone(&first.h_points);
        let mut proof_scalars = Vec::new();
        let mut proof_points = Vec::new();

        for equation in equations {
            if equation.pedersen_points != pedersen_points
                || equation.proof_scalars.len() != equation.proof_points.len()
            {
                return Err(R1CSError::VerificationError);
            }

            let coefficient = loop {
                let candidate = C::Scalar::random(&mut *rng);
                if !bool::from(candidate.is_zero()) {
                    break candidate;
                }
            };
            for (accumulator, scalar) in pedersen_scalars
                .iter_mut()
                .zip(equation.pedersen_scalars.iter())
            {
                *accumulator += coefficient * scalar;
            }
            Self::accumulate_generator_prefix(
                &mut g_scalars,
                &mut g_points,
                equation.g_scalars,
                equation.g_points,
                coefficient,
            )?;
            Self::accumulate_generator_prefix(
                &mut h_scalars,
                &mut h_points,
                equation.h_scalars,
                equation.h_points,
                coefficient,
            )?;
            proof_scalars.extend(
                equation
                    .proof_scalars
                    .into_iter()
                    .map(|scalar| coefficient * scalar),
            );
            proof_points.extend(equation.proof_points);
        }

        let g_len = g_scalars.len();
        let h_len = h_scalars.len();
        let scalars: Vec<C::Scalar> = pedersen_scalars.into_iter().chain(proof_scalars).collect();
        let points: Vec<Option<C::Point>> = pedersen_points
            .into_iter()
            .map(Some)
            .chain(proof_points)
            .collect();
        let mut check =
            C::vartime_msm_optional(&scalars, &points).ok_or(R1CSError::VerificationError)?;
        check += C::vartime_msm_affine(&g_scalars, &g_points[..g_len]);
        check += C::vartime_msm_affine(&h_scalars, &h_points[..h_len]);
        if !bool::from(check.is_identity()) {
            return Err(R1CSError::VerificationError);
        }
        Ok(())
    }

    fn accumulate_generator_prefix(
        accumulator_scalars: &mut Vec<C::Scalar>,
        accumulator_points: &mut Arc<Vec<C::Affine>>,
        scalars: Vec<C::Scalar>,
        points: Arc<Vec<C::Affine>>,
        coefficient: C::Scalar,
    ) -> Result<(), R1CSError> {
        if scalars.len() > points.len() {
            return Err(R1CSError::VerificationError);
        }
        let shared_len = accumulator_points.len().min(scalars.len());
        if accumulator_points[..shared_len] != points[..shared_len] {
            return Err(R1CSError::VerificationError);
        }
        if scalars.len() > accumulator_points.len() {
            *accumulator_points = points;
        }
        if scalars.len() > accumulator_scalars.len() {
            accumulator_scalars.resize(scalars.len(), C::Scalar::ZERO);
        }
        accumulator_scalars
            .par_iter_mut()
            .zip(scalars.into_par_iter())
            .for_each(|(accumulator, scalar)| *accumulator += coefficient * scalar);
        Ok(())
    }
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
                let weighted = scaled_by_coefficient(exp_z, coeff);
                match var.kind {
                    VariableKind::MultiplierLeft(i) => wL[i] += weighted,
                    VariableKind::MultiplierRight(i) => wR[i] += weighted,
                    VariableKind::MultiplierOutput(i) => wO[i] += weighted,
                    VariableKind::Committed(i) => wV[i] -= weighted,
                    VariableKind::One => wc -= weighted,
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
        self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<T, R1CSError> {
        let (equation, transcript) =
            self.verification_equation_and_return_transcript(proof, pc_gens, bp_gens, rng)?;
        equation.verify()?;
        Ok(transcript)
    }

    /// Prepare the proof's verification equation without running its MSM.
    pub fn verification_equation(
        self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<VerificationEquation<C>, R1CSError> {
        self.verification_equation_and_return_transcript(proof, pc_gens, bp_gens, rng)
            .map(|(equation, _)| equation)
    }

    /// Prepare the proof's verification equation without running its MSM.
    ///
    /// This retains the verifier transcript so callers that use a borrowed
    /// transcript receive the same state update as [`Verifier::verify`].
    pub fn verification_equation_and_return_transcript(
        mut self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(VerificationEquation<C>, T), R1CSError> {
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

        let proof_scalars: Vec<C::Scalar> = iter::once(x)
            .chain(iter::once(xx))
            .chain(iter::once(xxx))
            .chain(iter::once(u * x))
            .chain(iter::once(u * xx))
            .chain(iter::once(u * xxx))
            .chain(wV.iter().map(|wVi| *wVi * rxx))
            .chain(T_scalars.iter().copied())
            .chain(u_sq.iter().copied())
            .chain(u_inv_sq.iter().copied())
            .collect();

        let proof_points: Vec<Option<C::Point>> = iter::once(C::compressed_decompress(&proof.A_I1))
            .chain(iter::once(C::compressed_decompress(&proof.A_O1)))
            .chain(iter::once(C::compressed_decompress(&proof.S1)))
            .chain(iter::once(C::compressed_decompress(&proof.A_I2)))
            .chain(iter::once(C::compressed_decompress(&proof.A_O2)))
            .chain(iter::once(C::compressed_decompress(&proof.S2)))
            .chain(self.V.iter().map(C::compressed_decompress))
            .chain(T_points.iter().map(C::compressed_decompress))
            .chain(proof.ipp_proof.L_vec.iter().map(C::compressed_decompress))
            .chain(proof.ipp_proof.R_vec.iter().map(C::compressed_decompress))
            .collect();

        let pedersen_scalars = [
            w * (proof.t_x - a * b) + r * (xx * (wc + delta) - proof.t_x),
            -proof.e_blinding - r * proof.t_x_blinding,
        ];
        let pedersen_points = [pc_gens.B, pc_gens.B_blinding];
        let g_points = gens.shared_G();
        let h_points = gens.shared_H();

        Ok((
            VerificationEquation {
                pedersen_scalars,
                pedersen_points,
                g_scalars,
                g_points,
                h_scalars,
                h_points,
                proof_scalars,
                proof_points,
            },
            self.transcript,
        ))
    }
}
