//! Prover constraint system, generic over a [`Cycle`].

#![allow(non_snake_case)]

use core::borrow::BorrowMut;

use ff::Field;
use merlin::Transcript;
use p3_maybe_rayon::prelude::join;
use rand_core::CryptoRngCore;

use super::linear_combination::{scaled_by_coefficient, VariableKind};
use super::{
    ConstraintSystem, LinearCombination, Metrics, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};
use crate::cycle::Cycle;
use crate::errors::R1CSError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::{append_point, append_scalar, challenge_scalar, R1csDomain};
use crate::util::{exp_iter, VecPoly3};

/// Prover constraint system.
pub struct Prover<'g, C: Cycle, T: BorrowMut<Transcript>> {
    transcript: T,
    pc_gens: &'g PedersenGens<C>,
    constraints: Vec<LinearCombination<C::Scalar>>,
    secrets: Secrets<C>,
    deferred_constraints:
        Vec<Box<dyn FnOnce(&mut RandomizingProver<'g, C, T>) -> Result<(), R1CSError>>>,
    pending_multiplier: Option<usize>,
}

struct Secrets<C: Cycle> {
    a_L: Vec<C::Scalar>,
    a_R: Vec<C::Scalar>,
    a_O: Vec<C::Scalar>,
    v: Vec<C::Scalar>,
    v_blinding: Vec<C::Scalar>,
}

/// Prover in the randomization phase.
pub struct RandomizingProver<'g, C: Cycle, T: BorrowMut<Transcript>> {
    prover: Prover<'g, C, T>,
}

impl<C: Cycle> Secrets<C> {
    fn new() -> Self {
        Secrets {
            a_L: Vec::new(),
            a_R: Vec::new(),
            a_O: Vec::new(),
            v: Vec::new(),
            v_blinding: Vec::new(),
        }
    }
}

impl<'g, C: Cycle, T: BorrowMut<Transcript>> ConstraintSystem<C> for Prover<'g, C, T> {
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
        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = l * r;

        let l_var = Variable::multiplier_left(self.secrets.a_L.len());
        let r_var = Variable::multiplier_right(self.secrets.a_R.len());
        let o_var = Variable::multiplier_output(self.secrets.a_O.len());
        self.secrets.a_L.push(l);
        self.secrets.a_R.push(r);
        self.secrets.a_O.push(o);

        left.terms.push((l_var, -C::Scalar::ONE));
        right.terms.push((r_var, -C::Scalar::ONE));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(
        &mut self,
        assignment: Option<C::Scalar>,
    ) -> Result<Variable<C::Scalar>, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::MissingAssignment)?;
        match self.pending_multiplier {
            None => {
                let i = self.secrets.a_L.len();
                self.pending_multiplier = Some(i);
                self.secrets.a_L.push(scalar);
                self.secrets.a_R.push(C::Scalar::ZERO);
                self.secrets.a_O.push(C::Scalar::ZERO);
                Ok(Variable::multiplier_left(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.secrets.a_R[i] = scalar;
                self.secrets.a_O[i] = self.secrets.a_L[i] * self.secrets.a_R[i];
                Ok(Variable::multiplier_right(i))
            }
        }
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
        let (l, r) = input_assignments.ok_or(R1CSError::MissingAssignment)?;
        let o = l * r;

        let l_var = Variable::multiplier_left(self.secrets.a_L.len());
        let r_var = Variable::multiplier_right(self.secrets.a_R.len());
        let o_var = Variable::multiplier_output(self.secrets.a_O.len());
        self.secrets.a_L.push(l);
        self.secrets.a_R.push(r);
        self.secrets.a_O.push(o);

        Ok((l_var, r_var, o_var))
    }

    fn metrics(&self) -> Metrics {
        Metrics {
            multipliers: self.secrets.a_L.len(),
            constraints: self.constraints.len() + self.deferred_constraints.len(),
            phase_one_constraints: self.constraints.len(),
            phase_two_constraints: self.deferred_constraints.len(),
        }
    }

    fn constrain(&mut self, mut lc: LinearCombination<C::Scalar>) {
        // Constraints accumulate for the lifetime of the proof and are never
        // pushed to again once stored, so the `Vec` growth strategy's spare
        // capacity (typically ~1.5x the final term count) is pure overhead
        // across the hundreds of thousands of small per-constraint `terms`
        // allocations a real circuit produces.
        lc.terms.shrink_to_fit();
        self.constraints.push(lc);
    }
}

impl<'g, C: Cycle, T: BorrowMut<Transcript>> RandomizableConstraintSystem<C> for Prover<'g, C, T> {
    type RandomizedCS = RandomizingProver<'g, C, T>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + FnOnce(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<'g, C: Cycle, T: BorrowMut<Transcript>> ConstraintSystem<C> for RandomizingProver<'g, C, T> {
    fn transcript(&mut self) -> &mut Transcript {
        self.prover.transcript.borrow_mut()
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
        self.prover.multiply(left, right)
    }

    fn allocate(
        &mut self,
        assignment: Option<C::Scalar>,
    ) -> Result<Variable<C::Scalar>, R1CSError> {
        self.prover.allocate(assignment)
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
        self.prover.allocate_multiplier(input_assignments)
    }

    fn metrics(&self) -> Metrics {
        self.prover.metrics()
    }

    fn constrain(&mut self, lc: LinearCombination<C::Scalar>) {
        self.prover.constrain(lc)
    }
}

impl<'g, C: Cycle, T: BorrowMut<Transcript>> RandomizedConstraintSystem<C>
    for RandomizingProver<'g, C, T>
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> C::Scalar {
        challenge_scalar::<C>(self.prover.transcript.borrow_mut(), label)
    }
}

impl<'g, C: Cycle, T: BorrowMut<Transcript>> Prover<'g, C, T> {
    /// Construct a new prover constraint system.
    pub fn new(pc_gens: &'g PedersenGens<C>, mut transcript: T) -> Self {
        transcript.borrow_mut().r1cs_domain_sep();
        Prover {
            pc_gens,
            transcript,
            secrets: Secrets::new(),
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Commit to a high-level variable, appending the commitment to the
    /// transcript. Returns the compressed commitment and a [`Variable`].
    pub fn commit(
        &mut self,
        v: C::Scalar,
        v_blinding: C::Scalar,
    ) -> (C::Compressed, Variable<C::Scalar>) {
        let i = self.secrets.v.len();
        self.secrets.v.push(v);
        self.secrets.v_blinding.push(v_blinding);
        let V = C::point_compress(&self.pc_gens.commit(v, v_blinding));
        append_point::<C>(self.transcript.borrow_mut(), b"V", &V);
        (V, Variable::committed(i))
    }

    fn flattened_constraints(
        &self,
        z: &C::Scalar,
    ) -> (
        Vec<C::Scalar>,
        Vec<C::Scalar>,
        Vec<C::Scalar>,
        Vec<C::Scalar>,
    ) {
        let n = self.secrets.a_L.len();
        let m = self.secrets.v.len();

        let mut wL = vec![C::Scalar::ZERO; n];
        let mut wR = vec![C::Scalar::ZERO; n];
        let mut wO = vec![C::Scalar::ZERO; n];
        let mut wV = vec![C::Scalar::ZERO; m];

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                let weighted = scaled_by_coefficient(exp_z, coeff);
                match var.kind {
                    VariableKind::MultiplierLeft(i) => wL[i] += weighted,
                    VariableKind::MultiplierRight(i) => wR[i] += weighted,
                    VariableKind::MultiplierOutput(i) => wO[i] += weighted,
                    VariableKind::Committed(i) => wV[i] -= weighted,
                    VariableKind::One => {}
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV)
    }

    /// Evaluate a linear combination against the prover's secret assignments.
    fn eval(&self, lc: &LinearCombination<C::Scalar>) -> C::Scalar {
        let mut acc = C::Scalar::ZERO;
        for (var, coeff) in &lc.terms {
            let val = match var.kind {
                VariableKind::MultiplierLeft(i) => self.secrets.a_L[i],
                VariableKind::MultiplierRight(i) => self.secrets.a_R[i],
                VariableKind::MultiplierOutput(i) => self.secrets.a_O[i],
                VariableKind::Committed(i) => self.secrets.v[i],
                VariableKind::One => C::Scalar::ONE,
            };
            acc += *coeff * val;
        }
        acc
    }

    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        // Drop any half-allocated multiplier's continuation state. When the
        // first `allocate` of a pair runs, `a_L`, `a_R`, and `a_O` already
        // get a new entry with `a_R[i] = 0` and `a_O[i] = 0`. Clearing
        // `pending_multiplier` does not roll those back: the dangling
        // multiplier stays in the proof state with zero right and output
        // assignments. The only thing discarded here is the bookkeeping
        // that would let a future `allocate` complete the pair by writing
        // the right-wire value into `a_R[i]`. The dream audit flagged this
        // as silent; it is, but anything louder (returning an error on a
        // dangling pending_multiplier) would reject proofs that today
        // succeed for callers that happen to never allocate again. Treat
        // this comment as the contract: do not rely on a pending multiplier
        // surviving across `create_randomized_constraints`, and do not
        // assume `pending_multiplier == None` implies all multipliers are
        // fully populated.
        self.pending_multiplier = None;
        if self.deferred_constraints.is_empty() {
            self.transcript.borrow_mut().r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.borrow_mut().r1cs_2phase_domain_sep();
            let mut callbacks = std::mem::take(&mut self.deferred_constraints);
            let mut wrapped = RandomizingProver { prover: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped)?;
            }
            Ok(wrapped.prover)
        }
    }

    /// Consume the constraint system and produce a proof.
    pub fn prove(
        self,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<R1CSProof<C>, R1CSError> {
        self.prove_and_return_transcript(bp_gens, rng)
            .map(|(proof, _)| proof)
    }

    /// Consume the constraint system and produce a proof, returning the
    /// transcript passed into [`Prover::new`].
    pub fn prove_and_return_transcript(
        mut self,
        bp_gens: &BulletproofGens<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(R1CSProof<C>, T), R1CSError> {
        self.transcript
            .borrow_mut()
            .append_u64(b"m", self.secrets.v.len() as u64);

        // Build the prover RNG by reseeding the transcript RNG with each
        // committed-value blinding. The dream audit flagged the order here
        // (RNG finalized before A_I1/A_O1/S1 are appended) as suspicious; it
        // is in fact the standard Bulletproofs pattern and preserves
        // Fiat-Shamir binding. The RNG only draws the blindings for
        // A_I1/A_O1/S1; those commitments are then appended to the
        // transcript below, and the verifier challenges y/z (and later u/x)
        // are derived *after* the append, so the commitments bind the
        // challenges despite not seeding their own blindings. If A_I1 et al
        // fed the RNG that drew their own blindings, the prover could grind
        // them; the order below prevents that.
        let mut builder = self.transcript.borrow_mut().build_rng();
        for v_b in &self.secrets.v_blinding {
            builder = builder.rekey_with_witness_bytes(b"v_blinding", &C::scalar_to_canonical(v_b));
        }
        let mut rng = builder.finalize(rng);

        let n1 = self.secrets.a_L.len();
        if bp_gens.gens_capacity < n1 {
            return Err(R1CSError::InvalidGeneratorsLength);
        }
        let gens = bp_gens.share(0);

        let i_blinding1 = C::Scalar::random(&mut rng);
        let o_blinding1 = C::Scalar::random(&mut rng);
        let s_blinding1 = C::Scalar::random(&mut rng);

        let s_L1: Vec<C::Scalar> = (0..n1).map(|_| C::Scalar::random(&mut rng)).collect();
        let s_R1: Vec<C::Scalar> = (0..n1).map(|_| C::Scalar::random(&mut rng)).collect();

        let g_arc = gens.shared_G();
        let h_arc = gens.shared_H();
        let g_points = &g_arc[..n1];
        let h_points = &h_arc[..n1];
        let mut gh_points = Vec::with_capacity(2 * n1);
        gh_points.extend(g_points.iter().copied());
        gh_points.extend(h_points.iter().copied());

        let ((i_commit1, o_commit1), s_commit1) = join(
            || {
                join(
                    || {
                        let mut scalars = Vec::with_capacity(2 * n1);
                        scalars.extend(self.secrets.a_L.iter().copied());
                        scalars.extend(self.secrets.a_R.iter().copied());
                        C::vartime_msm_affine(&scalars, &gh_points)
                            + self.pc_gens.B_blinding * i_blinding1
                    },
                    || {
                        C::vartime_msm_affine(&self.secrets.a_O, g_points)
                            + self.pc_gens.B_blinding * o_blinding1
                    },
                )
            },
            || {
                let mut scalars = Vec::with_capacity(2 * n1);
                scalars.extend(s_L1.iter().copied());
                scalars.extend(s_R1.iter().copied());
                C::vartime_msm_affine(&scalars, &gh_points) + self.pc_gens.B_blinding * s_blinding1
            },
        );
        let A_I1 = C::point_compress(&i_commit1);
        let A_O1 = C::point_compress(&o_commit1);
        let S1 = C::point_compress(&s_commit1);

        {
            let transcript = self.transcript.borrow_mut();
            append_point::<C>(transcript, b"A_I1", &A_I1);
            append_point::<C>(transcript, b"A_O1", &A_O1);
            append_point::<C>(transcript, b"S1", &S1);
        }

        self = self.create_randomized_constraints()?;

        let n = self.secrets.a_L.len();
        let n2 = n - n1;
        let padded_n = n.next_power_of_two();
        let pad = padded_n - n;

        if bp_gens.gens_capacity < padded_n {
            return Err(R1CSError::InvalidGeneratorsLength);
        }

        let has_2nd_phase = n2 > 0;
        let (i_blinding2, o_blinding2, s_blinding2) = if has_2nd_phase {
            (
                C::Scalar::random(&mut rng),
                C::Scalar::random(&mut rng),
                C::Scalar::random(&mut rng),
            )
        } else {
            (C::Scalar::ZERO, C::Scalar::ZERO, C::Scalar::ZERO)
        };

        let s_L2: Vec<C::Scalar> = (0..n2).map(|_| C::Scalar::random(&mut rng)).collect();
        let s_R2: Vec<C::Scalar> = (0..n2).map(|_| C::Scalar::random(&mut rng)).collect();

        let (A_I2, A_O2, S2) = if has_2nd_phase {
            let gens = bp_gens.share(0);
            let g_arc = gens.shared_G();
            let h_arc = gens.shared_H();
            let g_tail = &g_arc[n1..n];
            let h_tail = &h_arc[n1..n];
            let mut gh_tail = Vec::with_capacity(2 * n2);
            gh_tail.extend(g_tail.iter().copied());
            gh_tail.extend(h_tail.iter().copied());

            let ((i_commit2, o_commit2), s_commit2) = join(
                || {
                    join(
                        || {
                            let mut scalars = Vec::with_capacity(2 * n2);
                            scalars.extend(self.secrets.a_L.iter().skip(n1).copied());
                            scalars.extend(self.secrets.a_R.iter().skip(n1).copied());
                            C::vartime_msm_affine(&scalars, &gh_tail)
                                + self.pc_gens.B_blinding * i_blinding2
                        },
                        || {
                            C::vartime_msm_affine(&self.secrets.a_O[n1..], g_tail)
                                + self.pc_gens.B_blinding * o_blinding2
                        },
                    )
                },
                || {
                    let mut scalars = Vec::with_capacity(2 * n2);
                    scalars.extend(s_L2.iter().copied());
                    scalars.extend(s_R2.iter().copied());
                    C::vartime_msm_affine(&scalars, &gh_tail)
                        + self.pc_gens.B_blinding * s_blinding2
                },
            );

            (
                C::point_compress(&i_commit2),
                C::point_compress(&o_commit2),
                C::point_compress(&s_commit2),
            )
        } else {
            (
                C::compressed_identity(),
                C::compressed_identity(),
                C::compressed_identity(),
            )
        };

        {
            let transcript = self.transcript.borrow_mut();
            append_point::<C>(transcript, b"A_I2", &A_I2);
            append_point::<C>(transcript, b"A_O2", &A_O2);
            append_point::<C>(transcript, b"S2", &S2);
        }

        let y = challenge_scalar::<C>(self.transcript.borrow_mut(), b"y");
        let z = challenge_scalar::<C>(self.transcript.borrow_mut(), b"z");

        let (wL, wR, wO, wV) = self.flattened_constraints(&z);

        // `l_poly`'s constant term and `r_poly`'s quadratic term are never
        // written below (`special_inner_product`'s doc contract already
        // assumes as much) — leave them unallocated instead of paying for
        // two more full-length zero-filled `Vec`s.
        let zeros = || vec![C::Scalar::ZERO; n];
        let mut l_poly = VecPoly3(Vec::new(), zeros(), zeros(), zeros());
        let mut r_poly = VecPoly3(zeros(), zeros(), Vec::new(), zeros());

        let mut exp_y = C::Scalar::ONE;
        let y_inv = C::scalar_invert(&y);
        let exp_y_inv: Vec<C::Scalar> = exp_iter(y_inv).take(padded_n).collect();

        let sLsR = s_L1
            .iter()
            .chain(s_L2.iter())
            .zip(s_R1.iter().chain(s_R2.iter()));
        for (i, (sl, sr)) in sLsR.enumerate() {
            l_poly.1[i] = self.secrets.a_L[i] + exp_y_inv[i] * wR[i];
            l_poly.2[i] = self.secrets.a_O[i];
            l_poly.3[i] = *sl;
            r_poly.0[i] = wO[i] - exp_y;
            r_poly.1[i] = exp_y * self.secrets.a_R[i] + wL[i];
            r_poly.3[i] = exp_y * sr;
            exp_y *= y;
        }

        let t_poly = VecPoly3::special_inner_product(&l_poly, &r_poly);

        let t_1_blinding = C::Scalar::random(&mut rng);
        let t_3_blinding = C::Scalar::random(&mut rng);
        let t_4_blinding = C::Scalar::random(&mut rng);
        let t_5_blinding = C::Scalar::random(&mut rng);
        let t_6_blinding = C::Scalar::random(&mut rng);

        let T_1 = C::point_compress(&self.pc_gens.commit(t_poly.t1, t_1_blinding));
        let T_3 = C::point_compress(&self.pc_gens.commit(t_poly.t3, t_3_blinding));
        let T_4 = C::point_compress(&self.pc_gens.commit(t_poly.t4, t_4_blinding));
        let T_5 = C::point_compress(&self.pc_gens.commit(t_poly.t5, t_5_blinding));
        let T_6 = C::point_compress(&self.pc_gens.commit(t_poly.t6, t_6_blinding));

        {
            let transcript = self.transcript.borrow_mut();
            append_point::<C>(transcript, b"T_1", &T_1);
            append_point::<C>(transcript, b"T_3", &T_3);
            append_point::<C>(transcript, b"T_4", &T_4);
            append_point::<C>(transcript, b"T_5", &T_5);
            append_point::<C>(transcript, b"T_6", &T_6);
        }

        let u = challenge_scalar::<C>(self.transcript.borrow_mut(), b"u");
        let x = challenge_scalar::<C>(self.transcript.borrow_mut(), b"x");

        let t_2_blinding: C::Scalar = wV
            .iter()
            .zip(self.secrets.v_blinding.iter())
            .map(|(c, v_b)| *c * *v_b)
            .fold(C::Scalar::ZERO, |a, b| a + b);

        let t_x = t_poly.eval(x);
        let t_x_blinding = {
            let x2 = x * x;
            let x3 = x2 * x;
            x * (t_1_blinding
                + x * t_2_blinding
                + x2 * t_3_blinding
                + x3 * t_4_blinding
                + x3 * x * t_5_blinding
                + x3 * x2 * t_6_blinding)
        };
        let mut l_vec = l_poly.eval(x);
        l_vec.resize(padded_n, C::Scalar::ZERO);

        let mut r_vec = r_poly.eval(x);
        r_vec.resize(padded_n, C::Scalar::ZERO);

        for slot in r_vec.iter_mut().skip(n) {
            *slot = -exp_y;
            exp_y *= y;
        }

        let i_blinding = i_blinding1 + u * i_blinding2;
        let o_blinding = o_blinding1 + u * o_blinding2;
        let s_blinding = s_blinding1 + u * s_blinding2;

        let e_blinding = x * (i_blinding + x * (o_blinding + x * s_blinding));

        {
            let transcript = self.transcript.borrow_mut();
            append_scalar::<C>(transcript, b"t_x", &t_x);
            append_scalar::<C>(transcript, b"t_x_blinding", &t_x_blinding);
            append_scalar::<C>(transcript, b"e_blinding", &e_blinding);
        }

        let w = challenge_scalar::<C>(self.transcript.borrow_mut(), b"w");
        let Q = self.pc_gens.B * w;

        let G_factors: Vec<C::Scalar> = std::iter::repeat_n(C::Scalar::ONE, n1)
            .chain(std::iter::repeat_n(u, n2 + pad))
            .collect();
        let H_factors: Vec<C::Scalar> = exp_y_inv
            .iter()
            .zip(G_factors.iter())
            .map(|(y, u_or_1)| *y * *u_or_1)
            .collect();

        let gens = bp_gens.share(0);
        let g_gens = gens.shared_G();
        let h_gens = gens.shared_H();

        let ipp_proof = InnerProductProof::<C>::create(
            self.transcript.borrow_mut(),
            &Q,
            &G_factors,
            &H_factors,
            &g_gens[..padded_n],
            &h_gens[..padded_n],
            l_vec,
            r_vec,
        );

        let proof = R1CSProof {
            A_I1,
            A_O1,
            S1,
            A_I2,
            A_O2,
            S2,
            T_1,
            T_3,
            T_4,
            T_5,
            T_6,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        };
        Ok((proof, self.transcript))
    }
}
