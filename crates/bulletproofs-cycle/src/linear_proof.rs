//! Linear proof, a lightweight variant of the Bulletproofs inner-product
//! argument. Ported from `bulletproofs 5.0.0/src/linear_proof.rs` and
//! cycle-abstracted over [`Cycle`](crate::cycle::Cycle).
//!
//! Proves `<a, b> = c` where `a` is secret and `b` is public.
//! Protocol: Section E.3 of [GHL'21](https://eprint.iacr.org/2021/1397.pdf).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::cycle::{random_scalar, Cycle};
use crate::errors::ProofError;
use crate::transcript::{
    append_point, append_scalar, challenge_scalar, validate_and_append_point, R1csDomain,
};
use crate::util::{inner_product, read32};

/// A linear proof: a lightweight variant of the inner-product argument.
#[derive(Clone, Debug)]
pub struct LinearProof<C: Cycle> {
    pub(crate) L_vec: Vec<C::Compressed>,
    pub(crate) R_vec: Vec<C::Compressed>,
    /// Commitment to the base-case elements.
    pub(crate) S: C::Compressed,
    /// `a_star`, corresponding to the base-case `a`.
    pub(crate) a: C::Scalar,
    /// `r_star`, corresponding to the base-case `r`.
    pub(crate) r: C::Scalar,
}

impl<C: Cycle> LinearProof<C> {
    /// Create a linear proof that `<a, b> = c` where `a` is secret and `b`
    /// is public.
    ///
    /// All input vectors must share one length that is either 0 or a power
    /// of two. The proof is created with respect to the generators `G`.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        // Commitment to witness.
        C_commit: &C::Compressed,
        // Blinding factor for the witness commitment.
        mut r: C::Scalar,
        // Secret scalar vector a.
        mut a_vec: Vec<C::Scalar>,
        // Public scalar vector b.
        mut b_vec: Vec<C::Scalar>,
        // Generator vector.
        mut G_vec: Vec<C::Point>,
        // Pedersen generator F, for committing to the secret value.
        F: &C::Point,
        // Pedersen generator B, for committing to the blinding value.
        B: &C::Point,
    ) -> Result<LinearProof<C>, ProofError> {
        let mut n = b_vec.len();
        if G_vec.len() != n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if a_vec.len() != n {
            return Err(ProofError::InvalidInputLength);
        }
        if !n.is_power_of_two() {
            return Err(ProofError::InvalidInputLength);
        }

        transcript.innerproduct_domain_sep(n as u64);
        append_point::<C>(transcript, b"C", C_commit);
        for b_i in &b_vec {
            append_scalar::<C>(transcript, b"b_i", b_i);
        }
        for G_i in &G_vec {
            let comp = C::point_compress(G_i);
            append_point::<C>(transcript, b"G_i", &comp);
        }
        let F_comp = C::point_compress(F);
        let B_comp = C::point_compress(B);
        append_point::<C>(transcript, b"F", &F_comp);
        append_point::<C>(transcript, b"B", &B_comp);

        let mut G = &mut G_vec[..];
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        while n != 1 {
            n /= 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);

            let c_L = inner_product(a_L, b_R);
            let c_R = inner_product(a_R, b_L);

            let s_j = random_scalar::<C>(rng);
            let t_j = random_scalar::<C>(rng);

            // L = <a_L, G_R> + s_j * B + c_L * F
            let mut scalars_l: Vec<C::Scalar> = a_L.to_vec();
            scalars_l.push(s_j);
            scalars_l.push(c_L);
            let mut points_l: Vec<C::Point> = G_R.to_vec();
            points_l.push(*B);
            points_l.push(*F);
            let L = C::point_compress(&C::vartime_msm(&scalars_l, &points_l));

            // R = <a_R, G_L> + t_j * B + c_R * F
            let mut scalars_r: Vec<C::Scalar> = a_R.to_vec();
            scalars_r.push(t_j);
            scalars_r.push(c_R);
            let mut points_r: Vec<C::Point> = G_L.to_vec();
            points_r.push(*B);
            points_r.push(*F);
            let R = C::point_compress(&C::vartime_msm(&scalars_r, &points_r));

            L_vec.push(L.clone());
            R_vec.push(R.clone());

            append_point::<C>(transcript, b"L", &L);
            append_point::<C>(transcript, b"R", &R);

            let x_j = challenge_scalar::<C>(transcript, b"x_j");
            let x_j_inv = C::scalar_invert(&x_j);

            for i in 0..n {
                a_L[i] += x_j_inv * a_R[i];
                b_L[i] += x_j * b_R[i];
                G_L[i] = C::vartime_msm(&[C::Scalar::ONE, x_j], &[G_L[i], G_R[i]]);
            }
            a = a_L;
            b = b_L;
            G = G_L;
            r = r + x_j * s_j + x_j_inv * t_j;
        }

        let s_star = random_scalar::<C>(rng);
        let t_star = random_scalar::<C>(rng);
        // S = t_star * B + s_star * b[0] * F + s_star * G[0]
        let S = C::point_compress(&C::vartime_msm(
            &[t_star, s_star * b[0], s_star],
            &[*B, *F, G[0]],
        ));
        append_point::<C>(transcript, b"S", &S);

        let x_star = challenge_scalar::<C>(transcript, b"x_star");
        let a_star = s_star + x_star * a[0];
        let r_star = t_star + x_star * r;

        Ok(LinearProof {
            L_vec,
            R_vec,
            S,
            a: a_star,
            r: r_star,
        })
    }

    /// Verify a linear proof against the public inputs.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        // Commitment to witness.
        C_commit: &C::Compressed,
        // Generator vector.
        G: &[C::Point],
        // Pedersen generator F, for committing to the secret value.
        F: &C::Point,
        // Pedersen generator B, for committing to the blinding value.
        B: &C::Point,
        // Public scalar vector b.
        b_vec: Vec<C::Scalar>,
    ) -> Result<(), ProofError> {
        let n = b_vec.len();
        if G.len() != n {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        transcript.innerproduct_domain_sep(n as u64);
        append_point::<C>(transcript, b"C", C_commit);
        for b_i in &b_vec {
            append_scalar::<C>(transcript, b"b_i", b_i);
        }
        for G_i in G {
            let comp = C::point_compress(G_i);
            append_point::<C>(transcript, b"G_i", &comp);
        }
        let F_comp = C::point_compress(F);
        let B_comp = C::point_compress(B);
        append_point::<C>(transcript, b"F", &F_comp);
        append_point::<C>(transcript, b"B", &B_comp);

        let (x_vec, x_inv_vec, b_0) = self.verification_scalars(n, transcript, b_vec)?;
        append_point::<C>(transcript, b"S", &self.S);
        let x_star = challenge_scalar::<C>(transcript, b"x_star");

        let Ls = self
            .L_vec
            .iter()
            .map(|p| C::compressed_decompress(p).ok_or(ProofError::VerificationError))
            .collect::<Result<Vec<_>, _>>()?;

        let Rs = self
            .R_vec
            .iter()
            .map(|p| C::compressed_decompress(p).ok_or(ProofError::VerificationError))
            .collect::<Result<Vec<_>, _>>()?;

        // L_R_factors = sum_{j=0}^{l-1} (x_j * L_j + x_j^{-1} * R_j).
        //
        // Note: in GHL'21 the verification equation is incorrect (as of
        // 05/03/22), with x_j and x_j^{-1} reversed. The incorrect paper
        // equation reads sum_{j=0}^{l-1} (x_j^{-1} * L_j + x_j * R_j).
        let mut lr_scalars: Vec<C::Scalar> = x_vec.to_vec();
        lr_scalars.extend(x_inv_vec.iter().copied());
        let mut lr_points: Vec<C::Point> = Ls.to_vec();
        lr_points.extend(Rs.iter().copied());
        let L_R_factors = C::vartime_msm(&lr_scalars, &lr_points);

        // G_0 = sum_{i=0}^{n-1} (x<i> * G_i), the base-case generator.
        let s = self.subset_product(n, &x_vec);
        let G_0 = C::vartime_msm(&s, G);

        let S = C::compressed_decompress(&self.S).ok_or(ProofError::VerificationError)?;
        let C_dec = C::compressed_decompress(C_commit).ok_or(ProofError::VerificationError)?;

        // expect_S = r_star * B + a_star * b_0 * F
        //            - x_star * (C + L_R_factors)
        //            + a_star * G_0
        let scalars: Vec<C::Scalar> = [self.r, self.a * b_0, -x_star, -x_star, self.a].to_vec();
        let points: Vec<C::Point> = [*B, *F, C_dec, L_R_factors, G_0].to_vec();
        let expect_S = C::vartime_msm(&scalars, &points);

        if expect_S == S {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Recompute the verifier challenges `[x_j]`, their inverses
    /// `[x_j^{-1}]`, and the base-case `b_0` derived from the public vector
    /// `b`. The verifier supplies `n` explicitly so we can bound allocation.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
        mut b_vec: Vec<C::Scalar>,
    ) -> Result<(Vec<C::Scalar>, Vec<C::Scalar>, C::Scalar), ProofError> {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        let mut n_mut = n;
        let mut b = &mut b_vec[..];
        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            validate_and_append_point::<C>(transcript, b"L", L)?;
            validate_and_append_point::<C>(transcript, b"R", R)?;
            let x_j = challenge_scalar::<C>(transcript, b"x_j");
            challenges.push(x_j);
            n_mut /= 2;
            let (b_L, b_R) = b.split_at_mut(n_mut);
            for i in 0..n_mut {
                b_L[i] += x_j * b_R[i];
            }
            b = b_L;
        }

        let mut challenges_inv = challenges.clone();
        C::scalar_batch_invert(&mut challenges_inv);

        Ok((challenges, challenges_inv, b[0]))
    }

    /// Subset-product `s_i = prod_{j=1}^{lg n} x_j^{b(i,j)}` where `b(i,j)`
    /// is the jth bit of `i-1`. In GHL'21 this is the subset-product `x<i>`.
    ///
    /// This differs from the Bulletproofs IPP `s_i` generation, which uses
    /// `+/-1` exponents rather than `{0,1}`.
    fn subset_product(&self, n: usize, challenges: &[C::Scalar]) -> Vec<C::Scalar> {
        let lg_n = self.L_vec.len();

        let mut s = Vec::with_capacity(n);
        s.push(C::Scalar::ONE);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // Challenges are stored in creation order as [x_k,...,x_1], so
            // x_{lg(i)+1} is indexed by (lg_n-1) - lg_i.
            let x_lg_i = challenges[(lg_n - 1) - lg_i];
            s.push(s[i - k] * x_lg_i);
        }

        s
    }

    /// Serialized size in bytes: `2 * lg_n * COMPRESSED_BYTES + COMPRESSED_BYTES + 2 * 32`,
    /// i.e. one L/R compressed-point pair per round, one `S` compressed point,
    /// and the two final scalars `a` and `r`.
    pub fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2 + 1) * C::COMPRESSED_BYTES + 2 * 32
    }

    /// Serialize the proof to bytes. Layout: `lg_n` pairs of compressed
    /// points `L_0, R_0, ..., L_{lg_n-1}, R_{lg_n-1}`, then one compressed
    /// point `S`, then two scalars `a`, `r`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        for (l, r) in self.L_vec.iter().zip(self.R_vec.iter()) {
            buf.extend_from_slice(C::compressed_as_bytes(l));
            buf.extend_from_slice(C::compressed_as_bytes(r));
        }
        buf.extend_from_slice(C::compressed_as_bytes(&self.S));
        buf.extend_from_slice(&C::scalar_to_canonical(&self.a));
        buf.extend_from_slice(&C::scalar_to_canonical(&self.r));
        buf
    }

    /// Deserialize a proof from a byte slice.
    pub fn from_bytes(slice: &[u8]) -> Result<LinearProof<C>, ProofError> {
        let cb = C::COMPRESSED_BYTES;
        let unit = 2 * cb;
        let tail = cb + 2 * 32;
        if slice.len() < tail {
            return Err(ProofError::FormatError);
        }
        let body_len = slice.len() - tail;
        if body_len % unit != 0 {
            return Err(ProofError::FormatError);
        }
        let pairs = body_len / unit;
        let lg_n = pairs;
        if lg_n >= 32 {
            return Err(ProofError::FormatError);
        }

        let mut L_vec: Vec<C::Compressed> = Vec::with_capacity(lg_n);
        let mut R_vec: Vec<C::Compressed> = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let pos = 2 * i * cb;
            let l = C::compressed_from_bytes(&slice[pos..pos + cb]);
            let r = C::compressed_from_bytes(&slice[pos + cb..pos + 2 * cb]);
            L_vec.push(l);
            R_vec.push(r);
        }

        let pos = 2 * lg_n * cb;
        let S = C::compressed_from_bytes(&slice[pos..pos + cb]);
        let a =
            C::scalar_from_canonical(&read32(&slice[pos + cb..])).ok_or(ProofError::FormatError)?;
        let r = C::scalar_from_canonical(&read32(&slice[pos + cb + 32..]))
            .ok_or(ProofError::FormatError)?;

        Ok(LinearProof {
            L_vec,
            R_vec,
            S,
            a,
            r,
        })
    }
}
