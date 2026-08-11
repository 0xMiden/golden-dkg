//! Inner-product proof, generic over a [`Cycle`].

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use core::borrow::Borrow;
use core::iter;
use merlin::Transcript;
use p3_maybe_rayon::prelude::*;

use crate::cycle::Cycle;
use crate::errors::ProofError;
use crate::transcript::{append_point, challenge_scalar, validate_and_append_point, R1csDomain};
use crate::util::{inner_product, read32};

/// Inner-product argument proof.
#[derive(Clone, Debug)]
pub struct InnerProductProof<C: Cycle> {
    pub(crate) L_vec: Vec<C::Compressed>,
    pub(crate) R_vec: Vec<C::Compressed>,
    pub(crate) a: C::Scalar,
    pub(crate) b: C::Scalar,
}

impl<C: Cycle> InnerProductProof<C> {
    /// Create an inner-product proof of `<a, b>` with respect to bases `G` and
    /// `H'` where `H'_i = H_factors[i] * H_i`, and a common base `Q`.
    ///
    /// All input vectors must share one length that is a power of two.
    pub fn create(
        transcript: &mut Transcript,
        Q: &C::Point,
        G_factors: &[C::Scalar],
        H_factors: &[C::Scalar],
        G: &[C::Affine],
        H: &[C::Affine],
        mut a_vec: Vec<C::Scalar>,
        mut b_vec: Vec<C::Scalar>,
    ) -> InnerProductProof<C> {
        let Q_affine = C::point_to_affine(Q);
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];

        let n = G.len();
        debug_assert_eq!(H.len(), n);
        debug_assert_eq!(a.len(), n);
        debug_assert_eq!(b.len(), n);
        debug_assert_eq!(G_factors.len(), n);
        debug_assert_eq!(H_factors.len(), n);
        debug_assert!(n.is_power_of_two());

        transcript.innerproduct_domain_sep(n as u64);

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        let mut g_coef = G_factors.to_vec();
        let mut h_coef = H_factors.to_vec();

        for round in 0..lg_n {
            let m = n >> (round + 1);
            let shift = lg_n - round - 1;
            let mask = m - 1;

            let (a_L, a_R) = a.split_at_mut(m);
            let (b_L, b_R) = b.split_at_mut(m);

            let c_L = inner_product(a_L, b_R);
            let c_R = inner_product(a_R, b_L);

            let mut scalars_l = Vec::with_capacity(n + 1);
            let mut points_l = Vec::with_capacity(n + 1);
            let mut scalars_r = Vec::with_capacity(n + 1);
            let mut points_r = Vec::with_capacity(n + 1);

            for j in 0..n {
                let idx = j & mask;
                if (j >> shift) & 1 == 1 {
                    // R-half this round: G feeds L (paired with a_L), H feeds R (paired with b_L).
                    scalars_l.push(a_L[idx] * g_coef[j]);
                    points_l.push(G[j]);
                    scalars_r.push(b_L[idx] * h_coef[j]);
                    points_r.push(H[j]);
                } else {
                    // L-half this round: G feeds R (paired with a_R), H feeds L (paired with b_R).
                    scalars_r.push(a_R[idx] * g_coef[j]);
                    points_r.push(G[j]);
                    scalars_l.push(b_R[idx] * h_coef[j]);
                    points_l.push(H[j]);
                }
            }
            scalars_l.push(c_L);
            points_l.push(Q_affine);
            scalars_r.push(c_R);
            points_r.push(Q_affine);

            let L = C::point_compress(&C::vartime_msm_affine(&scalars_l, &points_l));
            let R = C::point_compress(&C::vartime_msm_affine(&scalars_r, &points_r));

            L_vec.push(L.clone());
            R_vec.push(R.clone());

            append_point::<C>(transcript, b"L", &L);
            append_point::<C>(transcript, b"R", &R);

            let u = challenge_scalar::<C>(transcript, b"u");
            let u_inv = C::scalar_invert(&u);

            a_L.par_iter_mut()
                .enumerate()
                .for_each(|(i, a_L_i)| *a_L_i = *a_L_i * u + u_inv * a_R[i]);
            b_L.par_iter_mut()
                .enumerate()
                .for_each(|(i, b_L_i)| *b_L_i = *b_L_i * u_inv + u * b_R[i]);
            g_coef.par_iter_mut().enumerate().for_each(|(j, gc)| {
                *gc *= if (j >> shift) & 1 == 1 { u } else { u_inv };
            });
            h_coef.par_iter_mut().enumerate().for_each(|(j, hc)| {
                *hc *= if (j >> shift) & 1 == 1 { u_inv } else { u };
            });

            a = a_L;
            b = b_L;
        }

        InnerProductProof {
            L_vec,
            R_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Verification scalars `[u_i^2]`, `[u_i^{-2}]`, and `[s_i]` for a combined
    /// multiscalar multiplication in the parent protocol.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<C::Scalar>, Vec<C::Scalar>, Vec<C::Scalar>), ProofError> {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        transcript.innerproduct_domain_sep(n as u64);

        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            validate_and_append_point::<C>(transcript, b"L", L)?;
            validate_and_append_point::<C>(transcript, b"R", R)?;
            challenges.push(challenge_scalar::<C>(transcript, b"u"));
        }

        let mut challenges_inv = challenges.clone();
        let allinv = C::scalar_batch_invert(&mut challenges_inv);

        for i in 0..lg_n {
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        let mut s = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
            s.push(s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }

    /// Verify an inner-product proof that `<a,b>` is the value attached to
    /// the point `P`, given the generators `G`, `H`, the common base `Q`,
    /// and the per-generator blinding factors `G_factors`, `H_factors`
    /// (with `H'_i = H_factors[i] * H_i`).
    ///
    /// Mirrors `bulletproofs 5.0.0::InnerProductProof::verify`, cycle-
    /// abstracted over `C`. The R1CS verifier does its own inline MSM
    /// rather than calling this, but exposing the standalone verify makes
    /// the inner-product argument testable on its own and matches
    /// upstream's public surface.
    pub fn verify<IG, IH>(
        &self,
        n: usize,
        transcript: &mut Transcript,
        G_factors: IG,
        H_factors: IH,
        P: &C::Point,
        Q: &C::Point,
        G: &[C::Point],
        H: &[C::Point],
    ) -> Result<(), ProofError>
    where
        IG: IntoIterator,
        IG::Item: Borrow<C::Scalar>,
        IH: IntoIterator,
        IH::Item: Borrow<C::Scalar>,
    {
        // `verification_scalars` already pins `n = 1 << lg_n`, so all four
        // generator/factor inputs must provide exactly `n` entries to keep
        // the MSM dimensions aligned. Upstream relies on Ristretto's
        // zip-based multiscalar_mul to truncate silently; we collect to a
        // Vec before handing to `Cycle::vartime_msm`, so reject up front.
        if G.len() != n || H.len() != n {
            return Err(ProofError::VerificationError);
        }
        let G_factors: Vec<_> = G_factors.into_iter().take(n + 1).collect();
        let H_factors: Vec<_> = H_factors.into_iter().take(n + 1).collect();
        if G_factors.len() != n || H_factors.len() != n {
            return Err(ProofError::VerificationError);
        }

        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;

        let g_times_a_times_s = G_factors
            .into_iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (self.a * s_i) * g_i.borrow())
            .take(n);

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1.
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .into_iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (self.b * s_i_inv) * h_i.borrow())
            .take(n);

        let neg_u_sq = u_sq.iter().map(|ui| -*ui);
        let neg_u_inv_sq = u_inv_sq.iter().map(|ui| -*ui);

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

        let scalars: Vec<C::Scalar> = iter::once(self.a * self.b)
            .chain(g_times_a_times_s)
            .chain(h_times_b_div_s)
            .chain(neg_u_sq)
            .chain(neg_u_inv_sq)
            .collect();
        let points: Vec<C::Point> = iter::once(*Q)
            .chain(G.iter().copied())
            .chain(H.iter().copied())
            .chain(Ls.iter().copied())
            .chain(Rs.iter().copied())
            .collect();

        let expect_P = C::vartime_msm(&scalars, &points);

        if expect_P == *P {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Serialized size in bytes: `2 * lg_n * COMPRESSED_BYTES + 2 * 32`,
    /// where `lg_n = L_vec.len()` (one L/R compressed point pair per round,
    /// plus the two final scalars `a` and `b`).
    pub fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2) * C::COMPRESSED_BYTES + 2 * 32
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        for (l, r) in self.L_vec.iter().zip(self.R_vec.iter()) {
            buf.extend_from_slice(C::compressed_as_bytes(l));
            buf.extend_from_slice(C::compressed_as_bytes(r));
        }
        buf.extend_from_slice(&C::scalar_to_canonical(&self.a));
        buf.extend_from_slice(&C::scalar_to_canonical(&self.b));
        buf
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<InnerProductProof<C>, ProofError> {
        let cb = C::COMPRESSED_BYTES;
        let unit = 2 * cb;
        if slice.len() < 64 {
            return Err(ProofError::FormatError);
        }
        let body_len = slice.len() - 64;
        if !body_len.is_multiple_of(unit) {
            return Err(ProofError::FormatError);
        }
        let pairs = body_len / unit;
        let lg_n = pairs;

        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let pos = 2 * i * cb;
            let l = C::compressed_from_bytes(&slice[pos..pos + cb]);
            let r = C::compressed_from_bytes(&slice[pos + cb..pos + 2 * cb]);
            L_vec.push(l);
            R_vec.push(r);
        }

        let pos = 2 * lg_n * cb;
        let a = C::scalar_from_canonical(&read32(&slice[pos..])).ok_or(ProofError::FormatError)?;
        let b =
            C::scalar_from_canonical(&read32(&slice[pos + 32..])).ok_or(ProofError::FormatError)?;

        Ok(InnerProductProof { L_vec, R_vec, a, b })
    }

    /// Iterator over the serialized proof bytes.
    pub(crate) fn to_bytes_iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.L_vec
            .iter()
            .zip(self.R_vec.iter())
            .flat_map(|(l, r)| {
                C::compressed_as_bytes(l)
                    .iter()
                    .chain(C::compressed_as_bytes(r).iter())
                    .copied()
            })
            .chain(C::scalar_to_canonical(&self.a))
            .chain(C::scalar_to_canonical(&self.b))
    }
}

#[cfg(all(test, feature = "ristretto"))]
mod tests {
    use super::*;
    use crate::cycle::random_scalar;
    use crate::generators::BulletproofGens;
    use crate::ristretto_cycle::RistrettoCycle;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn roundtrip(n: usize) {
        let mut rng = ChaCha20Rng::seed_from_u64(n as u64);
        let bp_gens = BulletproofGens::<RistrettoCycle>::new(n, 1);
        let share = bp_gens.share(0);
        let G_affine: Vec<_> = share.G(n).copied().collect();
        let H_affine: Vec<_> = share.H(n).copied().collect();
        let G: Vec<_> = G_affine
            .iter()
            .map(RistrettoCycle::affine_to_point)
            .collect();
        let H: Vec<_> = H_affine
            .iter()
            .map(RistrettoCycle::affine_to_point)
            .collect();
        let Q = RistrettoCycle::point_hash_from_uniform(&[7u8; 64]);

        let G_factors: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();
        let H_factors: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();
        let a: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();
        let b: Vec<_> = (0..n)
            .map(|_| random_scalar::<RistrettoCycle>(&mut rng))
            .collect();

        let ab = inner_product(&a, &b);
        let mut scalars: Vec<_> = a
            .iter()
            .zip(G_factors.iter())
            .map(|(a_i, g)| *a_i * g)
            .collect();
        scalars.extend(b.iter().zip(H_factors.iter()).map(|(b_i, h)| *b_i * h));
        scalars.push(ab);
        let mut points = G.clone();
        points.extend(H.iter().copied());
        points.push(Q);
        let P = RistrettoCycle::vartime_msm(&scalars, &points);

        let mut prover_transcript = Transcript::new(b"ipp-roundtrip-test");
        let proof = InnerProductProof::<RistrettoCycle>::create(
            &mut prover_transcript,
            &Q,
            &G_factors,
            &H_factors,
            &G_affine,
            &H_affine,
            a,
            b,
        );

        let mut verifier_transcript = Transcript::new(b"ipp-roundtrip-test");
        assert!(proof
            .verify(
                n,
                &mut verifier_transcript,
                G_factors,
                H_factors,
                &P,
                &Q,
                &G,
                &H,
            )
            .is_ok());
    }

    #[test]
    fn roundtrips_for_small_powers_of_two() {
        for n in [1usize, 2, 4, 8, 16, 64] {
            roundtrip(n);
        }
    }
}
