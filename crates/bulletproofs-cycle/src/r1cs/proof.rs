//! R1CS proof type, generic over a [`Cycle`].

#![allow(non_snake_case)]

use alloc::vec::Vec;

use crate::cycle::Cycle;
use crate::errors::R1CSError;
use crate::inner_product_proof::InnerProductProof;
use crate::util::read32;

const ONE_PHASE_COMMITMENTS: u8 = 0;
const TWO_PHASE_COMMITMENTS: u8 = 1;

/// A proof of a statement specified by a [`ConstraintSystem`](super::ConstraintSystem).
#[derive(Clone, Debug)]
pub struct R1CSProof<C: Cycle> {
    /// First-phase input-wire commitment.
    pub(super) A_I1: C::Compressed,
    /// First-phase output-wire commitment.
    pub(super) A_O1: C::Compressed,
    /// First-phase blinding commitment.
    pub(super) S1: C::Compressed,
    /// Second-phase input-wire commitment.
    pub(super) A_I2: C::Compressed,
    /// Second-phase output-wire commitment.
    pub(super) A_O2: C::Compressed,
    /// Second-phase blinding commitment.
    pub(super) S2: C::Compressed,
    /// Commitment to the `t_1` coefficient of `t(x)`.
    pub(super) T_1: C::Compressed,
    /// Commitment to the `t_3` coefficient of `t(x)`.
    pub(super) T_3: C::Compressed,
    /// Commitment to the `t_4` coefficient of `t(x)`.
    pub(super) T_4: C::Compressed,
    /// Commitment to the `t_5` coefficient of `t(x)`.
    pub(super) T_5: C::Compressed,
    /// Commitment to the `t_6` coefficient of `t(x)`.
    pub(super) T_6: C::Compressed,
    /// Evaluation of `t(x)` at the challenge point `x`.
    pub(super) t_x: C::Scalar,
    /// Blinding factor for the synthetic `t(x)` commitment.
    pub(super) t_x_blinding: C::Scalar,
    /// Blinding factor for the inner-product arguments.
    pub(super) e_blinding: C::Scalar,
    /// Inner-product argument proof.
    pub(super) ipp_proof: InnerProductProof<C>,
}

impl<C: Cycle> R1CSProof<C> {
    /// [`Self::to_bytes`]'s wire length for a single-phase proof (the
    /// `ONE_PHASE_COMMITMENTS` branch: no `specify_randomized_constraints`
    /// deferred constraints) with an inner-product-proof fold of `lg_n`
    /// rounds, without constructing a proof.
    ///
    /// Fixed part: the version tag, the three phase-1 commitments (`A_I1`,
    /// `A_O1`, `S1`), the five `t(x)`-coefficient commitments (`T_1`, `T_3`,
    /// `T_4`, `T_5`, `T_6`), and the three canonical scalars (`t_x`,
    /// `t_x_blinding`, `e_blinding`, each [`Cycle::scalar_to_canonical`]'s
    /// fixed 32-byte width).
    pub fn single_phase_wire_len(lg_n: usize) -> usize {
        const VERSION_TAG_BYTES: usize = 1;
        const ONE_PHASE_POINTS: usize = 3 + 5;
        const SCALARS: usize = 3;
        const SCALAR_BYTES: usize = 32;
        VERSION_TAG_BYTES
            + ONE_PHASE_POINTS * C::COMPRESSED_BYTES
            + SCALARS * SCALAR_BYTES
            + InnerProductProof::<C>::serialized_size_for_rounds(lg_n)
    }

    /// Heuristic: detect "no phase-2 multiplier commitments emitted" by
    /// checking that all three phase-2 commitments compressed to the
    /// identity encoding.
    ///
    /// This conflates several distinct states:
    /// 1. The prover never called `specify_randomized_constraints`, so the
    ///    phase-2 commitment slots were filled with [`Cycle::compressed_identity`]
    ///    by the prover's phase-2 branch (see `prover.rs`).
    /// 2. The prover called `specify_randomized_constraints` with a callback
    ///    that added constraints but no new multipliers. With `n2 == 0` the
    ///    phase-2 commitment branch in the prover still skips emitting
    ///    A_I2/A_O2/S2, leaving them at identity.
    /// 3. The prover did emit phase-2 commitments but the random blindings
    ///    happened to produce identity compressed encodings. For the curves
    ///    in this workspace the chance of that is ~1/|Scalar|, so in
    ///    practice the heuristic is safe; it is still a heuristic rather
    ///    than a structural flag, so if a future Cycle backend has a small
    ///    subgroup the check should be replaced with an explicit
    ///    `has_phase2` boolean plumbed through the prover.
    fn missing_phase2_commitments(&self) -> bool {
        C::compressed_is_identity(&self.A_I2)
            && C::compressed_is_identity(&self.A_O2)
            && C::compressed_is_identity(&self.S2)
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if self.missing_phase2_commitments() {
            buf.push(ONE_PHASE_COMMITMENTS);
            for p in [&self.A_I1, &self.A_O1, &self.S1] {
                buf.extend_from_slice(C::compressed_as_bytes(p));
            }
        } else {
            buf.push(TWO_PHASE_COMMITMENTS);
            for p in [
                &self.A_I1, &self.A_O1, &self.S1, &self.A_I2, &self.A_O2, &self.S2,
            ] {
                buf.extend_from_slice(C::compressed_as_bytes(p));
            }
        }
        for p in [&self.T_1, &self.T_3, &self.T_4, &self.T_5, &self.T_6] {
            buf.extend_from_slice(C::compressed_as_bytes(p));
        }
        buf.extend_from_slice(&C::scalar_to_canonical(&self.t_x));
        buf.extend_from_slice(&C::scalar_to_canonical(&self.t_x_blinding));
        buf.extend_from_slice(&C::scalar_to_canonical(&self.e_blinding));
        buf.extend(self.ipp_proof.to_bytes_iter());
        buf
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<R1CSProof<C>, R1CSError> {
        if slice.is_empty() {
            return Err(R1CSError::FormatError);
        }
        let cb = C::COMPRESSED_BYTES;
        let version = slice[0];
        let mut slice = &slice[1..];

        let (phase1_points, has_phase2) = match version {
            ONE_PHASE_COMMITMENTS => (3usize, false),
            TWO_PHASE_COMMITMENTS => (6usize, true),
            _ => return Err(R1CSError::FormatError),
        };

        let points_needed = phase1_points + 5;
        let scalar_bytes = 3 * 32;
        let min_body = points_needed * cb + scalar_bytes;
        if slice.len() < min_body {
            return Err(R1CSError::FormatError);
        }

        let next_point = |s: &mut &[u8]| -> C::Compressed {
            let p = C::compressed_from_bytes(&s[..cb]);
            *s = &s[cb..];
            p
        };

        let A_I1 = next_point(&mut slice);
        let A_O1 = next_point(&mut slice);
        let S1 = next_point(&mut slice);
        let (A_I2, A_O2, S2) = if has_phase2 {
            (
                next_point(&mut slice),
                next_point(&mut slice),
                next_point(&mut slice),
            )
        } else {
            (
                C::compressed_identity(),
                C::compressed_identity(),
                C::compressed_identity(),
            )
        };
        let T_1 = next_point(&mut slice);
        let T_3 = next_point(&mut slice);
        let T_4 = next_point(&mut slice);
        let T_5 = next_point(&mut slice);
        let T_6 = next_point(&mut slice);

        let t_x = C::scalar_from_canonical(&read32(slice)).ok_or(R1CSError::FormatError)?;
        let t_x_blinding =
            C::scalar_from_canonical(&read32(&slice[32..])).ok_or(R1CSError::FormatError)?;
        let e_blinding =
            C::scalar_from_canonical(&read32(&slice[64..])).ok_or(R1CSError::FormatError)?;
        slice = &slice[96..];

        let ipp_proof =
            InnerProductProof::<C>::from_bytes(slice).map_err(|_| R1CSError::FormatError)?;

        Ok(R1CSProof {
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
        })
    }
}
