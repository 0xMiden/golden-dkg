//! Generic bucket-method (Pippenger) multi-scalar multiplication over any
//! [`group::Group`].
//!
//! `jubjub` ships no multi-exponentiation helper, so this fills that gap for
//! the Jubjub [`bulletproofs_cycle::Cycle`] implementation
//! ([`crate::jubjub_cycle`]). BLS12-381 G1's `Cycle` implementation instead
//! delegates to `blst`'s own tuned Pippenger MSM (see [`crate::msm_blst`]),
//! which has hardware-accelerated field arithmetic this module's generic
//! `group::Group` addition/doubling cannot use. This module only uses
//! generic projective addition and doubling, so it needs no curve-specific
//! fast path, at the cost of the affine-batched speedups a curve-specific
//! MSM could use. Optimizing this is a follow-up perf item, not a
//! correctness concern for the first working backend.

use group::Group;

/// Window size in bits. Larger windows trade more bucket memory for fewer
/// point additions.
pub(crate) const WINDOW_BITS: u32 = 4;

/// Multi-scalar multiplication `sum(scalars[i] * points[i])`.
///
/// `scalar_bytes[i]` is the little-endian encoding of `scalars[i]`, read for
/// exactly `scalar_bit_len` bits (higher bits, if any, are ignored). Panics
/// if `scalar_bytes.len() != points.len()`.
pub(crate) fn multi_scalar_mul<P: Group>(
    scalar_bytes: &[[u8; 32]],
    points: &[P],
    scalar_bit_len: u32,
) -> P {
    assert_eq!(scalar_bytes.len(), points.len());
    if points.is_empty() {
        return P::identity();
    }

    let num_windows = scalar_bit_len.div_ceil(WINDOW_BITS);
    let num_buckets = 1usize << WINDOW_BITS;

    let mut result = P::identity();
    for window_idx in (0..num_windows).rev() {
        for _ in 0..WINDOW_BITS {
            result = result.double();
        }

        let mut buckets = vec![P::identity(); num_buckets];
        for (bytes, point) in scalar_bytes.iter().zip(points) {
            let digit = window_digit(bytes, window_idx, WINDOW_BITS);
            if digit != 0 {
                buckets[digit] += point;
            }
        }

        // Running-sum trick: sum_{d=1}^{2^w-1} d * buckets[d] via one pass,
        // accumulating partial sums instead of scaling each bucket.
        let mut window_sum = P::identity();
        let mut running_sum = P::identity();
        for bucket in buckets.iter().skip(1).rev() {
            running_sum += bucket;
            window_sum += &running_sum;
        }

        result += &window_sum;
    }

    result
}

/// Extract the `window_bits`-bit digit at `window_idx` from a little-endian
/// byte array (digit 0 is the least-significant window).
pub(crate) fn window_digit(bytes: &[u8; 32], window_idx: u32, window_bits: u32) -> usize {
    let bit_offset = window_idx * window_bits;
    let mut digit = 0usize;
    for i in 0..window_bits {
        let bit_pos = (bit_offset + i) as usize;
        let byte_idx = bit_pos / 8;
        let bit = if byte_idx < bytes.len() {
            (bytes[byte_idx] >> (bit_pos % 8)) & 1
        } else {
            0
        };
        digit |= (bit as usize) << i;
    }
    digit
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use bls12_381::{G1Projective, Scalar};
    use ff::{Field, PrimeField};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn naive_msm(scalars: &[Scalar], points: &[G1Projective]) -> G1Projective {
        let mut acc = G1Projective::identity();
        for (s, p) in scalars.iter().zip(points) {
            acc += p * s;
        }
        acc
    }

    #[test]
    fn matches_naive_sum_for_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for len in [0usize, 1, 2, 3, 5, 17, 64] {
            let scalars: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
            let points: Vec<G1Projective> =
                (0..len).map(|_| G1Projective::random(&mut rng)).collect();
            let bytes: Vec<[u8; 32]> = scalars.iter().map(|s| s.to_repr()).collect();

            let got = multi_scalar_mul(&bytes, &points, Scalar::NUM_BITS);
            let want = naive_msm(&scalars, &points);
            assert_eq!(got, want, "mismatch at len={len}");
        }
    }

    #[test]
    fn empty_input_is_identity() {
        let out: G1Projective = multi_scalar_mul(&[], &[], Scalar::NUM_BITS);
        assert_eq!(out, G1Projective::identity());
    }
}
