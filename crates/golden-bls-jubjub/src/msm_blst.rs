//! BLS12-381 G1 multi-scalar multiplication backed by `blst`.
//!
//! Stored affine bases already use `blst_p1_affine`, so [`msm`] passes them
//! directly to `MultiPoint::mult`. Projective inputs use blst's batch
//! conversion and Pippenger implementation. Scalars stay in
//! `bls12_381::Scalar` because Jubjub and the R1CS field require that exact
//! type, and cross to blst through their canonical little-endian bytes.
//!
//! `MultiPoint::mult` runs on `blst`'s own internal thread pool (sized from
//! the host CPU count) whenever the `blst` crate's `no-threads` feature is
//! off, which it is in this workspace — independent of this workspace's own
//! `parallel` feature (`p3_maybe_rayon`). Every MSM through this module is
//! therefore multi-threaded regardless of `parallel`, including in a
//! "sequential" build or benchmark configuration. Benchmarks on the target
//! machine found that disabling this pool made representative large MSMs
//! more than three times slower, so blst remains the MSM parallelism owner.

use crate::BlsG1Projective;
use bls12_381::Scalar;
use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_double,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_p1s_tile_pippenger, p1_affines, MultiPoint,
};
use group::Group;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Multi-scalar multiplication `sum(scalars[i] * bases[i])` over BLS12-381
/// G1, with bases already converted to `blst`'s native affine
/// representation. Panics if `scalars.len() != bases.len()`.
pub(crate) fn msm(scalars: &[Scalar], bases: &[blst_p1_affine]) -> BlsG1Projective {
    assert_eq!(scalars.len(), bases.len());
    if bases.is_empty() {
        return BlsG1Projective::identity();
    }

    let scalar_bytes = scalar_bytes(scalars);
    let result: blst_p1 = bases.mult(&scalar_bytes, 255);
    BlsG1Projective(blstrs::G1Projective::from_raw_unchecked(
        result.x.into(),
        result.y.into(),
        result.z.into(),
    ))
}

/// Multi-scalar multiplication over projective inputs using `blstrs`' direct
/// bridge to `blst`'s projective-to-affine batch conversion and Pippenger.
pub(crate) fn msm_projective(scalars: &[Scalar], points: &[BlsG1Projective]) -> BlsG1Projective {
    assert_eq!(scalars.len(), points.len());
    if points.is_empty() {
        return BlsG1Projective::identity();
    }

    let points: Vec<blst_p1> = points.iter().map(|point| *point.0.as_ref()).collect();
    let affine = p1_affines::from(&points);
    let result = affine.mult(&scalar_bytes(scalars), 255);
    BlsG1Projective(blstrs::G1Projective::from_raw_unchecked(
        result.x.into(),
        result.y.into(),
        result.z.into(),
    ))
}

/// One MSM over several affine batches and a batch of projective points.
pub(crate) fn msm_mixed(
    affine_batches: &[(&[Scalar], &[blst_p1_affine])],
    dynamic_scalars: &[Scalar],
    dynamic_points: &[BlsG1Projective],
) -> BlsG1Projective {
    assert_eq!(dynamic_scalars.len(), dynamic_points.len());
    let affine_len = affine_batches
        .iter()
        .map(|(scalars, points)| {
            assert_eq!(scalars.len(), points.len());
            points.len()
        })
        .sum::<usize>();

    let mut nonidentity_scalars = Vec::with_capacity(dynamic_scalars.len());
    let mut nonidentity_points = Vec::with_capacity(dynamic_points.len());
    for (&scalar, &point) in dynamic_scalars.iter().zip(dynamic_points) {
        if !bool::from(point.is_identity()) {
            nonidentity_scalars.push(scalar);
            nonidentity_points.push(point);
        }
    }

    let dynamic_affine = batch_normalize(&nonidentity_points);
    let total_len = affine_len + dynamic_affine.len();
    if total_len == 0 {
        return BlsG1Projective::identity();
    }

    if total_len < 32 {
        let mut points = Vec::with_capacity(total_len);
        let mut scalars = Vec::with_capacity(total_len);
        for &(batch_scalars, batch_points) in affine_batches {
            scalars.extend_from_slice(batch_scalars);
            points.extend_from_slice(batch_points);
        }
        scalars.extend_from_slice(&nonidentity_scalars);
        points.extend_from_slice(&dynamic_affine);
        return msm(&scalars, &points);
    }

    let mut points = Vec::with_capacity(total_len);
    let mut scalar_bytes = Vec::with_capacity(total_len * 32);
    for &(batch_scalars, batch_points) in affine_batches {
        points.extend(batch_points.iter().map(AffinePointer::from));
        append_scalar_bytes(&mut scalar_bytes, batch_scalars);
    }
    points.extend(dynamic_affine.iter().map(AffinePointer::from));
    append_scalar_bytes(&mut scalar_bytes, &nonidentity_scalars);

    segmented_mult(&points, &scalar_bytes)
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct AffinePointer(*const blst_p1_affine);

impl From<&blst_p1_affine> for AffinePointer {
    fn from(point: &blst_p1_affine) -> Self {
        Self(point)
    }
}

// SAFETY: The pointers are created from immutable slices that remain borrowed
// until every scoped worker has joined. Workers only read through them.
#[allow(unsafe_code)]
unsafe impl Send for AffinePointer {}
// SAFETY: See the `Send` implementation. The pointees are immutable.
#[allow(unsafe_code)]
unsafe impl Sync for AffinePointer {}

#[derive(Clone, Copy)]
struct PippengerTile {
    x: usize,
    dx: usize,
    bit: usize,
}

/// Evaluate one `blst` Pippenger operation over disjoint affine slices.
///
/// This mirrors `blst`'s threaded `MultiPoint` scheduler but passes an array of
/// point pointers to its tile API. It avoids copying the two large generator
/// vectors into a temporary contiguous point vector.
fn segmented_mult(points: &[AffinePointer], scalar_bytes: &[u8]) -> BlsG1Projective {
    let ncpus = std::thread::available_parallelism().map_or(1, usize::from);
    segmented_mult_with_ncpus(points, scalar_bytes, ncpus)
}

fn segmented_mult_with_ncpus(
    points: &[AffinePointer],
    scalar_bytes: &[u8],
    ncpus: usize,
) -> BlsG1Projective {
    const NBITS: usize = 255;
    const SCALAR_BYTES: usize = 32;

    debug_assert!(ncpus > 0);
    debug_assert_eq!(scalar_bytes.len(), points.len() * SCALAR_BYTES);
    let npoints = points.len();
    // The widest input window makes the fused million-point shape allocate
    // twice as many buckets per worker as the former half-sized MSMs. Capping
    // it retains most of the fused speedup without that peak-memory jump.
    let input_window = pippenger_window_size(npoints).min(16);
    let (nx, ny, window) = pippenger_breakdown(NBITS, input_window, ncpus);

    let mut tiles = Vec::with_capacity(nx * ny);
    let chunk = npoints / nx;
    for row in 0..ny {
        let bit = window * (ny - row - 1);
        for column in 0..nx {
            let x = column * chunk;
            let dx = if column + 1 == nx { npoints - x } else { chunk };
            tiles.push(PippengerTile { x, dx, bit });
        }
    }

    let outputs = (0..tiles.len())
        .map(|_| Mutex::new(blst_p1::default()))
        .collect::<Vec<_>>();
    let next = AtomicUsize::new(0);
    let workers = ncpus.min(tiles.len());
    #[allow(unsafe_code)]
    let scratch_words =
        unsafe { blst_p1s_mult_pippenger_scratch_sizeof(0) / std::mem::size_of::<u64>() }
            << (window - 1);

    let worker = || {
        let mut scratch = vec![0_u64; scratch_words];
        loop {
            let work = next.fetch_add(1, Ordering::Relaxed);
            let Some(tile) = tiles.get(work) else {
                break;
            };
            let scalar_ptrs = [
                scalar_bytes.as_ptr().wrapping_add(tile.x * SCALAR_BYTES),
                ptr::null(),
            ];
            let mut result = blst_p1::default();
            // SAFETY: Every point pointer references a live immutable
            // affine input. This tile stays within both the point array
            // and the contiguous scalar-byte buffer. `scratch` is
            // private to this worker and sized as required by blst.
            #[allow(unsafe_code)]
            unsafe {
                blst_p1s_tile_pippenger(
                    &mut result,
                    points.as_ptr().add(tile.x).cast(),
                    tile.dx,
                    scalar_ptrs.as_ptr(),
                    NBITS,
                    scratch.as_mut_ptr(),
                    tile.bit,
                    window,
                );
            }
            *outputs[work]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = result;
        }
    };
    if workers == 1 {
        worker();
    } else {
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(worker);
            }
        });
    }

    let mut result = blst_p1::default();
    let result_ptr = std::ptr::addr_of_mut!(result);
    for row in 0..ny {
        if row != 0 {
            for _ in 0..window {
                // SAFETY: `result` is initialized, and blst permits in-place
                // doubling.
                #[allow(unsafe_code)]
                unsafe {
                    blst_p1_double(result_ptr, result_ptr.cast_const());
                }
            }
        }
        for column in 0..nx {
            let tile = *outputs[row * nx + column]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // SAFETY: Both operands are initialized blst points, and blst
            // permits the output to alias its first operand.
            #[allow(unsafe_code)]
            unsafe {
                blst_p1_add_or_double(result_ptr, result_ptr.cast_const(), &tile);
            }
        }
    }

    BlsG1Projective(blstrs::G1Projective::from_raw_unchecked(
        result.x.into(),
        result.y.into(),
        result.z.into(),
    ))
}

fn append_scalar_bytes(bytes: &mut Vec<u8>, scalars: &[Scalar]) {
    for scalar in scalars {
        bytes.extend_from_slice(&scalar.to_bytes());
    }
}

fn num_bits(value: usize) -> usize {
    usize::BITS as usize - value.leading_zeros() as usize
}

fn pippenger_window_size(npoints: usize) -> usize {
    match num_bits(npoints) {
        bits if bits > 13 => bits - 4,
        bits if bits > 5 => bits - 3,
        _ => 2,
    }
}

// Keep this scheduler in sync with blst's Rust `MultiPoint` implementation.
fn pippenger_breakdown(nbits: usize, window: usize, ncpus: usize) -> (usize, usize, usize) {
    let mut nx = 1;
    let mut wnd = window;

    if nbits > window * ncpus {
        wnd = num_bits(ncpus / 4);
        if window + wnd > 18 {
            wnd = window - wnd;
        } else {
            wnd = (nbits / window).div_ceil(ncpus);
            wnd = if (nbits / (window + 1)).div_ceil(ncpus) < wnd {
                window + 1
            } else {
                window
            };
        }
    } else if window > 3 {
        nx = 2;
        wnd = window - 2;
        while wnd > 1 && (nbits / wnd + 1) * nx < ncpus {
            nx += 1;
            wnd = window - num_bits(3 * nx / 2);
        }
        nx -= 1;
        wnd = window - num_bits(3 * nx / 2);
    }
    let ny = nbits / wnd + 1;
    wnd = nbits / ny + 1;

    (nx, ny, wnd)
}

/// Normalize projective points through `blst`.
pub(crate) fn batch_normalize(points: &[BlsG1Projective]) -> Vec<blst_p1_affine> {
    if points.is_empty() {
        return Vec::new();
    }

    let points: Vec<blst_p1> = points.iter().map(|point| *point.0.as_ref()).collect();
    p1_affines::from(&points).as_slice().to_vec()
}

fn scalar_bytes(scalars: &[Scalar]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(scalars.len() * 32);
    for scalar in scalars {
        bytes.extend_from_slice(&scalar.to_bytes());
    }
    bytes
}

/// Clear the BLS12-381 G1 cofactor with its 64-bit effective cofactor.
pub(crate) fn clear_cofactor(point: &blstrs::G1Projective) -> blstrs::G1Projective {
    const EFFECTIVE_COFACTOR: u64 = 0xd201_0000_0001_0001;
    let mut result = blst_p1::default();

    // SAFETY: Both point pointers are valid for the call and do not overlap.
    // The scalar buffer contains the requested 64 bits in blst's little-endian
    // format.
    #[allow(unsafe_code)]
    unsafe {
        blst::blst_p1_mult(
            &mut result,
            point.as_ref(),
            EFFECTIVE_COFACTOR.to_le_bytes().as_ptr(),
            64,
        );
    }

    blstrs::G1Projective::from_raw_unchecked(result.x.into(), result.y.into(), result.z.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ff::Field;
    use group::prime::PrimeCurveAffine;
    use group::{Curve, Group};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn naive_msm(scalars: &[Scalar], points: &[BlsG1Projective]) -> BlsG1Projective {
        let mut acc = BlsG1Projective::identity();
        for (s, p) in scalars.iter().zip(points) {
            acc += p * s;
        }
        acc
    }

    fn naive_msm_affine(scalars: &[Scalar], bases: &[blstrs::G1Affine]) -> BlsG1Projective {
        let points: Vec<_> = bases
            .iter()
            .map(|point| BlsG1Projective(blstrs::G1Projective::from(point)))
            .collect();
        naive_msm(scalars, &points)
    }

    fn raw_bases(bases: &[blstrs::G1Affine]) -> Vec<blst_p1_affine> {
        bases.iter().map(|base| *base.as_ref()).collect()
    }

    #[test]
    fn identity_bases_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let id = blstrs::G1Affine::identity();
        let p = blstrs::G1Projective::random(&mut rng).to_affine();
        let q = blstrs::G1Projective::random(&mut rng).to_affine();
        let s: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();

        for bases in [vec![id, p, q, id], vec![id, id, id, id], vec![p, id, q, p]] {
            assert_eq!(msm(&s, &raw_bases(&bases)), naive_msm_affine(&s, &bases));
        }
    }

    #[test]
    fn zero_scalars_are_handled() {
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let bases: Vec<_> = (0..4)
            .map(|_| blstrs::G1Projective::random(&mut rng).to_affine())
            .collect();
        let scalars = vec![
            Scalar::ZERO,
            Scalar::random(&mut rng),
            Scalar::ZERO,
            Scalar::ZERO,
        ];
        assert_eq!(
            msm(&scalars, &raw_bases(&bases)),
            naive_msm_affine(&scalars, &bases)
        );

        let all_zero = vec![Scalar::ZERO; 4];
        assert_eq!(
            msm(&all_zero, &raw_bases(&bases)),
            BlsG1Projective::identity()
        );
    }

    #[test]
    fn result_can_be_the_identity() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let base = blstrs::G1Projective::random(&mut rng).to_affine();
        let s = Scalar::random(&mut rng);
        assert_eq!(
            msm(&[s, -s], &raw_bases(&[base, base])),
            BlsG1Projective::identity()
        );
    }

    #[test]
    fn matches_naive_sum_for_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for len in [0usize, 1, 2, 3, 5, 17, 64] {
            let scalars: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
            let points: Vec<_> = (0..len)
                .map(|_| BlsG1Projective::random(&mut rng))
                .collect();
            let affine: Vec<_> = points.iter().map(|point| point.0.to_affine()).collect();

            let got = msm(&scalars, &raw_bases(&affine));
            let want = naive_msm(&scalars, &points);
            assert_eq!(got, want, "mismatch at len={len}");
        }
    }

    #[test]
    fn mixed_msm_matches_separate_calculation() {
        let mut rng = ChaCha20Rng::seed_from_u64(24);
        let fixed_points: Vec<_> = (0..64)
            .map(|_| blstrs::G1Projective::random(&mut rng).to_affine())
            .collect();
        let fixed = raw_bases(&fixed_points);
        let dynamic: Vec<_> = (0..3).map(|_| BlsG1Projective::random(&mut rng)).collect();
        let scalars: Vec<_> = (0..67).map(|_| Scalar::random(&mut rng)).collect();

        let expected = msm(&scalars[..40], &fixed[..40])
            + msm(&scalars[40..64], &fixed[40..])
            + msm_projective(&scalars[64..], &dynamic);
        assert_eq!(
            msm_mixed(
                &[
                    (&scalars[..40], &fixed[..40]),
                    (&scalars[40..64], &fixed[40..]),
                ],
                &scalars[64..],
                &dynamic,
            ),
            expected
        );
        assert_eq!(msm_mixed(&[], &[], &[]), BlsG1Projective::identity());
    }

    #[test]
    fn segmented_msm_handles_single_cpu() {
        let mut rng = ChaCha20Rng::seed_from_u64(26);
        let scalars: Vec<_> = (0..64).map(|_| Scalar::random(&mut rng)).collect();
        let bases: Vec<_> = (0..64)
            .map(|_| blstrs::G1Projective::random(&mut rng).to_affine())
            .collect();
        let bases = raw_bases(&bases);
        let points = bases.iter().map(AffinePointer::from).collect::<Vec<_>>();
        let mut scalar_bytes = Vec::with_capacity(scalars.len() * 32);
        append_scalar_bytes(&mut scalar_bytes, &scalars);

        assert_eq!(
            segmented_mult_with_ncpus(&points, &scalar_bytes, 1),
            msm(&scalars, &bases)
        );
    }

    #[test]
    fn mixed_msm_handles_identity_repetition_and_cancellation() {
        let mut rng = ChaCha20Rng::seed_from_u64(25);
        let base = blstrs::G1Projective::random(&mut rng).to_affine();
        let fixed = raw_bases(&[base, base]);
        let scalar = Scalar::random(&mut rng);

        assert_eq!(
            msm_mixed(
                &[(&[scalar, -scalar], &fixed)],
                &[scalar],
                &[BlsG1Projective::identity()],
            ),
            BlsG1Projective::identity()
        );
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn mixed_msm_rejects_affine_length_mismatch() {
        msm_mixed(&[(&[Scalar::ONE], &[])], &[], &[]);
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn mixed_msm_rejects_dynamic_length_mismatch() {
        msm_mixed(&[], &[Scalar::ONE], &[]);
    }

    #[test]
    fn empty_input_is_identity() {
        let out = msm(&[], &[]);
        assert_eq!(out, BlsG1Projective::identity());
    }

    #[test]
    fn single_base_matches_scalar_mul() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let scalar = Scalar::random(&mut rng);
        let point = BlsG1Projective::generator();
        let affine = *point.0.to_affine().as_ref();

        let got = msm(&[scalar], &[affine]);
        assert_eq!(got, point * scalar);
    }

    #[test]
    fn matches_naive_sum_with_repeated_and_negated_bases() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let base = blstrs::G1Projective::random(&mut rng).to_affine();
        let s = Scalar::random(&mut rng);
        let scalars = [s, -s, s, -s, s];
        let bases = [base; 5];

        let got = msm(&scalars, &raw_bases(&bases));
        let want = BlsG1Projective(blstrs::G1Projective::from(base)) * s;
        assert_eq!(got, want);
    }

    #[test]
    fn batch_normalize_matches_individual_normalization() {
        let generator = BlsG1Projective::generator();
        let points = [BlsG1Projective::identity(), generator, generator.double()];
        let expected: Vec<_> = points
            .iter()
            .map(|point| *point.0.to_affine().as_ref())
            .collect();

        assert_eq!(batch_normalize(&points), expected);
        assert!(batch_normalize(&[]).is_empty());
    }

    #[test]
    fn cofactor_clear_matches_scalar_multiplication() {
        const EFFECTIVE_COFACTOR: u64 = 0xd201_0000_0001_0001;
        let point = blstrs::G1Projective::generator().double();
        let expected = point * blstrs::Scalar::from(EFFECTIVE_COFACTOR);

        assert_eq!(clear_cofactor(&point), expected);
    }
}
