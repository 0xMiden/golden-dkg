//! Pedersen and Bulletproofs generators, generic over a [`Cycle`].

#![allow(non_snake_case)]

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use digest::{ExtendableOutput, Update, XofReader};
#[cfg(all(feature = "cycle-pedersen", not(feature = "bulletproofs-compat")))]
use group::Group;
use sha3::Shake256;

use crate::cycle::Cycle;

/// A pair of base points for Pedersen commitments.
#[derive(Copy, Clone)]
pub struct PedersenGens<C: Cycle> {
    /// Base for the committed value.
    pub B: C::Point,
    /// Base for the blinding factor.
    pub B_blinding: C::Point,
}

impl<C: Cycle> PedersenGens<C> {
    /// Pedersen commitment `value * B + blinding * B_blinding`.
    pub fn commit(&self, value: C::Scalar, blinding: C::Scalar) -> C::Point {
        C::vartime_msm(&[value, blinding], &[self.B, self.B_blinding])
    }
}

#[cfg(all(feature = "cycle-pedersen", not(feature = "bulletproofs-compat")))]
impl<C: Cycle> Default for PedersenGens<C> {
    fn default() -> Self {
        let B = C::Point::generator();
        let B_compressed = C::point_compress(&B);
        let B_bytes = C::compressed_as_bytes(&B_compressed);
        let mut shake = Shake256::default();
        shake.update(b"bulletproofs-cycle/pedersen-blinding");
        shake.update(B_bytes);
        let mut uniform = [0u8; 64];
        shake.finalize_xof().read(&mut uniform);
        let B_blinding = C::point_hash_from_uniform(&uniform);
        PedersenGens { B, B_blinding }
    }
}

#[cfg(all(feature = "bulletproofs-compat", feature = "ristretto"))]
impl Default for PedersenGens<crate::ristretto_cycle::RistrettoCycle> {
    fn default() -> Self {
        use curve25519_dalek::constants::{
            RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT,
        };
        use curve25519_dalek::ristretto::RistrettoPoint;
        use sha3::Sha3_512;

        // Match upstream zkcrypto/bulletproofs: B is the canonical basepoint,
        // B_blinding is hash_from_bytes::<Sha3_512> on its compressed encoding.
        let B = RISTRETTO_BASEPOINT_POINT;
        let B_blinding =
            RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        PedersenGens { B, B_blinding }
    }
}

/// SHAKE256-driven chain of independent generators rooted at a label.
struct GeneratorsChain {
    reader: Shake256Reader,
}

use sha3::Shake256Reader;

impl GeneratorsChain {
    fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);
        GeneratorsChain {
            reader: shake.finalize_xof(),
        }
    }

    fn fast_forward(mut self, n: usize) -> Self {
        let mut buf = [0u8; 64];
        for _ in 0..n {
            self.reader.read(&mut buf);
        }
        self
    }
}

impl Iterator for GeneratorsChain {
    type Item = [u8; 64];

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform = [0u8; 64];
        self.reader.read(&mut uniform);
        Some(uniform)
    }
}

/// Precomputed `G` and `H` generators for up to `party_capacity` parties, each
/// with up to `gens_capacity` generators.
#[derive(Clone)]
pub struct BulletproofGens<C: Cycle> {
    /// Maximum generators per party.
    pub gens_capacity: usize,
    /// Number of parties supported.
    pub party_capacity: usize,
    G_vec: Vec<Arc<Vec<C::Point>>>,
    H_vec: Vec<Arc<Vec<C::Point>>>,
}

impl<C: Cycle> BulletproofGens<C> {
    /// Create a new generator set with the given capacities.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        let mut gens = BulletproofGens {
            gens_capacity: 0,
            party_capacity,
            G_vec: (0..party_capacity).map(|_| Arc::new(Vec::new())).collect(),
            H_vec: (0..party_capacity).map(|_| Arc::new(Vec::new())).collect(),
        };
        gens.increase_capacity(gens_capacity);
        gens
    }

    /// The `j`-th party's share of the generators.
    pub fn share(&self, j: usize) -> BulletproofGensShare<'_, C> {
        BulletproofGensShare {
            gens: self,
            share: j,
        }
    }

    /// Extend the per-party generator capacity to `new_capacity` if needed.
    pub(crate) fn increase_capacity(&mut self, new_capacity: usize) {
        if self.gens_capacity >= new_capacity {
            return;
        }
        for i in 0..self.party_capacity {
            let party_index = i as u32;
            let mut label_g = [b'G', 0, 0, 0, 0];
            label_g[1..5].copy_from_slice(&party_index.to_le_bytes());
            Arc::make_mut(&mut self.G_vec[i]).extend(
                GeneratorsChain::new(&label_g)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity)
                    .map(|uniform| C::point_hash_from_uniform(&uniform)),
            );

            let mut label_h = [b'H', 0, 0, 0, 0];
            label_h[1..5].copy_from_slice(&party_index.to_le_bytes());
            Arc::make_mut(&mut self.H_vec[i]).extend(
                GeneratorsChain::new(&label_h)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity)
                    .map(|uniform| C::point_hash_from_uniform(&uniform)),
            );
        }
        self.gens_capacity = new_capacity;
    }
}

/// A view of one party's generators within a [`BulletproofGens`].
#[derive(Copy, Clone)]
pub struct BulletproofGensShare<'a, C: Cycle> {
    gens: &'a BulletproofGens<C>,
    share: usize,
}

impl<'a, C: Cycle> BulletproofGensShare<'a, C> {
    /// This party's first `n` `G` generators.
    pub fn G(&self, n: usize) -> impl Iterator<Item = &'a C::Point> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// This party's first `n` `H` generators.
    pub fn H(&self, n: usize) -> impl Iterator<Item = &'a C::Point> {
        self.gens.H_vec[self.share].iter().take(n)
    }

    pub(crate) fn shared_G(&self) -> Arc<Vec<C::Point>> {
        Arc::clone(&self.gens.G_vec[self.share])
    }

    pub(crate) fn shared_H(&self) -> Arc<Vec<C::Point>> {
        Arc::clone(&self.gens.H_vec[self.share])
    }
}
