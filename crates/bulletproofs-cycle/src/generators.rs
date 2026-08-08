//! Pedersen and Bulletproofs generators, generic over a [`Cycle`].

#![allow(non_snake_case)]

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use digest::{ExtendableOutput, Update, XofReader};
#[cfg(all(feature = "cycle-pedersen", not(feature = "bulletproofs-compat")))]
use group::Group;
use p3_maybe_rayon::prelude::*;
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
    G_vec: Vec<Arc<Vec<C::Affine>>>,
    H_vec: Vec<Arc<Vec<C::Affine>>>,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "A: serde::Serialize",
    deserialize = "A: serde::Deserialize<'de>"
))]
struct BulletproofGensRepr<A> {
    gens_capacity: usize,
    party_capacity: usize,
    g_vec: Vec<Arc<Vec<A>>>,
    h_vec: Vec<Arc<Vec<A>>>,
}

#[cfg(feature = "serde")]
impl<C> serde::Serialize for BulletproofGens<C>
where
    C: Cycle,
    C::Affine: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BulletproofGensRepr {
            gens_capacity: self.gens_capacity,
            party_capacity: self.party_capacity,
            g_vec: self.G_vec.clone(),
            h_vec: self.H_vec.clone(),
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for BulletproofGens<C>
where
    C: Cycle,
    C::Affine: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        fn validate<C: Cycle, E: serde::de::Error>(
            parties: &[Arc<Vec<C::Affine>>],
            gens_capacity: usize,
            party_capacity: usize,
        ) -> Result<(), E> {
            gens_capacity
                .checked_mul(party_capacity)
                .ok_or_else(|| E::custom("generator count overflow"))?;
            if parties.len() != party_capacity
                || parties.iter().any(|party| party.len() != gens_capacity)
            {
                return Err(E::custom("generator dimensions do not match capacities"));
            }
            for point in parties.iter().flat_map(|party| party.iter()) {
                if C::compressed_is_identity(&C::affine_compress(point)) {
                    return Err(E::custom("generator must not be the identity"));
                }
            }
            Ok(())
        }

        let repr = BulletproofGensRepr::<C::Affine>::deserialize(deserializer)?;
        validate::<C, D::Error>(&repr.g_vec, repr.gens_capacity, repr.party_capacity)?;
        validate::<C, D::Error>(&repr.h_vec, repr.gens_capacity, repr.party_capacity)?;
        Ok(Self {
            gens_capacity: repr.gens_capacity,
            party_capacity: repr.party_capacity,
            G_vec: repr.g_vec,
            H_vec: repr.h_vec,
        })
    }
}

impl<C: Cycle> BulletproofGens<C> {
    fn derive(label: &[u8], offset: usize, count: usize) -> Vec<C::Affine> {
        let uniforms: Vec<[u8; 64]> = GeneratorsChain::new(label)
            .fast_forward(offset)
            .take(count)
            .collect();
        let points: Vec<C::Point> = uniforms
            .into_par_iter()
            .map(|uniform| C::point_hash_from_uniform(&uniform))
            .collect();
        C::batch_normalize(&points)
    }

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
            Arc::make_mut(&mut self.G_vec[i]).extend(Self::derive(
                &label_g,
                self.gens_capacity,
                new_capacity - self.gens_capacity,
            ));

            let mut label_h = [b'H', 0, 0, 0, 0];
            label_h[1..5].copy_from_slice(&party_index.to_le_bytes());
            Arc::make_mut(&mut self.H_vec[i]).extend(Self::derive(
                &label_h,
                self.gens_capacity,
                new_capacity - self.gens_capacity,
            ));
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
    pub fn G(&self, n: usize) -> impl Iterator<Item = &'a C::Affine> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// This party's first `n` `H` generators.
    pub fn H(&self, n: usize) -> impl Iterator<Item = &'a C::Affine> {
        self.gens.H_vec[self.share].iter().take(n)
    }

    pub(crate) fn shared_G(&self) -> Arc<Vec<C::Affine>> {
        Arc::clone(&self.gens.G_vec[self.share])
    }

    pub(crate) fn shared_H(&self) -> Arc<Vec<C::Affine>> {
        Arc::clone(&self.gens.H_vec[self.share])
    }
}

#[cfg(all(test, feature = "ristretto"))]
mod tests {
    use super::*;
    use crate::ristretto_cycle::RistrettoCycle;

    #[test]
    fn parallel_derivation_matches_serial_chain() {
        type C = RistrettoCycle;

        let gens = BulletproofGens::<C>::new(64, 1);
        let expected_g: Vec<<C as Cycle>::Point> = GeneratorsChain::new(b"G\0\0\0\0")
            .take(64)
            .map(|uniform| C::point_hash_from_uniform(&uniform))
            .collect();
        let actual_g: Vec<<C as Cycle>::Point> =
            gens.share(0).G(64).map(C::affine_to_point).collect();

        assert_eq!(actual_g, expected_g);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn generator_serialization_roundtrip() {
        use group::Group as _;

        type C = RistrettoCycle;

        let gens = BulletproofGens::<C>::new(8, 2);
        let encoded = postcard::to_allocvec(&gens).expect("serialize generators");
        let decoded: BulletproofGens<C> =
            postcard::from_bytes(&encoded).expect("deserialize generators");

        assert_eq!(decoded.gens_capacity, gens.gens_capacity);
        assert_eq!(decoded.party_capacity, gens.party_capacity);
        for party in 0..gens.party_capacity {
            assert_eq!(
                decoded.share(party).G(8).collect::<Vec<_>>(),
                gens.share(party).G(8).collect::<Vec<_>>()
            );
            assert_eq!(
                decoded.share(party).H(8).collect::<Vec<_>>(),
                gens.share(party).H(8).collect::<Vec<_>>()
            );
        }

        assert!(postcard::from_bytes::<BulletproofGens<C>>(&encoded[..encoded.len() - 1]).is_err());

        #[derive(serde::Serialize)]
        struct Repr<A> {
            gens_capacity: usize,
            party_capacity: usize,
            g_vec: Vec<Arc<Vec<A>>>,
            h_vec: Vec<Arc<Vec<A>>>,
        }

        let identity = C::point_to_affine(&<C as Cycle>::Point::identity());
        let encoded_identity = postcard::to_allocvec(&Repr {
            gens_capacity: 1,
            party_capacity: 1,
            g_vec: vec![Arc::new(vec![identity])],
            h_vec: vec![Arc::new(vec![identity])],
        })
        .expect("serialize identity generators");
        assert!(postcard::from_bytes::<BulletproofGens<C>>(&encoded_identity).is_err());
    }
}
