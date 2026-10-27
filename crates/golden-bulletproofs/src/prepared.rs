//! Typed artifact storage, deliberately separate from proof/protocol encoding.
use crate::{driver::Backend, shape::required_capacity};
use bulletproofs_cycle::{
    generators::{BulletproofGens, PedersenGens},
    Cycle,
};
use golden_core::wire::{framed as frame, Reader};
use golden_core::{DkgConfig, DkgGroup, Error, Result, PROTOCOL_VERSION};
use group::Group;

const MAGIC: &[u8] = b"golden-dkg-prepared";
const VERSION: u32 = 1;

pub(crate) struct Prepared<C: Backend> {
    pub capacity: usize,
    pub generators: Option<(PedersenGens<C>, BulletproofGens<C>)>,
}
impl<C: Backend> Prepared<C> {
    pub fn prepare_for(config: &DkgConfig<C::Dkg>) -> Result<Self> {
        let capacity = required_capacity::<C>(config)?;
        let generators = if capacity == 0 {
            None
        } else {
            Some((
                PedersenGens::<C>::default(),
                BulletproofGens::<C>::new(capacity, 1),
            ))
        };
        Ok(Self {
            capacity,
            generators,
        })
    }
    pub fn check_capacity(&self, config: &DkgConfig<C::Dkg>) -> Result<()> {
        let required = required_capacity::<C>(config)?;
        if self.capacity < required {
            return Err(Error::InsufficientProofCapacity {
                required,
                available: self.capacity,
            });
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        frame(&mut bytes, MAGIC)?;
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        frame(&mut bytes, <C::Dkg as DkgGroup>::GROUP_ID.as_bytes())?;
        frame(&mut bytes, C::CYCLE_ID.as_bytes())?;
        frame(&mut bytes, C::PROOF_ID)?;
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(
            &u64::try_from(self.capacity)
                .map_err(|_| Error::MalformedPreparedGenerators)?
                .to_be_bytes(),
        );
        if self.capacity == 0 {
            if self.generators.is_some() {
                return Err(Error::MalformedPreparedGenerators);
            }
            return Ok(bytes);
        }
        let (pc, bp) = self
            .generators
            .as_ref()
            .ok_or(Error::MalformedPreparedGenerators)?;
        if !self.capacity.is_power_of_two()
            || bp.gens_capacity < self.capacity
            || bp.party_capacity != 1
        {
            return Err(Error::MalformedPreparedGenerators);
        }
        let point_count = self
            .capacity
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::MalformedPreparedGenerators)?;
        let additional = point_count
            .checked_mul(C::COMPRESSED_BYTES)
            .ok_or(Error::MalformedPreparedGenerators)?;
        bytes
            .try_reserve_exact(additional)
            .map_err(|_| Error::ProofOperationFailed)?;
        append_point::<C>(&mut bytes, &pc.B)?;
        append_point::<C>(&mut bytes, &pc.B_blinding)?;
        let share = bp.share(0);
        for point in share.G(self.capacity).chain(share.H(self.capacity)) {
            let encoded = C::affine_compress(point);
            bytes.extend_from_slice(C::compressed_as_bytes(&encoded));
        }
        Ok(bytes)
    }
    /// The caller must authenticate intact bytes from approved generation.
    /// Structural validity, arbitrary signatures, and received-byte digests do
    /// not establish correct generator generation. No bases are regenerated.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes).map_err(|error| match error {
            Error::ProofOperationFailed | Error::AllocationFailed => error,
            _ => Error::MalformedPreparedGenerators,
        })
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        expect_frame(&mut reader, MAGIC)?;
        if reader.u32()? != VERSION || reader.u32()? != PROTOCOL_VERSION {
            return Err(Error::MalformedPreparedGenerators);
        }
        expect_frame(&mut reader, <C::Dkg as DkgGroup>::GROUP_ID.as_bytes())?;
        expect_frame(&mut reader, C::CYCLE_ID.as_bytes())?;
        expect_frame(&mut reader, C::PROOF_ID)?;
        if reader.u32()? != 1 {
            return Err(Error::MalformedPreparedGenerators);
        }
        let capacity = usize::try_from(u64::from_be_bytes(reader.array::<8>()?))
            .map_err(|_| Error::MalformedPreparedGenerators)?;
        if capacity != 0 && !capacity.is_power_of_two() {
            return Err(Error::MalformedPreparedGenerators);
        }
        let point_count = if capacity == 0 {
            0
        } else {
            capacity
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or(Error::MalformedPreparedGenerators)?
        };
        let expected = point_count
            .checked_mul(C::COMPRESSED_BYTES)
            .ok_or(Error::MalformedPreparedGenerators)?;
        if reader.remaining() != expected {
            return Err(Error::MalformedPreparedGenerators);
        }
        if capacity == 0 {
            return Ok(Self {
                capacity,
                generators: None,
            });
        }
        let pc = PedersenGens::<C> {
            B: read_point::<C>(&mut reader)?,
            B_blinding: read_point::<C>(&mut reader)?,
        };
        let mut g = Vec::new();
        let mut h = Vec::new();
        g.try_reserve_exact(capacity)
            .map_err(|_| Error::ProofOperationFailed)?;
        h.try_reserve_exact(capacity)
            .map_err(|_| Error::ProofOperationFailed)?;
        for _ in 0..capacity {
            g.push(C::point_to_affine(&read_point::<C>(&mut reader)?));
        }
        for _ in 0..capacity {
            h.push(C::point_to_affine(&read_point::<C>(&mut reader)?));
        }
        let bp = BulletproofGens::<C>::from_prefixes(capacity, 1, vec![g], vec![h])
            .map_err(|_| Error::MalformedPreparedGenerators)?;
        Ok(Self {
            capacity,
            generators: Some((pc, bp)),
        })
    }
}
fn append_point<C: Cycle>(bytes: &mut Vec<u8>, point: &C::Point) -> Result<()> {
    if bool::from(point.is_identity()) {
        return Err(Error::MalformedPreparedGenerators);
    }
    let repr = C::point_compress(point);
    bytes.extend_from_slice(C::compressed_as_bytes(&repr));
    Ok(())
}
fn read_point<C: Cycle>(reader: &mut Reader<'_>) -> Result<C::Point> {
    let bytes = reader.take(C::COMPRESSED_BYTES)?;
    let repr = C::compressed_from_bytes(bytes);
    let point = C::compressed_decompress(&repr).ok_or(Error::MalformedPreparedGenerators)?;
    let canonical = C::point_compress(&point);
    if bool::from(point.is_identity()) || C::compressed_as_bytes(&canonical) != bytes {
        return Err(Error::MalformedPreparedGenerators);
    }
    Ok(point)
}
fn expect_frame(reader: &mut Reader<'_>, expected: &[u8]) -> Result<()> {
    if reader.framed()? != expected {
        return Err(Error::MalformedPreparedGenerators);
    }
    Ok(())
}

#[cfg(feature = "serde")]
pub(crate) fn serialize<C: Backend, S: serde::Serializer>(
    value: &Prepared<C>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    let bytes = value.to_bytes().map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}
/// Requires authenticated approved-generation storage, just like byte restoration.
#[cfg(feature = "serde")]
pub(crate) fn deserialize<'de, C: Backend, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Prepared<C>, D::Error> {
    struct Visitor<C>(core::marker::PhantomData<C>);
    impl<'de, C: Backend> serde::de::Visitor<'de> for Visitor<C> {
        type Value = Prepared<C>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("authenticated approved-generation Golden prepared artifact bytes")
        }
        fn visit_bytes<E: serde::de::Error>(
            self,
            bytes: &[u8],
        ) -> core::result::Result<Self::Value, E> {
            Prepared::<C>::from_bytes(bytes).map_err(E::custom)
        }
        fn visit_byte_buf<E: serde::de::Error>(
            self,
            bytes: Vec<u8>,
        ) -> core::result::Result<Self::Value, E> {
            self.visit_bytes(&bytes)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let mut bytes = Vec::<u8>::new();
            while let Some(byte) = sequence.next_element()? {
                bytes.try_reserve(1).map_err(serde::de::Error::custom)?;
                bytes.push(byte);
            }
            self.visit_bytes(&bytes)
        }
    }
    deserializer.deserialize_bytes(Visitor::<C>(core::marker::PhantomData))
}

macro_rules! concrete_system {
    ($prepared:ident,$system:ident,$cycle:ty,$group:ty) => {
        /// Immutable explicitly owned generator prefix. Restoring it requires
        /// authenticated intact storage from approved generation; structural
        /// validity alone does not establish correct generator generation.
        #[derive(Clone)]
        pub struct $prepared(std::sync::Arc<crate::prepared::Prepared<$cycle>>);
        impl $prepared {
            /// Expand the minimally padded generator requirement explicitly.
            /// Configurations without receivers, which are exactly the plain single-participant
            /// ones, return zero capacity without preparing bases.
            pub fn prepare_for(
                config: &golden_core::DkgConfig<$group>,
            ) -> golden_core::Result<Self> {
                Ok(Self(std::sync::Arc::new(
                    crate::prepared::Prepared::prepare_for(config)?,
                )))
            }
            /// Declared generator capacity, independent of other owners.
            pub fn capacity(&self) -> usize {
                self.0.capacity
            }
            /// Encode exactly the declared prefix for authenticated storage.
            pub fn to_bytes(&self) -> golden_core::Result<Vec<u8>> {
                self.0.to_bytes()
            }
            /// Restore canonical approved-generation artifact bytes.
            ///
            /// The caller must ensure intact authenticated approved-generation
            /// provenance. Structural validity, arbitrary producer signatures or
            /// received-byte digests do not establish correct generation.
            pub fn from_bytes(bytes: &[u8]) -> golden_core::Result<Self> {
                Ok(Self(std::sync::Arc::new(
                    crate::prepared::Prepared::from_bytes(bytes)?,
                )))
            }
        }
        impl core::fmt::Debug for $prepared {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($prepared))
                    .field("capacity", &self.capacity())
                    .finish_non_exhaustive()
            }
        }
        #[cfg(feature = "serde")]
        impl serde::Serialize for $prepared {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                crate::prepared::serialize(self.0.as_ref(), serializer)
            }
        }
        /// Serde restoration requires authenticated intact approved-generation
        /// storage, just like `from_bytes`; structural validity is insufficient.
        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $prepared {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                Ok(Self(std::sync::Arc::new(crate::prepared::deserialize::<
                    $cycle,
                    D,
                >(deserializer)?)))
            }
        }
        /// Reusable proof system sharing immutable explicitly prepared state.
        #[derive(Clone)]
        pub struct $system(std::sync::Arc<crate::prepared::Prepared<$cycle>>);
        impl $system {
            /// Construct from an owned or cloned approved prepared artifact.
            pub fn from_prepared(prepared: $prepared) -> Self {
                Self(prepared.0)
            }
            /// Prepare a proof system explicitly for this configuration.
            pub fn prepare_for(
                config: &golden_core::DkgConfig<$group>,
            ) -> golden_core::Result<Self> {
                Ok(Self::from_prepared($prepared::prepare_for(config)?))
            }
            /// Declared prepared generator capacity.
            pub fn capacity(&self) -> usize {
                self.0.capacity
            }
        }
        impl core::fmt::Debug for $system {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($system))
                    .field("capacity", &self.capacity())
                    .finish_non_exhaustive()
            }
        }
        impl golden_core::DealerProofSystem<$group> for $system {
            fn prove(
                &self,
                config: &golden_core::DkgConfig<$group>,
                statement: &golden_core::DealerProofStatement<$group>,
                witness: &golden_core::DealerProofWitness<$group>,
                rng: &mut impl rand_core::CryptoRngCore,
            ) -> golden_core::Result<Vec<u8>> {
                crate::driver::prove::<$cycle>(self.0.as_ref(), config, statement, witness, rng)
            }
            fn verify(
                &self,
                config: &golden_core::DkgConfig<$group>,
                statement: &golden_core::DealerProofStatement<$group>,
                proof: &[u8],
            ) -> golden_core::Result<()> {
                crate::driver::verify::<$cycle>(self.0.as_ref(), config, statement, proof)
            }
            fn verify_batch(
                &self,
                config: &golden_core::DkgConfig<$group>,
                proofs: &[golden_core::DealerProofRef<'_, $group>],
            ) -> golden_core::Result<()> {
                crate::driver::verify_batch::<$cycle>(self.0.as_ref(), config, proofs)
            }
        }
    };
}
pub(crate) use concrete_system;
