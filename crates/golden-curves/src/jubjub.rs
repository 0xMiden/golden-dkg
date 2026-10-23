//! Native Jubjub prime-order identity group and its strict protocol encoding.

use std::sync::OnceLock;

use ff::PrimeField;
use golden_core::{DkgGroup, Error, FieldByteOrder, Result};
use group::cofactor::CofactorGroup;
use group::{Group, GroupEncoding};
use jubjub::{AffinePoint, ExtendedPoint, Fq, Fr, SubgroupPoint};
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Native Jubjub scalar field.
pub type Scalar = Fr;
/// Native Jubjub prime-order subgroup point.
pub type Point = SubgroupPoint;
/// Native Jubjub base field (also the BLS12-381 scalar field).
pub type BaseField = Fq;

/// Jubjub as Golden's prime-order identity/DH group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JubjubGroup {}

impl DkgGroup for JubjubGroup {
    type Scalar = Scalar;
    type Point = Point;
    type BaseField = BaseField;

    const GROUP_ID: &'static str = "jubjub";
    const POINT_BYTES: usize = 32;

    fn encode_point(point: &Point) -> Vec<u8> {
        point.to_bytes().to_vec()
    }

    fn decode_point(bytes: &[u8]) -> Result<Point> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        // SubgroupPoint's checked decoder performs the torsion-free check.
        // Never substitute from_bytes_unchecked or clear a received cofactor.
        let point =
            Option::<Point>::from(Point::from_bytes(&bytes)).ok_or(Error::InvalidEncoding)?;
        if Self::encode_point(&point).as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(point)
    }

    fn encode_scalar(scalar: &Scalar) -> [u8; 32] {
        scalar.to_repr()
    }

    fn decode_scalar(bytes: &[u8]) -> Result<Scalar> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        let scalar =
            Option::<Scalar>::from(Scalar::from_repr(bytes)).ok_or(Error::InvalidEncoding)?;
        if Self::encode_scalar(&scalar) != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(scalar)
    }

    fn base_field_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }

    fn hash_to_point(domain: &[u8], input: &[u8]) -> Result<Point> {
        let domain_len = u64::try_from(domain.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let input_len = u64::try_from(input.len()).map_err(|_| Error::ArithmeticOverflow)?;
        for counter in 0..=u32::MAX {
            let mut hash = Sha256::new();
            hash.update(b"golden-jubjub-h2c-v1");
            hash.update(domain_len.to_be_bytes());
            hash.update(domain);
            hash.update(input_len.to_be_bytes());
            hash.update(input);
            hash.update(counter.to_be_bytes());
            let candidate: [u8; 32] = hash.finalize().into();
            if let Some(affine) = Option::<AffinePoint>::from(AffinePoint::from_bytes(candidate)) {
                let extended: ExtendedPoint = affine.into();
                let point = extended.clear_cofactor();
                if !bool::from(point.is_identity()) {
                    return Ok(point);
                }
            }
        }
        Err(Error::InvalidEncoding)
    }

    fn affine_x(point: &Point) -> Result<BaseField> {
        if bool::from(point.is_identity()) {
            return Err(Error::InvalidEncoding);
        }
        let affine = AffinePoint::from(ExtendedPoint::from(*point));
        Ok(affine.get_u())
    }

    fn reduce_base_field(value: &BaseField) -> Scalar {
        // The base modulus exceeds eight scalar orders; one subtraction or
        // reinterpretation is insufficient. Horner reduction covers all bytes.
        crate::reduce_le_bytes(value.to_repr().as_ref())
    }

    fn mul_generator(scalar: &Scalar) -> Point {
        mul_generator(scalar)
    }
}

const GENERATOR_WINDOWS: usize = 64;
const GENERATOR_WINDOW_ENTRIES: usize = 16;

/// Constant-time fixed-base multiplication using deterministic public tables.
///
/// Every scalar nibble visits every entry of its window; secret digits never
/// select a branch or a table index. This table is not proof preparation.
pub fn mul_generator(scalar: &Scalar) -> Point {
    static TABLE: OnceLock<Vec<[Point; GENERATOR_WINDOW_ENTRIES]>> = OnceLock::new();
    let table = TABLE.get_or_init(build_generator_table);
    let bytes = scalar.to_repr();
    let mut result = Point::identity();
    for (window, row) in table.iter().enumerate() {
        let digit = (bytes[window / 2] >> (4 * (window % 2))) & 0x0f;
        let mut selected = Point::identity();
        for (index, entry) in row.iter().enumerate() {
            selected.conditional_assign(entry, digit.ct_eq(&(index as u8)));
        }
        result += selected;
    }
    result
}

fn build_generator_table() -> Vec<[Point; GENERATOR_WINDOW_ENTRIES]> {
    let mut base = Point::generator();
    let mut table = Vec::with_capacity(GENERATOR_WINDOWS);
    for _ in 0..GENERATOR_WINDOWS {
        let mut row = [Point::identity(); GENERATOR_WINDOW_ENTRIES];
        for digit in 1..GENERATOR_WINDOW_ENTRIES {
            row[digit] = row[digit - 1] + base;
        }
        table.push(row);
        base = base.double().double().double().double();
    }
    table
}
