//! Native Secp256k1 identity group and its strict protocol encoding.

use std::sync::OnceLock;

use ff::PrimeField;
use golden_core::{DkgGroup, Error, FieldByteOrder, Result};
use group::{Curve, Group, GroupEncoding};
use halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2curves::serde::Repr;
use halo2curves::{Coordinates, CurveAffine, CurveExt};
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Native Secp256k1 scalar field.
pub type Scalar = Fq;
/// Native Secp256k1 projective point.
pub type Point = Secp256k1;
/// Native Secp256k1 base field.
pub type BaseField = Fp;

/// Secp256k1 as Golden's prime-order identity/DH group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Secp256k1Group {}

impl DkgGroup for Secp256k1Group {
    type Scalar = Scalar;
    type Point = Point;
    type BaseField = BaseField;

    const GROUP_ID: &'static str = "secp256k1";
    const POINT_BYTES: usize = 33;

    fn encode_point(point: &Point) -> Vec<u8> {
        if bool::from(point.is_identity()) {
            return vec![0; Self::POINT_BYTES];
        }
        // halo2curves uses a sign flag followed by little-endian x. Golden
        // uses SEC1: 02/03 followed by the big-endian x-coordinate.
        let native = point.to_bytes();
        let native = native.as_ref();
        let mut bytes = vec![0; Self::POINT_BYTES];
        bytes[0] = 2 | (native[0] >> 7);
        bytes[1..].copy_from_slice(&native[1..]);
        bytes[1..].reverse();
        bytes
    }

    fn decode_point(bytes: &[u8]) -> Result<Point> {
        let bytes: [u8; 33] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        if bytes == [0; 33] {
            return Ok(Point::identity());
        }
        if !matches!(bytes[0], 2 | 3) {
            return Err(Error::InvalidEncoding);
        }
        let mut native = bytes;
        native[0] = (bytes[0] & 1) << 7;
        native[1..].reverse();
        let point = Option::<Point>::from(Point::from_bytes(&Repr::from(native)))
            .ok_or(Error::InvalidEncoding)?;
        if Self::encode_point(&point).as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(point)
    }

    fn encode_scalar(scalar: &Scalar) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(scalar.to_repr().as_ref());
        bytes
    }

    fn decode_scalar(bytes: &[u8]) -> Result<Scalar> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        let scalar = Option::<Scalar>::from(Scalar::from_repr(Repr::from(bytes)))
            .ok_or(Error::InvalidEncoding)?;
        if Self::encode_scalar(&scalar) != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(scalar)
    }

    fn base_field_byte_order() -> FieldByteOrder {
        FieldByteOrder::LittleEndian
    }

    fn hash_to_point(domain: &[u8], input: &[u8]) -> Result<Point> {
        let domain = core::str::from_utf8(domain).map_err(|_| Error::InvalidEncoding)?;
        let point = <Point as CurveExt>::hash_to_curve(domain)(input);
        if bool::from(point.is_identity()) {
            return Err(Error::InvalidEncoding);
        }
        Ok(point)
    }

    fn affine_x(point: &Point) -> Result<BaseField> {
        if bool::from(point.is_identity()) {
            return Err(Error::InvalidEncoding);
        }
        let affine = point.to_affine();
        let coordinates = Option::<Coordinates<Secp256k1Affine>>::from(affine.coordinates())
            .ok_or(Error::InvalidEncoding)?;
        Ok(*coordinates.x())
    }

    fn reduce_base_field(value: &BaseField) -> Scalar {
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
/// select a branch or a table index. This table contains only public canonical
/// generator multiples and is independent of proof-generator preparation.
pub fn mul_generator(scalar: &Scalar) -> Point {
    static TABLE: OnceLock<Vec<[Point; GENERATOR_WINDOW_ENTRIES]>> = OnceLock::new();
    let table = TABLE.get_or_init(build_generator_table);
    let repr = scalar.to_repr();
    let bytes = repr.as_ref();
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
