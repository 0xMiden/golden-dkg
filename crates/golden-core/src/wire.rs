//! Private checked primitives shared by protocol and state encodings.
use crate::{Error, Result};

pub fn reserve<T>(length: usize) -> Result<Vec<T>> {
    let mut out = Vec::new();
    out.try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed)?;
    Ok(out)
}

pub fn count(out: &mut Vec<u8>, value: usize) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    Ok(())
}

pub fn framed(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| Error::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidEncoding)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn count(&mut self) -> Result<usize> {
        usize::try_from(self.u32()?).map_err(|_| Error::InvalidEncoding)
    }
    pub fn framed(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(u64::from_be_bytes(self.array()?))
            .map_err(|_| Error::InvalidEncoding)?;
        self.take(length)
    }
    pub fn ensure_items(&self, count: usize, item_size: usize) -> Result<()> {
        let length = count.checked_mul(item_size).ok_or(Error::InvalidEncoding)?;
        if length > self.remaining() {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}
