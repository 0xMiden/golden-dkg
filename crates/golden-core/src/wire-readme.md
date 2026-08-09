📋 Architecture & Performance Context
The canonical wire encoder in golden-core utilizes a varint parsing loop within read_len. The current implementation structurally checks for shift >= 64, but it fails to account for the upper bounds of u64 capacity at the final byte iteration. Specifically, when shift == 63 (the 10th byte of a varint), any raw byte value where byte & 0x7F > 1 will trigger a bitwise left-shift overflow. This results in a panic in debug environments and silent arithmetic wrapping in release builds, compromising state integrity.

This PR optimizes the abstraction by introducing a deterministic, low-level boundary check directly inside the loop. By preventing the arithmetic overflow before the shift operation executes, we strip out undefined runtime behavior, enforce strict data validation early in the execution path, and maintain the zero-overhead philosophy of the core decoder.

🔍 Key Changes
crates/golden-core/src/wire.rs / read_len: Replaced the naive shift >= 64 threshold with an optimized boundary guard. The logic now explicitly blocks invalid 10th-byte inputs (shift == 63 && byte > 0x01) that would overflow a 64-bit integer, guaranteeing safe, idiomatic Rust shift operations without framework-level wrappers.

💻 Proposed Code
File: crates/golden-core/src/wire.rs

Rust
    /// Read a varint length prefix.
    pub fn read_len(&mut self) -> Result<usize> {
        let mut value: u64 = 0;
        let mut shift = 0;
        
        loop {
            let byte = self.read_u8()?;
            
            // A 64-bit varint requires at most 10 bytes. At the 10th byte (shift == 63),
            // the value can only utilize 1 bit. Any value greater than 0x01 will overflow.
            if shift >= 64 || (shift == 63 && byte > 0x01) {
                return Err(Error::InvalidEncoding);
            }
            
            value |= u64::from(byte & 0x7F) << shift;
            
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        
        usize::try_from(value).map_err(|_| Error::InvalidEncoding)
    }