//! Bridge Golden's rand_core 0.6 RNGs to RustCrypto's rand_core 0.10 API.

use core::convert::Infallible;

pub(crate) struct RngCompat<'a, R>(pub(crate) &'a mut R);

impl<R: rand_core::CryptoRngCore> rand_core_10::TryRng for RngCompat<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: rand_core::CryptoRngCore> rand_core_10::TryCryptoRng for RngCompat<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use rand_core_10::Rng;

    #[test]
    fn bridge_preserves_rng_output_and_state() {
        let mut expected = ChaCha20Rng::from_seed([42; 32]);
        let mut source = expected.clone();
        let mut bridge = RngCompat(&mut source);

        assert_eq!(bridge.next_u32(), expected.next_u32());
        assert_eq!(bridge.next_u64(), expected.next_u64());
        let mut actual_bytes = [0; 37];
        let mut expected_bytes = [0; 37];
        bridge.fill_bytes(&mut actual_bytes);
        expected.fill_bytes(&mut expected_bytes);
        assert_eq!(actual_bytes, expected_bytes);
        assert_eq!(source.next_u64(), expected.next_u64());
    }
}
