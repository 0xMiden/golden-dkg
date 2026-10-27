//! Group-key resharing on both native adapters.
#![cfg(feature = "insecure-revealed-witness")]
#![allow(clippy::unwrap_used, clippy::panic)]

macro_rules! both {
    ($name:ident, $function:ident $(, $argument:expr)*) => {
        #[test]
        fn $name() {
            $function::<Secp256k1Group>($($argument),*);
            $function::<JubjubGroup>($($argument),*);
        }
    };
}

mod configuration;
mod dealing;
mod identity_share;
mod persistence;
mod support;
mod workflow;
