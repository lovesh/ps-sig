#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

pub mod errors;
#[macro_use]
pub mod pok_vc;
pub mod blind_signature;
pub mod keys;
pub mod multi_signature;
pub mod pok_sig;
pub mod pok_sig_2018;
pub mod signature;
pub mod signature_2018;

/// Create a deterministic RNG from a seed
pub(crate) fn deterministic_rng_from_seed(seed: [u8; 32]) -> impl rand_core::RngCore {
    use ark_std::rand::SeedableRng;
    ark_std::rand::rngs::StdRng::from_seed(seed)
}
