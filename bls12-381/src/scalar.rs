#[cfg(any(feature = "bytemuck", not(target_os = "solana")))]
use bytemuck_derive::{Pod, Zeroable};

/// Size of a BLS12-381 scalar field element in bytes.
pub const SCALAR_SIZE: usize = 32;

/// A BLS12-381 scalar field element.
/// Represents a 256-bit integer used for scalar multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "bytemuck", not(target_os = "solana")),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct Scalar(pub [u8; SCALAR_SIZE]);
