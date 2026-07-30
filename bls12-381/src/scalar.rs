use bytemuck::{Pod, Zeroable};

/// Size of a BLS12-381 scalar field element in bytes.
pub const SCALAR_SIZE: usize = 32;

/// A BLS12-381 scalar field element.
/// Represents a 256-bit integer used for scalar multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Scalar(pub [u8; SCALAR_SIZE]);
