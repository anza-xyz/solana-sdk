use bytemuck::{Pod, Zeroable};
pub const SCALAR_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Scalar(pub [u8; SCALAR_SIZE]);
