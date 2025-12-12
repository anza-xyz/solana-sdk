#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
use {
    base64::{prelude::BASE64_STANDARD, Engine},
    core::fmt,
};
#[cfg(feature = "serde")]
use {
    serde::{Deserialize, Serialize},
    serde_with::serde_as,
};

/// Size of a BLS signature in a compressed point representation
pub const BLS_SIGNATURE_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS signature in a compressed point representation in base64
pub const BLS_SIGNATURE_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS signature in an affine point representation
pub const BLS_SIGNATURE_AFFINE_SIZE: usize = 192;

/// Size of a BLS signature in an affine point representation in base64
pub const BLS_SIGNATURE_AFFINE_BASE64_SIZE: usize = 256;

/// A serialized BLS signature in a compressed point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SignatureCompressed(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_COMPRESSED_SIZE]"))]
    pub  [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
);

impl Default for SignatureCompressed {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_COMPRESSED_SIZE])
    }
}

impl fmt::Display for SignatureCompressed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = SignatureCompressed,
    BYTES_LEN = BLS_SIGNATURE_COMPRESSED_SIZE,
    BASE64_LEN = BLS_SIGNATURE_COMPRESSED_BASE64_SIZE
);

/// A serialized BLS signature in an affine point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Signature(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_AFFINE_SIZE]"))]
    pub  [u8; BLS_SIGNATURE_AFFINE_SIZE],
);

impl Default for Signature {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_AFFINE_SIZE])
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = Signature,
    BYTES_LEN = BLS_SIGNATURE_AFFINE_SIZE,
    BASE64_LEN = BLS_SIGNATURE_AFFINE_BASE64_SIZE
);

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
#[cfg(feature = "bytemuck")]
mod bytemuck_impls {
    use super::*;

    unsafe impl Zeroable for Signature {}
    unsafe impl Pod for Signature {}
    unsafe impl ZeroableInOption for Signature {}
    unsafe impl PodInOption for Signature {}

    unsafe impl Zeroable for SignatureCompressed {}
    unsafe impl Pod for SignatureCompressed {}
    unsafe impl ZeroableInOption for SignatureCompressed {}
    unsafe impl PodInOption for SignatureCompressed {}
}
