#[cfg(not(target_os = "solana"))]
use crate::error::BlsError;
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

/// Size of a BLS proof of possession in a compressed point representation
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS proof of possession in a compressed point representation in base64
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS proof of possession in an affine point representation
pub const BLS_PROOF_OF_POSSESSION_AFFINE_SIZE: usize = 192;

/// Size of a BLS proof of possession in an affine point representation in base64
pub const BLS_PROOF_OF_POSSESSION_AFFINE_BASE64_SIZE: usize = 256;

/// A trait for types that can be converted into a `ProofOfPossession` (affine).
#[cfg(not(target_os = "solana"))]
pub trait AsProofOfPossession {
    /// Attempt to convert the type into a `ProofOfPossession`.
    fn try_as_affine(&self) -> Result<ProofOfPossession, BlsError>;
}

/// A serialized BLS proof of possession in a compressed point representation.
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ProofOfPossessionCompressed(
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]")
    )]
    pub [u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
);

impl Default for ProofOfPossessionCompressed {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE])
    }
}

impl fmt::Display for ProofOfPossessionCompressed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = ProofOfPossessionCompressed,
    BYTES_LEN = BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
    BASE64_LEN = BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE
);

/// A serialized BLS proof of possession in an affine point representation.
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ProofOfPossession(
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE]")
    )]
    pub [u8; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE],
);

impl Default for ProofOfPossession {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE])
    }
}

impl fmt::Display for ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = ProofOfPossession,
    BYTES_LEN = BLS_PROOF_OF_POSSESSION_AFFINE_SIZE,
    BASE64_LEN = BLS_PROOF_OF_POSSESSION_AFFINE_BASE64_SIZE
);

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
#[cfg(feature = "bytemuck")]
mod bytemuck_impls {
    use super::*;

    unsafe impl Zeroable for ProofOfPossessionCompressed {}
    unsafe impl Pod for ProofOfPossessionCompressed {}
    unsafe impl ZeroableInOption for ProofOfPossessionCompressed {}
    unsafe impl PodInOption for ProofOfPossessionCompressed {}

    unsafe impl Zeroable for ProofOfPossession {}
    unsafe impl Pod for ProofOfPossession {}
    unsafe impl ZeroableInOption for ProofOfPossession {}
    unsafe impl PodInOption for ProofOfPossession {}
}
