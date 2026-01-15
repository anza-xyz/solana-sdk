//! Error types for V1 message operations.

use solana_sanitize::SanitizeError;

/// Errors that can occur when working with V1 messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1MessageError {
    /// Input buffer is too small during deserialization.
    BufferTooSmall,
    /// Heap size is not a multiple of 1024.
    InvalidHeapSize,
    /// Instruction has too many accounts (> 255).
    InstructionAccountsTooLarge,
    /// Instruction data is too large (> 65535 bytes).
    InstructionDataTooLarge,
    /// Invalid TransactionConfigMask.
    InvalidConfigMask,
    /// Instruction account index is out of bounds.
    InvalidInstructionAccountIndex,
    /// Program ID index is invalid (out of bounds or fee payer).
    InvalidProgramIdIndex,
    /// Invalid or missing version byte (expected 0x81).
    InvalidVersion,
    /// Lifetime specifier (blockhash) is required.
    MissingLifetimeSpecifier,
    /// Not enough addresses for the number of required signatures.
    NotEnoughAddressesForSignatures,
    /// Too many addresses (> 64).
    TooManyAddresses,
    /// Too many instructions (> 64).
    TooManyInstructions,
    /// Too many signatures (> 12).
    TooManySignatures,
    /// Unexpected trailing data after message.
    TrailingData,
    /// Transaction exceeds maximum size (4096 bytes).
    TransactionTooLarge,
    /// Must have at least one signer (fee payer).
    ZeroSigners,
}

impl std::fmt::Display for V1MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidHeapSize => write!(f, "heap size must be a multiple of 1024"),
            Self::InstructionAccountsTooLarge => {
                write!(f, "instruction has too many accounts (max 255)")
            }
            Self::InstructionDataTooLarge => {
                write!(f, "instruction data too large (max 65535 bytes)")
            }
            Self::InvalidConfigMask => write!(f, "invalid transaction config mask"),
            Self::InvalidInstructionAccountIndex => {
                write!(f, "instruction account index out of bounds")
            }
            Self::InvalidProgramIdIndex => {
                write!(f, "program ID index out of bounds or is fee payer")
            }
            Self::InvalidVersion => write!(f, "invalid version byte (expected 0x81)"),
            Self::MissingLifetimeSpecifier => {
                write!(f, "lifetime specifier (blockhash) is required")
            }
            Self::NotEnoughAddressesForSignatures => {
                write!(f, "not enough addresses for required signatures")
            }
            Self::TooManyAddresses => write!(f, "too many addresses (max 64)"),
            Self::TooManyInstructions => write!(f, "too many instructions (max 64)"),
            Self::TooManySignatures => write!(f, "too many signatures (max 12)"),
            Self::TrailingData => write!(f, "unexpected trailing data"),
            Self::TransactionTooLarge => write!(f, "transaction exceeds max size (4096 bytes)"),
            Self::ZeroSigners => write!(f, "must have at least one signer (fee payer)"),
        }
    }
}

impl std::error::Error for V1MessageError {}

impl From<V1MessageError> for SanitizeError {
    fn from(err: V1MessageError) -> Self {
        match err {
            V1MessageError::BufferTooSmall
            | V1MessageError::InvalidHeapSize
            | V1MessageError::InstructionAccountsTooLarge
            | V1MessageError::InstructionDataTooLarge
            | V1MessageError::InvalidConfigMask
            | V1MessageError::InvalidVersion
            | V1MessageError::MissingLifetimeSpecifier
            | V1MessageError::TrailingData
            | V1MessageError::TransactionTooLarge
            | V1MessageError::ZeroSigners => SanitizeError::InvalidValue,
            V1MessageError::InvalidInstructionAccountIndex
            | V1MessageError::InvalidProgramIdIndex
            | V1MessageError::NotEnoughAddressesForSignatures
            | V1MessageError::TooManyAddresses
            | V1MessageError::TooManyInstructions
            | V1MessageError::TooManySignatures => SanitizeError::IndexOutOfBounds,
        }
    }
}
