use solana_sanitize::SanitizeError;

/// Errors that can occur when working with V1 messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    /// Input buffer is too small during deserialization.
    BufferTooSmall,
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
    /// Too many addresses to encode in the wire format (> 255).
    TooManyAddresses,
    /// Too many instructions to encode in the wire format (> 255).
    TooManyInstructions,
    /// Unexpected trailing data after message.
    TrailingData,
    /// Transaction exceeds maximum size (4096 bytes).
    TransactionTooLarge,
    /// Must have at least one signer (fee payer).
    ZeroSigners,
    /// Invalid configuration value.
    InvalidConfigValue,
    /// Not enough account keys provided.
    NotEnoughAccountKeys,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
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
            Self::TooManyAddresses => write!(f, "too many addresses (max 255)"),
            Self::TooManyInstructions => write!(f, "too many instructions (max 255)"),
            Self::TrailingData => write!(f, "unexpected trailing data"),
            Self::TransactionTooLarge => write!(f, "transaction exceeds max size (4096 bytes)"),
            Self::ZeroSigners => write!(f, "must have at least one signer (fee payer)"),
            Self::InvalidConfigValue => write!(f, "invalid configuration value"),
            Self::NotEnoughAccountKeys => write!(f, "not enough account keys provided"),
        }
    }
}

impl core::error::Error for MessageError {}

impl From<MessageError> for SanitizeError {
    fn from(err: MessageError) -> Self {
        match err {
            MessageError::BufferTooSmall
            | MessageError::InstructionAccountsTooLarge
            | MessageError::InstructionDataTooLarge
            | MessageError::InvalidConfigMask
            | MessageError::InvalidVersion
            | MessageError::MissingLifetimeSpecifier
            | MessageError::TrailingData
            | MessageError::TransactionTooLarge
            | MessageError::ZeroSigners
            | MessageError::InvalidConfigValue
            | MessageError::NotEnoughAccountKeys => SanitizeError::InvalidValue,
            MessageError::InvalidInstructionAccountIndex
            | MessageError::InvalidProgramIdIndex
            | MessageError::NotEnoughAddressesForSignatures
            | MessageError::TooManyAddresses
            | MessageError::TooManyInstructions => SanitizeError::IndexOutOfBounds,
        }
    }
}
