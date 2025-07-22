//! Error types
use solana_program_error::{ProgramError, ToStr};

/// Errors that may be returned by the spl-pod library.
#[repr(u32)]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    thiserror::Error,
    num_enum::TryFromPrimitive,
    num_derive::FromPrimitive,
)]
pub enum PodSliceError {
    /// Error in checked math operation
    #[error("Error in checked math operation")]
    CalculationFailure,
    /// Provided byte buffer too small for expected type
    #[error("Provided byte buffer too small for expected type")]
    BufferTooSmall,
    /// Provided byte buffer too large for expected type
    #[error("Provided byte buffer too large for expected type")]
    BufferTooLarge,
}

impl From<PodSliceError> for ProgramError {
    fn from(e: PodSliceError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl ToStr for PodSliceError {
    fn to_str<E>(&self) -> &'static str {
        match self {
            PodSliceError::CalculationFailure => "Error in checked math operation",
            PodSliceError::BufferTooSmall => "Provided byte buffer too small for expected type",
            PodSliceError::BufferTooLarge => "Provided byte buffer too large for expected type",
        }
    }
}
