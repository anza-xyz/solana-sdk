//! Error types
use {
    core::num::TryFromIntError,
    solana_program_error::{ProgramError, ToStr},
};

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
    /// An integer conversion failed because the value was out of range for the target type
    #[error("An integer conversion failed because the value was out of range for the target type")]
    ValueOutOfRange,
}

impl From<PodSliceError> for ProgramError {
    fn from(e: PodSliceError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl ToStr for PodSliceError {
    fn to_str(&self) -> &'static str {
        match self {
            PodSliceError::CalculationFailure => "Error in checked math operation",
            PodSliceError::BufferTooSmall => "Provided byte buffer too small for expected type",
            PodSliceError::BufferTooLarge => "Provided byte buffer too large for expected type",
            PodSliceError::ValueOutOfRange => "An integer conversion failed because the value was out of range for the target type"
        }
    }
}

impl From<TryFromIntError> for PodSliceError {
    fn from(_: TryFromIntError) -> Self {
        PodSliceError::ValueOutOfRange
    }
}
