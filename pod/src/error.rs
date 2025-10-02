//! Error types
use pinocchio::program_error::ProgramError as PinocchioProgramError;
use {
    bytemuck::PodCastError,
    solana_program_error::{ProgramError, ToStr},
    std::num::TryFromIntError,
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
pub enum SplPodError {
    /// Error in checked math operation
    #[error("Error in checked math operation")]
    CalculationFailure,
    /// Provided byte buffer too small for expected type
    #[error("Provided byte buffer too small for expected type")]
    BufferTooSmall,
    /// Provided byte buffer too large for expected type
    #[error("Provided byte buffer too large for expected type")]
    BufferTooLarge,
    /// Index out of range for list operation
    #[error("Index out of range for list operation")]
    IndexOutOfRange,
    /// Type used as a length prefix has invalid alignment
    #[error("Type used as a length prefix has invalid alignment")]
    InvalidLengthTypeAlignment,
    /// A `PodCast` operation from `bytemuck` failed
    #[error("A `PodCast` operation from `bytemuck` failed")]
    PodCast,
    /// An integer conversion failed because the value was out of range for the target type
    #[error("An integer conversion failed because the value was out of range for the target type")]
    ValueOutOfRange,
}

impl From<SplPodError> for ProgramError {
    fn from(e: SplPodError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl ToStr for SplPodError {
    fn to_str(&self) -> &'static str {
        match self {
            SplPodError::CalculationFailure => "Error in checked math operation",
            SplPodError::BufferTooSmall => "Provided byte buffer too small for expected type",
            SplPodError::BufferTooLarge => "Provided byte buffer too large for expected type",
            SplPodError::IndexOutOfRange => "Index out of range for list operation",
            SplPodError::InvalidLengthTypeAlignment => "Type used as a length prefix has invalid alignment",
            SplPodError::PodCast => "A `PodCast` operation from `bytemuck` failed",
            SplPodError::ValueOutOfRange => "An integer conversion failed because the value was out of range for the target type",
        }
    }
}

impl From<PodCastError> for SplPodError {
    fn from(_: PodCastError) -> Self {
        SplPodError::PodCast
    }
}

impl From<TryFromIntError> for SplPodError {
    fn from(_: TryFromIntError) -> Self {
        SplPodError::ValueOutOfRange
    }
}

impl From<SplPodError> for PinocchioProgramError {
    fn from(e: SplPodError) -> Self {
        PinocchioProgramError::Custom(e as u32)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::list::ListView;
    use pinocchio::program_error::ProgramError as PinocchioProgramError;

    fn raises_solana_err() -> Result<(), ProgramError> {
        ListView::<u8>::size_of(usize::MAX)?; // raises err
        Ok(())
    }

    fn raises_pino_err() -> Result<(), PinocchioProgramError> {
        ListView::<u8>::size_of(usize::MAX)?; // raises err
        Ok(())
    }

    #[test]
    fn test_from_pod_slice_error_for_solana_program_error() {
        let result = raises_solana_err();
        assert!(result.is_err());
        let solana_err = result.unwrap_err();
        let expected_err: ProgramError = SplPodError::CalculationFailure.into();
        assert_eq!(solana_err, expected_err);
    }

    #[test]
    fn test_from_pod_slice_error_for_pinocchio_program_error() {
        let result = raises_pino_err();
        assert!(result.is_err());
        let pinocchio_err = result.unwrap_err();
        let expected_solana_err: ProgramError = SplPodError::CalculationFailure.into();
        let expected_pinocchio_err: PinocchioProgramError = u64::from(expected_solana_err).into();
        assert_eq!(pinocchio_err, expected_pinocchio_err);
    }
}
