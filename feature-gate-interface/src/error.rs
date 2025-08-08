//! Program error types.

use solana_program_error::{ProgramError, ToStr};

/// Program error types.
#[cfg_attr(test, derive(strum_macros::FromRepr, strum_macros::EnumIter))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FeatureGateError {
    /// Feature already activated
    FeatureAlreadyActivated,
}

impl core::error::Error for FeatureGateError {}

impl core::fmt::Display for FeatureGateError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.to_str())
    }
}

impl ToStr for FeatureGateError {
    fn to_str(&self) -> &'static str {
        match self {
            FeatureGateError::FeatureAlreadyActivated => "Feature already activated",
        }
    }
}

impl From<FeatureGateError> for ProgramError {
    fn from(e: FeatureGateError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl TryFrom<u32> for FeatureGateError {
    type Error = ProgramError;
    fn try_from(error: u32) -> Result<Self, Self::Error> {
        match error {
            0 => Ok(FeatureGateError::FeatureAlreadyActivated),
            _ => Err(ProgramError::InvalidArgument),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::FeatureGateError, strum::IntoEnumIterator};

    #[test]
    fn test_system_error_from_primitive_exhaustive() {
        for variant in FeatureGateError::iter() {
            let variant_u32 = variant.clone() as u32;
            assert_eq!(FeatureGateError::from_repr(variant_u32).unwrap(), variant);
            assert_eq!(FeatureGateError::try_from(variant_u32).unwrap(), variant);
        }
    }
}
