#[cfg(feature = "serde")]
use serde_derive::Serialize;
use {
    core::{convert::Infallible, fmt},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_program_error::ProgramError,
};

// Use strum when testing to ensure our FromPrimitive
// impl is exhaustive
#[cfg_attr(test, derive(strum_macros::FromRepr, strum_macros::EnumIter))]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,
    InvalidSeeds,
    IllegalOwner,
}

impl ToPrimitive for AddressError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            AddressError::MaxSeedLengthExceeded => AddressError::MaxSeedLengthExceeded as i64,
            AddressError::InvalidSeeds => AddressError::InvalidSeeds as i64,
            AddressError::IllegalOwner => AddressError::IllegalOwner as i64,
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

impl FromPrimitive for AddressError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == AddressError::MaxSeedLengthExceeded as i64 {
            Some(AddressError::MaxSeedLengthExceeded)
        } else if n == AddressError::InvalidSeeds as i64 {
            Some(AddressError::InvalidSeeds)
        } else if n == AddressError::IllegalOwner as i64 {
            Some(AddressError::IllegalOwner)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

impl core::error::Error for AddressError {}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressError::MaxSeedLengthExceeded => {
                f.write_str("Length of the seed is too long for address generation")
            }
            AddressError::InvalidSeeds => {
                f.write_str("Provided seeds do not result in a valid address")
            }
            AddressError::IllegalOwner => f.write_str("Provided owner is not allowed"),
        }
    }
}

impl From<u64> for AddressError {
    fn from(error: u64) -> Self {
        match error {
            0 => AddressError::MaxSeedLengthExceeded,
            1 => AddressError::InvalidSeeds,
            2 => AddressError::IllegalOwner,
            _ => panic!("Unsupported AddressError"),
        }
    }
}

impl From<AddressError> for ProgramError {
    fn from(error: AddressError) -> Self {
        match error {
            AddressError::MaxSeedLengthExceeded => Self::MaxSeedLengthExceeded,
            AddressError::InvalidSeeds => Self::InvalidSeeds,
            AddressError::IllegalOwner => Self::IllegalOwner,
        }
    }
}

// Use strum when testing to ensure our FromPrimitive
// impl is exhaustive
#[cfg_attr(test, derive(strum_macros::FromRepr, strum_macros::EnumIter))]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAddressError {
    WrongSize,
    Invalid,
}

impl ToPrimitive for ParseAddressError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            ParseAddressError::WrongSize => ParseAddressError::WrongSize as i64,
            ParseAddressError::Invalid => ParseAddressError::Invalid as i64,
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

impl FromPrimitive for ParseAddressError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == ParseAddressError::WrongSize as i64 {
            Some(ParseAddressError::WrongSize)
        } else if n == ParseAddressError::Invalid as i64 {
            Some(ParseAddressError::Invalid)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

impl core::error::Error for ParseAddressError {}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseAddressError::WrongSize => f.write_str("String is the wrong size"),
            ParseAddressError::Invalid => f.write_str("Invalid Base58 string"),
        }
    }
}

impl From<Infallible> for ParseAddressError {
    fn from(_: Infallible) -> Self {
        unreachable!("Infallible uninhabited");
    }
}
