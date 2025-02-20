//! Solana PubkeyError type.
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#[cfg(feature = "std")]
extern crate std;

use core::fmt;
#[cfg(feature = "num-traits")]
use {
    num_traits::{FromPrimitive, ToPrimitive},
    solana_decode_error::DecodeError,
};

// Use strum when testing to ensure our FromPrimitive
// impl is exhaustive
#[cfg_attr(test, derive(strum_macros::FromRepr, strum_macros::EnumIter))]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,
    InvalidSeeds,
    IllegalOwner,
}

#[cfg(feature = "num-traits")]
impl ToPrimitive for PubkeyError {
    #[inline]
    fn to_i64(&self) -> Option<i64> {
        Some(match *self {
            PubkeyError::MaxSeedLengthExceeded => PubkeyError::MaxSeedLengthExceeded as i64,
            PubkeyError::InvalidSeeds => PubkeyError::InvalidSeeds as i64,
            PubkeyError::IllegalOwner => PubkeyError::IllegalOwner as i64,
        })
    }
    #[inline]
    fn to_u64(&self) -> Option<u64> {
        self.to_i64().map(|x| x as u64)
    }
}

#[cfg(feature = "num-traits")]
impl FromPrimitive for PubkeyError {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n == PubkeyError::MaxSeedLengthExceeded as i64 {
            Some(PubkeyError::MaxSeedLengthExceeded)
        } else if n == PubkeyError::InvalidSeeds as i64 {
            Some(PubkeyError::InvalidSeeds)
        } else if n == PubkeyError::IllegalOwner as i64 {
            Some(PubkeyError::IllegalOwner)
        } else {
            None
        }
    }
    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        Self::from_i64(n as i64)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PubkeyError {}

impl fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PubkeyError::MaxSeedLengthExceeded => {
                f.write_str("Length of the seed is too long for address generation")
            }
            PubkeyError::InvalidSeeds => {
                f.write_str("Provided seeds do not result in a valid address")
            }
            PubkeyError::IllegalOwner => f.write_str("Provided owner is not allowed"),
        }
    }
}

#[cfg(feature = "num-traits")]
impl<T> DecodeError<T> for PubkeyError {
    fn type_of() -> &'static str {
        "PubkeyError"
    }
}
impl From<u64> for PubkeyError {
    fn from(error: u64) -> Self {
        match error {
            0 => PubkeyError::MaxSeedLengthExceeded,
            1 => PubkeyError::InvalidSeeds,
            2 => PubkeyError::IllegalOwner,
            _ => panic!("Unsupported PubkeyError"),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, strum::IntoEnumIterator};

    #[test]
    fn test_pubkey_error_from_primitive_exhaustive() {
        for variant in PubkeyError::iter() {
            let variant_i64 = variant.clone() as i64;
            assert_eq!(
                PubkeyError::from_repr(variant_i64 as usize),
                PubkeyError::from_i64(variant_i64)
            );
            assert_eq!(PubkeyError::from(variant_i64 as u64), variant);
        }
    }
}
