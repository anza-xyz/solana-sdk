//! Configuration for network [rent].
//!
//! [rent]: https://docs.solanalabs.com/implemented-proposals/rent

#![allow(clippy::arithmetic_side_effects)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#[cfg(feature = "frozen-abi")]
extern crate std;

#[cfg(feature = "sysvar")]
pub mod sysvar;

use solana_sdk_macro::CloneZeroed;

/// Configuration of network rent.
#[repr(C)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(PartialEq, CloneZeroed, Debug)]
pub struct Rent {
    /// Rental rate in lamports/byte.
    pub lamports_per_byte: u64,

    /// Formerly, the amount of time (in years) a balance must include rent for
    /// the account to be rent exempt. Now it's just empty space.
    unused_exemption_threshold: [u8; 8],

    /// Formerly, the percentage of collected rent that is burned.
    unused_burn_percent: u8,
}

/// Default rental rate in lamports/byte.
///
/// This calculation is based on:
/// - 10^9 lamports per SOL
/// - $1 per SOL
/// - $0.01 per megabyte day
/// - $7.30 per megabyte
pub const DEFAULT_LAMPORTS_PER_BYTE: u64 = 6_960;

// 1 as a 64-bit little-endian float, f64::to_le_bytes() is not stable in a
// const context for older rust versions
const DEFAULT_EXEMPTION_THRESHOLD: [u8; 8] = [0, 0, 0, 0, 0, 0, 240, 63];
// 2 as a 64-bit little-endian float, f64::to_le_bytes() is not stable in a
// const context for older rust versions. Remove this const and the match arm
// using it in `minimum_balance()` once SIMD-0194 is released.
const PREVIOUS_EXEMPTION_THRESHOLD: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 64];
const DEFAULT_BURN_PERCENT: u8 = 50;

/// Account storage overhead for calculation of base rent.
///
/// This is the number of bytes required to store an account with no data. It is
/// added to an accounts data length when calculating [`Rent::minimum_balance`].
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

impl Default for Rent {
    fn default() -> Self {
        Self {
            lamports_per_byte: DEFAULT_LAMPORTS_PER_BYTE,
            unused_exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
            unused_burn_percent: DEFAULT_BURN_PERCENT,
        }
    }
}

impl Rent {
    /// Minimum balance due for rent-exemption of a given account data size.
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        let bytes = data_len as u64;
        match self.unused_exemption_threshold {
            DEFAULT_EXEMPTION_THRESHOLD => {
                (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte
            }
            PREVIOUS_EXEMPTION_THRESHOLD => {
                2 * (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte
            }
            _ => {
                (((ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte) as f64
                    * f64::from_le_bytes(self.unused_exemption_threshold)) as u64
            }
        }
    }

    /// Whether a given balance and data length would be exempt.
    pub fn is_exempt(&self, balance: u64, data_len: usize) -> bool {
        balance >= self.minimum_balance(data_len)
    }

    /// Creates a `Rent` that charges no lamports.
    ///
    /// This is used for testing.
    pub fn free() -> Self {
        Self {
            lamports_per_byte: 0,
            ..Rent::default()
        }
    }

    /// Creates a `Rent` with lamports per byte
    pub fn with_lamports_per_byte(lamports_per_byte: u64) -> Self {
        Self {
            lamports_per_byte,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, proptest::proptest};

    #[test]
    fn test_clone() {
        let rent = Rent {
            lamports_per_byte: 1,
            unused_exemption_threshold: 2.2f64.to_le_bytes(),
            unused_burn_percent: 3,
        };
        #[allow(clippy::clone_on_copy)]
        let cloned_rent = rent.clone();
        assert_eq!(cloned_rent, rent);
    }

    #[test]
    fn test_exemption_threshold() {
        assert_eq!(1f64.to_le_bytes(), DEFAULT_EXEMPTION_THRESHOLD);
        assert_eq!(2f64.to_le_bytes(), PREVIOUS_EXEMPTION_THRESHOLD);
    }

    proptest! {
        #[test]
        fn test_minimum_balance(bytes in 0usize..u32::MAX as usize) {
            let default_rent = Rent::default();
            let previous_rent = Rent {
                lamports_per_byte: DEFAULT_LAMPORTS_PER_BYTE / 2,
                unused_exemption_threshold: 2.0f64.to_le_bytes(),
                ..Default::default()
            };
            let default_calc = default_rent.minimum_balance(bytes);
            assert_eq!(default_calc, previous_rent.minimum_balance(bytes));

            // check that the calculation gives the same result using floats
            let float_calc = (((ACCOUNT_STORAGE_OVERHEAD + bytes as u64) * previous_rent.lamports_per_byte) as f64
                * f64::from_le_bytes(previous_rent.unused_exemption_threshold)) as u64;
            assert_eq!(default_calc, float_calc);
        }
    }
}
