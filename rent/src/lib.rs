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
    #[deprecated(since = "4.1.0", note = "Use `Rent::minimum_balance()` directly")]
    pub exemption_threshold: [u8; 8],

    /// Formerly, the percentage of collected rent that is burned.
    #[deprecated(since = "4.1.0", note = "Rent no longer exists")]
    pub burn_percent: u8,
}

/// Maximum permitted size of account data (10 MiB).
const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

/// Default rental rate in lamports/byte.
///
/// This calculation is based on:
/// - 10^9 lamports per SOL
/// - $1 per SOL
/// - $0.01 per megabyte day
/// - $7.30 per megabyte
pub const DEFAULT_LAMPORTS_PER_BYTE: u64 = 6_960;

/// The `f64::to_le_bytes` representation of the SIMD-0194 exemption threshold.
///
/// This value is equivalent to `1.0f64`. It is only used to check whether
/// the exemption threshold is the deprecated value to avoid performing
/// floating-point operations on-chain.
const SIMD0194_EXEMPTION_THRESHOLD: [u8; 8] = [0, 0, 0, 0, 0, 0, 240, 63];

/// The `f64::to_le_bytes` representation of the default exemption threshold.
///
/// This value is equivalent to `2.0f64`. It is only used to check whether
/// the exemption threshold is the default value to avoid performing
/// floating-point operations on-chain.
const CURRENT_EXEMPTION_THRESHOLD: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 64];

/// Maximum lamports per byte for the SIMD-0194 exemption threshold.
const SIMD0194_MAX_LAMPORTS_PER_BYTE: u64 = 1_759_197_129_867;

/// Maximum lamports per byte for the current exemption threshold.
const CURRENT_MAX_LAMPORTS_PER_BYTE: u64 = 879_598_564_933;

const DEFAULT_BURN_PERCENT: u8 = 50;

/// Account storage overhead for calculation of base rent.
///
/// This is the number of bytes required to store an account with no data. It is
/// added to an accounts data length when calculating [`Rent::minimum_balance`].
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

impl Default for Rent {
    fn default() -> Self {
        #[allow(deprecated)]
        Self {
            lamports_per_byte: DEFAULT_LAMPORTS_PER_BYTE,
            exemption_threshold: SIMD0194_EXEMPTION_THRESHOLD,
            burn_percent: DEFAULT_BURN_PERCENT,
        }
    }
}

impl Rent {
    /// Calculates the minimum balance for rent exemption.
    ///
    /// This method avoids floating-point operations when the `exemption_threshold`
    /// is the default value.
    ///
    /// # Arguments
    ///
    /// * `data_len` - The number of bytes in the account
    ///
    /// # Returns
    ///
    /// The minimum balance in lamports for rent exemption.
    ///
    /// # Panics
    ///
    /// Panics if `data_len` exceeds the maximum permitted data length or if the
    /// `lamports_per_byte` is too large based on the `exemption_threshold`.
    #[inline(always)]
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        self.try_minimum_balance(data_len)
            .expect("Maximum permitted data length exceeded")
    }

    /// Calculates the minimum balance for rent exemption without performing
    /// any validation.
    ///
    /// This method avoids floating-point operations when the `exemption_threshold`
    /// is the default value.
    ///
    /// # Important
    ///
    /// The caller must ensure that `data_len` is within the permitted limit
    /// and the `lamports_per_byte` is within the permitted limit based on
    /// the `exemption_threshold` to avoid overflow.
    ///
    /// # Arguments
    ///
    /// * `data_len` - The number of bytes in the account
    ///
    /// # Returns
    ///
    /// The minimum balance in lamports for rent exemption.
    #[inline(always)]
    pub fn minimum_balance_unchecked(&self, data_len: usize) -> u64 {
        let bytes = data_len as u64;

        // There are two cases where it is possible to avoid floating-point
        // operations:
        //
        //   1)  exemption threshold is `1.0` (the SIMD-0194 default)
        //   2)  exemption threshold is `2.0` (the current default)
        //
        // In all other cases, perform the full calculation using floating-point
        // operations. Note that on BPF targets, floating-point operations are
        // not supported, so panic in that case.
        #[allow(deprecated)]
        if self.exemption_threshold == SIMD0194_EXEMPTION_THRESHOLD {
            (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte
        } else if self.exemption_threshold == CURRENT_EXEMPTION_THRESHOLD {
            2 * (ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte
        } else {
            #[cfg(not(target_arch = "bpf"))]
            {
                (((ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte) as f64
                    * f64::from_le_bytes(self.exemption_threshold)) as u64
            }
            #[cfg(target_arch = "bpf")]
            panic!("Floating-point operations are not supported on BPF targets");
        }
    }

    /// Calculates the minimum balance for rent exemption.
    ///
    /// This method avoids floating-point operations when the `exemption_threshold`
    /// is the default value.
    ///
    /// # Arguments
    ///
    /// * `data_len` - The number of bytes in the account
    ///
    /// # Returns
    ///
    /// The minimum balance in lamports for rent exemption.
    ///
    /// # Errors
    ///
    /// Returns `ProgramError::InvalidArgument` if `data_len` exceeds the maximum
    /// permitted data length or if the `lamports_per_byte` is too large based on
    /// the `exemption_threshold`, which would cause an overflow.
    #[inline(always)]
    pub fn try_minimum_balance(&self, data_len: usize) -> Option<u64> {
        if data_len as u64 > MAX_PERMITTED_DATA_LENGTH {
            return None;
        }

        // Validate `lamports_per_byte` based on `exemption_threshold`
        // to prevent overflow.

        #[allow(deprecated)]
        if (self.lamports_per_byte > CURRENT_MAX_LAMPORTS_PER_BYTE
            && self.exemption_threshold == CURRENT_EXEMPTION_THRESHOLD)
            || (self.lamports_per_byte > SIMD0194_MAX_LAMPORTS_PER_BYTE
                && self.exemption_threshold == SIMD0194_EXEMPTION_THRESHOLD)
        {
            return None;
        }

        Some(self.minimum_balance_unchecked(data_len))
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
        #[allow(deprecated)]
        let rent = Rent {
            lamports_per_byte: 1,
            exemption_threshold: 2.2f64.to_le_bytes(),
            burn_percent: 3,
        };
        #[allow(clippy::clone_on_copy)]
        let cloned_rent = rent.clone();
        assert_eq!(cloned_rent, rent);
    }

    #[test]
    fn test_exemption_threshold() {
        assert_eq!(1f64.to_le_bytes(), SIMD0194_EXEMPTION_THRESHOLD);
        assert_eq!(2f64.to_le_bytes(), CURRENT_EXEMPTION_THRESHOLD);
    }

    proptest! {
        #[test]
        fn test_minimum_balance(bytes in 0usize..=MAX_PERMITTED_DATA_LENGTH as usize) {
            let default_rent = Rent::default();
            #[allow(deprecated)]
            let previous_rent = Rent {
                lamports_per_byte: DEFAULT_LAMPORTS_PER_BYTE / 2,
                exemption_threshold: 2.0f64.to_le_bytes(),
                ..Default::default()
            };
            let default_calc = default_rent.minimum_balance(bytes);
            assert_eq!(default_calc, previous_rent.minimum_balance(bytes));

            // check that the calculation gives the same result using floats
            #[allow(deprecated)]
            let float_calc = (((ACCOUNT_STORAGE_OVERHEAD + bytes as u64) * previous_rent.lamports_per_byte) as f64
                * f64::from_le_bytes(previous_rent.exemption_threshold)) as u64;
            assert_eq!(default_calc, float_calc);
        }
    }
}
