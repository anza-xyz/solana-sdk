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

// inlined to avoid solana_clock dep
const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;
#[cfg(test)]
static_assertions::const_assert_eq!(
    DEFAULT_SLOTS_PER_EPOCH,
    solana_clock::DEFAULT_SLOTS_PER_EPOCH
);

/// Configuration of network rent.
#[repr(C)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(PartialEq, CloneZeroed, Debug)]
pub struct Rent {
    /// Rental rate in lamports/byte-year.
    #[deprecated(
        since = "3.1.0",
        note = "Field will be renamed to `lamports_per_byte` in v4, use `Rent::new_with_lamports_per_byte` to create, and `Rent::minimum_balance` or `Rent::is_exempt`"
    )]
    pub lamports_per_byte_year: u64,

    /// Amount of time (in years) a balance must include rent for the account to
    /// be rent exempt.
    #[deprecated(
        since = "3.1.0",
        note = "Exemption threshold will be set to 1f64 with SIMD-0194 and should no longer be used"
    )]
    pub exemption_threshold: f64,

    /// The percentage of collected rent that is burned.
    ///
    /// Valid values are in the range [0, 100]. The remaining percentage is
    /// distributed to validators.
    #[deprecated(
        since = "3.1.0",
        note = "The concept of rent no longer exists, only rent-exemption"
    )]
    pub burn_percent: u8,
}

/// Default rental rate in lamports/byte-year.
///
/// This calculation is based on:
/// - 10^9 lamports per SOL
/// - $1 per SOL
/// - $0.01 per megabyte day
/// - $3.65 per megabyte year
#[deprecated(
    since = "3.1.0",
    note = "The concept of rent no longer exists, only rent-exemption. Use `DEFAULT_LAMPORTS_PER_BYTE` instead"
)]
pub const DEFAULT_LAMPORTS_PER_BYTE_YEAR: u64 = 1_000_000_000 / 100 * 365 / (1024 * 1024);

/// Default rental rate in lamports/byte.
///
/// This calculation is based on:
/// - 10^9 lamports per SOL
/// - $1 per SOL
/// - $0.01 per megabyte day
/// - $7.30 per megabyte
pub const DEFAULT_LAMPORTS_PER_BYTE: u64 = 6_960;

/// Default amount of time (in years) the balance has to include rent for the
/// account to be rent exempt.
#[deprecated(
    since = "3.1.0",
    note = "The concept of rent no longer exists, only rent-exemption"
)]
pub const DEFAULT_EXEMPTION_THRESHOLD: f64 = 2.0;

/// Default percentage of collected rent that is burned.
///
/// Valid values are in the range [0, 100]. The remaining percentage is
/// distributed to validators.
#[deprecated(
    since = "3.1.0",
    note = "The concept of rent no longer exists, only rent-exemption"
)]
pub const DEFAULT_BURN_PERCENT: u8 = 50;

/// Account storage overhead for calculation of base rent.
///
/// This is the number of bytes required to store an account with no data. It is
/// added to an accounts data length when calculating [`Rent::minimum_balance`].
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

impl Default for Rent {
    #[allow(deprecated)]
    fn default() -> Self {
        Self {
            lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
            exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
            burn_percent: DEFAULT_BURN_PERCENT,
        }
    }
}

impl Rent {
    /// Calculate how much rent to burn from the collected rent.
    ///
    /// The first value returned is the amount burned. The second is the amount
    /// to distribute to validators.
    #[deprecated(
        since = "3.1.0",
        note = "The concept of rent no longer exists, only rent-exemption"
    )]
    #[allow(deprecated)]
    pub fn calculate_burn(&self, rent_collected: u64) -> (u64, u64) {
        let burned_portion = (rent_collected * u64::from(self.burn_percent)) / 100;
        (burned_portion, rent_collected - burned_portion)
    }

    /// Minimum balance due for rent-exemption of a given account data size.
    #[allow(deprecated)]
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        let bytes = data_len as u64;
        (((ACCOUNT_STORAGE_OVERHEAD + bytes) * self.lamports_per_byte_year) as f64
            * self.exemption_threshold) as u64
    }

    /// Whether a given balance and data length would be exempt.
    pub fn is_exempt(&self, balance: u64, data_len: usize) -> bool {
        balance >= self.minimum_balance(data_len)
    }

    /// Rent due on account's data length with balance.
    #[deprecated(
        since = "3.1.0",
        note = "The concept of rent no longer exists, only rent-exemption"
    )]
    #[allow(deprecated)]
    pub fn due(&self, balance: u64, data_len: usize, years_elapsed: f64) -> RentDue {
        if self.is_exempt(balance, data_len) {
            RentDue::Exempt
        } else {
            RentDue::Paying(self.due_amount(data_len, years_elapsed))
        }
    }

    /// Rent due for account that is known to be not exempt.
    #[deprecated(
        since = "3.1.0",
        note = "The concept of rent no longer exists, only rent-exemption"
    )]
    #[allow(deprecated)]
    pub fn due_amount(&self, data_len: usize, years_elapsed: f64) -> u64 {
        let actual_data_len = data_len as u64 + ACCOUNT_STORAGE_OVERHEAD;
        let lamports_per_year = self.lamports_per_byte_year * actual_data_len;
        (lamports_per_year as f64 * years_elapsed) as u64
    }

    /// Creates a `Rent` that charges no lamports.
    ///
    /// This is used for testing.
    #[allow(deprecated)]
    pub fn free() -> Self {
        Self {
            lamports_per_byte_year: 0,
            ..Rent::default()
        }
    }

    /// Creates a `Rent` that is scaled based on the number of slots in an epoch.
    ///
    /// This is used for testing.
    #[deprecated(
        since = "3.1.0",
        note = "The concept of rent no longer exists, only rent-exemption, use `Rent::with_lamports_per_byte`"
    )]
    #[allow(deprecated)]
    pub fn with_slots_per_epoch(slots_per_epoch: u64) -> Self {
        let ratio = slots_per_epoch as f64 / DEFAULT_SLOTS_PER_EPOCH as f64;
        let exemption_threshold = DEFAULT_EXEMPTION_THRESHOLD * ratio;
        let lamports_per_byte_year = (DEFAULT_LAMPORTS_PER_BYTE_YEAR as f64 / ratio) as u64;
        Self {
            lamports_per_byte_year,
            exemption_threshold,
            ..Self::default()
        }
    }

    /// Creates a `Rent` with lamports per byte
    #[allow(deprecated)]
    pub fn with_lamports_per_byte(lamports_per_byte: u64) -> Self {
        Self {
            lamports_per_byte_year: lamports_per_byte,
            exemption_threshold: 1.0,
            ..Self::default()
        }
    }
}

/// The return value of [`Rent::due`].
#[deprecated(
    since = "3.1.0",
    note = "The concept of rent no longer exists, only rent-exemption"
)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RentDue {
    /// Used to indicate the account is rent exempt.
    Exempt,
    /// The account owes this much rent.
    Paying(u64),
}

#[allow(deprecated)]
impl RentDue {
    /// Return the lamports due for rent.
    pub fn lamports(&self) -> u64 {
        match self {
            RentDue::Exempt => 0,
            RentDue::Paying(x) => *x,
        }
    }

    /// Return 'true' if rent exempt.
    pub fn is_exempt(&self) -> bool {
        match self {
            RentDue::Exempt => true,
            RentDue::Paying(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_due() {
        let default_rent = Rent::default();

        assert_eq!(
            default_rent.due(0, 2, 1.2),
            RentDue::Paying(
                (((2 + ACCOUNT_STORAGE_OVERHEAD) * DEFAULT_LAMPORTS_PER_BYTE_YEAR) as f64 * 1.2)
                    as u64
            ),
        );
        assert_eq!(
            default_rent.due(
                (((2 + ACCOUNT_STORAGE_OVERHEAD) * DEFAULT_LAMPORTS_PER_BYTE_YEAR) as f64
                    * DEFAULT_EXEMPTION_THRESHOLD) as u64,
                2,
                1.2
            ),
            RentDue::Exempt,
        );

        let custom_rent = Rent {
            lamports_per_byte_year: 5,
            exemption_threshold: 2.5,
            ..Rent::default()
        };

        assert_eq!(
            custom_rent.due(0, 2, 1.2),
            RentDue::Paying(
                (((2 + ACCOUNT_STORAGE_OVERHEAD) * custom_rent.lamports_per_byte_year) as f64 * 1.2)
                    as u64,
            )
        );

        assert_eq!(
            custom_rent.due(
                (((2 + ACCOUNT_STORAGE_OVERHEAD) * custom_rent.lamports_per_byte_year) as f64
                    * custom_rent.exemption_threshold) as u64,
                2,
                1.2
            ),
            RentDue::Exempt
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_rent_due_lamports() {
        assert_eq!(RentDue::Exempt.lamports(), 0);

        let amount = 123;
        assert_eq!(RentDue::Paying(amount).lamports(), amount);
    }

    #[test]
    #[allow(deprecated)]
    fn test_rent_due_is_exempt() {
        assert!(RentDue::Exempt.is_exempt());
        assert!(!RentDue::Paying(0).is_exempt());
    }

    #[test]
    #[allow(deprecated)]
    fn test_clone() {
        let rent = Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 2.2,
            burn_percent: 3,
        };
        #[allow(clippy::clone_on_copy)]
        let cloned_rent = rent.clone();
        assert_eq!(cloned_rent, rent);
    }
}
