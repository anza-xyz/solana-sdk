//! Current cluster fees.
//!
//! The _fees sysvar_ provides access to the [`Fees`] type, which contains the
//! current [`FeeCalculator`].
//!
//! [`Fees`] implements [`crate::Sysvar::get`] and can be loaded efficiently without
//! passing the sysvar account ID to the program.
//!
//! This sysvar is deprecated and will not be available in the future.
//! Transaction fees should be determined with the [`getFeeForMessage`] RPC
//! method. For additional context see the [Comprehensive Compute Fees
//! proposal][ccf].
//!
//! [`getFeeForMessage`]: https://solana.com/docs/rpc/http/getfeeformessage
//! [ccf]: https://docs.solanalabs.com/proposals/comprehensive-compute-fees
//!
//! See also the Solana [documentation on the fees sysvar][sdoc].
//!
//! [sdoc]: https://docs.solanalabs.com/runtime/sysvars#fees

#![allow(deprecated)]

#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
pub use solana_sdk_ids::sysvar::fees::{check_id, id, ID};
#[cfg(target_os = "solana")]
use {solana_define_syscall::definitions, solana_program_entrypoint::SUCCESS};
use {
    solana_fee_calculator::FeeCalculator, solana_get_sysvar::GetSysvar,
    solana_sdk_macro::CloneZeroed, solana_sysvar_id::impl_deprecated_sysvar_id,
};

impl_deprecated_sysvar_id!(Fees);

/// Transaction fees.
#[deprecated(
    since = "1.9.0",
    note = "Please do not use, will no longer be available in the future"
)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, CloneZeroed, Default, PartialEq, Eq)]
pub struct Fees {
    pub fee_calculator: FeeCalculator,
}

impl Fees {
    pub fn new(fee_calculator: &FeeCalculator) -> Self {
        #[allow(deprecated)]
        Self {
            fee_calculator: *fee_calculator,
        }
    }
}

// DEPRECATED: This impl is only for the deprecated Fees sysvar and should be
// removed once Fees is no longer in use. It uses the old-style direct syscall
// approach instead of the new sol_get_sysvar syscall.
impl GetSysvar for Fees {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        #[cfg(target_os = "solana")]
        {
            let mut fees = Self::default();
            let fees_addr = &mut fees as *mut _ as *mut u8;
            let result = unsafe { definitions::sol_get_fees_sysvar(fees_addr) };

            match result {
                SUCCESS => Ok(fees),
                _ => Err(solana_program_error::ProgramError::UnsupportedSysvar),
            }
        }

        #[cfg(not(target_os = "solana"))]
        {
            Err(solana_program_error::ProgramError::UnsupportedSysvar)
        }
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for Fees {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone() {
        let fees = Fees {
            fee_calculator: FeeCalculator {
                lamports_per_signature: 1,
            },
        };
        let cloned_fees = fees.clone();
        assert_eq!(cloned_fees, fees);
    }
}
