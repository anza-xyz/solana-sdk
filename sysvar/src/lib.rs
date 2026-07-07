#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
//! Access to special accounts with dynamically-updated data.
//!
//! Sysvars are special accounts that contain dynamically-updated data about the
//! network cluster, the blockchain history, and the executing transaction. Each
//! sysvar is defined in its own submodule within this module. The [`clock`],
//! [`epoch_schedule`], and [`rent`] sysvars are most useful to on-chain
//! programs.
//!
//! Simple sysvars implement the [`Sysvar::get`] method, which loads a sysvar
//! directly from the runtime, as in this example that logs the `clock` sysvar:
//!
//! ```
//! use solana_account_info::AccountInfo;
//! use solana_msg::msg;
//! use solana_sysvar::Sysvar;
//! use solana_program_error::ProgramResult;
//! use solana_pubkey::Pubkey;
//!
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let clock = solana_clock::Clock::get()?;
//!     msg!("clock: {:#?}", clock);
//!     Ok(())
//! }
//! ```
//!
//! Since Solana sysvars are accounts, if the `AccountInfo` is provided to the
//! program, then the program can deserialize the sysvar with
//! [`SysvarSerialize::from_account_info`] to access its data, as in this example that
//! again logs the [`clock`] sysvar.
//!
//! ```
//! use solana_account_info::{AccountInfo, next_account_info};
//! use solana_msg::msg;
//! use solana_sysvar::{Sysvar, SysvarSerialize};
//! use solana_program_error::ProgramResult;
//! use solana_pubkey::Pubkey;
//!
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let clock_account = next_account_info(account_info_iter)?;
//!     let clock = solana_clock::Clock::from_account_info(&clock_account)?;
//!     msg!("clock: {:#?}", clock);
//!     Ok(())
//! }
//! ```
//!
//! When possible, programs should prefer to call `Sysvar::get` instead of
//! deserializing with `Sysvar::from_account_info`, as the latter imposes extra
//! overhead of deserialization while also requiring the sysvar account address
//! be passed to the program, wasting the limited space available to
//! transactions. Deserializing sysvars that can instead be retrieved with
//! `Sysvar::get` should be only be considered for compatibility with older
//! programs that pass around sysvar accounts.
//!
//! Some sysvars are too large to deserialize within a program, and
//! `Sysvar::from_account_info` returns an error, or the serialization attempt
//! will exhaust the program's compute budget. Some sysvars do not implement
//! `Sysvar::get` and return an error. Some sysvars have custom deserializers
//! that do not implement the `Sysvar` trait. These cases are documented in the
//! modules for individual sysvars.
//!
//! All sysvar accounts are owned by the account identified by [`sysvar::ID`].
//!
//! [`sysvar::ID`]: https://docs.rs/solana-sdk-ids/latest/solana_sdk_ids/sysvar/constant.ID.html
//!
//! For more details see the Solana [documentation on sysvars][sysvardoc].
//!
//! [sysvardoc]: https://docs.solanalabs.com/runtime/sysvars

pub use solana_get_sysvar::{get_sysvar, impl_get_sysvar as impl_sysvar_get, GetSysvar as Sysvar};
#[cfg(feature = "bincode")]
use solana_program_error::ProgramError;
#[cfg(feature = "bincode")]
use {solana_account_info::AccountInfo, solana_sysvar_id::SysvarId};

pub mod clock;
pub mod epoch_rewards;
pub mod epoch_schedule;
pub mod fees;
pub mod last_restart_slot;
pub mod program_stubs;
pub mod recent_blockhashes;
pub mod rent;
pub mod rewards;
pub mod slot_hashes;
pub mod slot_history;
pub mod stake_history;

#[cfg(feature = "bincode")]
/// A type that holds sysvar data.
pub trait SysvarSerialize:
    Default + Sysvar + SysvarId + serde::Serialize + serde::de::DeserializeOwned
{
    /// The size in bytes of the sysvar as serialized account data.
    fn size_of() -> usize {
        bincode::serialized_size(&Self::default()).unwrap() as usize
    }

    /// Deserializes the sysvar from its `AccountInfo`.
    ///
    /// # Errors
    ///
    /// If `account_info` does not have the same ID as the sysvar this function
    /// returns [`ProgramError::InvalidArgument`].
    fn from_account_info(account_info: &AccountInfo) -> Result<Self, ProgramError> {
        if !Self::check_id(account_info.unsigned_key()) {
            return Err(ProgramError::InvalidArgument);
        }
        bincode::deserialize(&account_info.data.borrow()).map_err(|_| ProgramError::InvalidArgument)
    }

    /// Serializes the sysvar to `AccountInfo`.
    ///
    /// # Errors
    ///
    /// Returns `None` if serialization failed.
    fn to_account_info(&self, account_info: &mut AccountInfo) -> Option<()> {
        bincode::serialize_into(&mut account_info.data.borrow_mut()[..], self).ok()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        serde_derive::{Deserialize, Serialize},
        solana_program_error::ProgramError,
        solana_pubkey::Pubkey,
        std::{cell::RefCell, rc::Rc},
    };

    #[repr(C)]
    #[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
    struct TestSysvar {
        something: Pubkey,
    }
    solana_pubkey::declare_id!("TestSysvar111111111111111111111111111111111");
    impl solana_sysvar_id::SysvarId for TestSysvar {
        fn id() -> solana_pubkey::Pubkey {
            id()
        }

        fn check_id(pubkey: &solana_pubkey::Pubkey) -> bool {
            check_id(pubkey)
        }
    }
    impl Sysvar for TestSysvar {}
    impl SysvarSerialize for TestSysvar {}

    #[test]
    fn test_sysvar_account_info_to_from() {
        let test_sysvar = TestSysvar::default();
        let key = id();
        let wrong_key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 42;
        let mut data = vec![0_u8; TestSysvar::size_of()];
        let mut account_info =
            AccountInfo::new(&key, false, true, &mut lamports, &mut data, &owner, false);

        test_sysvar.to_account_info(&mut account_info).unwrap();
        let new_test_sysvar = TestSysvar::from_account_info(&account_info).unwrap();
        assert_eq!(test_sysvar, new_test_sysvar);

        account_info.key = &wrong_key;
        assert_eq!(
            TestSysvar::from_account_info(&account_info),
            Err(ProgramError::InvalidArgument)
        );

        let mut small_data = vec![];
        account_info.data = Rc::new(RefCell::new(&mut small_data));
        assert_eq!(test_sysvar.to_account_info(&mut account_info), None);
    }
}
