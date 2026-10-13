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
//! program, then the program can deserialize the sysvar with wincode to access
//! its data, as in this example that again logs the [`clock`] sysvar.
//!
//! ```
//! use solana_account_info::{AccountInfo, next_account_info};
//! use solana_clock::Clock;
//! use solana_msg::msg;
//! use solana_program_error::{ProgramError, ProgramResult};
//! use solana_pubkey::Pubkey;
//! use solana_sdk_ids::sysvar::clock;
//!
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let clock_account = next_account_info(account_info_iter)?;
//!     if !clock::check_id(clock_account.key) {
//!         return Err(ProgramError::InvalidArgument);
//!     }
//!     let clock: Clock = wincode::deserialize(&clock_account.data.borrow())
//!         .map_err(|_| ProgramError::InvalidArgument)?;
//!     msg!("clock: {:#?}", clock);
//!     Ok(())
//! }
//! ```
//!
//! When possible, programs should prefer to call `Sysvar::get` instead of
//! deserializing with wincode, as the latter imposes extra
//! overhead of deserialization while also requiring the sysvar account address
//! be passed to the program, wasting the limited space available to
//! transactions. Deserializing sysvars that can instead be retrieved with
//! `Sysvar::get` should be only be considered for compatibility with older
//! programs that pass around sysvar accounts.
//!
//! Some sysvars are too large to deserialize within a program, and
//! deserializing them may exhaust the program's compute budget. Some sysvars do
//! not implement `Sysvar::get` and return an error. Some sysvars have custom deserializers
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
