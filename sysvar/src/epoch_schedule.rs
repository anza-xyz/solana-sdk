//! Information about epoch duration.
//!
//! The _epoch schedule_ sysvar provides access to the [`EpochSchedule`] type,
//! which includes the number of slots per epoch, timing of leader schedule
//! selection, and information about epoch warm-up time.
//!
//! [`EpochSchedule`] implements [`Sysvar::get`] and can be loaded efficiently without
//! passing the sysvar account ID to the program.
//!
//! See also the Solana [documentation on the epoch schedule sysvar][sdoc].
//!
//! [sdoc]: https://docs.solanalabs.com/runtime/sysvars#epochschedule
//!
//! # Examples
//!
//! Accessing via on-chain program directly:
//!
//! ```no_run
//! # use solana_account_info::AccountInfo;
//! # use solana_epoch_schedule::EpochSchedule;
//! # use solana_msg::msg;
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_sdk_ids::sysvar::epoch_schedule;
//! # use solana_sysvar::Sysvar;
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!
//!     let epoch_schedule = EpochSchedule::get()?;
//!     msg!("epoch_schedule: {:#?}", epoch_schedule);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = EpochSchedule::id();
//! # let l = &mut 1120560;
//! # let d = &mut vec![0, 32, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Accessing via on-chain program's account parameters:
//!
//! ```
//! # use solana_account_info::{AccountInfo, next_account_info};
//! # use solana_epoch_schedule::EpochSchedule;
//! # use solana_msg::msg;
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_sdk_ids::sysvar::epoch_schedule;
//! # use solana_sysvar::{Sysvar, SysvarSerialize};
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let epoch_schedule_account_info = next_account_info(account_info_iter)?;
//!
//!     assert!(epoch_schedule::check_id(epoch_schedule_account_info.key));
//!
//!     let epoch_schedule = EpochSchedule::from_account_info(epoch_schedule_account_info)?;
//!     msg!("epoch_schedule: {:#?}", epoch_schedule);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = EpochSchedule::id();
//! # let l = &mut 1120560;
//! # let d = &mut vec![0, 32, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Accessing via the RPC client:
//!
//! ```
//! # use solana_epoch_schedule::EpochSchedule;
//! # use solana_example_mocks::solana_account;
//! # use solana_example_mocks::solana_rpc_client;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_account::Account;
//! # use solana_sdk_ids::sysvar::epoch_schedule;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_epoch_schedule(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(epoch_schedule::ID, Account {
//! #       lamports: 1120560,
//! #       data: vec![0, 32, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! # });
//! #
//!     let epoch_schedule = client.get_account(&epoch_schedule::ID)?;
//!     let data: EpochSchedule = bincode::deserialize(&epoch_schedule.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_epoch_schedule(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
use crate::{get_sysvar_via_packed, sysvar_packed_struct, Sysvar};
pub use {
    solana_epoch_schedule::EpochSchedule,
    solana_sdk_ids::sysvar::epoch_schedule::{check_id, id, ID},
};

sysvar_packed_struct! {
    struct EpochSchedulePacked(33) {
        slots_per_epoch: u64,
        leader_schedule_slot_offset: u64,
        warmup: u8, // bool as u8
        first_normal_epoch: u64,
        first_normal_slot: u64,
    }
}

impl From<EpochSchedulePacked> for EpochSchedule {
    fn from(p: EpochSchedulePacked) -> Self {
        Self {
            slots_per_epoch: p.slots_per_epoch,
            leader_schedule_slot_offset: p.leader_schedule_slot_offset,
            warmup: p.warmup != 0,
            first_normal_epoch: p.first_normal_epoch,
            first_normal_slot: p.first_normal_slot,
        }
    }
}

impl Sysvar for EpochSchedule {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        get_sysvar_via_packed::<Self, EpochSchedulePacked>(&id())
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for EpochSchedule {}

#[cfg(test)]
mod tests {
    use {super::*, crate::Sysvar, serial_test::serial};

    #[test]
    fn test_epoch_schedule_packed_size() {
        assert_eq!(core::mem::size_of::<EpochSchedulePacked>(), 33);
    }

    #[test]
    #[serial]
    #[cfg(feature = "bincode")]
    fn test_epoch_schedule_get() {
        use {
            crate::program_stubs::{set_syscall_stubs, SyscallStubs},
            solana_program_entrypoint::SUCCESS,
        };

        let expected = EpochSchedule::custom(1234, 5678, false);
        let data = bincode::serialize(&expected).unwrap();
        assert_eq!(data.len(), 33);

        struct MockSyscall {
            data: Vec<u8>,
        }
        impl SyscallStubs for MockSyscall {
            fn sol_get_sysvar(
                &self,
                _sysvar_id_addr: *const u8,
                var_addr: *mut u8,
                offset: u64,
                length: u64,
            ) -> u64 {
                unsafe {
                    let slice = core::slice::from_raw_parts_mut(var_addr, length as usize);
                    slice.copy_from_slice(&self.data[offset as usize..(offset + length) as usize]);
                }
                SUCCESS
            }
        }

        set_syscall_stubs(Box::new(MockSyscall { data }));
        let got = EpochSchedule::get().unwrap();
        assert_eq!(got, expected);
    }
}
