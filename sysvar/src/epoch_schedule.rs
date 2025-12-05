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
use crate::Sysvar;
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
pub use {
    solana_epoch_schedule::EpochSchedule,
    solana_sdk_ids::sysvar::epoch_schedule::{check_id, id, ID},
};

/// Pod (Plain Old Data) representation of [`EpochSchedule`] with no padding.
///
/// This type can be safely loaded via `sol_get_sysvar` without undefined behavior.
/// Provides performant zero-copy accessors as an alternative to the `EpochSchedule` type.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodEpochSchedule {
    slots_per_epoch: [u8; 8],
    leader_schedule_slot_offset: [u8; 8],
    warmup: u8,
    first_normal_epoch: [u8; 8],
    first_normal_slot: [u8; 8],
}

const POD_EPOCH_SCHEDULE_SIZE: usize = 33;
const _: () = assert!(core::mem::size_of::<PodEpochSchedule>() == POD_EPOCH_SCHEDULE_SIZE);

impl PodEpochSchedule {
    /// Fetch the sysvar data using the `sol_get_sysvar` syscall.
    /// This provides an alternative to `EpochSchedule` which provides zero-copy accessors.
    pub fn fetch() -> Result<Self, solana_program_error::ProgramError> {
        let mut pod = core::mem::MaybeUninit::<Self>::uninit();
        // Safety: `get_sysvar_unchecked` will initialize `pod` with the sysvar data,
        // and error if unsuccessful.
        unsafe {
            crate::get_sysvar_unchecked(
                pod.as_mut_ptr() as *mut u8,
                (&id()) as *const _ as *const u8,
                0,
                POD_EPOCH_SCHEDULE_SIZE as u64,
            )?;
            Ok(pod.assume_init())
        }
    }

    pub fn slots_per_epoch(&self) -> u64 {
        u64::from_le_bytes(self.slots_per_epoch)
    }

    pub fn leader_schedule_slot_offset(&self) -> u64 {
        u64::from_le_bytes(self.leader_schedule_slot_offset)
    }

    pub fn warmup(&self) -> bool {
        // SAFETY: upstream invariant: the sysvar data is created exclusively
        // by the Solana runtime and serializes bool as 0x00 or 0x01.
        self.warmup > 0
    }

    pub fn first_normal_epoch(&self) -> u64 {
        u64::from_le_bytes(self.first_normal_epoch)
    }

    pub fn first_normal_slot(&self) -> u64 {
        u64::from_le_bytes(self.first_normal_slot)
    }
}

impl From<PodEpochSchedule> for EpochSchedule {
    fn from(pod: PodEpochSchedule) -> Self {
        Self {
            slots_per_epoch: pod.slots_per_epoch(),
            leader_schedule_slot_offset: pod.leader_schedule_slot_offset(),
            warmup: pod.warmup(),
            first_normal_epoch: pod.first_normal_epoch(),
            first_normal_slot: pod.first_normal_slot(),
        }
    }
}

impl Sysvar for EpochSchedule {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        Ok(PodEpochSchedule::fetch()?.into())
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for EpochSchedule {}

#[cfg(test)]
mod tests {
    use {super::*, crate::Sysvar, serial_test::serial};

    #[test]
    fn test_pod_epoch_schedule_conversion() {
        let pod = PodEpochSchedule {
            slots_per_epoch: 432000u64.to_le_bytes(),
            leader_schedule_slot_offset: 432000u64.to_le_bytes(),
            warmup: 1,
            first_normal_epoch: 14u64.to_le_bytes(),
            first_normal_slot: 524256u64.to_le_bytes(),
        };

        let epoch_schedule = EpochSchedule::from(pod);

        assert_eq!(epoch_schedule.slots_per_epoch, 432000);
        assert_eq!(epoch_schedule.leader_schedule_slot_offset, 432000);
        assert!(epoch_schedule.warmup);
        assert_eq!(epoch_schedule.first_normal_epoch, 14);
        assert_eq!(epoch_schedule.first_normal_slot, 524256);
    }

    #[test]
    #[serial]
    #[cfg(feature = "bincode")]
    fn test_epoch_schedule_get() {
        let expected = EpochSchedule::custom(1234, 5678, false);
        let data = bincode::serialize(&expected).unwrap();
        assert_eq!(data.len(), 33);

        crate::tests::mock_get_sysvar_syscall(&data);
        let got = EpochSchedule::get().unwrap();
        assert_eq!(got, expected);
    }
}
