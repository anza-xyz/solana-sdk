//! Epoch rewards for current epoch
//!
//! The _epoch rewards_ sysvar provides access to the [`EpochRewards`] type,
//! which tracks whether the rewards period (including calculation and
//! distribution) is in progress, as well as the details needed to resume
//! distribution when starting from a snapshot during the rewards period. The
//! sysvar is repopulated at the start of the first block of each epoch.
//! Therefore, the sysvar contains data about the current epoch until a new
//! epoch begins. Fields in the sysvar include:
//!   - distribution starting block height
//!   - the number of partitions in the distribution
//!   - the parent-blockhash seed used to generate the partition hasher
//!   - the total rewards points calculated for the epoch
//!   - total rewards for epoch, in lamports
//!   - rewards for the epoch distributed so far, in lamports
//!   - whether the rewards period is active
//!
//! [`EpochRewards`] implements [`Sysvar::get`] and can be loaded efficiently without
//! passing the sysvar account ID to the program.
//!
//! See also the Solana [documentation on the epoch rewards sysvar][sdoc].
//!
//! [sdoc]: https://docs.solanalabs.com/runtime/sysvars#epochrewards
//!
//! # Examples
//!
//! Accessing via on-chain program directly:
//!
//! ```no_run
//! # use solana_account_info::AccountInfo;
//! # use solana_epoch_rewards::EpochRewards;
//! # use solana_msg::msg;
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_sysvar::Sysvar;
//! # use solana_sdk_ids::sysvar::epoch_rewards;
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!
//!     let epoch_rewards = EpochRewards::get()?;
//!     msg!("epoch_rewards: {:#?}", epoch_rewards);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = EpochRewards::id();
//! # let l = &mut 1559040;
//! # let epoch_rewards = EpochRewards {
//! #     distribution_starting_block_height: 42,
//! #     total_rewards: 100,
//! #     distributed_rewards: 10,
//! #     active: true,
//! #     ..EpochRewards::default()
//! # };
//! # let mut d: Vec<u8> = bincode::serialize(&epoch_rewards).unwrap();
//! # let a = AccountInfo::new(&p, false, false, l, &mut d, &p, false);
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
//! # use solana_epoch_rewards::EpochRewards;
//! # use solana_msg::msg;
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_sysvar::{Sysvar, SysvarSerialize};
//! # use solana_sdk_ids::sysvar::epoch_rewards;
//! #
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let epoch_rewards_account_info = next_account_info(account_info_iter)?;
//!
//!     assert!(epoch_rewards::check_id(epoch_rewards_account_info.key));
//!
//!     let epoch_rewards = EpochRewards::from_account_info(epoch_rewards_account_info)?;
//!     msg!("epoch_rewards: {:#?}", epoch_rewards);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = EpochRewards::id();
//! # let l = &mut 1559040;
//! # let epoch_rewards = EpochRewards {
//! #     distribution_starting_block_height: 42,
//! #     total_rewards: 100,
//! #     distributed_rewards: 10,
//! #     active: true,
//! #     ..EpochRewards::default()
//! # };
//! # let mut d: Vec<u8> = bincode::serialize(&epoch_rewards).unwrap();
//! # let a = AccountInfo::new(&p, false, false, l, &mut d, &p, false);
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
//! # use solana_epoch_rewards::EpochRewards;
//! # use solana_example_mocks::solana_account;
//! # use solana_example_mocks::solana_rpc_client;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_account::Account;
//! # use solana_sdk_ids::sysvar::epoch_rewards;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_epoch_rewards(client: &RpcClient) -> Result<()> {
//! #   let epoch_rewards = EpochRewards {
//! #       distribution_starting_block_height: 42,
//! #       total_rewards: 100,
//! #       distributed_rewards: 10,
//! #       active: true,
//! #       ..EpochRewards::default()
//! #   };
//! #   let data: Vec<u8> = bincode::serialize(&epoch_rewards)?;
//! #   client.set_get_account_response(epoch_rewards::ID, Account {
//! #       lamports: 1120560,
//! #       data,
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! # });
//! #
//!     let epoch_rewards = client.get_account(&epoch_rewards::ID)?;
//!     let data: EpochRewards = bincode::deserialize(&epoch_rewards.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_epoch_rewards(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```

#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
use crate::{get_sysvar_via_packed, sysvar_packed_struct, Sysvar};
pub use {
    solana_epoch_rewards::EpochRewards,
    solana_sdk_ids::sysvar::epoch_rewards::{check_id, id, ID},
};

sysvar_packed_struct! {
    struct EpochRewardsPacked(81) {
        distribution_starting_block_height: u64,
        num_partitions: u64,
        parent_blockhash: [u8; 32],
        total_points: u128,
        total_rewards: u64,
        distributed_rewards: u64,
        active: u8, // bool as u8
    }
}

impl From<EpochRewardsPacked> for EpochRewards {
    fn from(p: EpochRewardsPacked) -> Self {
        Self {
            distribution_starting_block_height: p.distribution_starting_block_height,
            num_partitions: p.num_partitions,
            parent_blockhash: solana_hash::Hash::new_from_array(p.parent_blockhash),
            total_points: p.total_points,
            total_rewards: p.total_rewards,
            distributed_rewards: p.distributed_rewards,
            active: p.active != 0,
        }
    }
}

impl Sysvar for EpochRewards {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        get_sysvar_via_packed::<Self, EpochRewardsPacked>(&id())
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for EpochRewards {}

#[cfg(test)]
mod tests {
    use {super::*, crate::Sysvar, serial_test::serial};

    #[test]
    fn test_epoch_rewards_packed_size() {
        assert_eq!(core::mem::size_of::<EpochRewardsPacked>(), 81);
    }

    #[test]
    #[serial]
    #[cfg(feature = "bincode")]
    fn test_epoch_rewards_get() {
        use {
            crate::program_stubs::{set_syscall_stubs, SyscallStubs},
            solana_program_entrypoint::SUCCESS,
        };

        let expected = EpochRewards {
            distribution_starting_block_height: 42,
            num_partitions: 7,
            parent_blockhash: solana_hash::Hash::new_unique(),
            total_points: 1234567890,
            total_rewards: 100,
            distributed_rewards: 10,
            active: true,
        };

        let data = bincode::serialize(&expected).unwrap();
        assert_eq!(data.len(), 81);

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
        let got = EpochRewards::get().unwrap();
        assert_eq!(got, expected);
    }
}
