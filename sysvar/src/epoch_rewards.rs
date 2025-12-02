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

use crate::Sysvar;
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
pub use {
    solana_epoch_rewards::EpochRewards,
    solana_sdk_ids::sysvar::epoch_rewards::{check_id, id, ID},
};

/// Pod (Plain Old Data) representation of [`EpochRewards`] with no padding.
///
/// This type can be safely loaded via `sol_get_sysvar` without undefined behavior.
/// Provides performant zero-copy accessors as an alternative to the `EpochRewards` type.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodEpochRewards {
    distribution_starting_block_height: [u8; 8],
    num_partitions: [u8; 8],
    parent_blockhash: [u8; 32],
    total_points: [u8; 16],
    total_rewards: [u8; 8],
    distributed_rewards: [u8; 8],
    active: u8,
}

const _: () = assert!(core::mem::size_of::<PodEpochRewards>() == 81);

impl PodEpochRewards {
    pub fn fetch() -> Result<Self, solana_program_error::ProgramError> {
        let mut pod = core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            crate::get_sysvar_unchecked(
                pod.as_mut_ptr() as *mut u8,
                (&id()) as *const _ as *const u8,
                0,
                81,
            )?;
            Ok(pod.assume_init())
        }
    }

    pub fn distribution_starting_block_height(&self) -> u64 {
        u64::from_le_bytes(self.distribution_starting_block_height)
    }

    pub fn num_partitions(&self) -> u64 {
        u64::from_le_bytes(self.num_partitions)
    }

    pub fn parent_blockhash(&self) -> solana_hash::Hash {
        solana_hash::Hash::new_from_array(self.parent_blockhash)
    }

    pub fn total_points(&self) -> u128 {
        u128::from_le_bytes(self.total_points)
    }

    pub fn total_rewards(&self) -> u64 {
        u64::from_le_bytes(self.total_rewards)
    }

    pub fn distributed_rewards(&self) -> u64 {
        u64::from_le_bytes(self.distributed_rewards)
    }

    pub fn active(&self) -> bool {
        match self.active {
            0 => false,
            1 => true,
            _ => panic!("invalid active value"),
        }
    }
}

impl From<PodEpochRewards> for EpochRewards {
    fn from(pod: PodEpochRewards) -> Self {
        Self {
            distribution_starting_block_height: pod.distribution_starting_block_height(),
            num_partitions: pod.num_partitions(),
            parent_blockhash: pod.parent_blockhash(),
            total_points: pod.total_points(),
            total_rewards: pod.total_rewards(),
            distributed_rewards: pod.distributed_rewards(),
            active: pod.active(),
        }
    }
}

impl Sysvar for EpochRewards {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        Ok(Self::from(PodEpochRewards::fetch()?))
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for EpochRewards {}

#[cfg(test)]
mod tests {
    use {super::*, crate::Sysvar, serial_test::serial};

    #[test]
    fn test_pod_epoch_rewards_conversion() {
        let pod = PodEpochRewards {
            distribution_starting_block_height: 42u64.to_le_bytes(),
            num_partitions: 7u64.to_le_bytes(),
            parent_blockhash: [0xAA; 32],
            total_points: 1234567890u128.to_le_bytes(),
            total_rewards: 100u64.to_le_bytes(),
            distributed_rewards: 10u64.to_le_bytes(),
            active: 1,
        };

        let epoch_rewards = EpochRewards::from(pod);

        assert_eq!(epoch_rewards.distribution_starting_block_height, 42);
        assert_eq!(epoch_rewards.num_partitions, 7);
        assert_eq!(
            epoch_rewards.parent_blockhash,
            solana_hash::Hash::new_from_array([0xAA; 32])
        );
        assert_eq!(epoch_rewards.total_points, 1234567890);
        assert_eq!(epoch_rewards.total_rewards, 100);
        assert_eq!(epoch_rewards.distributed_rewards, 10);
        assert!(epoch_rewards.active);
    }

    #[test]
    #[serial]
    #[cfg(feature = "bincode")]
    fn test_epoch_rewards_get() {
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

        crate::tests::mock_get_sysvar_syscall(&data);
        let got = EpochRewards::get().unwrap();
        assert_eq!(got, expected);
    }
}
