//! A type to hold data for the [`EpochRewards` sysvar][sv].
//!
//! [sv]: https://docs.solanalabs.com/runtime/sysvars#epochrewards
//!
//! The sysvar ID is declared in [`sysvar`].
//!
//! [`sysvar`]: crate::sysvar

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

#[cfg(feature = "sysvar")]
pub mod sysvar;

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
use {solana_hash::Hash, solana_sdk_macro::CloneZeroed};

#[repr(C)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Default, CloneZeroed)]
pub struct EpochRewards {
    /// The starting block height of the rewards distribution in the current
    /// epoch
    distribution_starting_block_height: [u8; 8],

    /// Number of partitions in the rewards distribution in the current epoch,
    /// used to generate an EpochRewardsHasher
    num_partitions: [u8; 8],

    /// The blockhash of the parent block of the first block in the epoch, used
    /// to seed an EpochRewardsHasher
    pub parent_blockhash: Hash,

    /// The total rewards points calculated for the current epoch, where points
    /// equals the sum of (delegated stake * credits observed) for all
    /// delegations
    total_points: [u8; 16],

    /// The total rewards calculated for the current epoch. This may be greater
    /// than the total `distributed_rewards` at the end of the rewards period,
    /// due to rounding and inability to deliver rewards smaller than 1 lamport.
    total_rewards: [u8; 8],

    /// The rewards currently distributed for the current epoch, in lamports
    distributed_rewards: [u8; 8],

    /// Whether the rewards period (including calculation and distribution) is
    /// active
    pub active: u8,
}

impl EpochRewards {
    pub fn distribution_starting_block_height(&self) -> u64 {
        u64::from_le_bytes(self.distribution_starting_block_height)
    }

    pub fn num_partitions(&self) -> u64 {
        u64::from_le_bytes(self.num_partitions)
    }

    pub fn parent_blockhash(&self) -> &Hash {
        &self.parent_blockhash
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

    pub fn new(
        total_rewards: u64,
        distributed_rewards: u64,
        distribution_starting_block_height: u64,
    ) -> Self {
        Self {
            distribution_starting_block_height: distribution_starting_block_height.to_le_bytes(),
            total_rewards: total_rewards.to_le_bytes(),
            distributed_rewards: distributed_rewards.to_le_bytes(),
            ..Self::default()
        }
    }

    pub fn distribute(&mut self, amount: u64) {
        let new_distributed_rewards = self.distributed_rewards().saturating_add(amount);
        assert!(new_distributed_rewards <= self.total_rewards());
        self.distributed_rewards = new_distributed_rewards.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_rewards_distribute() {
        let mut epoch_rewards = EpochRewards::new(100, 0, 64);
        epoch_rewards.distribute(100);

        assert_eq!(epoch_rewards.total_rewards(), 100);
        assert_eq!(epoch_rewards.distributed_rewards(), 100);
    }

    #[test]
    #[should_panic(expected = "new_distributed_rewards <= self.total_rewards")]
    fn test_epoch_rewards_distribute_panic() {
        let mut epoch_rewards = EpochRewards::new(100, 0, 64);
        epoch_rewards.distribute(200);
    }
}
