#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{AbiEnumVisitor, AbiExample};
use std::fmt;

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RewardType {
    Fee,
    Rent,
    Staking,
    Voting,
}

impl fmt::Display for RewardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RewardType::Fee => "fee",
                RewardType::Rent => "rent",
                RewardType::Staking => "staking",
                RewardType::Voting => "voting",
            }
        )
    }
}
