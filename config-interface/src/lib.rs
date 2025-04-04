#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(clippy::arithmetic_side_effects)]
#[cfg(feature = "bincode")]
pub mod config_instruction;

use solana_pubkey::Pubkey;
pub use solana_sdk_ids::config::id;
#[cfg(feature = "bincode")]
#[allow(deprecated)]
use {
    bincode::{deserialize, serialize, serialized_size},
    solana_account::{Account, AccountSharedData},
    solana_stake_interface::config::Config as StakeConfig,
};
#[cfg(feature = "serde")]
use {
    serde_derive::{Deserialize, Serialize},
    solana_short_vec as short_vec,
};

#[cfg(feature = "serde")]
pub trait ConfigState: serde::Serialize + Default {
    /// Maximum space that the serialized representation will require
    fn max_space() -> u64;
}

// TODO move ConfigState into `solana_program` to implement trait locally
#[cfg(feature = "bincode")]
#[allow(deprecated)]
impl ConfigState for StakeConfig {
    fn max_space() -> u64 {
        serialized_size(&StakeConfig::default()).unwrap()
    }
}

/// A collection of keys to be stored in Config account data.
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct ConfigKeys {
    // Each key tuple comprises a unique `Pubkey` identifier,
    // and `bool` whether that key is a signer of the data
    #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
    pub keys: Vec<(Pubkey, bool)>,
}

#[cfg(feature = "bincode")]
impl ConfigKeys {
    pub fn serialized_size(keys: Vec<(Pubkey, bool)>) -> u64 {
        serialized_size(&ConfigKeys { keys }).unwrap()
    }
}

#[cfg(feature = "bincode")]
pub fn get_config_data(bytes: &[u8]) -> Result<&[u8], bincode::Error> {
    deserialize::<ConfigKeys>(bytes)
        .and_then(|keys| serialized_size(&keys))
        .map(|offset| &bytes[offset as usize..])
}

#[cfg(feature = "bincode")]
// utility for pre-made Accounts
pub fn create_config_account<T: ConfigState>(
    keys: Vec<(Pubkey, bool)>,
    config_data: &T,
    lamports: u64,
) -> AccountSharedData {
    let mut data = serialize(&ConfigKeys { keys }).unwrap();
    data.extend_from_slice(&serialize(config_data).unwrap());
    AccountSharedData::from(Account {
        lamports,
        data,
        owner: id(),
        ..Account::default()
    })
}
