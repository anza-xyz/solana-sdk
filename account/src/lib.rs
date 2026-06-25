#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! The Solana [`Account`] type.

#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi, StableAbiSample};
use {solana_clock::Epoch, solana_pubkey::Pubkey, std::sync::Arc};

mod account;
pub use account::*;

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "bincode")]
pub mod state_traits;

// NOTE: `Account` and `AccountSharedData` are defined here, in the crate root, on
// purpose. The frozen-abi digest of any downstream struct that has an
// `Account`/`AccountSharedData` field hashes that field's fully-qualified
// `std::any::type_name`, so the definitions must stay at `solana_account::*` to keep
// `type_name` (and therefore those digests) stable. Everything else (impls, traits,
// helpers) lives in the `account` module.

/// An Account with data that is stored on chain
#[repr(C)]
#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiExample, StableAbi, StableAbiSample),
    frozen_abi(
        api_digest = "62EqVoynUFvuui7DVfqWCvZP7bxKGJGioeSBnWrdjRME",
        abi_digest = "G4phLpfhujMpk4wS1WswCe4HqnQjCBPWjrXjvDZ6iUw8"
    )
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[derive(PartialEq, Eq, Clone, Default)]
pub struct Account {
    /// lamports in the account
    pub lamports: u64,
    /// data held in this account
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    #[cfg_attr(
        feature = "frozen-abi",
        stable_abi_sample(
            with = "(0..rng.random_range(0..=1000)).map(|_| rng.random()).collect()"
        )
    )]
    pub data: Vec<u8>,
    /// the program that owns this account. If executable, the program that loads this account.
    pub owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    pub rent_epoch: Epoch,
}

/// An Account with data that is stored on chain
/// This will be the in-memory representation of the 'Account' struct data.
/// The existing 'Account' structure cannot easily change due to downstream projects.
#[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize),
    serde(from = "Account")
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[derive(PartialEq, Eq, Clone, Default)]
pub struct AccountSharedData {
    /// lamports in the account
    lamports: u64,
    /// data held in this account
    data: Arc<Vec<u8>>,
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,
}
