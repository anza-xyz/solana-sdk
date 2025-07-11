//! The Solana host and client SDK.
//!
//! This is the base library for all off-chain programs that interact with
//! Solana or otherwise operate on Solana data structures. On-chain programs
//! instead use the [`solana-program`] crate, the modules of which are
//! re-exported by this crate, like the relationship between the Rust
//! `core` and `std` crates. As much of the functionality of this crate is
//! provided by `solana-program`, see that crate's documentation for an
//! overview.
//!
//! [`solana-program`]: https://docs.rs/solana-program
//!
//! Many of the modules in this crate are primarily of use to the Solana runtime
//! itself. Additional crates provide capabilities built on `solana-sdk`, and
//! many programs will need to link to those crates as well, particularly for
//! clients communicating with Solana nodes over RPC.
//!
//! Such crates include:
//!
//! - [`solana-client`] - For interacting with a Solana node via the [JSON-RPC API][json].
//! - [`solana-cli-config`] - Loading and saving the Solana CLI configuration file.
//! - [`solana-clap-utils`] - Routines for setting up the CLI using [`clap`], as
//!   used by the Solana CLI. Includes functions for loading all types of
//!   signers supported by the CLI.
//!
//! [`solana-client`]: https://docs.rs/solana-client
//! [`solana-cli-config`]: https://docs.rs/solana-cli-config
//! [`solana-clap-utils`]: https://docs.rs/solana-clap-utils
//! [json]: https://solana.com/docs/rpc
//! [`clap`]: https://docs.rs/clap

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Allows macro expansion of `use ::solana_sdk::*` to work within this crate
extern crate self as solana_sdk;

#[deprecated(since = "2.2.0", note = "Use `solana-message` crate instead")]
pub use solana_message as message;
#[cfg(feature = "borsh")]
pub use solana_program::borsh1;
#[cfg(not(target_os = "solana"))]
pub use solana_program::program_stubs;
pub use solana_program::{
    account_info, big_mod_exp, blake3, bpf_loader, bpf_loader_deprecated, clock, config,
    custom_heap_default, custom_panic_default, debug_account_data, declare_deprecated_sysvar_id,
    declare_sysvar_id, ed25519_program, epoch_rewards, epoch_schedule, fee_calculator,
    impl_sysvar_get, incinerator, instruction, keccak, lamports, msg, native_token, program,
    program_error, program_option, program_pack, rent, secp256k1_program, serialize_utils,
    slot_hashes, slot_history, stable_layout, syscalls, sysvar, unchecked_div_by_const,
};
#[cfg(feature = "full")]
#[deprecated(since = "2.2.0", note = "Use `solana-signer` crate instead")]
pub use solana_signer::signers;
pub mod entrypoint;
pub mod entrypoint_deprecated;
pub mod example_mocks;
pub mod hash;
pub mod log;
pub mod native_loader;
pub mod pubkey;
#[cfg(feature = "full")]
#[deprecated(since = "2.2.0", note = "Use `solana-shred-version` crate instead")]
pub use solana_shred_version as shred_version;
pub mod signature;
pub mod signer;
pub mod transaction;
pub mod transport;

#[deprecated(since = "2.1.0", note = "Use `solana-account` crate instead")]
pub use solana_account as account;
#[deprecated(
    since = "2.1.0",
    note = "Use `solana_account::state_traits` crate instead"
)]
pub use solana_account::state_traits as account_utils;
#[deprecated(since = "2.2.0", note = "Use `solana-epoch-info` crate instead")]
pub use solana_epoch_info as epoch_info;
#[deprecated(
    since = "2.2.0",
    note = "Use `solana-epoch-rewards-hasher` crate instead"
)]
pub use solana_epoch_rewards_hasher as epoch_rewards_hasher;
#[deprecated(since = "2.2.0", note = "Use `solana-fee-structure` crate instead")]
pub use solana_fee_structure as fee;
#[deprecated(since = "2.1.0", note = "Use `solana-inflation` crate instead")]
pub use solana_inflation as inflation;
#[deprecated(
    since = "2.2.0",
    note = "Use `solana_message::inner_instruction` instead"
)]
pub use solana_message::inner_instruction;
#[cfg(feature = "full")]
#[deprecated(since = "2.2.0", note = "Use `solana-offchain-message` crate instead")]
pub use solana_offchain_message as offchain_message;
#[deprecated(since = "2.1.0", note = "Use `solana-program-memory` crate instead")]
pub use solana_program_memory as program_memory;
#[deprecated(since = "2.1.0", note = "Use `solana_pubkey::pubkey` instead")]
/// Convenience macro to define a static public key.
///
/// Input: a single literal base58 string representation of a Pubkey
///
/// # Example
///
/// ```
/// use std::str::FromStr;
/// use solana_program::{pubkey, pubkey::Pubkey};
///
/// static ID: Pubkey = pubkey!("My11111111111111111111111111111111111111111");
///
/// let my_id = Pubkey::from_str("My11111111111111111111111111111111111111111").unwrap();
/// assert_eq!(ID, my_id);
/// ```
pub use solana_pubkey::pubkey;
#[deprecated(since = "2.1.0", note = "Use `solana-sanitize` crate instead")]
pub use solana_sanitize as sanitize;
/// Same as `declare_id` except report that this id has been deprecated.
pub use solana_sdk_macro::declare_deprecated_id;
/// Convenience macro to declare a static public key and functions to interact with it.
///
/// Input: a single literal base58 string representation of a program's id
///
/// # Example
///
/// ```
/// # // wrapper is used so that the macro invocation occurs in the item position
/// # // rather than in the statement position which isn't allowed.
/// use std::str::FromStr;
/// use solana_sdk::{declare_id, pubkey::Pubkey};
///
/// # mod item_wrapper {
/// #   use solana_sdk::declare_id;
/// declare_id!("My11111111111111111111111111111111111111111");
/// # }
/// # use item_wrapper::id;
///
/// let my_id = Pubkey::from_str("My11111111111111111111111111111111111111111").unwrap();
/// assert_eq!(id(), my_id);
/// ```
pub use solana_sdk_macro::declare_id;
/// Convenience macro to define multiple static public keys.
pub use solana_sdk_macro::pubkeys;
#[deprecated(since = "2.2.0", note = "Use `solana-serde` crate instead")]
pub use solana_serde as deserialize_utils;
#[deprecated(since = "2.1.0", note = "Use `solana-serde-varint` crate instead")]
pub use solana_serde_varint as serde_varint;
#[deprecated(since = "2.1.0", note = "Use `solana-short-vec` crate instead")]
pub use solana_short_vec as short_vec;
#[deprecated(since = "2.2.0", note = "Use `solana-time-utils` crate instead")]
pub use solana_time_utils as timing;
#[cfg(feature = "full")]
#[deprecated(
    since = "2.2.0",
    note = "Use `solana_transaction::simple_vote_transaction_checker` instead"
)]
pub use solana_transaction::simple_vote_transaction_checker;

pub extern crate bs58;
