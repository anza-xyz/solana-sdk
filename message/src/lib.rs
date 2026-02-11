#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
//! Sequences of [`Instruction`]s executed within a single transaction.
//!
//! [`Instruction`]: https://docs.rs/solana-instruction/latest/solana_instruction/struct.Instruction.html
//!
//! In Solana, programs execute instructions, and clients submit sequences
//! of instructions to the network to be atomically executed as [`Transaction`]s.
//!
//! [`Transaction`]: https://docs.rs/solana-sdk/latest/solana-sdk/transaction/struct.Transaction.html
//!
//! A [`Message`] is the compact internal encoding of a transaction, as
//! transmitted across the network and stored in, and operated on, by the
//! runtime. It contains a flat array of all accounts accessed by all
//! instructions in the message, a [`MessageHeader`] that describes the layout
//! of that account array, a [recent blockhash], and a compact encoding of the
//! message's instructions.
//!
//! [recent blockhash]: https://solana.com/docs/core/transactions#recent-blockhash
//!
//! Clients most often deal with `Instruction`s and `Transaction`s, with
//! `Message`s being created by `Transaction` constructors.
//!
//! To ensure reliable network delivery, serialized messages must fit into the
//! IPv6 MTU size, conservatively assumed to be 1280 bytes. Thus constrained,
//! care must be taken in the amount of data consumed by instructions, and the
//! number of accounts they require to function.
//!
//! This module defines two versions of `Message` in their own modules:
//! [`legacy`] and [`v0`]. `legacy` is reexported here and is the current
//! version as of Solana 1.10.0. `v0` is a [future message format] that encodes
//! more account keys into a transaction than the legacy format. The
//! [`VersionedMessage`] type is a thin wrapper around either message version.
//!
//! [future message format]: https://docs.solanalabs.com/proposals/versioned-transactions
//!
//! Despite living in the `solana-program` crate, there is no way to access the
//! runtime's messages from within a Solana program, and only the legacy message
//! types continue to be exposed to Solana programs, for backwards compatibility
//! reasons.

pub mod compiled_instruction;
mod compiled_keys;
pub mod inline_nonce;
pub mod inner_instruction;
pub mod legacy;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite, UninitBuilder};
use {solana_sdk_ids::bpf_loader_upgradeable, std::collections::HashSet};

#[cfg(not(target_os = "solana"))]
#[path = ""]
mod non_bpf_modules {
    mod account_keys;
    mod address_loader;
    mod sanitized;
    mod versions;

    pub use {account_keys::*, address_loader::*, sanitized::*, versions::*};
}

use crate::compiled_instruction::CompiledInstruction;
#[cfg(not(target_os = "solana"))]
pub use non_bpf_modules::*;
pub use {
    compiled_keys::CompileError,
    legacy::Message,
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
};

/// The length of a message header in bytes.
pub const MESSAGE_HEADER_LENGTH: usize = 3;

/// Describes the organization of a `Message`'s account keys.
///
/// Every [`Instruction`] specifies which accounts it may reference, or
/// otherwise requires specific permissions of. Those specifications are:
/// whether the account is read-only, or read-write; and whether the account
/// must have signed the transaction containing the instruction.
///
/// Whereas individual `Instruction`s contain a list of all accounts they may
/// access, along with their required permissions, a `Message` contains a
/// single shared flat list of _all_ accounts required by _all_ instructions in
/// a transaction. When building a `Message`, this flat list is created and
/// `Instruction`s are converted to [`CompiledInstruction`]s. Those
/// `CompiledInstruction`s then reference by index the accounts they require in
/// the single shared account list.
///
/// [`Instruction`]: https://docs.rs/solana-instruction/latest/solana_instruction/struct.Instruction.html
/// [`CompiledInstruction`]: crate::compiled_instruction::CompiledInstruction
///
/// The shared account list is ordered by the permissions required of the accounts:
///
/// - accounts that are writable and signers
/// - accounts that are read-only and signers
/// - accounts that are writable and not signers
/// - accounts that are read-only and not signers
///
/// Given this ordering, the fields of `MessageHeader` describe which accounts
/// in a transaction require which permissions.
///
/// When multiple transactions access the same read-only accounts, the runtime
/// may process them in parallel, in a single [PoH] entry. Transactions that
/// access the same read-write accounts are processed sequentially.
///
/// [PoH]: https://docs.solanalabs.com/consensus/synchronization
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead, UninitBuilder))]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct MessageHeader {
    /// The number of signatures required for this message to be considered
    /// valid. The signers of those signatures must match the first
    /// `num_required_signatures` of [`Message::account_keys`].
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    pub num_required_signatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    pub num_readonly_signed_accounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    pub num_readonly_unsigned_accounts: u8,
}

/// The definition of address lookup table accounts.
///
/// As used by the `crate::v0` message format.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressLookupTableAccount {
    pub key: Address,
    pub addresses: Vec<Address>,
}

/// Returns true if the account at the specified index was requested to be
/// writable.
///
/// This method should not be used directly. It is used by Legacy and V1
/// message types.
#[inline(always)]
fn is_writable_index(i: usize, header: MessageHeader, account_keys: &[Address]) -> bool {
    i < (header.num_required_signatures as usize)
        .saturating_sub(header.num_readonly_signed_accounts as usize)
        || (i >= header.num_required_signatures as usize
            && i < account_keys
                .len()
                .saturating_sub(header.num_readonly_unsigned_accounts as usize))
}

/// Returns true if the account at the specified index is in the optional
/// reserved account keys set.
#[inline(always)]
fn is_account_maybe_reserved(
    i: usize,
    account_keys: &[Address],
    reserved_account_keys: Option<&HashSet<Address>>,
) -> bool {
    let mut is_maybe_reserved = false;
    if let Some(reserved_account_keys) = reserved_account_keys {
        if let Some(key) = account_keys.get(i) {
            is_maybe_reserved = reserved_account_keys.contains(key);
        }
    }
    is_maybe_reserved
}

#[inline(always)]
fn is_program_id_write_demoted(
    i: usize,
    account_keys: &[Address],
    instructions: &[CompiledInstruction],
) -> bool {
    is_key_called_as_program(instructions, i) && !is_upgradeable_loader_present(account_keys)
}

#[inline(always)]
fn is_key_called_as_program(instructions: &[CompiledInstruction], key_index: usize) -> bool {
    if let Ok(key_index) = u8::try_from(key_index) {
        instructions
            .iter()
            .any(|ix| ix.program_id_index == key_index)
    } else {
        false
    }
}

/// Returns `true` if any account is the BPF upgradeable loader.
#[inline(always)]
fn is_upgradeable_loader_present(account_keys: &[Address]) -> bool {
    account_keys
        .iter()
        .any(|&key| key == bpf_loader_upgradeable::id())
}

/// Returns true if the account at the specified index is writable by the
/// instructions in this message. The `reserved_account_keys` param has been
/// optional to allow clients to approximate writability without requiring
/// fetching the latest set of reserved account keys. If this method is
/// called by the runtime, the latest set of reserved account keys must be
/// passed.
#[inline(always)]
fn is_maybe_writable(
    i: usize,
    header: MessageHeader,
    account_keys: &[Address],
    instructions: &[CompiledInstruction],
    reserved_account_keys: Option<&HashSet<Address>>,
) -> bool {
    (is_writable_index(i, header, account_keys))
        && !is_account_maybe_reserved(i, account_keys, reserved_account_keys)
        && !is_program_id_write_demoted(i, account_keys, instructions)
}

#[cfg(test)]
mod tests {
    use {
        crate::{is_account_maybe_reserved, Message},
        solana_address::Address,
        std::collections::HashSet,
    };

    #[test]
    fn test_is_account_maybe_reserved() {
        let key0 = Address::new_unique();
        let key1 = Address::new_unique();

        let message = Message {
            account_keys: vec![key0, key1],
            ..Message::default()
        };

        let reserved_account_keys = HashSet::from([key1]);

        assert!(!is_account_maybe_reserved(
            0,
            &message.account_keys,
            Some(&reserved_account_keys)
        ));
        assert!(is_account_maybe_reserved(
            1,
            &message.account_keys,
            Some(&reserved_account_keys)
        ));
        assert!(!is_account_maybe_reserved(
            2,
            &message.account_keys,
            Some(&reserved_account_keys)
        ));
        assert!(!is_account_maybe_reserved(0, &message.account_keys, None));
        assert!(!is_account_maybe_reserved(1, &message.account_keys, None));
        assert!(!is_account_maybe_reserved(2, &message.account_keys, None));
    }
}
