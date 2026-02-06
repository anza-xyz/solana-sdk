use crate::{MessageHeader, MESSAGE_VERSION_PREFIX};

mod cached;
mod config;
mod error;
mod message;

use solana_hash::Hash;
pub use {cached::*, config::*, error::*, message::*};

/// A type definition for an  instruction header:
///  - program_id_index
///  - num_accounts
///  - data_len
///
/// This is used to parse the instruction portion of a V1 message.
pub type InstructionHeader = (u8, u8, [u8; 2]);

/// Version byte for V1 messages (decimal 129).
pub const V1_PREFIX: u8 = MESSAGE_VERSION_PREFIX | 1;

/// Maximum transaction size for V1 format in bytes.
pub const MAX_TRANSACTION_SIZE: usize = 4096;

/// Maximum number of account addresses in a V1 message.
pub const MAX_ADDRESSES: u8 = 64;

/// Maximum number of instructions in a V1 message.
pub const MAX_INSTRUCTIONS: u8 = 64;

/// Maximum number of signatures in a V1 transaction.
pub const MAX_SIGNATURES: u8 = 12;

/// Default heap size in bytes when not specified (32KB).
pub const DEFAULT_HEAP_SIZE: u32 = 32_768;

/// Size of the fixed header portion of a serialized V1 message.
pub const FIXED_HEADER_SIZE: usize = size_of::<MessageHeader>() // legacy header
    + size_of::<TransactionConfigMask>() // config mask
    + size_of::<Hash>() // lifetime specifier
    + size_of::<u8>() // number of instructions
    + size_of::<u8>(); // number of addresses

/// Size of a single Ed25519 signature (64 bytes).
pub const SIGNATURE_SIZE: usize = 64;
