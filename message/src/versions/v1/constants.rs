//! Constants for V1 message format (SIMD-0385).

use {super::TransactionConfigMask, crate::MessageHeader, solana_hash::Hash, std::mem::size_of};

/// Version byte for V1 messages (`MESSAGE_VERSION_PREFIX | 1` = decimal 129).
pub const V1_VERSION_BYTE: u8 = 0x81;

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
pub const FIXED_HEADER_SIZE: usize = size_of::<u8>() // version
    + size_of::<MessageHeader>() // legacy header
    + size_of::<TransactionConfigMask>() // config mask
    + size_of::<Hash>() // lifetime_specifier
    + size_of::<u8>() // num_instructions
    + size_of::<u8>(); // num_addresses

/// Size of an instruction header: program_id (u8) + num_accounts (u8) + data_len (u16).
pub const INSTRUCTION_HEADER_SIZE: usize = size_of::<u8>() + size_of::<u8>() + size_of::<u16>();

/// Size of a single Ed25519 signature (64 bytes).
pub const SIGNATURE_SIZE: usize = 64;
