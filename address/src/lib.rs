//! Define how a Solana account address is represented.

#![no_std]

#[cfg(feature = "syscall")]
mod syscalls;
#[cfg(feature = "syscall")]
pub use syscalls::*;

/// Number of bytes in an address.
pub const PUBKEY_BYTES: usize = 32;

/// Maximum length of derived `Address` seed.
pub const MAX_SEED_LEN: usize = 32;

/// Maximum number of seeds for address derivation.
pub const MAX_SEEDS: usize = 16;

/// The address of a [Solana account][account].
///
/// [account]: https://solana.com/docs/core/accounts
pub type Address = [u8; PUBKEY_BYTES];
