//! Define how a Solana account address is represented.

#![no_std]

#[cfg(feature = "syscalls")]
mod syscalls;
#[cfg(feature = "syscalls")]
pub use syscalls::*;

/// Number of bytes in an address.
pub const ADDRESS_BYTES: usize = 32;

/// Maximum length of derived `Address` seed.
pub const MAX_SEED_LEN: usize = 32;

/// Maximum number of seeds for address derivation.
pub const MAX_SEEDS: usize = 16;

/// The address of a [Solana account][account].
///
/// Some account addresses are [ed25519] public keys, with corresponding secret
/// keys that are managed off-chain. Often, though, account addresses do not
/// have corresponding secret keys &mdash; as with [_program derived
/// addresses_][pdas] &mdash; or the secret key is not relevant to the operation
/// of a program, and may have even been disposed of.
///
/// [account]: https://solana.com/docs/core/accounts
/// [ed25519]: https://ed25519.cr.yp.to/
/// [pdas]: https://solana.com/docs/core/cpi#program-derived-addresses
pub type Address = [u8; ADDRESS_BYTES];
