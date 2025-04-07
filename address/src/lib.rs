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

/// Convenience macro to declare a static address and functions to interact with it.
///
/// This macro is useful to declare a constant representing a program ID for a
/// Solana program.
///
/// # Example
///
/// ```
/// # // wrapper is used so that the macro invocation occurs in the item position
/// # // rather than in the statement position which isn't allowed.
/// use solana_address::{declare_id, Address};
///
/// # mod program {
/// #   use solana_address::declare_id;
/// declare_id!([0; 32]);
/// # }
/// # use program::id;
///
/// let address = [0; 32];
/// assert_eq!(id(), address);
/// ```
#[macro_export]
macro_rules! declare_id {
    ( $id:expr ) => {
        #[doc = "The constant program ID."]
        pub const ID: $crate::Address = $id;

        #[doc = "Returns `true` if the given address is equal to the program ID."]
        #[inline]
        pub fn check_id(id: &$crate::Address) -> bool {
            id == &ID
        }

        #[doc = "Returns the program ID."]
        #[inline]
        pub const fn id() -> $crate::Address {
            ID
        }
    };
}
