#![allow(incomplete_features)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(specialization))]

// Allows macro expansion of `use ::solana_frozen_abi::*` to work within this crate
extern crate self as solana_frozen_abi;

#[cfg(feature = "frozen-abi")]
pub mod abi_digester;
#[cfg(feature = "frozen-abi")]
pub mod abi_example;
#[cfg(feature = "frozen-abi")]
pub mod hash;
#[cfg(feature = "frozen-abi")]
#[cfg(not(target_os = "solana"))]
pub mod stable_abi;

#[cfg(feature = "frozen-abi")]
#[macro_use]
extern crate solana_frozen_abi_macro;

// Not public API. Previously referenced by macro-generated code. Remove the
// `log` dependency from Cargo.toml when this is cleaned up in the next major
// version bump
#[deprecated(since = "3.0.1", note = "Please use the `log` crate directly instead")]
#[doc(hidden)]
pub mod __private {
    #[doc(hidden)]
    pub use log;
}
