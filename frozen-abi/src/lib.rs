#![allow(incomplete_features)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(specialization))]
// Activate some of the Rust 2024 lints to make the future migration easier.
#![warn(if_let_rescope)]
#![warn(keyword_idents_2024)]
#![warn(rust_2024_incompatible_pat)]
#![warn(tail_expr_drop_order)]
#![warn(unsafe_attr_outside_unsafe)]
#![warn(unsafe_op_in_unsafe_fn)]

// Allows macro expansion of `use ::solana_frozen_abi::*` to work within this crate
extern crate self as solana_frozen_abi;

#[cfg(feature = "frozen-abi")]
pub mod abi_digester;
#[cfg(feature = "frozen-abi")]
pub mod abi_example;
#[cfg(feature = "frozen-abi")]
pub mod hash;

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
pub mod stable_abi;

#[cfg(feature = "frozen-abi")]
#[macro_use]
extern crate solana_frozen_abi_macro;

#[cfg(all(feature = "frozen-abi", not(target_os = "solana")))]
pub use {bincode, rand, rand_chacha};

// Not public API. Previously referenced by macro-generated code. Remove the
// `log` dependency from Cargo.toml when this is cleaned up in the next major
// version bump
#[deprecated(since = "3.0.1", note = "Please use the `log` crate directly instead")]
#[doc(hidden)]
pub mod __private {
    #[doc(hidden)]
    pub use log;
}
