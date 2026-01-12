//! # StableAbi
//!
//! The `StableAbi` is an optional extension to `frozen-abi` that provides functionality for
//! detecting unintended encoding changes. It is designed to be used in conjunction with the
//! mandatory `AbiExample`.
//!
//! ## How it works?
//!
//! When you annotate a type with:
//!
//! ```rust,ignore
//! #[frozen_abi(abi_digest = "...")]
//! struct MyType { ... }
//! ```
//!
//! The macro would generate the `test_abi_digest` test that verifies binary layout stability:
//! - Initializes a deterministic random number generator with fixed seed
//! - Generates 10_000 instances of the type via `StableAbi::random()`
//! - Serializes each instance with bincode
//! - Hashes all serialized bytes together
//! - Compares the resulting hash against the provided in `abi_digest` attribute
//!
//! Using the seeded RNG ensures same sequence of random values across runs, while the 10_000
//! iterations brings a wide range of value combinations. By hashing serialized bytes, changes
//! to padding, endianness or encoding are detected.
//!
//!
//! ## Adding StableAbi to a New Type
//!
//! For types which implement `Distribution<T>` for `StandardUniform`:
//!
//! ```rust,ignore
//! #[derive(StableAbi)]
//! #[frozen_abi(abi_digest = "...")]
//!    struct MyType { ... }
//! ```
//!
//! For types which don't, you must provide as well a custom implementation:
//!
//! ```rust,ignore
//! #[cfg(feature = "frozen-abi")]
//! impl solana_frozen_abi::rand::prelude::Distribution<MyType>
//!     for solana_frozen_abi::rand::distr::StandardUniform
//! {
//!     fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> MyType {
//!            MyType {
//!                field: rng.random(),
//!                ...
//!            }
//!        }
//!    }
//! ```
//!
//! Deriving the `StableAbi` adds the following impl, which comes with the default `random()`
//! implementation:
//!
//! ```rust,ignore
//! impl ::solana_frozen_abi::stable_abi::StableAbi for MyType {}
//! ```
//!
//! ## Edge Cases
//!
//! 1. It will not detect field name or order changes, nor same size type swaps (e.g., `i64`
//!    and `u64`). These cases are still covered by `AbiExample`
//! 2. The implementor must ensure a consistent order of `rng.random()` calls, as any change
//!    will result in different hash
//! 3. For collection types with non deterministic ordering (e.g., `HashMap`), it is recommended
//!    to insert only one item to avoid false positives caused by iteration order differences

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
