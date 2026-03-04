//! Solana Plain Old Data (Pod) zero-copy types and traits.
//!
//! This crate provides zero-copy primitives for use in Solana programs:
//!
//! - [`Nullable`] trait and [`PodOption<T>`] — a space-efficient option type
//!   that reserves a value to represent `None` instead of using a tag byte.
//! - Pod-safe integer wrappers ([`PodBool`], [`PodU16`], [`PodU64`], etc.)
//!   that avoid alignment issues in zero-copy structures.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "borsh")]
extern crate alloc;

mod option;
mod primitives;

pub use {option::*, primitives::*};
