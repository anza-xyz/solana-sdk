//! Solana zero-copy types.
//!
//! This crate provides unaligned primitive wrappers for use in Solana
//! zero-copy data structures.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "borsh")]
extern crate alloc;

pub mod unaligned;
