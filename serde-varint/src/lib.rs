//! Integers that serialize to variable size.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::arithmetic_side_effects)]

#[cfg(feature = "serde")]
pub mod serde;

#[cfg(feature = "serde")]
pub use serde::{deserialize, serialize, VarInt};

#[cfg(feature = "wincode")]
pub mod wincode;
