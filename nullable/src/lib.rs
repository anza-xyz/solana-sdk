//! Types for values that can reserve a designated null value.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "borsh", test))]
extern crate alloc;

mod maybe_null;
mod nullable;
#[cfg(feature = "serde-with")]
mod serde_with;

pub use self::{maybe_null::*, nullable::*};
