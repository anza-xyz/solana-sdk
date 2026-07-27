#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
//! Durable transaction nonces.

pub mod state;
pub mod versions;

pub const NONCED_TX_MARKER_IX_INDEX: u8 = 0;
