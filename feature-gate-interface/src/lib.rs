//! Runtime features.
//!
//! Runtime features provide a mechanism for features to be simultaneously activated across the
//! network. Since validators may choose when to upgrade, features must remain dormant until a
//! sufficient majority of the network is running a version that would support a given feature.
//!
//! Feature activation is accomplished by:
//! 1. Activation is requested by the feature authority, who issues a transaction to create the
//!    feature account. The newly created feature account will have the value of
//!    `Feature::default()`
//! 2. When the next epoch is entered the runtime will check for new activation requests and
//!    active them.  When this occurs, the activation slot is recorded in the feature account
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod instruction;
pub mod state;

#[cfg(feature = "bincode")]
#[allow(deprecated)]
pub use crate::instruction::activate;
#[cfg(feature = "bincode")]
pub use crate::{
    instruction::activate_with_lamports,
    state::{create_account, from_account, to_account},
};
pub use {
    crate::state::Feature,
    solana_sdk_ids::feature::{check_id, id, ID},
};
