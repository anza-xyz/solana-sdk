//! This sysvar is deprecated and unused.
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
pub use solana_sdk_ids::sysvar::rewards::{check_id, id, ID};
use {crate::Sysvar, solana_sysvar_id::impl_sysvar_id};

impl_sysvar_id!(Rewards);

#[repr(C)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq)]
pub struct Rewards {
    pub validator_point_value: f64,
    pub unused: f64,
}
impl Rewards {
    pub fn new(validator_point_value: f64) -> Self {
        Self {
            validator_point_value,
            unused: 0.0,
        }
    }
}
impl Sysvar for Rewards {}
#[cfg(feature = "bincode")]
impl SysvarSerialize for Rewards {}
