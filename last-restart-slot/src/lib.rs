//! Information about the last restart slot (hard fork).
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "sysvar")]
pub mod sysvar;

use solana_sdk_macro::CloneZeroed;

#[repr(C)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, CloneZeroed, PartialEq, Eq, Default)]
pub struct LastRestartSlot {
    /// The last restart `Slot`.
    pub last_restart_slot: u64,
}

/// Serialized size of the `LastRestartSlot` sysvar account.
pub const SIZE: usize = size_of::<LastRestartSlot>();
const _: () = assert!(SIZE == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_of() {
        assert_eq!(
            wincode::serialized_size(&LastRestartSlot::default()).unwrap() as usize,
            SIZE,
        );
    }
}
