pub use solana_sdk_ids::sysvar::epoch_rewards::{check_id, id, ID};
use {
    crate::EpochRewards,
    solana_get_sysvar::{impl_get_sysvar, GetSysvar},
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(EpochRewards);

impl GetSysvar for EpochRewards {
    // SAFETY: upstream invariant: the sysvar data is created exclusively
    // by the Solana runtime and serializes bool as 0x00 or 0x01, so the final
    // `bool` field of `EpochRewards` can be re-aligned with padding and read
    // directly without validation.
    impl_get_sysvar!(ID, 15);
}
