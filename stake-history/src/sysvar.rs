pub use solana_sdk_ids::sysvar::stake_history::{check_id, id, ID};
use {crate::StakeHistory, solana_sysvar_id::impl_sysvar_id};

impl_sysvar_id!(StakeHistory);
