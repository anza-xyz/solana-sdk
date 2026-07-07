pub use solana_sdk_ids::sysvar::slot_history::{check_id, id, ID};
use {crate::SlotHistory, solana_get_sysvar::GetSysvar, solana_sysvar_id::impl_sysvar_id};

impl_sysvar_id!(SlotHistory);

impl GetSysvar for SlotHistory {}
