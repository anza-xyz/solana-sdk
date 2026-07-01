pub use solana_sdk_ids::sysvar::slot_hashes::{check_id, id, ID};
use {crate::SlotHashes, solana_get_sysvar::GetSysvar, solana_sysvar_id::impl_sysvar_id};

impl_sysvar_id!(SlotHashes);

impl GetSysvar for SlotHashes {}
