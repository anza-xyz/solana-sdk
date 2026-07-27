pub use solana_sdk_ids::sysvar::last_restart_slot::{check_id, id, ID};
use {
    crate::LastRestartSlot,
    solana_get_sysvar::{impl_get_sysvar, GetSysvar},
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(LastRestartSlot);

impl GetSysvar for LastRestartSlot {
    impl_get_sysvar!(ID);
}
