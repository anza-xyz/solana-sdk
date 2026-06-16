pub use solana_sdk_ids::sysvar::clock::{check_id, id, ID};
use {
    crate::Clock,
    solana_get_sysvar::{impl_sysvar_get, GetSysvar},
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(Clock);

impl GetSysvar for Clock {
    impl_sysvar_get!(id());
}
