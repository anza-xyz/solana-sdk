pub use solana_sdk_ids::sysvar::rent::{check_id, id, ID};
use {
    crate::Rent,
    solana_get_sysvar::{impl_get_sysvar, GetSysvar},
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(Rent);

impl GetSysvar for Rent {
    impl_get_sysvar!(id(), 7);
}
