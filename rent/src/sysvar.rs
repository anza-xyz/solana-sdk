use {crate::Rent, solana_get_sysvar::impl_get_sysvar, solana_sysvar_id::impl_sysvar_id};
pub use {
    solana_get_sysvar::GetSysvar,
    solana_sdk_ids::sysvar::rent::{check_id, id, ID},
};

impl_sysvar_id!(Rent);

impl GetSysvar for Rent {
    impl_get_sysvar!(ID, 7);
}
