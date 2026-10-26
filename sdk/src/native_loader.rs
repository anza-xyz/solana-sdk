//! The native loader native program.
#[allow(deprecated)]
use solana_account::InheritableAccountFields;
pub use solana_sdk_ids::native_loader::{check_id, id, ID};
use {
    crate::clock::Epoch,
    solana_account::{Account, AccountSharedData},
};

/// Create an executable account with the given shared object name.
#[deprecated(since = "5.1.0", note = "Construct the `Account` directly instead")]
#[allow(deprecated)]
pub fn create_loadable_account_with_fields(
    name: &str,
    (lamports, rent_epoch): InheritableAccountFields,
) -> AccountSharedData {
    AccountSharedData::from(Account {
        lamports,
        owner: id(),
        data: name.as_bytes().to_vec(),
        executable: true,
        rent_epoch,
    })
}

pub fn create_loadable_account_for_test(name: &str) -> AccountSharedData {
    AccountSharedData::from(Account {
        lamports: 1,
        owner: id(),
        data: name.as_bytes().to_vec(),
        executable: true,
        rent_epoch: Epoch::MAX,
    })
}
