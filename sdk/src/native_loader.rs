//! The native loader native program.

use solana_account::{Account, AccountSharedData, DUMMY_INHERITABLE_LAMPORTS};
pub use solana_sdk_ids::native_loader::{check_id, id, ID};

/// Create an executable account with the given shared object name.
pub fn create_loadable_account_with_fields(name: &str, lamports: u64) -> AccountSharedData {
    AccountSharedData::from(Account {
        lamports,
        owner: id(),
        data: name.as_bytes().to_vec(),
        executable: true,
    })
}

pub fn create_loadable_account_for_test(name: &str) -> AccountSharedData {
    create_loadable_account_with_fields(name, DUMMY_INHERITABLE_LAMPORTS)
}
