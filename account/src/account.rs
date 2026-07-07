//! The [`Account`] and [`AccountSharedData`] types and their codec-independent APIs.

#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::{Account, AccountSharedData},
    solana_account_info::{debug_account_data::*, AccountInfo},
    solana_clock::{Epoch, INITIAL_RENT_EPOCH},
    solana_instruction_error::LamportsError,
    solana_pubkey::Pubkey,
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4},
    std::{cell::RefCell, fmt, mem::MaybeUninit, ops::Deref, ptr, rc::Rc, sync::Arc},
};

#[cfg(feature = "bincode")]
mod bincode;
#[cfg(feature = "bincode")]
pub use bincode::*;

// NOTE: `Account` and `AccountSharedData` are defined in the crate root (`lib.rs`)
// rather than here. The frozen-abi digest of any downstream struct that holds an
// `Account`/`AccountSharedData` field hashes that field's fully-qualified
// `std::any::type_name`, so the definitions must stay at `solana_account::*` to keep
// `type_name` stable. Moving them into this module would silently change ABI digests
// across the ecosystem.

/// Compares two ReadableAccounts
///
/// Returns true if accounts are essentially equivalent as in all fields are equivalent.
pub fn accounts_equal<T: ReadableAccount, U: ReadableAccount>(me: &T, other: &U) -> bool {
    me.lamports() == other.lamports()
        && me.executable() == other.executable()
        && me.rent_epoch() == other.rent_epoch()
        && me.owner() == other.owner()
        && me.data() == other.data()
}

impl From<AccountSharedData> for Account {
    fn from(mut other: AccountSharedData) -> Self {
        let account_data = Arc::make_mut(&mut other.data);
        Self {
            lamports: other.lamports,
            data: std::mem::take(account_data),
            owner: other.owner,
            executable: other.executable,
            rent_epoch: other.rent_epoch,
        }
    }
}

impl From<Account> for AccountSharedData {
    fn from(other: Account) -> Self {
        Self {
            lamports: other.lamports,
            data: Arc::new(other.data),
            owner: other.owner,
            executable: other.executable,
            rent_epoch: other.rent_epoch,
        }
    }
}

pub trait WritableAccount: ReadableAccount {
    fn set_lamports(&mut self, lamports: u64);
    fn checked_add_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_add(lamports)
                .ok_or(LamportsError::ArithmeticOverflow)?,
        );
        Ok(())
    }
    fn checked_sub_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_sub(lamports)
                .ok_or(LamportsError::ArithmeticUnderflow)?,
        );
        Ok(())
    }
    fn saturating_add_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_add(lamports))
    }
    fn saturating_sub_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_sub(lamports))
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8];
    fn set_owner(&mut self, owner: Pubkey);
    fn copy_into_owner_from_slice(&mut self, source: &[u8]);
    fn set_executable(&mut self, executable: bool);
    fn set_rent_epoch(&mut self, epoch: Epoch);
}

pub trait ReadableAccount: Sized {
    fn lamports(&self) -> u64;
    fn data(&self) -> &[u8];
    fn owner(&self) -> &Pubkey;
    fn executable(&self) -> bool;
    fn rent_epoch(&self) -> Epoch;
}

impl<T> ReadableAccount for T
where
    T: Deref,
    T::Target: ReadableAccount,
{
    fn lamports(&self) -> u64 {
        self.deref().lamports()
    }
    fn data(&self) -> &[u8] {
        self.deref().data()
    }
    fn owner(&self) -> &Pubkey {
        self.deref().owner()
    }
    fn executable(&self) -> bool {
        self.deref().executable()
    }
    fn rent_epoch(&self) -> Epoch {
        self.deref().rent_epoch()
    }
}

impl ReadableAccount for Account {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

impl WritableAccount for Account {
    fn set_lamports(&mut self, lamports: u64) {
        self.lamports = lamports;
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }
    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        self.owner.as_mut().copy_from_slice(source);
    }
    fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
    fn set_rent_epoch(&mut self, epoch: Epoch) {
        self.rent_epoch = epoch;
    }
}

impl WritableAccount for AccountSharedData {
    fn set_lamports(&mut self, lamports: u64) {
        self.lamports = lamports;
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data_mut()[..]
    }
    fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }
    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        self.owner.as_mut().copy_from_slice(source);
    }
    fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
    fn set_rent_epoch(&mut self, epoch: Epoch) {
        self.rent_epoch = epoch;
    }
}

impl ReadableAccount for AccountSharedData {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

fn debug_fmt<T: ReadableAccount>(item: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut f = f.debug_struct("Account");

    f.field("lamports", &item.lamports())
        .field("data.len", &item.data().len())
        .field("owner", &item.owner())
        .field("executable", &item.executable())
        .field("rent_epoch", &item.rent_epoch());
    debug_account_data(item.data(), &mut f);

    f.finish()
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_fmt(self, f)
    }
}

impl fmt::Debug for AccountSharedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_fmt(self, f)
    }
}

impl Account {
    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        Account {
            lamports,
            data: vec![0; space],
            owner: *owner,
            executable: false,
            rent_epoch: Epoch::default(),
        }
    }
    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Account::new(lamports, space, owner)))
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        Account {
            lamports,
            data: vec![0; space],
            owner: *owner,
            executable: false,
            rent_epoch,
        }
    }
}

impl AccountSharedData {
    pub fn is_shared(&self) -> bool {
        Arc::strong_count(&self.data) > 1
    }

    pub fn reserve(&mut self, additional: usize) {
        if let Some(data) = Arc::get_mut(&mut self.data) {
            data.reserve(additional)
        } else {
            let mut data = Vec::with_capacity(self.data.len().saturating_add(additional));
            data.extend_from_slice(&self.data);
            self.data = Arc::new(data);
        }
    }

    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    pub fn data_clone(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.data)
    }

    fn data_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.data)
    }

    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data_mut().resize(new_len, value)
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.data_mut().extend_from_slice(data)
    }

    pub fn set_data_from_slice(&mut self, new_data: &[u8]) {
        // If the buffer isn't shared, we're going to memcpy in place.
        let Some(data) = Arc::get_mut(&mut self.data) else {
            // If the buffer is shared, the cheapest thing to do is to clone the
            // incoming slice and replace the buffer.
            return self.set_data(new_data.to_vec());
        };

        let new_len = new_data.len();

        // Reserve additional capacity if needed. Here we make the assumption
        // that growing the current buffer is cheaper than doing a whole new
        // allocation to make `new_data` owned.
        //
        // This assumption holds true during CPI, especially when the account
        // size doesn't change but the account is only changed in place. And
        // it's also true when the account is grown by a small margin (the
        // realloc limit is quite low), in which case the allocator can just
        // update the allocation metadata without moving.
        //
        // Shrinking and copying in place is always faster than making
        // `new_data` owned, since shrinking boils down to updating the Vec's
        // length.

        data.reserve(new_len.saturating_sub(data.len()));

        // Safety:
        // We just reserved enough capacity. We set data::len to 0 to avoid
        // possible UB on panic (dropping uninitialized elements), do the copy,
        // finally set the new length once everything is initialized.
        #[allow(clippy::uninit_vec)]
        // this is a false positive, the lint doesn't currently special case set_len(0)
        unsafe {
            data.set_len(0);
            ptr::copy_nonoverlapping(new_data.as_ptr(), data.as_mut_ptr(), new_len);
            data.set_len(new_len);
        };
    }

    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn set_data(&mut self, data: Vec<u8>) {
        self.data = Arc::new(data);
    }

    pub fn spare_data_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.data_mut().spare_capacity_mut()
    }

    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        AccountSharedData {
            lamports,
            data: Arc::new(vec![0u8; space]),
            owner: *owner,
            executable: false,
            rent_epoch: Epoch::default(),
        }
    }
    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(AccountSharedData::new(lamports, space, owner)))
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        AccountSharedData {
            lamports,
            data: Arc::new(vec![0; space]),
            owner: *owner,
            executable: false,
            rent_epoch,
        }
    }
    pub fn create_from_existing_shared_data(
        lamports: u64,
        data: Arc<Vec<u8>>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> AccountSharedData {
        AccountSharedData {
            lamports,
            data,
            owner,
            executable,
            rent_epoch,
        }
    }
}

pub type InheritableAccountFields = (u64, Epoch);
pub const DUMMY_INHERITABLE_ACCOUNT_FIELDS: InheritableAccountFields = (1, INITIAL_RENT_EPOCH);

/// Return the information required to construct an `AccountInfo`.  Used by the
/// `AccountInfo` conversion implementations.
impl solana_account_info::Account for Account {
    fn get(&mut self) -> (&mut u64, &mut [u8], &Pubkey, bool) {
        (
            &mut self.lamports,
            &mut self.data,
            &self.owner,
            self.executable,
        )
    }
}

/// Create `AccountInfo`s
pub fn create_is_signer_account_infos<'a>(
    accounts: &'a mut [(&'a Pubkey, bool, &'a mut Account)],
) -> Vec<AccountInfo<'a>> {
    accounts
        .iter_mut()
        .map(|(key, is_signer, account)| {
            AccountInfo::new(
                key,
                *is_signer,
                false,
                &mut account.lamports,
                &mut account.data,
                &account.owner,
                account.executable,
            )
        })
        .collect()
}

/// Replacement for the executable flag: An account being owned by one of these contains a program.
#[deprecated(since = "4.3.0", note = "no longer available as a constant")]
pub const PROGRAM_OWNERS: &[Pubkey] = &[
    bpf_loader_upgradeable::id(),
    bpf_loader::id(),
    bpf_loader_deprecated::id(),
    loader_v4::id(),
];

#[cfg(test)]
pub mod tests {
    use super::*;

    fn make_two_accounts(key: &Pubkey) -> (Account, AccountSharedData) {
        let mut account1 = Account::new(1, 2, key);
        account1.executable = true;
        account1.rent_epoch = 4;
        let mut account2 = AccountSharedData::new(1, 2, key);
        account2.executable = true;
        account2.rent_epoch = 4;
        assert!(accounts_equal(&account1, &account2));
        (account1, account2)
    }

    #[test]
    fn test_account_data_copy_as_slice() {
        let key = Pubkey::new_unique();
        let key2 = Pubkey::new_unique();
        let (mut account1, mut account2) = make_two_accounts(&key);
        account1.copy_into_owner_from_slice(key2.as_ref());
        account2.copy_into_owner_from_slice(key2.as_ref());
        assert!(accounts_equal(&account1, &account2));
        assert_eq!(account1.owner(), &key2);
    }

    #[test]
    fn test_account_set_data_from_slice() {
        let key = Pubkey::new_unique();
        let (_, mut account) = make_two_accounts(&key);
        assert_eq!(account.data(), &vec![0, 0]);
        account.set_data_from_slice(&[1, 2]);
        assert_eq!(account.data(), &vec![1, 2]);
        account.set_data_from_slice(&[1, 2, 3]);
        assert_eq!(account.data(), &vec![1, 2, 3]);
        account.set_data_from_slice(&[4, 5, 6]);
        assert_eq!(account.data(), &vec![4, 5, 6]);
        account.set_data_from_slice(&[4, 5, 6, 0]);
        assert_eq!(account.data(), &vec![4, 5, 6, 0]);
        account.set_data_from_slice(&[]);
        assert_eq!(account.data().len(), 0);
        account.set_data_from_slice(&[44]);
        assert_eq!(account.data(), &vec![44]);
        account.set_data_from_slice(&[44]);
        assert_eq!(account.data(), &vec![44]);
    }

    #[test]
    fn test_account_data_set_data() {
        let key = Pubkey::new_unique();
        let (_, mut account) = make_two_accounts(&key);
        assert_eq!(account.data(), &vec![0, 0]);
        account.set_data(vec![1, 2]);
        assert_eq!(account.data(), &vec![1, 2]);
        account.set_data(vec![]);
        assert_eq!(account.data().len(), 0);
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: Io(Kind(UnexpectedEof))"
    )]
    fn test_account_deserialize() {
        let key = Pubkey::new_unique();
        let (account1, _account2) = make_two_accounts(&key);
        account1.deserialize_data::<String>().unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: SizeLimit")]
    fn test_account_serialize() {
        let key = Pubkey::new_unique();
        let (mut account1, _account2) = make_two_accounts(&key);
        account1.serialize_data(&"hello world").unwrap();
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: Io(Kind(UnexpectedEof))"
    )]
    fn test_account_shared_data_deserialize() {
        let key = Pubkey::new_unique();
        let (_account1, account2) = make_two_accounts(&key);
        account2.deserialize_data::<String>().unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: SizeLimit")]
    fn test_account_shared_data_serialize() {
        let key = Pubkey::new_unique();
        let (_account1, mut account2) = make_two_accounts(&key);
        account2.serialize_data(&"hello world").unwrap();
    }

    #[test]
    fn test_account_shared_data() {
        let key = Pubkey::new_unique();
        let (account1, account2) = make_two_accounts(&key);
        assert!(accounts_equal(&account1, &account2));
        let account = account1;
        assert_eq!(account.lamports, 1);
        assert_eq!(account.lamports(), 1);
        assert_eq!(account.data.len(), 2);
        assert_eq!(account.data().len(), 2);
        assert_eq!(account.owner, key);
        assert_eq!(account.owner(), &key);
        assert!(account.executable);
        assert!(account.executable());
        assert_eq!(account.rent_epoch, 4);
        assert_eq!(account.rent_epoch(), 4);
        let account = account2;
        assert_eq!(account.lamports, 1);
        assert_eq!(account.lamports(), 1);
        assert_eq!(account.data.len(), 2);
        assert_eq!(account.data().len(), 2);
        assert_eq!(account.owner, key);
        assert_eq!(account.owner(), &key);
        assert!(account.executable);
        assert!(account.executable());
        assert_eq!(account.rent_epoch, 4);
        assert_eq!(account.rent_epoch(), 4);
    }

    // test clone and from for both types against expected
    fn test_equal(
        should_be_equal: bool,
        account1: &Account,
        account2: &AccountSharedData,
        account_expected: &Account,
    ) {
        assert_eq!(should_be_equal, accounts_equal(account1, account2));
        if should_be_equal {
            assert!(accounts_equal(account_expected, account2));
        }
        assert_eq!(
            accounts_equal(account_expected, account1),
            accounts_equal(account_expected, &account1.clone())
        );
        assert_eq!(
            accounts_equal(account_expected, account2),
            accounts_equal(account_expected, &account2.clone())
        );
        assert_eq!(
            accounts_equal(account_expected, account1),
            accounts_equal(account_expected, &AccountSharedData::from(account1.clone()))
        );
        assert_eq!(
            accounts_equal(account_expected, account2),
            accounts_equal(account_expected, &Account::from(account2.clone()))
        );
    }

    #[test]
    fn test_account_add_sub_lamports() {
        let key = Pubkey::new_unique();
        let (mut account1, mut account2) = make_two_accounts(&key);
        assert!(accounts_equal(&account1, &account2));
        account1.checked_add_lamports(1).unwrap();
        account2.checked_add_lamports(1).unwrap();
        assert!(accounts_equal(&account1, &account2));
        assert_eq!(account1.lamports(), 2);
        account1.checked_sub_lamports(2).unwrap();
        account2.checked_sub_lamports(2).unwrap();
        assert!(accounts_equal(&account1, &account2));
        assert_eq!(account1.lamports(), 0);
    }

    #[test]
    #[should_panic(expected = "Overflow")]
    fn test_account_checked_add_lamports_overflow() {
        let key = Pubkey::new_unique();
        let (mut account1, _account2) = make_two_accounts(&key);
        account1.checked_add_lamports(u64::MAX).unwrap();
    }

    #[test]
    #[should_panic(expected = "Underflow")]
    fn test_account_checked_sub_lamports_underflow() {
        let key = Pubkey::new_unique();
        let (mut account1, _account2) = make_two_accounts(&key);
        account1.checked_sub_lamports(u64::MAX).unwrap();
    }

    #[test]
    #[should_panic(expected = "Overflow")]
    fn test_account_checked_add_lamports_overflow2() {
        let key = Pubkey::new_unique();
        let (_account1, mut account2) = make_two_accounts(&key);
        account2.checked_add_lamports(u64::MAX).unwrap();
    }

    #[test]
    #[should_panic(expected = "Underflow")]
    fn test_account_checked_sub_lamports_underflow2() {
        let key = Pubkey::new_unique();
        let (_account1, mut account2) = make_two_accounts(&key);
        account2.checked_sub_lamports(u64::MAX).unwrap();
    }

    #[test]
    fn test_account_saturating_add_lamports() {
        let key = Pubkey::new_unique();
        let (mut account, _) = make_two_accounts(&key);

        let remaining = 22;
        account.set_lamports(u64::MAX - remaining);
        account.saturating_add_lamports(remaining * 2);
        assert_eq!(account.lamports(), u64::MAX);
    }

    #[test]
    fn test_account_saturating_sub_lamports() {
        let key = Pubkey::new_unique();
        let (mut account, _) = make_two_accounts(&key);

        let remaining = 33;
        account.set_lamports(remaining);
        account.saturating_sub_lamports(remaining * 2);
        assert_eq!(account.lamports(), 0);
    }

    #[test]
    fn test_account_shared_data_all_fields() {
        let key = Pubkey::new_unique();
        let key2 = Pubkey::new_unique();
        let key3 = Pubkey::new_unique();
        let (mut account1, mut account2) = make_two_accounts(&key);
        assert!(accounts_equal(&account1, &account2));

        let mut account_expected = account1.clone();
        assert!(accounts_equal(&account1, &account_expected));
        assert!(accounts_equal(&account1, &account2.clone())); // test the clone here

        for field_index in 0..5 {
            for pass in 0..4 {
                if field_index == 0 {
                    if pass == 0 {
                        account1.checked_add_lamports(1).unwrap();
                    } else if pass == 1 {
                        account_expected.checked_add_lamports(1).unwrap();
                        account2.set_lamports(account2.lamports + 1);
                    } else if pass == 2 {
                        account1.set_lamports(account1.lamports + 1);
                    } else if pass == 3 {
                        account_expected.checked_add_lamports(1).unwrap();
                        account2.checked_add_lamports(1).unwrap();
                    }
                } else if field_index == 1 {
                    if pass == 0 {
                        account1.data[0] += 1;
                    } else if pass == 1 {
                        account_expected.data[0] += 1;
                        account2.data_as_mut_slice()[0] = account2.data[0] + 1;
                    } else if pass == 2 {
                        account1.data_as_mut_slice()[0] = account1.data[0] + 1;
                    } else if pass == 3 {
                        account_expected.data[0] += 1;
                        account2.data_as_mut_slice()[0] += 1;
                    }
                } else if field_index == 2 {
                    if pass == 0 {
                        account1.owner = key2;
                    } else if pass == 1 {
                        account_expected.owner = key2;
                        account2.set_owner(key2);
                    } else if pass == 2 {
                        account1.set_owner(key3);
                    } else if pass == 3 {
                        account_expected.owner = key3;
                        account2.owner = key3;
                    }
                } else if field_index == 3 {
                    if pass == 0 {
                        account1.executable = !account1.executable;
                    } else if pass == 1 {
                        account_expected.executable = !account_expected.executable;
                        account2.set_executable(!account2.executable);
                    } else if pass == 2 {
                        account1.set_executable(!account1.executable);
                    } else if pass == 3 {
                        account_expected.executable = !account_expected.executable;
                        account2.executable = !account2.executable;
                    }
                } else if field_index == 4 {
                    if pass == 0 {
                        account1.rent_epoch += 1;
                    } else if pass == 1 {
                        account_expected.rent_epoch += 1;
                        account2.set_rent_epoch(account2.rent_epoch + 1);
                    } else if pass == 2 {
                        account1.set_rent_epoch(account1.rent_epoch + 1);
                    } else if pass == 3 {
                        account_expected.rent_epoch += 1;
                        account2.rent_epoch += 1;
                    }
                }

                let should_be_equal = pass == 1 || pass == 3;
                test_equal(should_be_equal, &account1, &account2, &account_expected);

                // test new_ref
                if should_be_equal {
                    assert!(accounts_equal(
                        &Account::new_ref(
                            account_expected.lamports(),
                            account_expected.data().len(),
                            account_expected.owner()
                        )
                        .borrow(),
                        &AccountSharedData::new_ref(
                            account_expected.lamports(),
                            account_expected.data().len(),
                            account_expected.owner()
                        )
                        .borrow()
                    ));

                    {
                        // test new_data
                        let account1_with_data = Account::new_data(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            account_expected.owner(),
                        )
                        .unwrap();
                        let account2_with_data = AccountSharedData::new_data(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            account_expected.owner(),
                        )
                        .unwrap();

                        assert!(accounts_equal(&account1_with_data, &account2_with_data));
                        assert_eq!(
                            account1_with_data.deserialize_data::<u8>().unwrap(),
                            account2_with_data.deserialize_data::<u8>().unwrap()
                        );
                    }

                    // test new_data_with_space
                    assert!(accounts_equal(
                        &Account::new_data_with_space(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            1,
                            account_expected.owner()
                        )
                        .unwrap(),
                        &AccountSharedData::new_data_with_space(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            1,
                            account_expected.owner()
                        )
                        .unwrap()
                    ));

                    // test new_ref_data
                    assert!(accounts_equal(
                        &Account::new_ref_data(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            account_expected.owner()
                        )
                        .unwrap()
                        .borrow(),
                        &AccountSharedData::new_ref_data(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            account_expected.owner()
                        )
                        .unwrap()
                        .borrow()
                    ));

                    //new_ref_data_with_space
                    assert!(accounts_equal(
                        &Account::new_ref_data_with_space(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            1,
                            account_expected.owner()
                        )
                        .unwrap()
                        .borrow(),
                        &AccountSharedData::new_ref_data_with_space(
                            account_expected.lamports(),
                            &account_expected.data()[0],
                            1,
                            account_expected.owner()
                        )
                        .unwrap()
                        .borrow()
                    ));
                }
            }
        }
    }
}
