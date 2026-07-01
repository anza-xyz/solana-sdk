//! bincode-based serialization helpers for [`Account`] and [`AccountSharedData`].

use {
    crate::{
        Account, AccountSharedData, InheritableAccountFields, ReadableAccount, WritableAccount,
        DUMMY_INHERITABLE_ACCOUNT_FIELDS,
    },
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
    solana_sysvar::SysvarSerialize,
    std::{cell::RefCell, sync::Arc},
};

fn shared_deserialize_data<T: serde::de::DeserializeOwned, U: ReadableAccount>(
    account: &U,
) -> Result<T, bincode::Error> {
    bincode::deserialize(account.data())
}

fn shared_serialize_data<T: serde::Serialize, U: WritableAccount>(
    account: &mut U,
    state: &T,
) -> Result<(), bincode::Error> {
    if bincode::serialized_size(state)? > account.data().len() as u64 {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    bincode::serialize_into(account.data_as_mut_slice(), state)
}

impl Account {
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        let data = bincode::serialize(state)?;
        Ok(Account {
            lamports,
            data,
            owner: *owner,
            executable: false,
            rent_epoch: Epoch::default(),
        })
    }
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        Account::new_data(lamports, state, owner).map(RefCell::new)
    }
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        let mut account = Account::new(lamports, space, owner);
        shared_serialize_data(&mut account, state)?;
        Ok(account)
    }
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        Account::new_data_with_space(lamports, state, space, owner).map(RefCell::new)
    }
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
}

impl AccountSharedData {
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        let data = bincode::serialize(state)?;
        Ok(Self::create_from_existing_shared_data(
            lamports,
            Arc::new(data),
            *owner,
            false,
            Epoch::default(),
        ))
    }
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        AccountSharedData::new_data(lamports, state, owner).map(RefCell::new)
    }
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        let mut account = AccountSharedData::new(lamports, space, owner);
        shared_serialize_data(&mut account, state)?;
        Ok(account)
    }
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        AccountSharedData::new_data_with_space(lamports, state, space, owner).map(RefCell::new)
    }
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
}

pub fn create_account_with_fields<S: SysvarSerialize>(
    sysvar: &S,
    (lamports, rent_epoch): InheritableAccountFields,
) -> Account {
    let data_len = S::size_of().max(bincode::serialized_size(sysvar).unwrap() as usize);
    let mut account = Account::new(lamports, data_len, &solana_sdk_ids::sysvar::id());
    to_account::<S, Account>(sysvar, &mut account).unwrap();
    account.rent_epoch = rent_epoch;
    account
}

pub fn create_account_for_test<S: SysvarSerialize>(sysvar: &S) -> Account {
    create_account_with_fields(sysvar, DUMMY_INHERITABLE_ACCOUNT_FIELDS)
}

/// Create an `Account` from a `Sysvar`.
pub fn create_account_shared_data_with_fields<S: SysvarSerialize>(
    sysvar: &S,
    fields: InheritableAccountFields,
) -> AccountSharedData {
    AccountSharedData::from(create_account_with_fields(sysvar, fields))
}

pub fn create_account_shared_data_for_test<S: SysvarSerialize>(sysvar: &S) -> AccountSharedData {
    AccountSharedData::from(create_account_with_fields(
        sysvar,
        DUMMY_INHERITABLE_ACCOUNT_FIELDS,
    ))
}

/// Create a `Sysvar` from an `Account`'s data.
pub fn from_account<S: SysvarSerialize, T: ReadableAccount>(account: &T) -> Option<S> {
    bincode::deserialize(account.data()).ok()
}

/// Serialize a `Sysvar` into an `Account`'s data.
pub fn to_account<S: SysvarSerialize, T: WritableAccount>(
    sysvar: &S,
    account: &mut T,
) -> Option<()> {
    bincode::serialize_into(account.data_as_mut_slice(), sysvar).ok()
}
