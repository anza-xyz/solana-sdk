//! bincode-based serialization helpers for [`Account`] and [`AccountSharedData`].

use {
    crate::{Account, AccountSharedData, ReadableAccount, WritableAccount},
    bincode::Options,
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
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
        let mut data = Vec::with_capacity(space);
        bincode::options()
            .with_fixint_encoding()
            .with_limit(space as u64)
            .serialize_into(&mut data, state)?;
        data.resize(space, 0);
        Ok(Self::new_with_data(lamports, data, owner))
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
        Account::new_data_with_space(lamports, state, space, owner).map(Self::from)
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

#[cfg(test)]
mod tests {
    use {super::*, crate::accounts_equal};

    #[test]
    fn test_new_data_with_space() {
        let owner = Pubkey::new_unique();
        let state = (42u64, vec![1u8, 2, 3]);
        let encoded = bincode::serialize(&state).unwrap();

        for space in [encoded.len(), encoded.len() + 4] {
            let account = Account::new_data_with_space(1, &state, space, &owner).unwrap();
            let shared = AccountSharedData::new_data_with_space(1, &state, space, &owner).unwrap();

            assert!(accounts_equal(&account, &shared));
            assert_eq!(account.lamports(), 1);
            assert_eq!(account.owner(), &owner);
            assert!(!account.executable());
            assert_eq!(account.rent_epoch(), Epoch::default());
            assert_eq!(account.data().len(), space);
            assert_eq!(&account.data()[..encoded.len()], encoded);
            assert!(account.data()[encoded.len()..]
                .iter()
                .all(|byte| *byte == 0));
            assert_eq!(account.deserialize_data::<(u64, Vec<u8>)>().unwrap(), state);
        }
    }

    #[test]
    fn test_new_data_with_space_too_small() {
        let owner = Pubkey::new_unique();
        for space in [0, std::mem::size_of::<u64>() - 1] {
            assert!(matches!(
                *Account::new_data_with_space(1, &42u64, space, &owner).unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *AccountSharedData::new_data_with_space(1, &42u64, space, &owner).unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *Account::new_ref_data_with_space(1, &42u64, space, &owner).unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
            assert!(matches!(
                *AccountSharedData::new_ref_data_with_space(1, &42u64, space, &owner).unwrap_err(),
                bincode::ErrorKind::SizeLimit
            ));
        }
    }

    #[test]
    fn test_new_data_with_space_empty_state() {
        let owner = Pubkey::new_unique();
        for space in [0, 4] {
            let account = Account::new_data_with_space(1, &(), space, &owner).unwrap();
            let shared = AccountSharedData::new_data_with_space(1, &(), space, &owner).unwrap();
            assert!(accounts_equal(&account, &shared));
            assert_eq!(account.data(), vec![0; space]);
            account.deserialize_data::<()>().unwrap();
        }
    }

    #[test]
    fn test_new_data_with_space_serialization_error() {
        struct InvalidState;

        impl serde::Serialize for InvalidState {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("invalid state"))
            }
        }

        let owner = Pubkey::new_unique();
        for err in [
            Account::new_data_with_space(1, &InvalidState, 8, &owner).unwrap_err(),
            AccountSharedData::new_data_with_space(1, &InvalidState, 8, &owner).unwrap_err(),
        ] {
            assert!(matches!(*err, bincode::ErrorKind::Custom(ref msg) if msg == "invalid state"));
        }
    }
}
