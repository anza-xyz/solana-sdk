//! bincode-based implementations of [`StateMut`] for the account types.

use {
    crate::{state_traits::StateMut, Account, AccountSharedData},
    bincode::ErrorKind,
    solana_instruction_error::InstructionError,
    std::cell::Ref,
};

impl<T> StateMut<T> for Account
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        self.serialize_data(state).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }
}

impl<T> StateMut<T> for AccountSharedData
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        self.serialize_data(state).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }
}

impl<T> StateMut<T> for Ref<'_, AccountSharedData>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, _state: &T) -> Result<(), InstructionError> {
        panic!("illegal");
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_pubkey::Pubkey};

    #[test]
    fn test_account_state() {
        let state = 42u64;

        assert!(AccountSharedData::default().set_state(&state).is_err());
        let res = AccountSharedData::default().state() as Result<u64, InstructionError>;
        assert!(res.is_err());

        let mut account = AccountSharedData::new(0, std::mem::size_of::<u64>(), &Pubkey::default());

        assert!(account.set_state(&state).is_ok());
        let stored_state: u64 = account.state().unwrap();
        assert_eq!(stored_state, state);
    }
}
