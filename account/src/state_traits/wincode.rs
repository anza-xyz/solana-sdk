//! wincode-based state trait for the account types.
//!
//! wincode gets its own [`StateMutWincode`] trait rather than implementing
//! [`StateMut`](crate::state_traits::StateMut), so the bincode and wincode
//! implementations can coexist when both features are enabled. The trait calls
//! wincode directly instead of going through the `account::wincode` helpers: those
//! replace the bincode `Account` methods only under `wincode && not(bincode)`, so
//! when both features are on `Account::{deserialize,serialize}_data` are the bincode
//! ones and unusable here.

use {
    crate::{
        Account, AccountSharedData, ReadableAccount, WincodeConfig, WritableAccount, WINCODE_CONFIG,
    },
    solana_instruction_error::InstructionError,
    std::cell::Ref,
    wincode::{SchemaRead, SchemaWrite},
};

/// wincode counterpart of [`StateMut`](crate::state_traits::StateMut).
pub trait StateMutWincode<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError>;
}

fn deserialize_state<T, U>(account: &U) -> Result<T, InstructionError>
where
    T: for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
    U: ReadableAccount,
{
    wincode::config::deserialize(account.data(), WINCODE_CONFIG)
        .map_err(|_| InstructionError::InvalidAccountData)
}

fn serialize_state<T, U>(account: &mut U, state: &T) -> Result<(), InstructionError>
where
    T: SchemaWrite<WincodeConfig, Src = T>,
    U: WritableAccount,
{
    // The bounded slice writer fails with `WriteSizeLimit` when the value is too large
    // for the account data, so no `serialized_size` pre-check is needed.
    wincode::config::serialize_into(account.data_as_mut_slice(), state, WINCODE_CONFIG).map_err(
        |err| match err {
            wincode::WriteError::Io(wincode::io::WriteError::WriteSizeLimit(_)) => {
                InstructionError::AccountDataTooSmall
            }
            _ => InstructionError::GenericError,
        },
    )
}

impl<T> StateMutWincode<T> for Account
where
    T: SchemaWrite<WincodeConfig, Src = T> + for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
{
    fn state(&self) -> Result<T, InstructionError> {
        deserialize_state(self)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        serialize_state(self, state)
    }
}

impl<T> StateMutWincode<T> for AccountSharedData
where
    T: SchemaWrite<WincodeConfig, Src = T> + for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
{
    fn state(&self) -> Result<T, InstructionError> {
        deserialize_state(self)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        serialize_state(self, state)
    }
}

impl<T> StateMutWincode<T> for Ref<'_, AccountSharedData>
where
    T: SchemaWrite<WincodeConfig, Src = T> + for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
{
    fn state(&self) -> Result<T, InstructionError> {
        deserialize_state(&**self)
    }
    fn set_state(&mut self, _state: &T) -> Result<(), InstructionError> {
        panic!("illegal");
    }
}

// NOTE: no unit tests here — the crate's test builds always enable `bincode` (via
// `dev-context-only-utils`), so there is no wincode-only target to exercise this from.
