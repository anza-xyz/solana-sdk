//! wincode-based state trait for the account types.
//!
//! wincode gets its own [`StateMutWincode`] trait rather than reusing
//! [`StateMut`](crate::state_traits::StateMut), so the bincode and wincode
//! implementations can coexist when both features are enabled. It is the crate's
//! entire wincode codec surface: reading (`state`), in-place writing (`set_state`),
//! and construction (`new_data`/`new_data_with_space`).

use {
    crate::{Account, AccountSharedData, ReadableAccount, WincodeConfig, WINCODE_CONFIG},
    solana_instruction_error::InstructionError,
    solana_pubkey::Pubkey,
    std::sync::Arc,
    wincode::{SchemaRead, SchemaWrite, WriteError, WriteResult},
};

/// wincode counterpart of [`StateMut`](crate::state_traits::StateMut) that also
/// constructs accounts whose data is wincode-encoded.
pub trait StateMutWincode<T>: Sized {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError>;

    /// Create an account sized to the wincode-serialized length of `state`.
    fn new_data(lamports: u64, state: &T, owner: &Pubkey) -> WriteResult<Self>;

    /// Create an account of `space` bytes with `state` serialized into the front and
    /// the remainder zero-padded; fails with `WriteSizeLimit` if `state` does not fit.
    fn new_data_with_space(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<Self>;
}

impl<T> StateMutWincode<T> for Account
where
    T: SchemaWrite<WincodeConfig, Src = T> + for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
{
    fn state(&self) -> Result<T, InstructionError> {
        deserialize_state(self)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        serialize_state_into(&mut self.data, state)
    }
    fn new_data(lamports: u64, state: &T, owner: &Pubkey) -> WriteResult<Self> {
        let data = wincode::config::serialize(state, WINCODE_CONFIG)?;
        Ok(Account::new_with_data(lamports, data, owner))
    }
    fn new_data_with_space(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        let mut data = serialize_bounded(state, space, space)?;
        data.resize(space, 0);
        Ok(Account::new_with_data(lamports, data, owner))
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
        self.set_state_with_cow_capacity(state, 0)
    }
    fn new_data(lamports: u64, state: &T, owner: &Pubkey) -> WriteResult<Self> {
        <Account as StateMutWincode<T>>::new_data(lamports, state, owner)
            .map(AccountSharedData::from)
    }
    fn new_data_with_space(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        <Account as StateMutWincode<T>>::new_data_with_space(lamports, state, space, owner)
            .map(AccountSharedData::from)
    }
}

impl AccountSharedData {
    /// Encodes `state` over the start of the data and keeps the rest.
    ///
    /// `cow_capacity` is the minimum capacity of the copy-on-write buffer that replaces a shared
    /// one, e.g. to leave headroom for the account to grow during an instruction. The replacement
    /// skips copying the overwritten bytes. An unshared buffer is written in place and keeps its
    /// capacity.
    pub fn set_state_with_cow_capacity<T>(
        &mut self,
        state: &T,
        cow_capacity: usize,
    ) -> Result<(), InstructionError>
    where
        T: SchemaWrite<WincodeConfig, Src = T>,
    {
        if let Some(data) = Arc::get_mut(&mut self.data) {
            return serialize_state_into(data, state);
        }
        let len = self.data.len();
        let mut data = serialize_bounded(state, len, cow_capacity.max(len))
            .map_err(write_error_to_instruction_error)?;
        data.extend_from_slice(&self.data[data.len()..]);
        self.data = Arc::new(data);
        Ok(())
    }
}

fn deserialize_state<T, U>(account: &U) -> Result<T, InstructionError>
where
    T: for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
    U: ReadableAccount,
{
    wincode::config::deserialize(account.data(), WINCODE_CONFIG)
        .map_err(|_| InstructionError::InvalidAccountData)
}

fn serialize_state_into<T>(data: &mut [u8], state: &T) -> Result<(), InstructionError>
where
    T: SchemaWrite<WincodeConfig, Src = T>,
{
    // The bounded slice writer fails with `WriteSizeLimit` when the value is too large
    // for the account data, so no `serialized_size` pre-check is needed.
    wincode::config::serialize_into(data, state, WINCODE_CONFIG)
        .map_err(write_error_to_instruction_error)
}

fn write_error_to_instruction_error(err: WriteError) -> InstructionError {
    match err {
        WriteError::Io(wincode::io::WriteError::WriteSizeLimit(_)) => {
            InstructionError::AccountDataTooSmall
        }
        _ => InstructionError::GenericError,
    }
}

/// wincode-serialize `state` into a freshly allocated buffer of `capacity` bytes, capped at
/// `limit` bytes, returning the exact-length encoded bytes or `WriteSizeLimit` if it does not fit.
///
/// Avoids both zero-filling bytes that are immediately overwritten and a separate
/// `serialized_size` pass to enforce `limit`.
fn serialize_bounded<T>(state: &T, limit: usize, capacity: usize) -> WriteResult<Vec<u8>>
where
    T: SchemaWrite<WincodeConfig, Src = T>,
{
    let mut data = Vec::with_capacity(capacity);
    let mut uninit = &mut data.spare_capacity_mut()[..limit];
    <T as SchemaWrite<WincodeConfig>>::write(&mut uninit, state)?;
    // `write` only reslices `uninit` to a suffix of the original `limit`-length slice, so
    // `uninit.len() <= limit` always holds and this never actually wraps.
    let written = limit.wrapping_sub(uninit.len());
    // SAFETY: `write` initialized exactly `written` bytes at the front of the buffer
    // (advancing `uninit` past them), and `written <= limit <= capacity`.
    unsafe { data.set_len(written) };
    Ok(data)
}

#[cfg(test)]
mod tests {
    use {
        super::{StateMutWincode as StateMut, *},
        solana_pubkey::Pubkey,
    };

    // Mirrors `state_traits::bincode`'s `test_account_state`, through the wincode trait.
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

    #[test]
    fn test_new_data() {
        let state = 42u64;
        let owner = Pubkey::new_unique();

        let account = <AccountSharedData as StateMut<u64>>::new_data(1, &state, &owner).unwrap();
        assert_eq!(account.lamports(), 1);
        assert_eq!(account.owner(), &owner);
        assert_eq!(account.data().len(), std::mem::size_of::<u64>());
        let stored: u64 = account.state().unwrap();
        assert_eq!(stored, state);
    }

    #[test]
    fn test_new_data_with_space() {
        let state = 42u64;
        let owner = Pubkey::new_unique();
        let size = std::mem::size_of::<u64>();

        // extra space is zero-padded, and the value still reads back
        let account =
            <AccountSharedData as StateMut<u64>>::new_data_with_space(1, &state, size + 4, &owner)
                .unwrap();
        assert_eq!(account.data().len(), size + 4);
        let stored: u64 = account.state().unwrap();
        assert_eq!(stored, state);

        // a value that does not fit `space` fails
        assert!(<AccountSharedData as StateMut<u64>>::new_data_with_space(
            1,
            &state,
            size - 1,
            &owner,
        )
        .is_err());
    }

    #[test]
    fn test_set_state_with_cow_capacity() {
        let state = 42u64;
        let size = std::mem::size_of::<u64>();
        let tail = [7u8; 4];
        let mut data = vec![0u8; size];
        data.extend_from_slice(&tail);
        let len = data.len();

        // exclusive buffer: written in place, the tail and the allocation are kept
        let mut account = AccountSharedData::new_with_data(0, data.clone(), &Pubkey::default());
        let ptr = account.data().as_ptr();
        let capacity = account.capacity();
        account
            .set_state_with_cow_capacity(&state, len + 100)
            .unwrap();
        assert_eq!(&account.data()[size..], &tail);
        assert_eq!(account.data().as_ptr(), ptr);
        assert_eq!(account.capacity(), capacity);
        assert_eq!(StateMut::<u64>::state(&account).unwrap(), state);

        // shared buffer: replaced, the other owner keeps the old bytes
        let mut account = AccountSharedData::new_with_data(0, data.clone(), &Pubkey::default());
        let other = account.clone();
        account
            .set_state_with_cow_capacity(&state, len + 100)
            .unwrap();
        assert!(!account.is_shared());
        assert_eq!(account.data().len(), len);
        assert_eq!(&account.data()[size..], &tail);
        assert!(account.capacity() >= len + 100);
        assert_eq!(StateMut::<u64>::state(&account).unwrap(), state);
        assert_eq!(other.data(), &data[..]);

        // a cow capacity below the length keeps the data intact
        let mut account = AccountSharedData::new_with_data(0, data.clone(), &Pubkey::default());
        let _other = account.clone();
        account.set_state_with_cow_capacity(&state, 0).unwrap();
        assert_eq!(account.data().len(), len);
        assert_eq!(StateMut::<u64>::state(&account).unwrap(), state);

        // a value that does not fit the data fails in both paths, leaving a shared buffer intact
        let mut account = AccountSharedData::new(0, size - 1, &Pubkey::default());
        assert_eq!(
            account.set_state_with_cow_capacity(&state, 100),
            Err(InstructionError::AccountDataTooSmall)
        );
        let other = account.clone();
        assert_eq!(
            account.set_state_with_cow_capacity(&state, 100),
            Err(InstructionError::AccountDataTooSmall)
        );
        assert!(account.is_shared());
        assert_eq!(account.data(), other.data());
    }
}
