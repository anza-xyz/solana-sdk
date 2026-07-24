//! wincode-based serialization helpers for [`Account`] and [`AccountSharedData`].
//!
//! These mirror the bincode helpers and are compiled in their place when the
//! `wincode` feature is enabled without `bincode`. wincode's wire format here is
//! byte-for-byte identical to bincode's, so the encoded account data matches; the
//! only deliberate difference is the preallocation limit (see [`crate::WincodeConfig`]).

use {
    crate::{
        Account, AccountSharedData, ReadableAccount, WincodeConfig, WritableAccount, WINCODE_CONFIG,
    },
    solana_pubkey::Pubkey,
    std::cell::RefCell,
    wincode::{ReadResult, SchemaRead, SchemaWrite, WriteResult},
};

fn shared_deserialize_data<T, U>(account: &U) -> ReadResult<T>
where
    T: for<'de> SchemaRead<'de, WincodeConfig, Dst = T>,
    U: ReadableAccount,
{
    wincode::config::deserialize(account.data(), WINCODE_CONFIG)
}

fn shared_serialize_data<T, U>(account: &mut U, state: &T) -> WriteResult<()>
where
    T: SchemaWrite<WincodeConfig, Src = T>,
    U: WritableAccount,
{
    // Serialize straight into the existing account buffer; the bounded slice writer
    // fails with `WriteSizeLimit` (mapped to `AccountDataTooSmall` by `state_traits`)
    // when the value is too large, so no `serialized_size` pre-check is needed.
    wincode::config::serialize_into(account.data_as_mut_slice(), state, WINCODE_CONFIG)
}

/// wincode-serialize `state` into a freshly allocated buffer capped at `limit` bytes,
/// returning the exact-length encoded bytes or `WriteSizeLimit` if it does not fit.
///
/// Avoids both zero-filling bytes that are immediately overwritten and a separate
/// `serialized_size` pass to enforce `limit`.
fn serialize_bounded<T>(state: &T, limit: usize) -> WriteResult<Vec<u8>>
where
    T: SchemaWrite<WincodeConfig, Src = T>,
{
    let mut data = Vec::with_capacity(limit);
    let mut uninit = &mut data.spare_capacity_mut()[..limit];
    <T as SchemaWrite<WincodeConfig>>::write(&mut uninit, state)?;
    let written = limit - uninit.len();
    // SAFETY: `write` initialized exactly `written` bytes at the front of the buffer
    // (advancing `uninit` past them), and `written <= limit == capacity`.
    unsafe { data.set_len(written) };
    Ok(data)
}

impl Account {
    pub fn new_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        let data = wincode::config::serialize(state, WINCODE_CONFIG)?;
        Ok(Account::new_with_data(lamports, data, owner))
    }
    pub fn new_ref_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> WriteResult<RefCell<Self>> {
        Account::new_data(lamports, state, owner).map(RefCell::new)
    }
    pub fn new_data_with_space<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        let mut data = serialize_bounded(state, space)?;
        // Zero-pad up to `space`, matching the bincode path that serializes into a
        // zero-initialized buffer of length `space`.
        data.resize(space, 0);
        Ok(Account::new_with_data(lamports, data, owner))
    }
    pub fn new_ref_data_with_space<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<RefCell<Self>> {
        Account::new_data_with_space(lamports, state, space, owner).map(RefCell::new)
    }
    pub fn deserialize_data<T: for<'de> SchemaRead<'de, WincodeConfig, Dst = T>>(
        &self,
    ) -> ReadResult<T> {
        shared_deserialize_data(self)
    }
    pub fn serialize_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        &mut self,
        state: &T,
    ) -> WriteResult<()> {
        shared_serialize_data(self, state)
    }
}

impl AccountSharedData {
    pub fn new_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        Account::new_data(lamports, state, owner).map(AccountSharedData::from)
    }
    pub fn new_ref_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> WriteResult<RefCell<Self>> {
        AccountSharedData::new_data(lamports, state, owner).map(RefCell::new)
    }
    pub fn new_data_with_space<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<Self> {
        Account::new_data_with_space(lamports, state, space, owner).map(AccountSharedData::from)
    }
    pub fn new_ref_data_with_space<T: SchemaWrite<WincodeConfig, Src = T>>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> WriteResult<RefCell<Self>> {
        AccountSharedData::new_data_with_space(lamports, state, space, owner).map(RefCell::new)
    }
    pub fn deserialize_data<T: for<'de> SchemaRead<'de, WincodeConfig, Dst = T>>(
        &self,
    ) -> ReadResult<T> {
        shared_deserialize_data(self)
    }
    pub fn serialize_data<T: SchemaWrite<WincodeConfig, Src = T>>(
        &mut self,
        state: &T,
    ) -> WriteResult<()> {
        shared_serialize_data(self, state)
    }
}

// NOTE: the `create_account_*` sysvar helpers are omitted: they size accounts via the
// bincode-gated `SysvarSerialize::size_of()`, and sizing to the wincode-serialized
// length instead would undersize sysvars whose canonical size exceeds it. These helpers
// are being deprecated/removed in favor of caller-provided sizing.

/// Deserialize a value from an `Account`'s data.
pub fn from_account<S, T>(account: &T) -> Option<S>
where
    S: for<'de> SchemaRead<'de, WincodeConfig, Dst = S>,
    T: ReadableAccount,
{
    wincode::config::deserialize(account.data(), WINCODE_CONFIG).ok()
}

/// Serialize a value into an `Account`'s data.
pub fn to_account<S, T>(state: &S, account: &mut T) -> Option<()>
where
    S: SchemaWrite<WincodeConfig, Src = S>,
    T: WritableAccount,
{
    wincode::config::serialize_into(account.data_as_mut_slice(), state, WINCODE_CONFIG).ok()
}
