//! The most recent hashes of a slot's parent banks.
//!
//! The _slot hashes sysvar_ provides access to the [`SlotHashes`] type.
//!
//! The [`SysvarSerialize::from_account_info`] and [`Sysvar::get`] methods always return
//! [`solana_program_error::ProgramError::UnsupportedSysvar`] because this sysvar account is too large
//! to process on-chain. Thus this sysvar cannot be accessed on chain, though
//! one can still use the [`SysvarId::id`], [`SysvarId::check_id`] and
//! [`SysvarSerialize::size_of`] methods in an on-chain program, and it can be accessed
//! off-chain through RPC.
//!
//! [`SysvarId::id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.id
//! [`SysvarId::check_id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.check_id
//!
//! # Examples
//!
//! Calling via the RPC client:
//!
//! ```
//! # use solana_example_mocks::solana_account;
//! # use solana_example_mocks::solana_rpc_client;
//! # use solana_account::Account;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_sdk_ids::sysvar::slot_hashes;
//! # use solana_slot_hashes::SlotHashes;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_slot_hashes(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(slot_hashes::ID, Account {
//! #       lamports: 1009200,
//! #       data: vec![1, 0, 0, 0, 0, 0, 0, 0, 86, 190, 235, 7, 0, 0, 0, 0, 133, 242, 94, 158, 223, 253, 207, 184, 227, 194, 235, 27, 176, 98, 73, 3, 175, 201, 224, 111, 21, 65, 73, 27, 137, 73, 229, 19, 255, 192, 193, 126],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! # });
//! #
//!     let slot_hashes = client.get_account(&slot_hashes::ID)?;
//!     let data: SlotHashes = bincode::deserialize(&slot_hashes.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_slot_hashes(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```
#[cfg(feature = "bytemuck")]
use bytemuck_derive::{Pod, Zeroable};
use {crate::Sysvar, solana_clock::Slot, solana_hash::Hash};
#[cfg(feature = "bincode")]
use {crate::SysvarSerialize, solana_account_info::AccountInfo};

#[cfg(feature = "bytemuck")]
const U64_SIZE: usize = std::mem::size_of::<u64>();

#[cfg(any(feature = "bytemuck", feature = "bincode"))]
const SYSVAR_LEN: usize = 20_488; // golden, update if MAX_ENTRIES changes

pub use {
    solana_sdk_ids::sysvar::slot_hashes::{check_id, id, ID},
    solana_slot_hashes::SlotHashes,
    solana_sysvar_id::SysvarId,
};

impl Sysvar for SlotHashes {}
#[cfg(feature = "bincode")]
impl SysvarSerialize for SlotHashes {
    // override
    fn size_of() -> usize {
        // hard-coded so that we don't have to construct an empty
        SYSVAR_LEN
    }
    fn from_account_info(
        _account_info: &AccountInfo,
    ) -> Result<Self, solana_program_error::ProgramError> {
        // This sysvar is too large to bincode::deserialize in-program
        Err(solana_program_error::ProgramError::UnsupportedSysvar)
    }
}

/// A bytemuck-compatible (plain old data) version of `SlotHash`.
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct PodSlotHash {
    pub slot: Slot,
    pub hash: Hash,
}

#[cfg(feature = "bytemuck")]
/// API for querying of the `SlotHashes` sysvar by on-chain programs.
///
/// Hangs onto the allocated raw buffer from the account data, which can be
/// queried or accessed directly as a slice of `PodSlotHash`.
#[derive(Default)]
pub struct PodSlotHashes {
    data: Vec<u8>,
    slot_hashes_start: usize,
    slot_hashes_end: usize,
}

#[cfg(feature = "bytemuck")]
impl PodSlotHashes {
    /// Fetch all of the raw sysvar data using the `sol_get_sysvar` syscall.
    pub fn fetch() -> Result<Self, solana_program_error::ProgramError> {
        // Allocate an uninitialized buffer for the raw sysvar data.
        let sysvar_len = SYSVAR_LEN;
        let mut data = vec![0; sysvar_len];

        // Ensure the created buffer is aligned to 8.
        if data.as_ptr().align_offset(8) != 0 {
            return Err(solana_program_error::ProgramError::InvalidAccountData);
        }

        // Populate the buffer by fetching all sysvar data using the
        // `sol_get_sysvar` syscall.
        crate::get_sysvar(
            &mut data,
            &SlotHashes::id(),
            /* offset */ 0,
            /* length */ sysvar_len as u64,
        )?;

        // Get the number of slot hashes present in the data by reading the
        // `u64` length at the beginning of the data, then use that count to
        // calculate the length of the slot hashes data.
        //
        // The rest of the buffer is uninitialized and should not be accessed.
        let length = data
            .get(..U64_SIZE)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .and_then(|length| length.checked_mul(std::mem::size_of::<PodSlotHash>() as u64))
            .ok_or(solana_program_error::ProgramError::InvalidAccountData)?;

        let slot_hashes_start = U64_SIZE;
        let slot_hashes_end = slot_hashes_start.saturating_add(length as usize);

        Ok(Self {
            data,
            slot_hashes_start,
            slot_hashes_end,
        })
    }

    /// Return the `SlotHashes` sysvar data as a slice of `PodSlotHash`.
    /// Returns a slice of only the initialized sysvar data.
    pub fn as_slice(&self) -> Result<&[PodSlotHash], solana_program_error::ProgramError> {
        self.data
            .get(self.slot_hashes_start..self.slot_hashes_end)
            .and_then(|data| bytemuck::try_cast_slice(data).ok())
            .ok_or(solana_program_error::ProgramError::InvalidAccountData)
    }

    /// Given a slot, get its corresponding hash in the `SlotHashes` sysvar
    /// data. Returns `None` if the slot is not found.
    pub fn get(&self, slot: &Slot) -> Result<Option<Hash>, solana_program_error::ProgramError> {
        self.as_slice().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .map(|idx| pod_hashes[idx].hash)
                .ok()
        })
    }

    /// Given a slot, get its position in the `SlotHashes` sysvar data. Returns
    /// `None` if the slot is not found.
    pub fn position(
        &self,
        slot: &Slot,
    ) -> Result<Option<usize>, solana_program_error::ProgramError> {
        self.as_slice().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::tests::mock_get_sysvar_syscall, serial_test::serial, solana_hash::Hash,
        solana_sha256_hasher::hash, solana_slot_hashes::MAX_ENTRIES, test_case::test_case,
    };

    #[test]
    fn test_size_of() {
        assert_eq!(
            SlotHashes::size_of(),
            bincode::serialized_size(
                &(0..MAX_ENTRIES)
                    .map(|slot| (slot as Slot, Hash::default()))
                    .collect::<SlotHashes>()
            )
            .unwrap() as usize
        );
    }

    fn mock_slot_hashes(slot_hashes: &SlotHashes) {
        // The data is always `SlotHashes::size_of()`.
        let mut data = vec![0; SlotHashes::size_of()];
        bincode::serialize_into(&mut data[..], slot_hashes).unwrap();
        mock_get_sysvar_syscall(&data);
    }

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(2)]
    #[test_case(5)]
    #[test_case(10)]
    #[test_case(64)]
    #[test_case(128)]
    #[test_case(192)]
    #[test_case(256)]
    #[test_case(384)]
    #[test_case(MAX_ENTRIES)]
    #[serial]
    fn test_pod_slot_hashes(num_entries: usize) {
        let mut slot_hashes = vec![];
        for i in 0..num_entries {
            slot_hashes.push((
                i as u64,
                hash(&[(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8]),
            ));
        }

        let check_slot_hashes = SlotHashes::new(&slot_hashes);
        mock_slot_hashes(&check_slot_hashes);

        let pod_slot_hashes = PodSlotHashes::fetch().unwrap();

        // Assert the slice of `PodSlotHash` has the same length as
        // `SlotHashes`.
        let pod_slot_hashes_slice = pod_slot_hashes.as_slice().unwrap();
        assert_eq!(pod_slot_hashes_slice.len(), slot_hashes.len());

        // Assert `PodSlotHashes` and `SlotHashes` contain the same slot hashes
        // in the same order.
        for slot in slot_hashes.iter().map(|(slot, _hash)| slot) {
            // `get`:
            assert_eq!(
                pod_slot_hashes.get(slot).unwrap().as_ref(),
                check_slot_hashes.get(slot),
            );
            // `position`:
            assert_eq!(
                pod_slot_hashes.position(slot).unwrap(),
                check_slot_hashes.position(slot),
            );
        }

        // Check a few `None` values.
        let not_a_slot = num_entries.saturating_add(1) as u64;
        assert_eq!(
            pod_slot_hashes.get(&not_a_slot).unwrap().as_ref(),
            check_slot_hashes.get(&not_a_slot),
        );
        assert_eq!(pod_slot_hashes.get(&not_a_slot).unwrap(), None);
        assert_eq!(
            pod_slot_hashes.position(&not_a_slot).unwrap(),
            check_slot_hashes.position(&not_a_slot),
        );
        assert_eq!(pod_slot_hashes.position(&not_a_slot).unwrap(), None);

        let not_a_slot = num_entries.saturating_add(2) as u64;
        assert_eq!(
            pod_slot_hashes.get(&not_a_slot).unwrap().as_ref(),
            check_slot_hashes.get(&not_a_slot),
        );
        assert_eq!(pod_slot_hashes.get(&not_a_slot).unwrap(), None);
        assert_eq!(
            pod_slot_hashes.position(&not_a_slot).unwrap(),
            check_slot_hashes.position(&not_a_slot),
        );
        assert_eq!(pod_slot_hashes.position(&not_a_slot).unwrap(), None);
    }
}
