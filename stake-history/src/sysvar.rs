//! History of stake activations and de-activations.
//!
//! The _stake history sysvar_ provides access to the [`StakeHistory`] type.
//!
//! The [`GetSysvar::get`] method always returns
//! [`ProgramError::UnsupportedSysvar`], and in practice the data size of this
//! sysvar is too large to process on chain. One can still use the
//! [`SysvarId::id`] and [`SysvarId::check_id`] methods in an on-chain program,
//! and it can be accessed off-chain through RPC.
//!
//! [`GetSysvar::get`]: solana_get_sysvar::GetSysvar::get
//! [`ProgramError::UnsupportedSysvar`]: https://docs.rs/solana-program-error/latest/solana_program_error/enum.ProgramError.html#variant.UnsupportedSysvar
//! [`SysvarId::id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html
//! [`SysvarId::check_id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.check_id
//!
//! # Examples
//!
//! Calling via the RPC client:
//!
//! ```
//! # use solana_example_mocks::{solana_account, solana_rpc_client};
//! # use solana_stake_history::{sysvar, StakeHistory};
//! # use solana_account::Account;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_stake_history(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(sysvar::ID, Account {
//! #       lamports: 114979200,
//! #       data: vec![0, 0, 0, 0, 0, 0, 0, 0],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! #   });
//! #
//!     let stake_history = client.get_account(&sysvar::ID)?;
//!     let data: StakeHistory = bincode::deserialize(&stake_history.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_stake_history(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```

pub use solana_sdk_ids::sysvar::stake_history::{check_id, id, ID};
use {
    crate::{
        Epoch, StakeHistory, StakeHistoryEntry, StakeHistoryGetEntry,
        EPOCH_AND_ENTRY_SERIALIZED_SIZE, MAX_ENTRIES,
    },
    solana_get_sysvar::{get_sysvar, GetSysvar},
    solana_sysvar_id::impl_sysvar_id,
};

impl_sysvar_id!(StakeHistory);

impl GetSysvar for StakeHistory {}

// we do not provide Default because this requires the real current epoch
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StakeHistorySysvar(pub Epoch);

impl StakeHistoryGetEntry for StakeHistorySysvar {
    fn get_entry(&self, target_epoch: Epoch) -> Option<StakeHistoryEntry> {
        let current_epoch = self.0;

        // if current epoch is zero this returns None because there is no history yet
        let newest_historical_epoch = current_epoch.checked_sub(1)?;
        let oldest_historical_epoch = current_epoch.saturating_sub(MAX_ENTRIES as u64);

        // target epoch is old enough to have fallen off history; presume fully active/deactive
        if target_epoch < oldest_historical_epoch {
            return None;
        }

        // epoch delta is how many epoch-entries we offset in the stake history vector, which may be zero
        // None means target epoch is current or in the future; this is a user error
        let epoch_delta = newest_historical_epoch.checked_sub(target_epoch)?;

        // offset is the number of bytes to our desired entry, including eight for vector length
        let offset = epoch_delta
            .checked_mul(EPOCH_AND_ENTRY_SERIALIZED_SIZE as u64)?
            .checked_add(core::mem::size_of::<u64>() as u64)?;

        let mut entry_buf = [0; EPOCH_AND_ENTRY_SERIALIZED_SIZE];
        let result = get_sysvar(
            &mut entry_buf,
            &id(),
            offset,
            EPOCH_AND_ENTRY_SERIALIZED_SIZE as u64,
        );

        match result {
            Ok(()) => {
                // All safe because `entry_buf` is a 32-length array
                let entry_epoch = u64::from_le_bytes(entry_buf[0..8].try_into().unwrap());
                let effective = u64::from_le_bytes(entry_buf[8..16].try_into().unwrap());
                let activating = u64::from_le_bytes(entry_buf[16..24].try_into().unwrap());
                let deactivating = u64::from_le_bytes(entry_buf[24..32].try_into().unwrap());

                // this would only fail if stake history skipped an epoch or the binary format of the sysvar changed
                assert_eq!(entry_epoch, target_epoch);

                Some(StakeHistoryEntry {
                    effective,
                    activating,
                    deactivating,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::SIZE, alloc::vec::Vec};

    #[test]
    fn test_size_of() {
        let mut stake_history = StakeHistory::default();
        for i in 0..MAX_ENTRIES as u64 {
            stake_history.add(
                i,
                StakeHistoryEntry {
                    activating: i,
                    ..StakeHistoryEntry::default()
                },
            );
        }

        assert_eq!(
            bincode::serialized_size(&stake_history).unwrap() as usize,
            SIZE,
        );

        let stake_history_inner: Vec<(Epoch, StakeHistoryEntry)> =
            bincode::deserialize(&bincode::serialize(&stake_history).unwrap()).unwrap();
        let epoch_entry = stake_history_inner.into_iter().next().unwrap();

        assert_eq!(
            bincode::serialized_size(&epoch_entry).unwrap() as usize,
            EPOCH_AND_ENTRY_SERIALIZED_SIZE,
        );
    }

    #[test]
    fn test_stake_history_get_entry() {
        let unique_entry_for_epoch = |epoch: u64| StakeHistoryEntry {
            activating: epoch.saturating_mul(2),
            deactivating: epoch.saturating_mul(3),
            effective: epoch.saturating_mul(5),
        };

        let current_epoch = MAX_ENTRIES.saturating_add(2) as u64;

        // make a stake history object with at least one valid entry that has expired
        let mut stake_history = StakeHistory::default();
        for i in 0..current_epoch {
            stake_history.add(i, unique_entry_for_epoch(i));
        }
        assert_eq!(stake_history.len(), MAX_ENTRIES);
        assert_eq!(stake_history.iter().map(|entry| entry.0).min().unwrap(), 2);

        // now test the stake history interfaces

        assert_eq!(stake_history.get(0), None);
        assert_eq!(stake_history.get(1), None);
        assert_eq!(stake_history.get(current_epoch), None);

        assert_eq!(stake_history.get_entry(0), None);
        assert_eq!(stake_history.get_entry(1), None);
        assert_eq!(stake_history.get_entry(current_epoch), None);

        for i in 2..current_epoch {
            let entry = Some(unique_entry_for_epoch(i));

            assert_eq!(stake_history.get(i), entry.as_ref(),);

            assert_eq!(stake_history.get_entry(i), entry,);
        }
    }

    #[test]
    fn test_stake_history_get_entry_zero() {
        let mut current_epoch = 0;

        // first test that an empty history returns None
        let stake_history = StakeHistory::default();
        assert_eq!(stake_history.len(), 0);

        assert_eq!(stake_history.get(0), None);
        assert_eq!(stake_history.get_entry(0), None);

        // next test that we can get a zeroth entry in the first epoch
        let entry_zero = StakeHistoryEntry {
            effective: 100,
            ..StakeHistoryEntry::default()
        };
        let entry = Some(entry_zero.clone());

        let mut stake_history = StakeHistory::default();
        stake_history.add(current_epoch, entry_zero);
        assert_eq!(stake_history.len(), 1);
        current_epoch = current_epoch.saturating_add(1);

        assert_eq!(stake_history.get(0), entry.as_ref());
        assert_eq!(stake_history.get_entry(0), entry);

        // finally test that we can still get a zeroth entry in later epochs
        stake_history.add(current_epoch, StakeHistoryEntry::default());
        assert_eq!(stake_history.len(), 2);

        assert_eq!(stake_history.get(0), entry.as_ref());
        assert_eq!(stake_history.get_entry(0), entry);
    }
}
