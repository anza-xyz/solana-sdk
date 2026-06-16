//! A type to hold data for the [`StakeHistory` sysvar][sv].
//!
//! [sv]: https://docs.solanalabs.com/runtime/sysvars#stakehistory

pub use solana_clock::Epoch;
use std::ops::Deref;

pub const MAX_ENTRIES: usize = 512; // it should never take as many as 512 epochs to warm up or cool down

/// Serialized size of a single `(Epoch, StakeHistoryEntry)` tuple
pub(crate) const EPOCH_AND_ENTRY_SERIALIZED_SIZE: usize = 32;
const _: () =
    assert!(EPOCH_AND_ENTRY_SERIALIZED_SIZE == size_of::<u64>() + size_of::<StakeHistoryEntry>());

const LEN_PREFIX: usize = size_of::<u64>();

/// Serialized size of `StakeHistory` sysvar account
pub const SIZE: usize = LEN_PREFIX + MAX_ENTRIES * EPOCH_AND_ENTRY_SERIALIZED_SIZE;
const _: () = assert!(SIZE == 16_392);

#[repr(C)]
#[cfg_attr(
    feature = "frozen-abi",
    derive(
        solana_frozen_abi_macro::AbiExample,
        solana_frozen_abi_macro::StableAbi,
        solana_frozen_abi_macro::StableAbiSample
    )
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct StakeHistoryEntry {
    pub effective: u64,    // effective stake at this epoch
    pub activating: u64,   // sum of portion of stakes not fully warmed up
    pub deactivating: u64, // requested to be cooled down, not fully deactivated yet
}

impl StakeHistoryEntry {
    pub fn with_effective(effective: u64) -> Self {
        Self {
            effective,
            ..Self::default()
        }
    }

    pub fn with_effective_and_activating(effective: u64, activating: u64) -> Self {
        Self {
            effective,
            activating,
            ..Self::default()
        }
    }

    pub fn with_deactivating(deactivating: u64) -> Self {
        Self {
            effective: deactivating,
            deactivating,
            ..Self::default()
        }
    }

    pub fn checked_add(self, rhs: StakeHistoryEntry) -> Option<Self> {
        Some(Self {
            effective: self.effective.checked_add(rhs.effective)?,
            activating: self.activating.checked_add(rhs.activating)?,
            deactivating: self.deactivating.checked_add(rhs.deactivating)?,
        })
    }

    pub fn wrapping_add(self, rhs: StakeHistoryEntry) -> Self {
        Self {
            effective: self.effective.wrapping_add(rhs.effective),
            activating: self.activating.wrapping_add(rhs.activating),
            deactivating: self.deactivating.wrapping_add(rhs.deactivating),
        }
    }

    pub fn saturating_add(self, rhs: StakeHistoryEntry) -> Self {
        Self {
            effective: self.effective.saturating_add(rhs.effective),
            activating: self.activating.saturating_add(rhs.activating),
            deactivating: self.deactivating.saturating_add(rhs.deactivating),
        }
    }
}

// TODO: Remove once we are comfortable with adding breaking changes.
impl std::ops::Add for StakeHistoryEntry {
    type Output = StakeHistoryEntry;
    fn add(self, rhs: StakeHistoryEntry) -> Self::Output {
        Self {
            effective: self.effective.saturating_add(rhs.effective),
            activating: self.activating.saturating_add(rhs.activating),
            deactivating: self.deactivating.saturating_add(rhs.deactivating),
        }
    }
}

#[repr(C)]
#[cfg_attr(
    feature = "frozen-abi",
    derive(
        solana_frozen_abi_macro::AbiExample,
        solana_frozen_abi_macro::StableAbi,
        solana_frozen_abi_macro::StableAbiSample
    )
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct StakeHistory(Vec<(Epoch, StakeHistoryEntry)>);

impl StakeHistory {
    #[inline]
    fn latest_epoch(&self) -> Option<&Epoch> {
        self.first().map(|(epoch, _)| epoch)
    }

    pub fn get(&self, epoch: Epoch) -> Option<&StakeHistoryEntry> {
        self.latest_epoch()
            .and_then(|latest| latest.checked_sub(epoch))
            .and_then(|index| self.0.get(index as usize).map(|(_, entry)| entry))
    }

    pub fn add(&mut self, epoch: Epoch, entry: StakeHistoryEntry) {
        match self.binary_search_by(|probe| epoch.cmp(&probe.0)) {
            Ok(index) => (self.0)[index] = (epoch, entry),
            Err(index) => (self.0).insert(index, (epoch, entry)),
        }
        (self.0).truncate(MAX_ENTRIES);
    }
}

impl Deref for StakeHistory {
    type Target = Vec<(Epoch, StakeHistoryEntry)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait StakeHistoryGetEntry {
    fn get_entry(&self, epoch: Epoch) -> Option<StakeHistoryEntry>;
}

impl StakeHistoryGetEntry for StakeHistory {
    fn get_entry(&self, epoch: Epoch) -> Option<StakeHistoryEntry> {
        self.get(epoch).map(|entry| entry.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_sysvar_id::SysvarId};

    #[test]
    fn test_stake_history() {
        let mut stake_history = StakeHistory::default();

        let current_epoch = MAX_ENTRIES as u64 + 1;
        for i in 0..current_epoch {
            stake_history.add(
                i,
                StakeHistoryEntry {
                    activating: i,
                    ..StakeHistoryEntry::default()
                },
            );
        }
        assert_eq!(stake_history.len(), MAX_ENTRIES);
        assert_eq!(stake_history.iter().map(|entry| entry.0).min().unwrap(), 1);
        assert_eq!(stake_history.get(0), None);
        for epoch in 1..current_epoch {
            assert_eq!(
                stake_history.get(epoch),
                Some(&StakeHistoryEntry {
                    activating: epoch,
                    ..StakeHistoryEntry::default()
                })
            );
        }
        assert_eq!(stake_history.get(current_epoch), None);
    }

    #[test]
    fn test_id() {
        assert_eq!(
            StakeHistory::id(),
            solana_sdk_ids::sysvar::stake_history::id()
        );
    }
}
