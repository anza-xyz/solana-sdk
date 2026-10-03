//! A type to hold data for the [`SlotHashes` sysvar][sv].
//!
//! [sv]: https://docs.solanalabs.com/runtime/sysvars#slothashes
//!
//! The sysvar ID is declared in [`solana_program::sysvar::slot_hashes`].
//!
//! [`solana_program::sysvar::slot_hashes`]: https://docs.rs/solana-program/latest/solana_program/sysvar/slot_hashes/index.html
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "sysvar")]
pub mod sysvar;

use {
    solana_hash::Hash,
    std::{
        iter::FromIterator,
        ops::Deref,
        sync::atomic::{AtomicUsize, Ordering},
    },
};

pub const MAX_ENTRIES: usize = 512; // about 2.5 minutes to get your vote in

// This is to allow tests with custom slot hash expiry to avoid having to generate
// 512 blocks for such tests.
static NUM_ENTRIES: AtomicUsize = AtomicUsize::new(MAX_ENTRIES);

pub fn get_entries() -> usize {
    NUM_ENTRIES.load(Ordering::Relaxed)
}

pub fn set_entries_for_tests_only(entries: usize) {
    NUM_ENTRIES.store(entries, Ordering::Relaxed);
}

const LEN_PREFIX: usize = size_of::<u64>();
const SLOT_HASH_SERIALIZED_SIZE: usize = size_of::<u64>() + size_of::<Hash>();

/// Serialized size of the `SlotHashes` sysvar account.
pub const SIZE: usize = LEN_PREFIX + MAX_ENTRIES * SLOT_HASH_SERIALIZED_SIZE;
const _: () = assert!(SIZE == 20_488);

/// A single entry of the [`SlotHashes`] sysvar.
///
/// `#[repr(C)]` and padding-free so wincode decodes the whole sysvar in one copy.
#[repr(C)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
// Big-endian targets encode integers byte-swapped, so they never qualify as zero-copy.
#[cfg_attr(
    all(feature = "wincode", target_endian = "little"),
    wincode(assert_zero_copy)
)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct SlotHash {
    pub slot: u64,
    pub hash: Hash,
}

// Unlike `assert_zero_copy`, this also holds on big-endian targets.
const _: () = assert!(size_of::<SlotHash>() == SLOT_HASH_SERIALIZED_SIZE);

impl SlotHash {
    pub const fn new(slot: u64, hash: Hash) -> Self {
        Self { slot, hash }
    }
}

impl From<(u64, Hash)> for SlotHash {
    fn from((slot, hash): (u64, Hash)) -> Self {
        Self { slot, hash }
    }
}

impl From<SlotHash> for (u64, Hash) {
    fn from(SlotHash { slot, hash }: SlotHash) -> Self {
        (slot, hash)
    }
}

#[repr(C)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(PartialEq, Eq, Debug, Default)]
pub struct SlotHashes(Vec<SlotHash>);

impl SlotHashes {
    pub fn add(&mut self, slot: u64, hash: Hash) {
        let entry = SlotHash { slot, hash };
        match self.binary_search_by(|probe| slot.cmp(&probe.slot)) {
            Ok(index) => (self.0)[index] = entry,
            Err(index) => (self.0).insert(index, entry),
        }
        (self.0).truncate(get_entries());
    }
    pub fn position(&self, slot: &u64) -> Option<usize> {
        self.binary_search_by(|probe| slot.cmp(&probe.slot)).ok()
    }
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn get(&self, slot: &u64) -> Option<&Hash> {
        self.binary_search_by(|probe| slot.cmp(&probe.slot))
            .ok()
            .map(|index| &self[index].hash)
    }
    pub fn new(slot_hashes: &[SlotHash]) -> Self {
        slot_hashes.iter().cloned().collect()
    }
    pub fn slot_hashes(&self) -> &[SlotHash] {
        &self.0
    }
}

impl FromIterator<SlotHash> for SlotHashes {
    fn from_iter<I: IntoIterator<Item = SlotHash>>(iter: I) -> Self {
        let mut slot_hashes: Vec<_> = iter.into_iter().collect();
        slot_hashes.sort_by_key(|entry| std::cmp::Reverse(entry.slot));
        Self(slot_hashes)
    }
}

impl FromIterator<(u64, Hash)> for SlotHashes {
    fn from_iter<I: IntoIterator<Item = (u64, Hash)>>(iter: I) -> Self {
        iter.into_iter().map(SlotHash::from).collect()
    }
}

impl Deref for SlotHashes {
    type Target = Vec<SlotHash>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_sha256_hasher::hash};

    fn entry(slot: u64) -> SlotHash {
        SlotHash::new(slot, hash(&slot.to_le_bytes()))
    }

    #[test]
    fn test_size_of() {
        let slot_hashes = SlotHashes(vec![SlotHash::default(); MAX_ENTRIES]);
        assert_eq!(
            wincode::serialized_size(&slot_hashes).unwrap() as usize,
            SIZE,
        );
    }

    #[test]
    fn test() {
        let mut slot_hashes = SlotHashes::new(&[entry(1), entry(3)]);
        slot_hashes.add(2, hash(&2u64.to_le_bytes()));
        assert_eq!(slot_hashes, SlotHashes(vec![entry(3), entry(2), entry(1)]));

        let mut slot_hashes = SlotHashes::new(&[]);
        for i in 0..MAX_ENTRIES + 1 {
            slot_hashes.add(
                i as u64,
                hash(&[(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8]),
            );
        }
        for i in 0..MAX_ENTRIES {
            assert_eq!(slot_hashes[i].slot, (MAX_ENTRIES - i) as u64);
        }

        assert_eq!(slot_hashes.len(), MAX_ENTRIES);
    }

    #[test]
    fn test_from_iter() {
        let cases: &[(&[u64], &[u64])] = &[
            (&[], &[]),
            (&[1], &[1]),
            (&[1, 2, 3], &[3, 2, 1]),
            (&[3, 2, 1], &[3, 2, 1]),
            (&[2, 0, u64::MAX, 1], &[u64::MAX, 2, 1, 0]),
        ];
        for &(slots, sorted_slots) in cases {
            let entries: Vec<_> = slots.iter().copied().map(entry).collect();
            let expected: Vec<_> = sorted_slots.iter().copied().map(entry).collect();
            let from_entries: SlotHashes = entries.iter().cloned().collect();
            let from_tuples: SlotHashes = entries
                .into_iter()
                .map(|entry| (entry.slot, entry.hash))
                .collect();
            for slot_hashes in [from_entries, from_tuples] {
                for (index, entry) in expected.iter().enumerate() {
                    assert_eq!(slot_hashes.get(&entry.slot), Some(&entry.hash));
                    assert_eq!(slot_hashes.position(&entry.slot), Some(index));
                }
                assert_eq!(slot_hashes.slot_hashes(), expected);
                assert_eq!(slot_hashes.position(&4), None);
                assert_eq!(slot_hashes.get(&4), None);
            }
        }
    }

    #[test]
    fn test_from_iter_duplicate_slots() {
        let first = SlotHash::new(2, Hash::new_from_array([1; 32]));
        let second = SlotHash::new(2, Hash::new_from_array([2; 32]));
        let entries = [first.clone(), entry(1), second.clone(), entry(3)];
        let expected = [entry(3), first, second, entry(1)];
        let from_entries: SlotHashes = entries.iter().cloned().collect();
        let from_tuples: SlotHashes = entries
            .into_iter()
            .map(|entry| (entry.slot, entry.hash))
            .collect();
        for slot_hashes in [from_entries, from_tuples] {
            assert_eq!(slot_hashes.slot_hashes(), expected);
        }
    }

    #[test]
    fn test_from_iter_preserves_all_entries() {
        let entries: Vec<_> = (0..=MAX_ENTRIES as u64).map(entry).collect();
        let from_entries: SlotHashes = entries.iter().cloned().collect();
        let from_tuples: SlotHashes = entries
            .into_iter()
            .map(|entry| (entry.slot, entry.hash))
            .collect();
        for slot_hashes in [from_entries, from_tuples] {
            assert_eq!(slot_hashes.len(), MAX_ENTRIES + 1);
            assert_eq!(slot_hashes.first(), Some(&entry(MAX_ENTRIES as u64)));
            assert_eq!(slot_hashes.last(), Some(&entry(0)));
            assert_eq!(slot_hashes.get(&0), Some(&entry(0).hash));
        }
    }

    #[test]
    fn test_add_after_from_iter() {
        let entries = [entry(2), entry(0), entry(4)];
        let from_entries: SlotHashes = entries.iter().cloned().collect();
        let from_tuples: SlotHashes = entries
            .into_iter()
            .map(|entry| (entry.slot, entry.hash))
            .collect();
        for mut slot_hashes in [from_entries, from_tuples] {
            slot_hashes.add(3, entry(3).hash);
            assert_eq!(
                slot_hashes.slot_hashes(),
                [entry(4), entry(3), entry(2), entry(0)]
            );

            let replacement = SlotHash::new(2, Hash::new_from_array([3; 32]));
            slot_hashes.add(replacement.slot, replacement.clone().hash);
            assert_eq!(
                slot_hashes.slot_hashes(),
                [entry(4), entry(3), replacement, entry(0)]
            );
        }
    }

    /// Deployed accounts fix the layout to a length prefix followed by packed
    /// slot/hash pairs. Checked against the equivalent tuple encoding.
    #[test]
    fn test_wire_compat() {
        let entries: Vec<SlotHash> = (0..MAX_ENTRIES as u64).rev().map(entry).collect();
        let tuples: Vec<(u64, Hash)> = entries.iter().cloned().map(Into::into).collect();
        let slot_hashes = SlotHashes::new(&entries);

        let expected = wincode::serialize(&tuples).unwrap();
        assert_eq!(expected.len(), SIZE);
        assert_eq!(wincode::serialize(&slot_hashes).unwrap(), expected);
        assert_eq!(
            wincode::deserialize::<SlotHashes>(&expected).unwrap(),
            slot_hashes
        );
    }
}
