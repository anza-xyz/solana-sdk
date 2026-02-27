//! Vote state

#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
use {
    crate::authorized_voters::AuthorizedVoters,
    solana_clock::{Epoch, Slot, UnixTimestamp},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    std::{collections::VecDeque, fmt::Debug},
};

pub mod vote_state_1_14_11;
pub use vote_state_1_14_11::*;
pub mod vote_state_versions;
pub use vote_state_versions::*;
pub mod vote_state_v3;
pub use vote_state_v3::VoteStateV3;
pub mod vote_state_v4;
pub use vote_state_v4::VoteStateV4;
mod vote_instruction_data;
pub use vote_instruction_data::*;
#[cfg(any(target_os = "solana", feature = "bincode"))]
pub(crate) mod vote_state_deserialize;

/// Size of a BLS public key in a compressed point representation
pub const BLS_PUBLIC_KEY_COMPRESSED_SIZE: usize = 48;

/// Size of a BLS proof of possession in a compressed point representation; matches BLS signature size
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE: usize = 96;

// Maximum number of votes to keep around, tightly coupled with epoch_schedule::MINIMUM_SLOTS_PER_EPOCH
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const INITIAL_LOCKOUT: usize = 2;

// Maximum number of credits history to keep around
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// Offset of VoteState::prior_voters, for determining initialization status without deserialization
const DEFAULT_PRIOR_VOTERS_OFFSET: usize = 114;

// Number of slots of grace period for which maximum vote credits are awarded - votes landing within this number of slots of the slot that is being voted on are awarded full credits.
pub const VOTE_CREDITS_GRACE_SLOTS: u8 = 2;

// Maximum number of credits to award for a vote; this number of credits is awarded to votes on slots that land within the grace period. After that grace period, vote credits are reduced.
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u8 = 16;

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct Lockout {
    slot: Slot,
    confirmation_count: u32,
}

impl Lockout {
    pub fn new(slot: Slot) -> Self {
        Self::new_with_confirmation_count(slot, 1)
    }

    pub fn new_with_confirmation_count(slot: Slot, confirmation_count: u32) -> Self {
        Self {
            slot,
            confirmation_count,
        }
    }

    // The number of slots for which this vote is locked
    pub fn lockout(&self) -> u64 {
        (INITIAL_LOCKOUT as u64).wrapping_pow(std::cmp::min(
            self.confirmation_count(),
            MAX_LOCKOUT_HISTORY as u32,
        ))
    }

    // The last slot at which a vote is still locked out. Validators should not
    // vote on a slot in another fork which is less than or equal to this slot
    // to avoid having their stake slashed.
    pub fn last_locked_out_slot(&self) -> Slot {
        self.slot.saturating_add(self.lockout())
    }

    pub fn is_locked_out_at_slot(&self, slot: Slot) -> bool {
        self.last_locked_out_slot() >= slot
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn confirmation_count(&self) -> u32 {
        self.confirmation_count
    }

    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by)
    }
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct LandedVote {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    pub latency: u8,
    pub lockout: Lockout,
}

impl LandedVote {
    pub fn slot(&self) -> Slot {
        self.lockout.slot
    }

    pub fn confirmation_count(&self) -> u32 {
        self.lockout.confirmation_count
    }
}

impl From<LandedVote> for Lockout {
    fn from(landed_vote: LandedVote) -> Self {
        landed_vote.lockout
    }
}

impl From<Lockout> for LandedVote {
    fn from(lockout: Lockout) -> Self {
        Self {
            latency: 0,
            lockout,
        }
    }
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct BlockTimestamp {
    pub slot: Slot,
    pub timestamp: UnixTimestamp,
}

// this is how many epochs a voter can be remembered for slashing
const MAX_ITEMS: usize = 32;

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct CircBuf<I> {
    buf: [I; MAX_ITEMS],
    /// next pointer
    idx: usize,
    is_empty: bool,
}

impl<I: Default + Copy> Default for CircBuf<I> {
    fn default() -> Self {
        Self {
            buf: [I::default(); MAX_ITEMS],
            idx: MAX_ITEMS
                .checked_sub(1)
                .expect("`MAX_ITEMS` should be positive"),
            is_empty: true,
        }
    }
}

impl<I> CircBuf<I> {
    pub fn append(&mut self, item: I) {
        // remember prior delegate and when we switched, to support later slashing
        self.idx = self
            .idx
            .checked_add(1)
            .and_then(|idx| idx.checked_rem(MAX_ITEMS))
            .expect("`self.idx` should be < `MAX_ITEMS` which should be non-zero");

        self.buf[self.idx] = item;
        self.is_empty = false;
    }

    pub fn buf(&self) -> &[I; MAX_ITEMS] {
        &self.buf
    }

    pub fn last(&self) -> Option<&I> {
        if !self.is_empty {
            self.buf.get(self.idx)
        } else {
            None
        }
    }
}

#[cfg(feature = "serde")]
pub mod serde_compact_vote_state_update {
    use {
        super::*,
        crate::state::Lockout,
        serde::{Deserialize, Deserializer, Serialize, Serializer},
        solana_hash::Hash,
        solana_serde_varint as serde_varint, solana_short_vec as short_vec,
    };

    #[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
    #[derive(serde_derive::Deserialize, serde_derive::Serialize)]
    struct LockoutOffset {
        #[serde(with = "serde_varint")]
        offset: Slot,
        confirmation_count: u8,
    }

    #[derive(serde_derive::Deserialize, serde_derive::Serialize)]
    struct CompactVoteStateUpdate {
        root: Slot,
        #[serde(with = "short_vec")]
        lockout_offsets: Vec<LockoutOffset>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
    }

    pub fn serialize<S>(
        vote_state_update: &VoteStateUpdate,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let lockout_offsets = vote_state_update.lockouts.iter().scan(
            vote_state_update.root.unwrap_or_default(),
            |slot, lockout| {
                let Some(offset) = lockout.slot().checked_sub(*slot) else {
                    return Some(Err(serde::ser::Error::custom("Invalid vote lockout")));
                };
                let Ok(confirmation_count) = u8::try_from(lockout.confirmation_count()) else {
                    return Some(Err(serde::ser::Error::custom("Invalid confirmation count")));
                };
                let lockout_offset = LockoutOffset {
                    offset,
                    confirmation_count,
                };
                *slot = lockout.slot();
                Some(Ok(lockout_offset))
            },
        );
        let compact_vote_state_update = CompactVoteStateUpdate {
            root: vote_state_update.root.unwrap_or(Slot::MAX),
            lockout_offsets: lockout_offsets.collect::<Result<_, _>>()?,
            hash: Hash::new_from_array(vote_state_update.hash.to_bytes()),
            timestamp: vote_state_update.timestamp,
        };
        compact_vote_state_update.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VoteStateUpdate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CompactVoteStateUpdate {
            root,
            lockout_offsets,
            hash,
            timestamp,
        } = CompactVoteStateUpdate::deserialize(deserializer)?;
        let root = (root != Slot::MAX).then_some(root);
        let lockouts =
            lockout_offsets
                .iter()
                .scan(root.unwrap_or_default(), |slot, lockout_offset| {
                    *slot = match slot.checked_add(lockout_offset.offset) {
                        None => {
                            return Some(Err(serde::de::Error::custom("Invalid lockout offset")))
                        }
                        Some(slot) => slot,
                    };
                    let lockout = Lockout::new_with_confirmation_count(
                        *slot,
                        u32::from(lockout_offset.confirmation_count),
                    );
                    Some(Ok(lockout))
                });
        Ok(VoteStateUpdate {
            root,
            lockouts: lockouts.collect::<Result<_, _>>()?,
            hash,
            timestamp,
        })
    }
}

#[cfg(feature = "serde")]
pub mod serde_tower_sync {
    use {
        super::*,
        crate::state::Lockout,
        serde::{Deserialize, Deserializer, Serialize, Serializer},
        solana_hash::Hash,
        solana_serde_varint as serde_varint, solana_short_vec as short_vec,
    };

    #[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
    #[derive(serde_derive::Deserialize, serde_derive::Serialize)]
    struct LockoutOffset {
        #[serde(with = "serde_varint")]
        offset: Slot,
        confirmation_count: u8,
    }

    #[derive(serde_derive::Deserialize, serde_derive::Serialize)]
    struct CompactTowerSync {
        root: Slot,
        #[serde(with = "short_vec")]
        lockout_offsets: Vec<LockoutOffset>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
        block_id: Hash,
    }

    pub fn serialize<S>(tower_sync: &TowerSync, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let lockout_offsets = tower_sync.lockouts.iter().scan(
            tower_sync.root.unwrap_or_default(),
            |slot, lockout| {
                let Some(offset) = lockout.slot().checked_sub(*slot) else {
                    return Some(Err(serde::ser::Error::custom("Invalid vote lockout")));
                };
                let Ok(confirmation_count) = u8::try_from(lockout.confirmation_count()) else {
                    return Some(Err(serde::ser::Error::custom("Invalid confirmation count")));
                };
                let lockout_offset = LockoutOffset {
                    offset,
                    confirmation_count,
                };
                *slot = lockout.slot();
                Some(Ok(lockout_offset))
            },
        );
        let compact_tower_sync = CompactTowerSync {
            root: tower_sync.root.unwrap_or(Slot::MAX),
            lockout_offsets: lockout_offsets.collect::<Result<_, _>>()?,
            hash: Hash::new_from_array(tower_sync.hash.to_bytes()),
            timestamp: tower_sync.timestamp,
            block_id: Hash::new_from_array(tower_sync.block_id.to_bytes()),
        };
        compact_tower_sync.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TowerSync, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CompactTowerSync {
            root,
            lockout_offsets,
            hash,
            timestamp,
            block_id,
        } = CompactTowerSync::deserialize(deserializer)?;
        let root = (root != Slot::MAX).then_some(root);
        let lockouts =
            lockout_offsets
                .iter()
                .scan(root.unwrap_or_default(), |slot, lockout_offset| {
                    *slot = match slot.checked_add(lockout_offset.offset) {
                        None => {
                            return Some(Err(serde::de::Error::custom("Invalid lockout offset")))
                        }
                        Some(slot) => slot,
                    };
                    let lockout = Lockout::new_with_confirmation_count(
                        *slot,
                        u32::from(lockout_offset.confirmation_count),
                    );
                    Some(Ok(lockout))
                });
        Ok(TowerSync {
            root,
            lockouts: lockouts.collect::<Result<_, _>>()?,
            hash,
            timestamp,
            block_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use {super::*, itertools::Itertools, rand::Rng, solana_clock::Clock, solana_hash::Hash};

    #[test]
    fn test_default_vote_state_is_uninitialized() {
        // The default `VoteStateV3` is stored to de-initialize a zero-balance vote account,
        // so must remain such that `VoteStateVersions::is_uninitialized()` returns true
        // when called on a `VoteStateVersions` that stores it
        assert!(VoteStateVersions::new_v3(VoteStateV3::default()).is_uninitialized());
    }

    #[test]
    fn test_is_correct_size_and_initialized() {
        // Check all zeroes
        let mut vote_account_data = vec![0; VoteStateV3::size_of()];
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check default VoteStateV3
        let default_account_state = VoteStateVersions::new_v3(VoteStateV3::default());
        VoteStateV3::serialize(&default_account_state, &mut vote_account_data).unwrap();
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check non-zero data shorter than offset index used
        let short_data = vec![1; DEFAULT_PRIOR_VOTERS_OFFSET];
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &short_data
        ));

        // Check non-zero large account
        let mut large_vote_data = vec![1; 2 * VoteStateV3::size_of()];
        let default_account_state = VoteStateVersions::new_v3(VoteStateV3::default());
        VoteStateV3::serialize(&default_account_state, &mut large_vote_data).unwrap();
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check populated VoteStateV3
        let vote_state = VoteStateV3::new(
            &VoteInit {
                node_pubkey: Pubkey::new_unique(),
                authorized_voter: Pubkey::new_unique(),
                authorized_withdrawer: Pubkey::new_unique(),
                commission: 0,
            },
            &Clock::default(),
        );
        let account_state = VoteStateVersions::new_v3(vote_state.clone());
        VoteStateV3::serialize(&account_state, &mut vote_account_data).unwrap();
        assert!(VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check old VoteStateV3 that hasn't been upgraded to newest version yet
        let old_vote_state = VoteState1_14_11::from(vote_state);
        let account_state = VoteStateVersions::V1_14_11(Box::new(old_vote_state));
        let mut vote_account_data = vec![0; VoteState1_14_11::size_of()];
        VoteStateV3::serialize(&account_state, &mut vote_account_data).unwrap();
        assert!(VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));
    }

    #[test]
    fn test_serde_compact_vote_state_update() {
        let mut rng = rand::rng();
        for _ in 0..5000 {
            run_serde_compact_vote_state_update(&mut rng);
        }
    }

    fn run_serde_compact_vote_state_update<R: Rng>(rng: &mut R) {
        let lockouts: VecDeque<_> = std::iter::repeat_with(|| {
            let slot = 149_303_885_u64.saturating_add(rng.random_range(0..10_000));
            let confirmation_count = rng.random_range(0..33);
            Lockout::new_with_confirmation_count(slot, confirmation_count)
        })
        .take(32)
        .sorted_by_key(|lockout| lockout.slot())
        .collect();
        let root = rng.random_bool(0.5).then(|| {
            lockouts[0]
                .slot()
                .checked_sub(rng.random_range(0..1_000))
                .expect("All slots should be greater than 1_000")
        });
        let timestamp = rng.random_bool(0.5).then(|| rng.random());
        let hash = Hash::from(rng.random::<[u8; 32]>());
        let vote_state_update = VoteStateUpdate {
            lockouts,
            root,
            hash,
            timestamp,
        };
        #[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
        enum VoteInstruction {
            #[serde(with = "serde_compact_vote_state_update")]
            UpdateVoteState(VoteStateUpdate),
            UpdateVoteStateSwitch(
                #[serde(with = "serde_compact_vote_state_update")] VoteStateUpdate,
                Hash,
            ),
        }
        let vote = VoteInstruction::UpdateVoteState(vote_state_update.clone());
        let bytes = bincode::serialize(&vote).unwrap();
        assert_eq!(vote, bincode::deserialize(&bytes).unwrap());
        let hash = Hash::from(rng.random::<[u8; 32]>());
        let vote = VoteInstruction::UpdateVoteStateSwitch(vote_state_update, hash);
        let bytes = bincode::serialize(&vote).unwrap();
        assert_eq!(vote, bincode::deserialize(&bytes).unwrap());
    }

    #[test]
    fn test_circbuf_oob() {
        // Craft an invalid CircBuf with out-of-bounds index
        let data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        let circ_buf: CircBuf<()> = bincode::deserialize(data).unwrap();
        assert_eq!(circ_buf.last(), None);
    }

    #[test]
    fn test_vote_state_version_conversion_bls_pubkey() {
        let vote_pubkey = Pubkey::new_unique();

        // All versions before v4 should result in `None` for BLS pubkey.
        let v1_14_11_state = VoteState1_14_11::default();
        let v1_14_11_versioned = VoteStateVersions::V1_14_11(Box::new(v1_14_11_state));

        let v3_state = VoteStateV3::default();
        let v3_versioned = VoteStateVersions::V3(Box::new(v3_state));

        for versioned in [v1_14_11_versioned, v3_versioned] {
            let converted = versioned.try_convert_to_v4(&vote_pubkey).unwrap();
            assert_eq!(converted.bls_pubkey_compressed, None);
        }

        // v4 to v4 conversion should preserve the BLS pubkey.
        let test_bls_key = [128u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE];
        let v4_state = VoteStateV4 {
            bls_pubkey_compressed: Some(test_bls_key),
            ..VoteStateV4::default()
        };
        let v4_versioned = VoteStateVersions::V4(Box::new(v4_state));
        let converted = v4_versioned.try_convert_to_v4(&vote_pubkey).unwrap();
        assert_eq!(converted.bls_pubkey_compressed, Some(test_bls_key));
    }
}
