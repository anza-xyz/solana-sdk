//! Vote state

#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{AbiExample, StableAbi, StableAbiSample};
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

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct Lockout {
    slot: Slot,
    /// Effectively bounded by `MAX_LOCKOUT_HISTORY`, the cap applied to it as the
    /// lockout exponent in [`Lockout::lockout`]; the ABI sample uses that range.
    #[cfg_attr(
        feature = "frozen-abi",
        stable_abi_sample(with = "sampling::sample_confirmation_count(rng)")
    )]
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

/// Sampling support for random lockout towers, shared by the `frozen-abi` ABI
/// samplers and the round-trip tests.
///
/// The compact (offset-encoded) wire format used on the wire requires strictly
/// increasing slots and a root at or below the first slot. Slots are sampled
/// starting at `LOCKOUT_SAMPLE_SLOT_BASE` and grow by up to
/// `LOCKOUT_SAMPLE_SLOT_STEP` per lockout; the (optional) root sits just below
/// the base, so the first delta-encoded offset is always non-negative.
#[cfg(any(feature = "frozen-abi", test))]
mod sampling {
    use {
        super::{Lockout, MAX_LOCKOUT_HISTORY},
        solana_clock::Slot,
        std::collections::VecDeque,
    };

    const LOCKOUT_SAMPLE_SLOT_BASE: Slot = 149_303_885;
    const LOCKOUT_SAMPLE_SLOT_STEP: Slot = 1_000;

    /// A `confirmation_count` capped to `MAX_LOCKOUT_HISTORY`, the range usable
    /// by the compact wire format (and the lockout exponent).
    pub(super) fn sample_confirmation_count<R: rand::Rng + ?Sized>(rng: &mut R) -> u32 {
        rng.random_range(0..=MAX_LOCKOUT_HISTORY as u32)
    }

    /// Build a tower with strictly increasing slots and in-range
    /// `confirmation_count`s, so the sample survives the compact codec.
    pub(super) fn sample_lockouts<R: rand::Rng + ?Sized>(rng: &mut R) -> VecDeque<Lockout> {
        let mut slot = LOCKOUT_SAMPLE_SLOT_BASE;
        (0..rng.random_range(0..=MAX_LOCKOUT_HISTORY))
            .map(|_| {
                slot = slot.saturating_add(rng.random_range(1..=LOCKOUT_SAMPLE_SLOT_STEP));
                Lockout::new_with_confirmation_count(slot, sample_confirmation_count(rng))
            })
            .collect()
    }

    /// An optional root just below the first sampled slot, keeping the first
    /// delta-encoded offset non-negative.
    pub(super) fn sample_root<R: rand::Rng + ?Sized>(rng: &mut R) -> Option<Slot> {
        rng.random_bool(0.5).then(|| {
            LOCKOUT_SAMPLE_SLOT_BASE.saturating_sub(rng.random_range(0..=LOCKOUT_SAMPLE_SLOT_STEP))
        })
    }
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
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

#[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct BlockTimestamp {
    pub slot: Slot,
    pub timestamp: UnixTimestamp,
}

// this is how many epochs a voter can be remembered for slashing
const MAX_ITEMS: usize = 32;

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
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

/// Shared compact wire-format representations for [`VoteStateUpdate`] and
/// [`TowerSync`]: lockout slots are stored as varint offsets from the previous
/// slot in a `short_vec`.
///
/// The [`serde_compact_vote_state_update`]/[`serde_tower_sync`] (serde) and
/// [`wincode_compact`] (wincode) modules bridge the original types to these
/// representations.
#[cfg(any(feature = "serde", feature = "wincode"))]
mod compact {
    #[cfg(feature = "serde")]
    use serde_derive::{Deserialize, Serialize};
    #[cfg(feature = "frozen-abi")]
    use solana_frozen_abi_macro::{AbiExample, StableAbi, StableAbiSample};
    use {
        super::{Lockout, TowerSync, VoteStateUpdate},
        solana_clock::{Slot, UnixTimestamp},
        solana_hash::Hash,
        std::collections::VecDeque,
    };
    #[cfg(feature = "wincode")]
    use {
        solana_short_vec::ShortU16,
        solana_wincode_varint::Leb128Int,
        wincode::{containers, SchemaRead, SchemaWrite},
    };

    #[cfg_attr(feature = "frozen-abi", derive(AbiExample, StableAbi, StableAbiSample))]
    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    #[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
    struct LockoutOffset {
        #[cfg_attr(feature = "serde", serde(with = "solana_serde_varint"))]
        #[cfg_attr(feature = "wincode", wincode(with = "Leb128Int<Slot>"))]
        offset: Slot,
        confirmation_count: u8,
    }

    /// `short_vec`-length-encoded `Vec<LockoutOffset>`, the wincode counterpart
    /// of `#[serde(with = "solana_short_vec")]`.
    #[cfg(feature = "wincode")]
    type LockoutOffsetShortVec = containers::Vec<LockoutOffset, ShortU16>;

    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    #[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
    pub(super) struct CompactVoteStateUpdate {
        root: Slot,
        #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
        #[cfg_attr(feature = "wincode", wincode(with = "LockoutOffsetShortVec"))]
        lockout_offsets: Vec<LockoutOffset>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
    }

    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    #[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
    pub(super) struct CompactTowerSync {
        root: Slot,
        #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
        #[cfg_attr(feature = "wincode", wincode(with = "LockoutOffsetShortVec"))]
        lockout_offsets: Vec<LockoutOffset>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
        block_id: Hash,
    }

    /// Convert a tower's absolute lockout slots into the relative, delta-encoded
    /// offsets used by the compact wire format.
    ///
    /// Shared by the serde and wincode encoders; the returned error message is
    /// mapped to each backend's error type by the caller.
    fn lockout_offsets(
        lockouts: &VecDeque<Lockout>,
        root: Option<Slot>,
    ) -> Result<Vec<LockoutOffset>, &'static str> {
        let mut offsets = Vec::with_capacity(lockouts.len());
        let mut slot = root.unwrap_or_default();
        for lockout in lockouts {
            let offset = lockout
                .slot()
                .checked_sub(slot)
                .ok_or("Invalid vote lockout")?;
            let confirmation_count = u8::try_from(lockout.confirmation_count())
                .map_err(|_| "Invalid confirmation count")?;
            offsets.push(LockoutOffset {
                offset,
                confirmation_count,
            });
            slot = lockout.slot();
        }
        Ok(offsets)
    }

    /// Reconstruct the absolute lockouts from the relative offsets stored in the
    /// compact wire format. Inverse of [`lockout_offsets`].
    fn lockouts_from_offsets(
        lockout_offsets: &[LockoutOffset],
        root: Option<Slot>,
    ) -> Result<VecDeque<Lockout>, &'static str> {
        let mut lockouts = VecDeque::with_capacity(lockout_offsets.len());
        let mut slot = root.unwrap_or_default();
        for lockout_offset in lockout_offsets {
            slot = slot
                .checked_add(lockout_offset.offset)
                .ok_or("Invalid lockout offset")?;
            lockouts.push_back(Lockout::new_with_confirmation_count(
                slot,
                u32::from(lockout_offset.confirmation_count),
            ));
        }
        Ok(lockouts)
    }

    pub(super) fn vote_state_update_to_compact(
        src: &VoteStateUpdate,
    ) -> Result<CompactVoteStateUpdate, &'static str> {
        #[allow(clippy::clone_on_copy)]
        Ok(CompactVoteStateUpdate {
            root: src.root.unwrap_or(Slot::MAX),
            lockout_offsets: lockout_offsets(&src.lockouts, src.root)?,
            hash: src.hash.clone(),
            timestamp: src.timestamp,
        })
    }

    pub(super) fn vote_state_update_from_compact(
        repr: CompactVoteStateUpdate,
    ) -> Result<VoteStateUpdate, &'static str> {
        let root = (repr.root != Slot::MAX).then_some(repr.root);
        Ok(VoteStateUpdate {
            lockouts: lockouts_from_offsets(&repr.lockout_offsets, root)?,
            root,
            hash: repr.hash,
            timestamp: repr.timestamp,
        })
    }

    pub(super) fn tower_sync_to_compact(src: &TowerSync) -> Result<CompactTowerSync, &'static str> {
        #[allow(clippy::clone_on_copy)]
        Ok(CompactTowerSync {
            root: src.root.unwrap_or(Slot::MAX),
            lockout_offsets: lockout_offsets(&src.lockouts, src.root)?,
            hash: src.hash.clone(),
            timestamp: src.timestamp,
            block_id: src.block_id.clone(),
        })
    }

    pub(super) fn tower_sync_from_compact(
        repr: CompactTowerSync,
    ) -> Result<TowerSync, &'static str> {
        let root = (repr.root != Slot::MAX).then_some(repr.root);
        Ok(TowerSync {
            lockouts: lockouts_from_offsets(&repr.lockout_offsets, root)?,
            root,
            hash: repr.hash,
            timestamp: repr.timestamp,
            block_id: repr.block_id,
        })
    }
}

#[cfg(feature = "serde")]
pub mod serde_compact_vote_state_update {
    use {
        super::{compact, compact::CompactVoteStateUpdate, *},
        serde::{Deserialize, Deserializer, Serialize, Serializer},
    };

    pub fn serialize<S>(
        vote_state_update: &VoteStateUpdate,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        compact::vote_state_update_to_compact(vote_state_update)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VoteStateUpdate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CompactVoteStateUpdate::deserialize(deserializer)?;
        compact::vote_state_update_from_compact(repr).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
pub mod serde_tower_sync {
    use {
        super::{compact, compact::CompactTowerSync, *},
        serde::{Deserialize, Deserializer, Serialize, Serializer},
    };

    pub fn serialize<S>(tower_sync: &TowerSync, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        compact::tower_sync_to_compact(tower_sync)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TowerSync, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CompactTowerSync::deserialize(deserializer)?;
        compact::tower_sync_from_compact(repr).map_err(serde::de::Error::custom)
    }
}

/// Wincode schemas for the compact wire encodings of [`VoteStateUpdate`] and
/// [`TowerSync`].
///
/// These are the wincode analog of [`serde_compact_vote_state_update`] /
/// [`serde_tower_sync`]: the types' own (derived) wincode schemas encode the
/// non-compact form, so the compact form is selected per-field via
/// `#[wincode(with = ...)]` on [`crate::instruction::VoteInstruction`]. Each
/// schema is a thin marker that converts to/from the shared `compact`
/// representation (whose derived schema does the actual encoding) and produces
/// bytes identical to bincode.
#[cfg(feature = "wincode")]
pub mod wincode_compact {
    use {
        super::{
            compact,
            compact::{
                CompactTowerSync as CompactTowerSyncRepr,
                CompactVoteStateUpdate as CompactVoteStateUpdateRepr,
            },
            TowerSync, VoteStateUpdate,
        },
        std::mem::MaybeUninit,
        wincode::{
            config::Config,
            io::{Reader, Writer},
            ReadError, ReadResult, SchemaRead, SchemaWrite, WriteError, WriteResult,
        },
    };

    /// Wincode schema mirroring [`super::serde_compact_vote_state_update`].
    pub struct CompactVoteStateUpdate;

    unsafe impl<C: Config> SchemaWrite<C> for CompactVoteStateUpdate {
        type Src = VoteStateUpdate;

        fn size_of(src: &Self::Src) -> WriteResult<usize> {
            let repr = compact::vote_state_update_to_compact(src).map_err(WriteError::Custom)?;
            <CompactVoteStateUpdateRepr as SchemaWrite<C>>::size_of(&repr)
        }

        fn write(writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
            let repr = compact::vote_state_update_to_compact(src).map_err(WriteError::Custom)?;
            <CompactVoteStateUpdateRepr as SchemaWrite<C>>::write(writer, &repr)
        }
    }

    unsafe impl<'de, C: Config> SchemaRead<'de, C> for CompactVoteStateUpdate {
        type Dst = VoteStateUpdate;

        fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
            let repr = <CompactVoteStateUpdateRepr as SchemaRead<C>>::get(reader)?;
            dst.write(compact::vote_state_update_from_compact(repr).map_err(ReadError::Custom)?);
            Ok(())
        }
    }

    /// Wincode schema mirroring [`super::serde_tower_sync`].
    pub struct CompactTowerSync;

    unsafe impl<C: Config> SchemaWrite<C> for CompactTowerSync {
        type Src = TowerSync;

        fn size_of(src: &Self::Src) -> WriteResult<usize> {
            let repr = compact::tower_sync_to_compact(src).map_err(WriteError::Custom)?;
            <CompactTowerSyncRepr as SchemaWrite<C>>::size_of(&repr)
        }

        fn write(writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
            let repr = compact::tower_sync_to_compact(src).map_err(WriteError::Custom)?;
            <CompactTowerSyncRepr as SchemaWrite<C>>::write(writer, &repr)
        }
    }

    unsafe impl<'de, C: Config> SchemaRead<'de, C> for CompactTowerSync {
        type Dst = TowerSync;

        fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
            let repr = <CompactTowerSyncRepr as SchemaRead<C>>::get(reader)?;
            dst.write(compact::tower_sync_from_compact(repr).map_err(ReadError::Custom)?);
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use {super::*, rand::Rng, solana_hash::Hash};

    /// Build a random `VoteStateUpdate` with strictly increasing lockout slots
    /// and an optional root below the first slot, suitable for exercising the
    /// compact (offset-encoded) wire formats.
    fn random_vote_state_update<R: Rng>(rng: &mut R) -> VoteStateUpdate {
        VoteStateUpdate {
            lockouts: sampling::sample_lockouts(rng),
            root: sampling::sample_root(rng),
            hash: Hash::from(rng.random::<[u8; 32]>()),
            timestamp: rng.random_bool(0.5).then(|| rng.random()),
        }
    }

    #[test]
    fn test_serde_compact_vote_state_update() {
        let mut rng = rand::rng();
        for _ in 0..5000 {
            run_serde_compact_vote_state_update(&mut rng);
        }
    }

    fn run_serde_compact_vote_state_update<R: Rng>(rng: &mut R) {
        let vote_state_update = random_vote_state_update(rng);
        #[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
        #[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
        enum VoteInstruction {
            #[serde(with = "serde_compact_vote_state_update")]
            UpdateVoteState(
                #[cfg_attr(
                    feature = "wincode",
                    wincode(with = "wincode_compact::CompactVoteStateUpdate")
                )]
                VoteStateUpdate,
            ),
            UpdateVoteStateSwitch(
                #[serde(with = "serde_compact_vote_state_update")]
                #[cfg_attr(
                    feature = "wincode",
                    wincode(with = "wincode_compact::CompactVoteStateUpdate")
                )]
                VoteStateUpdate,
                Hash,
            ),
        }

        // bincode is the reference encoding; when wincode is enabled, assert it
        // produces identical bytes and round-trips the same value.
        let check = |vote: &VoteInstruction| {
            let bytes = bincode::serialize(vote).unwrap();
            assert_eq!(*vote, bincode::deserialize(&bytes).unwrap());
            #[cfg(feature = "wincode")]
            {
                assert_eq!(bytes, wincode::serialize(vote).unwrap());
                assert_eq!(*vote, wincode::deserialize(&bytes).unwrap());
            }
        };

        check(&VoteInstruction::UpdateVoteState(vote_state_update.clone()));
        let hash = Hash::from(rng.random::<[u8; 32]>());
        check(&VoteInstruction::UpdateVoteStateSwitch(
            vote_state_update,
            hash,
        ));
    }

    #[test]
    fn test_circbuf_oob() {
        // Craft an invalid CircBuf with out-of-bounds index
        let data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        let circ_buf: CircBuf<()> = bincode::deserialize(data).unwrap();
        assert_eq!(circ_buf.last(), None);

        #[cfg(feature = "wincode")]
        {
            let circ_buf: CircBuf<()> = wincode::deserialize(data).unwrap();
            assert_eq!(circ_buf.last(), None);
        }
    }
}
