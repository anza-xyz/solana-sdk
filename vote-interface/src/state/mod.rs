//! Vote state

#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{AbiExample, StableAbi, StableAbiSample};
use {
    crate::authorized_voters::AuthorizedVoters,
    solana_clock::{Epoch, Slot, UnixTimestamp},
    solana_pubkey::Pubkey,
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
#[cfg(any(target_os = "solana", feature = "bincode", feature = "wincode"))]
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

#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct Lockout {
    slot: Slot,
    /// Effectively bounded by `MAX_LOCKOUT_HISTORY`, the cap applied to it as the
    /// lockout exponent in [`Lockout::lockout`]; the ABI sample uses that range.
    #[cfg_attr(
        feature = "stable-abi",
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

/// Sampling support for the `frozen-abi` ABI samplers.
#[cfg(feature = "stable-abi")]
mod sampling {
    use super::MAX_LOCKOUT_HISTORY;

    /// A `confirmation_count` capped to `MAX_LOCKOUT_HISTORY`, the range usable
    /// by the lockout exponent.
    pub(super) fn sample_confirmation_count<R: rand::Rng + ?Sized>(rng: &mut R) -> u32 {
        rng.random_range(0..=MAX_LOCKOUT_HISTORY as u32)
    }
}

#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
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

#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
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
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
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

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use super::*;

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
