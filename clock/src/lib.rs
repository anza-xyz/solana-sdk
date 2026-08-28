//! Information about the network's clock, ticks, slots, etc.
//!
//! Time in Solana is marked primarily by _slots_, which are numbered sequentially.
//! For every slot, a leader is chosen from the validator set, and that leader is
//! expected to produce a new block, though sometimes leaders may fail to do so.
//! Blocks can be identified by their slot number, and some slots do not contain a
//! block.
//!
//! An approximation of the passage of real-world time can be calculated by
//! multiplying a number of slots by [`DEFAULT_MS_PER_SLOT`], which is the SDK's
//! default target time for the network to produce slots. Note though that this
//! method suffers a variable amount of drift, as the network does not produce
//! slots at exactly the target rate. Furthermore, the effective target is changed
//! dynamically by [SIMD-0525], so clients that require the cluster's current value
//! must not assume the SDK default reflects the cluster.
//!
//! The network's current view of the real-world time can always be accessed via
//! [`Clock::unix_timestamp`], which is produced by an [oracle derived from the
//! validator set][oracle].
//!
//! [oracle]: https://docs.solanalabs.com/implemented-proposals/validator-timestamp-oracle
//! [SIMD-0525]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0525-reduce-slot-times.md
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "sysvar")]
pub mod sysvar;

#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
use solana_sdk_macro::CloneZeroed;

/// The number of ticks in a slot.
pub const DEFAULT_TICKS_PER_SLOT: u64 = 64;

pub const DEFAULT_NS_PER_SLOT_400_MS: u64 = 400_000_000;
pub const DEFAULT_NS_PER_SLOT_350_MS: u64 = 350_000_000;
pub const DEFAULT_NS_PER_SLOT_300_MS: u64 = 300_000_000;
pub const DEFAULT_NS_PER_SLOT_250_MS: u64 = 250_000_000;
pub const DEFAULT_NS_PER_SLOT_200_MS: u64 = 200_000_000;

/// The SDK's default expected duration of a slot, in nanoseconds.
pub const DEFAULT_NS_PER_SLOT: u64 = DEFAULT_NS_PER_SLOT_300_MS;

pub const DEFAULT_NS_PER_TICK_400_MS: u64 = DEFAULT_NS_PER_SLOT_400_MS / DEFAULT_TICKS_PER_SLOT;
pub const DEFAULT_NS_PER_TICK_350_MS: u64 = DEFAULT_NS_PER_SLOT_350_MS / DEFAULT_TICKS_PER_SLOT;
pub const DEFAULT_NS_PER_TICK_300_MS: u64 = DEFAULT_NS_PER_SLOT_300_MS / DEFAULT_TICKS_PER_SLOT;
pub const DEFAULT_NS_PER_TICK_250_MS: u64 = DEFAULT_NS_PER_SLOT_250_MS / DEFAULT_TICKS_PER_SLOT;
pub const DEFAULT_NS_PER_TICK_200_MS: u64 = DEFAULT_NS_PER_SLOT_200_MS / DEFAULT_TICKS_PER_SLOT;

/// The default duration of a tick, in nanoseconds.
pub const DEFAULT_NS_PER_TICK: u64 = DEFAULT_NS_PER_TICK_300_MS;

/// Whole ticks per second at each target slot time.
///
/// Values which are not integral are rounded down. Prefer the corresponding
/// `DEFAULT_NS_PER_TICK_*` constant when an exact duration is required.
pub const DEFAULT_TICKS_PER_SECOND_400_MS: u64 = 1_000_000_000 / DEFAULT_NS_PER_TICK_400_MS;
pub const DEFAULT_TICKS_PER_SECOND_350_MS: u64 = 1_000_000_000 / DEFAULT_NS_PER_TICK_350_MS;
pub const DEFAULT_TICKS_PER_SECOND_300_MS: u64 = 1_000_000_000 / DEFAULT_NS_PER_TICK_300_MS;
pub const DEFAULT_TICKS_PER_SECOND_250_MS: u64 = 1_000_000_000 / DEFAULT_NS_PER_TICK_250_MS;
pub const DEFAULT_TICKS_PER_SECOND_200_MS: u64 = 1_000_000_000 / DEFAULT_NS_PER_TICK_200_MS;

/// The default whole-number tick rate (213 per second).
///
/// Note that the exact 300 millisecond target is 213 1/3 ticks per second and
/// that the actual tick rate at any given time should be expected to drift.
pub const DEFAULT_TICKS_PER_SECOND: u64 = DEFAULT_TICKS_PER_SECOND_300_MS;

#[cfg(test)]
static_assertions::const_assert_eq!(MS_PER_TICK, 4);

pub const MS_PER_TICK_400_MS: u64 = DEFAULT_NS_PER_TICK_400_MS / 1_000_000;
pub const MS_PER_TICK_350_MS: u64 = DEFAULT_NS_PER_TICK_350_MS / 1_000_000;
pub const MS_PER_TICK_300_MS: u64 = DEFAULT_NS_PER_TICK_300_MS / 1_000_000;
pub const MS_PER_TICK_250_MS: u64 = DEFAULT_NS_PER_TICK_250_MS / 1_000_000;
pub const MS_PER_TICK_200_MS: u64 = DEFAULT_NS_PER_TICK_200_MS / 1_000_000;

/// The number of whole milliseconds per tick (4).
///
/// This value is rounded down. Use [`DEFAULT_NS_PER_TICK`] for the exact target.
pub const MS_PER_TICK: u64 = MS_PER_TICK_300_MS;

pub const DEFAULT_HASHES_PER_SECOND: u64 = 10_000_000;

#[cfg(test)]
static_assertions::const_assert_eq!(DEFAULT_HASHES_PER_TICK, 46_875);
pub const DEFAULT_HASHES_PER_TICK_400_MS: u64 = 62_500;
pub const DEFAULT_HASHES_PER_TICK_350_MS: u64 = 54_687;
pub const DEFAULT_HASHES_PER_TICK_300_MS: u64 = 46_875;
pub const DEFAULT_HASHES_PER_TICK_250_MS: u64 = 39_062;
pub const DEFAULT_HASHES_PER_TICK_200_MS: u64 = 31_250;
pub const DEFAULT_HASHES_PER_TICK: u64 = DEFAULT_HASHES_PER_TICK_300_MS;

// 1 Dev Epoch = 300 ms * 8192 ~= 41 minutes
pub const DEFAULT_DEV_SLOTS_PER_EPOCH: u64 = 8192;

#[cfg(test)]
static_assertions::const_assert_eq!(SECONDS_PER_DAY, 86_400);
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

#[cfg(test)]
static_assertions::const_assert_eq!(TICKS_PER_DAY, 18_432_000);
pub const TICKS_PER_DAY_400_MS: u64 = SECONDS_PER_DAY * 1_000_000_000 / DEFAULT_NS_PER_TICK_400_MS;
pub const TICKS_PER_DAY_350_MS: u64 = SECONDS_PER_DAY * 1_000_000_000 / DEFAULT_NS_PER_TICK_350_MS;
pub const TICKS_PER_DAY_300_MS: u64 = SECONDS_PER_DAY * 1_000_000_000 / DEFAULT_NS_PER_TICK_300_MS;
pub const TICKS_PER_DAY_250_MS: u64 = SECONDS_PER_DAY * 1_000_000_000 / DEFAULT_NS_PER_TICK_250_MS;
pub const TICKS_PER_DAY_200_MS: u64 = SECONDS_PER_DAY * 1_000_000_000 / DEFAULT_NS_PER_TICK_200_MS;
pub const TICKS_PER_DAY: u64 = TICKS_PER_DAY_300_MS;

/// The number of slots per epoch after initial network warmup.
///
/// At the default 300 millisecond slot time, one epoch is approximately 36 hours.
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

// leader schedule is governed by this
#[deprecated(since = "3.1.0", note = "Moved to solana-leader-schedule crate")]
pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;

#[cfg(test)]
static_assertions::const_assert_eq!(DEFAULT_MS_PER_SLOT, 300);
pub const DEFAULT_MS_PER_SLOT_400_MS: u64 = DEFAULT_NS_PER_SLOT_400_MS / 1_000_000;
pub const DEFAULT_MS_PER_SLOT_350_MS: u64 = DEFAULT_NS_PER_SLOT_350_MS / 1_000_000;
pub const DEFAULT_MS_PER_SLOT_300_MS: u64 = DEFAULT_NS_PER_SLOT_300_MS / 1_000_000;
pub const DEFAULT_MS_PER_SLOT_250_MS: u64 = DEFAULT_NS_PER_SLOT_250_MS / 1_000_000;
pub const DEFAULT_MS_PER_SLOT_200_MS: u64 = DEFAULT_NS_PER_SLOT_200_MS / 1_000_000;

/// The SDK's default expected duration of a slot (300 milliseconds).
pub const DEFAULT_MS_PER_SLOT: u64 = DEFAULT_MS_PER_SLOT_300_MS;

pub const DEFAULT_S_PER_SLOT_400_MS: f64 = DEFAULT_MS_PER_SLOT_400_MS as f64 / 1_000.0;
pub const DEFAULT_S_PER_SLOT_350_MS: f64 = DEFAULT_MS_PER_SLOT_350_MS as f64 / 1_000.0;
pub const DEFAULT_S_PER_SLOT_300_MS: f64 = DEFAULT_MS_PER_SLOT_300_MS as f64 / 1_000.0;
pub const DEFAULT_S_PER_SLOT_250_MS: f64 = DEFAULT_MS_PER_SLOT_250_MS as f64 / 1_000.0;
pub const DEFAULT_S_PER_SLOT_200_MS: f64 = DEFAULT_MS_PER_SLOT_200_MS as f64 / 1_000.0;
pub const DEFAULT_S_PER_SLOT: f64 = DEFAULT_S_PER_SLOT_300_MS;

/// The time window of recent block hash values over which the bank will track
/// signatures.
///
/// Once the bank discards a block hash, it will reject any transactions that
/// use that `recent_blockhash` in a transaction. Lowering this value reduces
/// memory consumption, but requires a client to update its `recent_blockhash`
/// more frequently. Raising the value lengthens the time a client must wait to
/// be certain a missing transaction will not be processed by the network.
pub const MAX_HASH_AGE_IN_SECONDS_400_MS: usize = 120;
pub const MAX_HASH_AGE_IN_SECONDS_350_MS: usize = 105;
pub const MAX_HASH_AGE_IN_SECONDS_300_MS: usize = 90;
pub const MAX_HASH_AGE_IN_SECONDS_250_MS: usize = 75;
pub const MAX_HASH_AGE_IN_SECONDS_200_MS: usize = 60;
pub const MAX_HASH_AGE_IN_SECONDS: usize = MAX_HASH_AGE_IN_SECONDS_300_MS;

// Maximum number of recent blockhashes (one blockhash per non-skipped slot).
pub const MAX_RECENT_BLOCKHASHES: usize = 300;

#[cfg(test)]
static_assertions::const_assert_eq!(MAX_PROCESSING_AGE, 150);
// The maximum age of a blockhash that will be accepted by the leader
pub const MAX_PROCESSING_AGE: usize = MAX_RECENT_BLOCKHASHES / 2;

/// This is maximum time consumed in forwarding a transaction from one node to next, before
/// it can be processed in the target node
pub const MAX_TRANSACTION_FORWARDING_DELAY_GPU: usize = 2;

/// More delay is expected if CUDA is not enabled (as signature verification takes longer)
pub const MAX_TRANSACTION_FORWARDING_DELAY: usize = 6;

/// Transaction forwarding, which leader to forward to and how long to hold
pub const FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET: u64 = 2;
pub const HOLD_TRANSACTIONS_SLOT_OFFSET: u64 = 20;

/// The unit of time given to a leader for encoding a block.
///
/// It is some number of _ticks_ long.
pub type Slot = u64;

/// Uniquely distinguishes every version of a slot.
///
/// The `BankId` is unique even if the slot number of two different slots is the
/// same. This can happen in the case of e.g. duplicate slots.
pub type BankId = u64;

/// The unit of time a given leader schedule is honored.
///
/// It lasts for some number of [`Slot`]s.
pub type Epoch = u64;

pub const GENESIS_EPOCH: Epoch = 0;
// must be sync with Account::rent_epoch::default()
pub const INITIAL_RENT_EPOCH: Epoch = 0;

/// An index to the slots of a epoch.
pub type SlotIndex = u64;

/// The number of slots in a epoch.
pub type SlotCount = u64;

/// An approximate measure of real-world time.
///
/// Expressed as Unix time (i.e. seconds since the Unix epoch).
pub type UnixTimestamp = i64;

/// A representation of network time.
///
/// All members of `Clock` start from 0 upon network boot.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaWrite, wincode::SchemaRead))]
#[derive(Debug, CloneZeroed, Default, PartialEq, Eq)]
pub struct Clock {
    /// The current `Slot`.
    pub slot: Slot,
    /// The timestamp of the first `Slot` in this `Epoch`.
    pub epoch_start_timestamp: UnixTimestamp,
    /// The current `Epoch`.
    pub epoch: Epoch,
    /// The future `Epoch` for which the leader schedule has
    /// most recently been calculated.
    pub leader_schedule_epoch: Epoch,
    /// The approximate real world time of the current slot.
    ///
    /// This value was originally computed from genesis creation time and
    /// network time in slots, incurring a lot of drift. Following activation of
    /// the [`timestamp_correction` and `timestamp_bounding`][tsc] features it
    /// is calculated using a [validator timestamp oracle][oracle].
    ///
    /// [tsc]: https://docs.solanalabs.com/implemented-proposals/bank-timestamp-correction
    /// [oracle]: https://docs.solanalabs.com/implemented-proposals/validator-timestamp-oracle
    pub unix_timestamp: UnixTimestamp,
}

/// Serialized size of the `Clock` sysvar account.
pub const SIZE: usize = size_of::<Clock>();
const _: () = assert!(SIZE == 40);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_of() {
        assert_eq!(
            wincode::serialized_size(&Clock::default()).unwrap() as usize,
            SIZE,
        );
    }

    #[test]
    fn test_clone() {
        let clock = Clock {
            slot: 1,
            epoch_start_timestamp: 2,
            epoch: 3,
            leader_schedule_epoch: 4,
            unix_timestamp: 5,
        };
        let cloned_clock = clock.clone();
        assert_eq!(cloned_clock, clock);
    }
}
