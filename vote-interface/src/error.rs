//! Vote program errors

// The `FromPrimitive`/`ToPrimitive` derive expansions reference the
// deprecated `VoteError` variants and cannot be silenced at the item level.
#![allow(deprecated)]

use {
    core::fmt,
    num_derive::{FromPrimitive, ToPrimitive},
};

/// Reasons the vote might have had an error
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[non_exhaustive]
pub enum VoteError {
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    VoteTooOld,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    SlotsMismatch,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    SlotHashMismatch,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    EmptySlots,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    TimestampTooOld,
    TooSoonToReauthorize,
    // TODO: figure out how to migrate these new errors
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    LockoutConflict,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    NewVoteStateLockoutMismatch,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    SlotsNotOrdered,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    ConfirmationsNotOrdered,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    ZeroConfirmations,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    ConfirmationTooLarge,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    RootRollBack,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    ConfirmationRollBack,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    SlotSmallerThanRoot,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    TooManyVotes,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    VotesTooOldAllFiltered,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    RootOnDifferentFork,
    ActiveVoteAccountClose,
    CommissionUpdateTooLate,
    #[deprecated(
        since = "7.4.0",
        note = "Only returned by tower vote instructions, which are disabled since the Alpenglow migration; will be removed in a future release."
    )]
    AssertionFailed,
}

impl core::error::Error for VoteError {}

impl fmt::Display for VoteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::VoteTooOld => "vote already recorded or not in slot hashes history",
            Self::SlotsMismatch => "vote slots do not match bank history",
            Self::SlotHashMismatch => "vote hash does not match bank hash",
            Self::EmptySlots => "vote has no slots, invalid",
            Self::TimestampTooOld => "vote timestamp not recent",
            Self::TooSoonToReauthorize => "authorized voter has already been changed this epoch",
            Self::LockoutConflict => {
                "Old state had vote which should not have been popped off by vote in new state"
            }
            Self::NewVoteStateLockoutMismatch => {
                "Proposed state had earlier slot which should have been popped off by later vote"
            }
            Self::SlotsNotOrdered => "Vote slots are not ordered",
            Self::ConfirmationsNotOrdered => "Confirmations are not ordered",
            Self::ZeroConfirmations => "Zero confirmations",
            Self::ConfirmationTooLarge => "Confirmation exceeds limit",
            Self::RootRollBack => "Root rolled back",
            Self::ConfirmationRollBack => {
                "Confirmations for same vote were smaller in new proposed state"
            }
            Self::SlotSmallerThanRoot => "New state contained a vote slot smaller than the root",
            Self::TooManyVotes => "New state contained too many votes",
            Self::VotesTooOldAllFiltered => {
                "every slot in the vote was older than the SlotHashes history"
            }
            Self::RootOnDifferentFork => "Proposed root is not in slot hashes",
            Self::ActiveVoteAccountClose => {
                "Cannot close vote account unless it stopped voting at least one full epoch ago"
            }
            Self::CommissionUpdateTooLate => "Cannot update commission at this point in the epoch",
            Self::AssertionFailed => "Assertion failed",
        })
    }
}
