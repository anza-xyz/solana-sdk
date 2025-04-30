#![deprecated(since = "2.3.0", note = "Use `solana-stake-interface` crate instead")]
pub use {
    crate::sysvar::stake_history::{
        StakeHistory, StakeHistoryEntry, StakeHistoryGetEntry, MAX_ENTRIES,
    },
    solana_clock::Epoch,
};
