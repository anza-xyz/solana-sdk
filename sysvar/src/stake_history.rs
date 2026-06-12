//! Re-exports for the `StakeHistory` sysvar.

pub use {
    solana_stake_history::{
        sysvar::{check_id, id, StakeHistorySysvar, ID},
        StakeHistory, StakeHistoryEntry, StakeHistoryGetEntry, MAX_ENTRIES, SIZE,
    },
    solana_sysvar_id::SysvarId,
};
