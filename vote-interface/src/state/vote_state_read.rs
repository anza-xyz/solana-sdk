//! Vote state reader API.

use {
    super::BlockTimestamp,
    solana_clock::{Epoch, Slot},
    solana_pubkey::Pubkey,
};

/// Read-only trait for accessing vote state data.
pub trait VoteStateRead {
    /// Returns the authorized withdrawer.
    fn authorized_withdrawer(&self) -> &Pubkey;

    /// Returns the total credits.
    fn credits(&self) -> u64 {
        if self.epoch_credits().is_empty() {
            0
        } else {
            self.epoch_credits().last().unwrap().1
        }
    }

    /// Returns the epoch credits.
    fn epoch_credits(&self) -> &Vec<(Epoch, u64, u64)>;

    /// Returns the inflation rewards commission in basis points.
    fn inflation_rewards_commission_bps(&self) -> u16;

    /// Returns the last timestamp.
    fn last_timestamp(&self) -> &BlockTimestamp;

    /// Returns the node pubkey.
    fn node_pubkey(&self) -> &Pubkey;

    /// Returns the root slot.
    fn root_slot(&self) -> Option<Slot>;
}
