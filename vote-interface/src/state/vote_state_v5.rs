#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
use {
    super::{BlockTimestamp, LandedVote, BLS_PUBLIC_KEY_COMPRESSED_SIZE},
    crate::authorized_voters::AuthorizedVoters,
    solana_clock::{Epoch, Slot},
    solana_pubkey::Pubkey,
    std::{collections::VecDeque, fmt::Debug},
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "9hJQid4SQhrhjZgW4cpZFqWXQ28u3eerNP8we89269y2"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct TowerVoteState {
    /// The node that votes in this account.
    pub node_pubkey: Pubkey,
    /// List of votes that the validator submitted.
    pub votes: VecDeque<LandedVote>,
    /// The signer for vote transactions.
    /// Contains entries for the current epoch and the previous epoch.
    pub authorized_voters: AuthorizedVoters,
    /// History of credits earned by the end of each epoch.
    /// Each tuple is (Epoch, credits, prev_credits).
    pub epoch_credits: Vec<(Epoch, u64, u64)>,
    /// Most recent timestamp submitted with a vote.
    pub last_timestamp: BlockTimestamp,
}

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "ADCemLE3bhT6awSr4386T6v3iK3vThDAANM7AP9kK5j"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct AlpenglowVoteState {
    /// History of vote rewards earned by the end of each epoch in lamports.
    /// Each tuple is (Epoch, rewards for current_epoch, rewards for previous_epoch).
    pub earned_vote_rewards: Vec<(Epoch, u128, u128)>,
}

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "Dw4ABepWD24R1XjVbe1YkLeJuWiDP2WxZWu29DN4HhSL"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct VoteStateV5 {
    /// The signer for withdrawals.
    pub authorized_withdrawer: Pubkey,

    /// The collector account for inflation rewards.
    pub inflation_rewards_collector: Pubkey,
    /// The collector account for block revenue.
    pub block_revenue_collector: Pubkey,

    /// Basis points (0-10,000) that represent how much of the inflation
    /// rewards should be given to this vote account.
    pub inflation_rewards_commission_bps: u16,
    /// Basis points (0-10,000) that represent how much of the block revenue
    /// should be given to this vote account.
    pub block_revenue_commission_bps: u16,

    /// Reward amount pending distribution to stake delegators.
    pub pending_delegator_rewards: u64,

    /// Compressed BLS pubkey for Alpenglow.
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "Option<[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]>")
    )]
    pub bls_pubkey_compressed: Option<[u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE]>,

    pub root_slot: Option<Slot>,

    /// Additional vote state for tower consensus.
    ///
    /// This state should be used while tower is in used and also after migration till the vote rewards from tower are fully paid.
    pub tower_vote_state: TowerVoteState,
    /// Additional vote state for alpenglow consensus.
    ///
    /// This state should be used right after migration to alpenglow.
    pub alpenglow_vote_state: AlpenglowVoteState,
}
