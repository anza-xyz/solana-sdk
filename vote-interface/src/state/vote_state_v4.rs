#[cfg(feature = "bincode")]
use super::VoteStateVersions;
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
#[cfg(any(target_os = "solana", feature = "bincode"))]
use solana_instruction::error::InstructionError;
use {
    super::{BlockTimestamp, LandedVote, VoteInit, VoteInitV2, BLS_PUBLIC_KEY_COMPRESSED_SIZE},
    crate::authorized_voters::AuthorizedVoters,
    solana_clock::{Clock, Epoch, Slot},
    solana_pubkey::Pubkey,
    std::{collections::VecDeque, fmt::Debug},
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "2H9WgTh7LgdnpinvEwxzP3HF6SDuKp6qdwFmJk9jHDRP"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct VoteStateV4 {
    /// The node that votes in this account.
    pub node_pubkey: Pubkey,
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

    pub votes: VecDeque<LandedVote>,
    pub root_slot: Option<Slot>,

    /// The signer for vote transactions.
    /// Contains entries for the current epoch and the previous epoch.
    pub authorized_voters: AuthorizedVoters,

    /// History of credits earned by the end of each epoch.
    /// Each tuple is (Epoch, credits, prev_credits).
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// Most recent timestamp submitted with a vote.
    pub last_timestamp: BlockTimestamp,
}

impl VoteStateV4 {
    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // Same size as V3 to avoid account resizing
    }

    pub fn new_with_defaults(vote_pubkey: &Pubkey, vote_init: &VoteInit, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            // SAFETY: u16::MAX > u8::MAX * 100
            inflation_rewards_commission_bps: (vote_init.commission as u16).saturating_mul(100),
            // Per SIMD-0185, set default collectors and commission.
            inflation_rewards_collector: *vote_pubkey,
            block_revenue_collector: vote_init.node_pubkey,
            block_revenue_commission_bps: 10_000, // 100%
            ..Self::default()
        }
    }

    pub fn new(vote_init: &VoteInitV2, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            bls_pubkey_compressed: Some(vote_init.authorized_voter_bls_pubkey),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            inflation_rewards_commission_bps: vote_init.inflation_rewards_commission_bps,
            inflation_rewards_collector: vote_init.inflation_rewards_collector,
            block_revenue_commission_bps: vote_init.block_revenue_commission_bps,
            block_revenue_collector: vote_init.block_revenue_collector,
            ..Self::default()
        }
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8], vote_pubkey: &Pubkey) -> Result<Self, InstructionError> {
        let mut vote_state = Self::default();
        Self::deserialize_into(input, &mut vote_state, vote_pubkey)?;
        Ok(vote_state)
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided `VoteStateV4`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` reflects the state of the input data. On failure, `vote_state` is
    /// reset to `VoteStateV4::default()`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into(
        input: &[u8],
        vote_state: &mut VoteStateV4,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize;
        vote_state_deserialize::deserialize_into(input, vote_state, |input, vote_state| {
            Self::deserialize_into_ptr(input, vote_state, vote_pubkey)
        })
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided
    /// `MaybeUninit<VoteStateV4>`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` is fully initialized and can be converted to
    /// `VoteStateV4` using
    /// [`MaybeUninit::assume_init`](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.assume_init).
    /// On failure, `vote_state` may still be uninitialized and must not be
    /// converted to `VoteStateV4`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into_uninit(
        input: &[u8],
        vote_state: &mut std::mem::MaybeUninit<VoteStateV4>,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        Self::deserialize_into_ptr(input, vote_state.as_mut_ptr(), vote_pubkey)
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    fn deserialize_into_ptr(
        input: &[u8],
        vote_state: *mut VoteStateV4,
        vote_pubkey: &Pubkey,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize::{deserialize_vote_state_into_v4, SourceVersion};

        let mut cursor = std::io::Cursor::new(input);

        let variant = solana_serialize_utils::cursor::read_u32(&mut cursor)?;
        match variant {
            // Variant 0 is not a valid vote state.
            0 => Err(InstructionError::InvalidAccountData),
            // V1_14_11
            1 => deserialize_vote_state_into_v4(
                &mut cursor,
                vote_state,
                SourceVersion::V1_14_11 { vote_pubkey },
            ),
            // V3
            2 => deserialize_vote_state_into_v4(
                &mut cursor,
                vote_state,
                SourceVersion::V3 { vote_pubkey },
            ),
            // V4
            3 => deserialize_vote_state_into_v4(&mut cursor, vote_state, SourceVersion::V4),
            _ => Err(InstructionError::InvalidAccountData),
        }?;

        Ok(())
    }

    #[cfg(feature = "bincode")]
    pub fn serialize(
        versioned: &VoteStateVersions,
        output: &mut [u8],
    ) -> Result<(), InstructionError> {
        bincode::serialize_into(output, versioned).map_err(|err| match *err {
            bincode::ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        data.len() == VoteStateV4::size_of() && data[..4] == [3, 0, 0, 0] // little-endian 3u32
                                                                          // Always initialized
    }

    /// Number of credits owed to this account.
    pub fn credits(&self) -> u64 {
        self.epoch_credits.last().map_or(0, |v| v.1)
    }

    #[cfg(test)]
    pub(crate) fn get_max_sized_vote_state() -> Self {
        use super::{MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY};

        // V4 stores a maximum of 4 authorized voter entries.
        const MAX_AUTHORIZED_VOTERS: usize = 4;

        let mut authorized_voters = AuthorizedVoters::default();
        for i in 0..MAX_AUTHORIZED_VOTERS as u64 {
            authorized_voters.insert(i, Pubkey::new_unique());
        }

        Self {
            votes: VecDeque::from(vec![LandedVote::default(); MAX_LOCKOUT_HISTORY]),
            root_slot: Some(u64::MAX),
            epoch_credits: vec![(0, 0, 0); MAX_EPOCH_CREDITS_HISTORY],
            authorized_voters,
            ..Self::default()
        }
    }
}
