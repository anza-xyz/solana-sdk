#[cfg(feature = "bincode")]
use super::VoteStateVersions;
#[cfg(test)]
use super::{MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY};
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
use {
    super::{BlockTimestamp, CircBuf, LandedVote, Lockout, VoteInit},
    crate::{authorized_voters::AuthorizedVoters, state::DEFAULT_PRIOR_VOTERS_OFFSET},
    solana_clock::{Clock, Epoch, Slot},
    solana_instruction_error::InstructionError,
    solana_pubkey::Pubkey,
    std::{collections::VecDeque, fmt::Debug},
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "pZqasQc6duzMYzpzU7eriHH9cMXmubuUP4NmCrkWZjt"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct VoteStateV3 {
    /// the node that votes in this account
    pub node_pubkey: Pubkey,

    /// the signer for withdrawals
    pub authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    pub commission: u8,

    pub votes: VecDeque<LandedVote>,

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    pub root_slot: Option<Slot>,

    /// the signer for vote transactions
    pub authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    pub prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// most recent timestamp submitted with a vote
    pub last_timestamp: BlockTimestamp,
}

impl VoteStateV3 {
    pub fn new(vote_init: &VoteInit, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            commission: vote_init.commission,
            ..VoteStateV3::default()
        }
    }

    pub fn new_rand_for_tests(node_pubkey: Pubkey, root_slot: Slot) -> Self {
        let votes = (1..32)
            .map(|x| LandedVote {
                latency: 0,
                lockout: Lockout::new_with_confirmation_count(
                    u64::from(x).saturating_add(root_slot),
                    32_u32.saturating_sub(x),
                ),
            })
            .collect();
        Self {
            node_pubkey,
            root_slot: Some(root_slot),
            votes,
            ..VoteStateV3::default()
        }
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // see test_vote_state_size_of.
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8]) -> Result<Self, InstructionError> {
        let mut vote_state = Self::default();
        Self::deserialize_into(input, &mut vote_state)?;
        Ok(vote_state)
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided `VoteStateV3`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` reflects the state of the input data. On failure, `vote_state` is
    /// reset to `VoteStateV3::default()`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into(
        input: &[u8],
        vote_state: &mut VoteStateV3,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize;
        vote_state_deserialize::deserialize_into(input, vote_state, Self::deserialize_into_ptr)
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided
    /// `MaybeUninit<VoteStateV3>`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` is fully initialized and can be converted to
    /// `VoteStateV3` using
    /// [`MaybeUninit::assume_init`](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.assume_init).
    /// On failure, `vote_state` may still be uninitialized and must not be
    /// converted to `VoteStateV3`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into_uninit(
        input: &[u8],
        vote_state: &mut std::mem::MaybeUninit<VoteStateV3>,
    ) -> Result<(), InstructionError> {
        VoteStateV3::deserialize_into_ptr(input, vote_state.as_mut_ptr())
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    fn deserialize_into_ptr(
        input: &[u8],
        vote_state: *mut VoteStateV3,
    ) -> Result<(), InstructionError> {
        use super::vote_state_deserialize::deserialize_vote_state_into_v3;

        let mut cursor = std::io::Cursor::new(input);

        let variant = solana_serialize_utils::cursor::read_u32(&mut cursor)?;
        match variant {
            // V0_23_5. not supported for bpf targets; these should not exist on mainnet
            // supported for non-bpf targets for backwards compatibility
            0 => {
                #[cfg(not(target_os = "solana"))]
                {
                    // Safety: vote_state is valid as it comes from `&mut MaybeUninit<VoteStateV3>` or
                    // `&mut VoteStateV3`. In the first case, the value is uninitialized so we write()
                    // to avoid dropping invalid data; in the latter case, we `drop_in_place()`
                    // before writing so the value has already been dropped and we just write a new
                    // one in place.
                    unsafe {
                        vote_state.write(
                            bincode::deserialize::<VoteStateVersions>(input)
                                .map_err(|_| InstructionError::InvalidAccountData)
                                .and_then(|versioned| versioned.try_convert_to_v3())?,
                        );
                    }
                    Ok(())
                }
                #[cfg(target_os = "solana")]
                Err(InstructionError::InvalidAccountData)
            }
            // V1_14_11. substantially different layout and data from V0_23_5
            1 => deserialize_vote_state_into_v3(&mut cursor, vote_state, false),
            // V3. the only difference from V1_14_11 is the addition of a slot-latency to each vote
            2 => deserialize_vote_state_into_v3(&mut cursor, vote_state, true),
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

    #[cfg(test)]
    pub(crate) fn get_max_sized_vote_state() -> VoteStateV3 {
        use solana_epoch_schedule::MAX_LEADER_SCHEDULE_EPOCH_OFFSET;
        let mut authorized_voters = AuthorizedVoters::default();
        for i in 0..=MAX_LEADER_SCHEDULE_EPOCH_OFFSET {
            authorized_voters.insert(i, Pubkey::new_unique());
        }

        VoteStateV3 {
            votes: VecDeque::from(vec![LandedVote::default(); MAX_LOCKOUT_HISTORY]),
            root_slot: Some(u64::MAX),
            epoch_credits: vec![(0, 0, 0); MAX_EPOCH_CREDITS_HISTORY],
            authorized_voters,
            ..Self::default()
        }
    }

    // Upto MAX_LOCKOUT_HISTORY many recent unexpired
    // vote slots pushed onto the stack.
    pub fn tower(&self) -> Vec<Slot> {
        self.votes.iter().map(|v| v.slot()).collect()
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        const VERSION_OFFSET: usize = 4;
        const DEFAULT_PRIOR_VOTERS_END: usize = VERSION_OFFSET + DEFAULT_PRIOR_VOTERS_OFFSET;
        data.len() == VoteStateV3::size_of()
            && data[VERSION_OFFSET..DEFAULT_PRIOR_VOTERS_END] != [0; DEFAULT_PRIOR_VOTERS_OFFSET]
    }
}
