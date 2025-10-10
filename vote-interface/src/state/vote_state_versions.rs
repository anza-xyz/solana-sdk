#[cfg(test)]
use arbitrary::{Arbitrary, Unstructured};
use {
    crate::state::{
        vote_state_0_23_5::VoteState0_23_5, vote_state_1_14_11::VoteState1_14_11, BlockTimestamp,
        VoteStateRead, VoteStateV3, VoteStateV4,
    },
    solana_clock::{Epoch, Slot},
    solana_pubkey::Pubkey,
};
#[cfg(any(test, all(not(target_os = "solana"), feature = "bincode")))]
use {
    crate::state::{AuthorizedVoters, CircBuf, LandedVote, Lockout},
    solana_instruction::error::InstructionError,
    std::collections::VecDeque,
};

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VoteStateVersions {
    V0_23_5(Box<VoteState0_23_5>),
    V1_14_11(Box<VoteState1_14_11>),
    V3(Box<VoteStateV3>),
    V4(Box<VoteStateV4>),
}

impl VoteStateVersions {
    pub fn new_v3(vote_state: VoteStateV3) -> Self {
        Self::V3(Box::new(vote_state))
    }

    pub fn new_v4(vote_state: VoteStateV4) -> Self {
        Self::V4(Box::new(vote_state))
    }

    /// Convert from vote state `V0_23_5`, `V1_14_11`, or `V3` to `V3`.
    ///
    /// NOTE: Does not support conversion from `V4`. Attempting to convert from
    /// v4 to v3 will throw an error.
    #[cfg(any(test, all(not(target_os = "solana"), feature = "bincode")))]
    pub(crate) fn try_convert_to_v3(self) -> Result<VoteStateV3, InstructionError> {
        match self {
            VoteStateVersions::V0_23_5(state) => {
                let authorized_voters = if state.is_uninitialized() {
                    AuthorizedVoters::default()
                } else {
                    AuthorizedVoters::new(state.authorized_voter_epoch, state.authorized_voter)
                };

                Ok(VoteStateV3 {
                    node_pubkey: state.node_pubkey,

                    authorized_withdrawer: state.authorized_withdrawer,

                    commission: state.commission,

                    votes: Self::landed_votes_from_lockouts(state.votes),

                    root_slot: state.root_slot,

                    authorized_voters,

                    prior_voters: CircBuf::default(),

                    epoch_credits: state.epoch_credits.clone(),

                    last_timestamp: state.last_timestamp.clone(),
                })
            }

            VoteStateVersions::V1_14_11(state) => Ok(VoteStateV3 {
                node_pubkey: state.node_pubkey,
                authorized_withdrawer: state.authorized_withdrawer,
                commission: state.commission,

                votes: Self::landed_votes_from_lockouts(state.votes),

                root_slot: state.root_slot,

                authorized_voters: state.authorized_voters.clone(),

                prior_voters: state.prior_voters,

                epoch_credits: state.epoch_credits,

                last_timestamp: state.last_timestamp,
            }),

            VoteStateVersions::V3(state) => Ok(*state),

            // Cannot convert V4 to V3.
            VoteStateVersions::V4(_) => Err(InstructionError::InvalidArgument),
        }
    }

    // Currently, all versions can be converted to v4 without data loss, so
    // this function returns `Ok(..)`. However, future versions may not be
    // convertible to v4 without data loss, so this function returns a `Result`
    // for forward compatibility.
    #[cfg(any(test, all(not(target_os = "solana"), feature = "bincode")))]
    pub(crate) fn try_convert_to_v4(
        self,
        vote_pubkey: &Pubkey,
    ) -> Result<VoteStateV4, InstructionError> {
        Ok(match self {
            VoteStateVersions::V0_23_5(state) => {
                let authorized_voters = if state.is_uninitialized() {
                    AuthorizedVoters::default()
                } else {
                    AuthorizedVoters::new(state.authorized_voter_epoch, state.authorized_voter)
                };

                VoteStateV4 {
                    node_pubkey: state.node_pubkey,
                    authorized_withdrawer: state.authorized_withdrawer,
                    inflation_rewards_collector: *vote_pubkey,
                    block_revenue_collector: state.node_pubkey,
                    inflation_rewards_commission_bps: u16::from(state.commission)
                        .saturating_mul(100),
                    block_revenue_commission_bps: 10_000u16,
                    pending_delegator_rewards: 0,
                    bls_pubkey_compressed: None,
                    votes: Self::landed_votes_from_lockouts(state.votes),
                    root_slot: state.root_slot,
                    authorized_voters,
                    epoch_credits: state.epoch_credits.clone(),
                    last_timestamp: state.last_timestamp.clone(),
                }
            }

            VoteStateVersions::V1_14_11(state) => VoteStateV4 {
                node_pubkey: state.node_pubkey,
                authorized_withdrawer: state.authorized_withdrawer,
                inflation_rewards_collector: *vote_pubkey,
                block_revenue_collector: state.node_pubkey,
                inflation_rewards_commission_bps: u16::from(state.commission).saturating_mul(100),
                block_revenue_commission_bps: 10_000u16,
                pending_delegator_rewards: 0,
                bls_pubkey_compressed: None,
                votes: Self::landed_votes_from_lockouts(state.votes),
                root_slot: state.root_slot,
                authorized_voters: state.authorized_voters.clone(),
                epoch_credits: state.epoch_credits,
                last_timestamp: state.last_timestamp,
            },

            VoteStateVersions::V3(state) => VoteStateV4 {
                node_pubkey: state.node_pubkey,
                authorized_withdrawer: state.authorized_withdrawer,
                inflation_rewards_collector: *vote_pubkey,
                block_revenue_collector: state.node_pubkey,
                inflation_rewards_commission_bps: u16::from(state.commission).saturating_mul(100),
                block_revenue_commission_bps: 10_000u16,
                pending_delegator_rewards: 0,
                bls_pubkey_compressed: None,
                votes: state.votes,
                root_slot: state.root_slot,
                authorized_voters: state.authorized_voters,
                epoch_credits: state.epoch_credits,
                last_timestamp: state.last_timestamp,
            },

            VoteStateVersions::V4(state) => *state,
        })
    }

    #[cfg(any(test, all(not(target_os = "solana"), feature = "bincode")))]
    fn landed_votes_from_lockouts(lockouts: VecDeque<Lockout>) -> VecDeque<LandedVote> {
        lockouts.into_iter().map(|lockout| lockout.into()).collect()
    }

    pub fn is_uninitialized(&self) -> bool {
        match self {
            VoteStateVersions::V0_23_5(vote_state) => vote_state.is_uninitialized(),

            VoteStateVersions::V1_14_11(vote_state) => vote_state.is_uninitialized(),

            VoteStateVersions::V3(vote_state) => vote_state.is_uninitialized(),

            // As per SIMD-0185, v4 is always initialized.
            VoteStateVersions::V4(_) => false,
        }
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        VoteStateV4::is_correct_size_and_initialized(data)
            || VoteStateV3::is_correct_size_and_initialized(data)
            || VoteState1_14_11::is_correct_size_and_initialized(data)
    }
}

impl VoteStateRead for VoteStateVersions {
    fn authorized_withdrawer(&self) -> &Pubkey {
        match self {
            VoteStateVersions::V0_23_5(state) => &state.authorized_withdrawer,
            VoteStateVersions::V1_14_11(state) => &state.authorized_withdrawer,
            VoteStateVersions::V3(state) => state.authorized_withdrawer(),
            VoteStateVersions::V4(state) => state.authorized_withdrawer(),
        }
    }

    fn epoch_credits(&self) -> &Vec<(Epoch, u64, u64)> {
        match self {
            VoteStateVersions::V0_23_5(state) => &state.epoch_credits,
            VoteStateVersions::V1_14_11(state) => &state.epoch_credits,
            VoteStateVersions::V3(state) => state.epoch_credits(),
            VoteStateVersions::V4(state) => state.epoch_credits(),
        }
    }

    fn inflation_rewards_commission_bps(&self) -> u16 {
        match self {
            VoteStateVersions::V0_23_5(state) => (state.commission as u16).saturating_mul(100),
            VoteStateVersions::V1_14_11(state) => (state.commission as u16).saturating_mul(100),
            VoteStateVersions::V3(state) => state.inflation_rewards_commission_bps(),
            VoteStateVersions::V4(state) => state.inflation_rewards_commission_bps(),
        }
    }

    fn last_timestamp(&self) -> &BlockTimestamp {
        match self {
            VoteStateVersions::V0_23_5(state) => &state.last_timestamp,
            VoteStateVersions::V1_14_11(state) => &state.last_timestamp,
            VoteStateVersions::V3(state) => state.last_timestamp(),
            VoteStateVersions::V4(state) => state.last_timestamp(),
        }
    }

    fn node_pubkey(&self) -> &Pubkey {
        match self {
            VoteStateVersions::V0_23_5(state) => &state.node_pubkey,
            VoteStateVersions::V1_14_11(state) => &state.node_pubkey,
            VoteStateVersions::V3(state) => state.node_pubkey(),
            VoteStateVersions::V4(state) => state.node_pubkey(),
        }
    }

    fn root_slot(&self) -> Option<Slot> {
        match self {
            VoteStateVersions::V0_23_5(state) => state.root_slot,
            VoteStateVersions::V1_14_11(state) => state.root_slot,
            VoteStateVersions::V3(state) => state.root_slot(),
            VoteStateVersions::V4(state) => state.root_slot(),
        }
    }
}

#[cfg(test)]
impl Arbitrary<'_> for VoteStateVersions {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let variant = u.choose_index(3)?;
        match variant {
            0 => Ok(Self::V4(Box::new(VoteStateV4::arbitrary(u)?))),
            1 => Ok(Self::V3(Box::new(VoteStateV3::arbitrary(u)?))),
            2 => Ok(Self::V1_14_11(Box::new(VoteState1_14_11::arbitrary(u)?))),
            _ => unreachable!(),
        }
    }
}
