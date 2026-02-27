use crate::state::{vote_state_1_14_11::VoteState1_14_11, VoteStateV3, VoteStateV4};
#[cfg(test)]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(any(target_os = "solana", feature = "bincode"))]
use solana_instruction_error::InstructionError;
#[cfg(test)]
use {
    crate::state::{LandedVote, Lockout},
    solana_pubkey::Pubkey,
    std::collections::VecDeque,
};

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VoteStateVersions {
    Uninitialized,
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

    /// Convert from vote state `V1_14_11` or `V3` to `V3`.
    ///
    /// NOTE: Does not support conversion from `V4`. Attempting to convert from
    /// v4 to v3 will throw an error.
    #[cfg(test)]
    pub(crate) fn try_convert_to_v3(self) -> Result<VoteStateV3, InstructionError> {
        match self {
            VoteStateVersions::Uninitialized => Err(InstructionError::UninitializedAccount),

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

    #[cfg(test)]
    pub(crate) fn try_convert_to_v4(
        self,
        vote_pubkey: &Pubkey,
    ) -> Result<VoteStateV4, InstructionError> {
        match self {
            VoteStateVersions::Uninitialized => Err(InstructionError::UninitializedAccount),

            VoteStateVersions::V1_14_11(state) => Ok(VoteStateV4 {
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
            }),

            VoteStateVersions::V3(state) => Ok(VoteStateV4 {
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
            }),

            VoteStateVersions::V4(state) => Ok(*state),
        }
    }

    #[cfg(test)]
    fn landed_votes_from_lockouts(lockouts: VecDeque<Lockout>) -> VecDeque<LandedVote> {
        lockouts.into_iter().map(|lockout| lockout.into()).collect()
    }

    pub fn is_uninitialized(&self) -> bool {
        match self {
            VoteStateVersions::Uninitialized => true,

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

    /// Deserializes the input buffer directly into the appropriate `VoteStateVersions` variant.
    ///
    /// V0_23_5 is not supported. All other versions (V1_14_11, V3, V4) are deserialized as-is
    /// without any version coercion.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8]) -> Result<Self, InstructionError> {
        use {
            crate::state::vote_state_deserialize::{
                deserialize_vote_state_into_v1_14_11, deserialize_vote_state_into_v3,
                deserialize_vote_state_into_v4, SourceVersion,
            },
            std::mem::MaybeUninit,
        };

        let mut cursor = std::io::Cursor::new(input);

        let variant = solana_serialize_utils::cursor::read_u32(&mut cursor)?;
        match variant {
            // V0_23_5 not supported.
            0 => Err(InstructionError::InvalidAccountData),
            // V1_14_11
            1 => {
                let mut vote_state = Box::new(MaybeUninit::uninit());
                deserialize_vote_state_into_v1_14_11(&mut cursor, vote_state.as_mut_ptr())?;
                let vote_state =
                    unsafe { Box::from_raw(Box::into_raw(vote_state) as *mut VoteState1_14_11) };
                Ok(VoteStateVersions::V1_14_11(vote_state))
            }
            // V3
            2 => {
                let mut vote_state = Box::new(MaybeUninit::uninit());
                deserialize_vote_state_into_v3(&mut cursor, vote_state.as_mut_ptr(), true)?;
                let vote_state =
                    unsafe { Box::from_raw(Box::into_raw(vote_state) as *mut VoteStateV3) };
                Ok(VoteStateVersions::V3(vote_state))
            }
            // V4
            3 => {
                let mut vote_state = Box::new(MaybeUninit::uninit());
                deserialize_vote_state_into_v4(
                    &mut cursor,
                    vote_state.as_mut_ptr(),
                    SourceVersion::V4,
                )?;
                let vote_state =
                    unsafe { Box::from_raw(Box::into_raw(vote_state) as *mut VoteStateV4) };
                Ok(VoteStateVersions::V4(vote_state))
            }
            _ => Err(InstructionError::InvalidAccountData),
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

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::state::{VoteInit, BLS_PUBLIC_KEY_COMPRESSED_SIZE, DEFAULT_PRIOR_VOTERS_OFFSET},
        solana_clock::Clock,
    };

    #[test]
    fn test_default_vote_state_is_uninitialized() {
        // The default `VoteStateV3` is stored to de-initialize a zero-balance vote account,
        // so must remain such that `VoteStateVersions::is_uninitialized()` returns true
        // when called on a `VoteStateVersions` that stores it
        assert!(VoteStateVersions::new_v3(VoteStateV3::default()).is_uninitialized());
    }

    #[test]
    fn test_is_correct_size_and_initialized() {
        // Check all zeroes
        let mut vote_account_data = vec![0; VoteStateV3::size_of()];
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check default VoteStateV3
        let default_account_state = VoteStateVersions::new_v3(VoteStateV3::default());
        VoteStateV3::serialize(&default_account_state, &mut vote_account_data).unwrap();
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check non-zero data shorter than offset index used
        let short_data = vec![1; DEFAULT_PRIOR_VOTERS_OFFSET];
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &short_data
        ));

        // Check non-zero large account
        let mut large_vote_data = vec![1; 2 * VoteStateV3::size_of()];
        let default_account_state = VoteStateVersions::new_v3(VoteStateV3::default());
        VoteStateV3::serialize(&default_account_state, &mut large_vote_data).unwrap();
        assert!(!VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check populated VoteStateV3
        let vote_state = VoteStateV3::new(
            &VoteInit {
                node_pubkey: Pubkey::new_unique(),
                authorized_voter: Pubkey::new_unique(),
                authorized_withdrawer: Pubkey::new_unique(),
                commission: 0,
            },
            &Clock::default(),
        );
        let account_state = VoteStateVersions::new_v3(vote_state.clone());
        VoteStateV3::serialize(&account_state, &mut vote_account_data).unwrap();
        assert!(VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));

        // Check old VoteStateV3 that hasn't been upgraded to newest version yet
        let old_vote_state = VoteState1_14_11::from(vote_state);
        let account_state = VoteStateVersions::V1_14_11(Box::new(old_vote_state));
        let mut vote_account_data = vec![0; VoteState1_14_11::size_of()];
        VoteStateV3::serialize(&account_state, &mut vote_account_data).unwrap();
        assert!(VoteStateVersions::is_correct_size_and_initialized(
            &vote_account_data
        ));
    }

    #[test]
    fn test_vote_state_version_conversion_bls_pubkey() {
        let vote_pubkey = Pubkey::new_unique();

        // All versions before v4 should result in `None` for BLS pubkey.
        let v1_14_11_state = VoteState1_14_11::default();
        let v1_14_11_versioned = VoteStateVersions::V1_14_11(Box::new(v1_14_11_state));

        let v3_state = VoteStateV3::default();
        let v3_versioned = VoteStateVersions::V3(Box::new(v3_state));

        for versioned in [v1_14_11_versioned, v3_versioned] {
            let converted = versioned.try_convert_to_v4(&vote_pubkey).unwrap();
            assert_eq!(converted.bls_pubkey_compressed, None);
        }

        // v4 to v4 conversion should preserve the BLS pubkey.
        let test_bls_key = [128u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE];
        let v4_state = VoteStateV4 {
            bls_pubkey_compressed: Some(test_bls_key),
            ..VoteStateV4::default()
        };
        let v4_versioned = VoteStateVersions::V4(Box::new(v4_state));
        let converted = v4_versioned.try_convert_to_v4(&vote_pubkey).unwrap();
        assert_eq!(converted.bls_pubkey_compressed, Some(test_bls_key));
    }

    #[test]
    fn test_vote_state_versions_deserialize() {
        let ser_deser = |original: VoteStateVersions| {
            let serialized = bincode::serialize(&original).unwrap();
            VoteStateVersions::deserialize(&serialized)
        };

        let v1_14_11 = VoteStateVersions::V1_14_11(Box::default());
        assert_eq!(
            ser_deser(v1_14_11.clone()),
            Ok(v1_14_11), // <-- Matches original
        );

        let v3 = VoteStateVersions::V3(Box::default());
        assert_eq!(
            ser_deser(v3.clone()),
            Ok(v3), // <-- Matches original
        );

        let v4 = VoteStateVersions::V4(Box::default());
        assert_eq!(
            ser_deser(v4.clone()),
            Ok(v4), // <-- Matches original
        );
    }
}
