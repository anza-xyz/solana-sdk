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
    frozen_abi(digest = "ALZS4x22Ga8M6KkLVgdEJu3ZQUUSBkFHAkErmSvFLzUM"),
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
    /// V0_23_5 is not supported. Supported versions: V1_14_11, V3, V4.
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
    /// V0_23_5 is not supported. Supported versions: V1_14_11, V3, V4.
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

    #[cfg(test)]
    fn new_rand_for_tests(node_pubkey: Pubkey, root_slot: Slot) -> Self {
        let votes = (1..32)
            .map(|x| LandedVote {
                latency: 0,
                lockout: super::Lockout::new_with_confirmation_count(
                    u64::from(x).saturating_add(root_slot),
                    32_u32.saturating_sub(x),
                ),
            })
            .collect();
        Self {
            node_pubkey,
            root_slot: Some(root_slot),
            votes,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{VoteStateVersions, BLS_PUBLIC_KEY_COMPRESSED_SIZE, MAX_LOCKOUT_HISTORY},
            *,
        },
        arbitrary::Unstructured,
        bincode::serialized_size,
        core::mem::MaybeUninit,
        rand::Rng,
        solana_instruction::error::InstructionError,
    };

    #[test]
    fn test_vote_state_v4_size_of() {
        let vote_state = VoteStateV4::get_max_sized_vote_state();
        let vote_state = VoteStateVersions::new_v4(vote_state);
        let size = serialized_size(&vote_state).unwrap();
        assert!(size < VoteStateV4::size_of() as u64); // v4 is smaller than the max size
    }

    #[test]
    fn test_minimum_balance() {
        let rent = solana_rent::Rent::default();
        let minimum_balance = rent.minimum_balance(VoteStateV4::size_of());
        // golden, may need updating when vote_state grows
        assert!(minimum_balance as f64 / 10f64.powf(9.0) < 0.04)
    }

    #[test]
    fn test_vote_serialize_v4() {
        // Use two different pubkeys to demonstrate that v4 ignores the
        // `vote_pubkey` parameter.
        let vote_pubkey_for_deserialize = Pubkey::new_unique();
        let vote_pubkey_for_convert = Pubkey::new_unique();

        let mut buffer: Vec<u8> = vec![0; VoteStateV4::size_of()];
        let mut vote_state = VoteStateV4::default();
        vote_state
            .votes
            .resize(MAX_LOCKOUT_HISTORY, LandedVote::default());
        vote_state.root_slot = Some(1);
        let versioned = VoteStateVersions::new_v4(vote_state);
        assert!(VoteStateV4::serialize(&versioned, &mut buffer[0..4]).is_err());
        VoteStateV4::serialize(&versioned, &mut buffer).unwrap();
        assert_eq!(
            VoteStateV4::deserialize(&buffer, &vote_pubkey_for_deserialize).unwrap(),
            versioned
                .try_convert_to_v4(&vote_pubkey_for_convert)
                .unwrap()
        );
    }

    #[test]
    fn test_vote_deserialize_into_v4() {
        let vote_pubkey = Pubkey::new_unique();

        // base case
        let target_vote_state = VoteStateV4::default();
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v4(target_vote_state.clone())).unwrap();

        let mut test_vote_state = VoteStateV4::default();
        VoteStateV4::deserialize_into(&vote_state_buf, &mut test_vote_state, &vote_pubkey).unwrap();

        assert_eq!(target_vote_state, test_vote_state);

        // variant
        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV4>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let target_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let vote_state_buf = bincode::serialize(&target_vote_state_versions).unwrap();
            let target_vote_state = target_vote_state_versions
                .try_convert_to_v4(&vote_pubkey)
                .unwrap();

            let mut test_vote_state = VoteStateV4::default();
            VoteStateV4::deserialize_into(&vote_state_buf, &mut test_vote_state, &vote_pubkey)
                .unwrap();

            assert_eq!(target_vote_state, test_vote_state);
        }
    }

    #[test]
    fn test_vote_deserialize_into_error_v4() {
        let vote_pubkey = Pubkey::new_unique();

        let target_vote_state = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 42);
        let mut vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v4(target_vote_state.clone())).unwrap();
        let len = vote_state_buf.len();
        vote_state_buf.truncate(len - 1);

        let mut test_vote_state = VoteStateV4::default();
        VoteStateV4::deserialize_into(&vote_state_buf, &mut test_vote_state, &vote_pubkey)
            .unwrap_err();
        assert_eq!(test_vote_state, VoteStateV4::default());
    }

    #[test]
    fn test_vote_deserialize_into_uninit_v4() {
        let vote_pubkey = Pubkey::new_unique();

        // base case
        let target_vote_state = VoteStateV4::default();
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v4(target_vote_state.clone())).unwrap();

        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV4::deserialize_into_uninit(&vote_state_buf, &mut test_vote_state, &vote_pubkey)
            .unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };

        assert_eq!(target_vote_state, test_vote_state);

        // variant
        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV4>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let target_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let vote_state_buf = bincode::serialize(&target_vote_state_versions).unwrap();
            let target_vote_state = target_vote_state_versions
                .try_convert_to_v4(&Pubkey::default())
                .unwrap();

            let mut test_vote_state = MaybeUninit::uninit();
            VoteStateV4::deserialize_into_uninit(
                &vote_state_buf,
                &mut test_vote_state,
                &Pubkey::default(),
            )
            .unwrap();
            let test_vote_state = unsafe { test_vote_state.assume_init() };

            assert_eq!(target_vote_state, test_vote_state);
        }
    }

    #[test]
    fn test_vote_deserialize_into_uninit_nopanic_v4() {
        let vote_pubkey = Pubkey::new_unique();

        // base case
        let mut test_vote_state = MaybeUninit::uninit();
        let e = VoteStateV4::deserialize_into_uninit(&[], &mut test_vote_state, &vote_pubkey)
            .unwrap_err();
        assert_eq!(e, InstructionError::InvalidAccountData);

        // variant
        let serialized_len_x4 = serialized_size(&VoteStateV4::default()).unwrap() * 4;
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let raw_data_length = rng.random_range(1..serialized_len_x4);
            let mut raw_data: Vec<u8> = (0..raw_data_length).map(|_| rng.random::<u8>()).collect();

            // pure random data will ~never have a valid enum tag, so lets help it out
            if raw_data_length >= 4 && rng.random::<bool>() {
                let tag = rng.random_range(1u8..=3);
                raw_data[0] = tag;
                raw_data[1] = 0;
                raw_data[2] = 0;
                raw_data[3] = 0;
            }

            // it is extremely improbable, though theoretically possible, for random bytes to be syntactically valid
            // so we only check that the parser does not panic and that it succeeds or fails exactly in line with bincode
            let mut test_vote_state = MaybeUninit::uninit();
            let test_res =
                VoteStateV4::deserialize_into_uninit(&raw_data, &mut test_vote_state, &vote_pubkey);
            let bincode_res = bincode::deserialize::<VoteStateVersions>(&raw_data)
                .map(|versioned| versioned.try_convert_to_v4(&vote_pubkey).unwrap());

            if test_res.is_err() {
                assert!(bincode_res.is_err());
            } else {
                let test_vote_state = unsafe { test_vote_state.assume_init() };
                assert_eq!(test_vote_state, bincode_res.unwrap());
            }
        }
    }

    #[test]
    fn test_vote_deserialize_into_uninit_ill_sized_v4() {
        let vote_pubkey = Pubkey::new_unique();

        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV4>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let original_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let original_buf = bincode::serialize(&original_vote_state_versions).unwrap();

            let mut truncated_buf = original_buf.clone();
            let mut expanded_buf = original_buf.clone();

            truncated_buf.resize(original_buf.len() - 8, 0);
            expanded_buf.resize(original_buf.len() + 8, 0);

            // truncated fails
            let mut test_vote_state = MaybeUninit::uninit();
            let test_res = VoteStateV4::deserialize_into_uninit(
                &truncated_buf,
                &mut test_vote_state,
                &vote_pubkey,
            );
            let bincode_res = bincode::deserialize::<VoteStateVersions>(&truncated_buf)
                .map(|versioned| versioned.try_convert_to_v4(&vote_pubkey).unwrap());

            assert!(test_res.is_err());
            assert!(bincode_res.is_err());

            // expanded succeeds
            let mut test_vote_state = MaybeUninit::uninit();
            VoteStateV4::deserialize_into_uninit(&expanded_buf, &mut test_vote_state, &vote_pubkey)
                .unwrap();
            let bincode_res = bincode::deserialize::<VoteStateVersions>(&expanded_buf)
                .map(|versioned| versioned.try_convert_to_v4(&vote_pubkey).unwrap());

            let test_vote_state = unsafe { test_vote_state.assume_init() };
            assert_eq!(test_vote_state, bincode_res.unwrap());
        }
    }

    #[test]
    fn test_vote_state_v4_bls_pubkey_compressed() {
        let vote_pubkey = Pubkey::new_unique();

        let run_test = |start, expected| {
            let versioned = VoteStateVersions::new_v4(start);
            let serialized = bincode::serialize(&versioned).unwrap();
            let deserialized = VoteStateV4::deserialize(&serialized, &vote_pubkey).unwrap();
            assert_eq!(deserialized.bls_pubkey_compressed, expected);
        };

        // First try `None`.
        let vote_state_none = VoteStateV4::default();
        assert_eq!(vote_state_none.bls_pubkey_compressed, None);
        run_test(vote_state_none, None);

        // Now try `Some`.
        let test_bls_key = [42u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE];
        let vote_state_some = VoteStateV4 {
            bls_pubkey_compressed: Some(test_bls_key),
            ..VoteStateV4::default()
        };
        assert_eq!(vote_state_some.bls_pubkey_compressed, Some(test_bls_key));
        run_test(vote_state_some, Some(test_bls_key));
    }
}
