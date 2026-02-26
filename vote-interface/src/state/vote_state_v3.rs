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
#[cfg(any(target_os = "solana", feature = "bincode"))]
use solana_instruction_error::InstructionError;
use {
    super::{BlockTimestamp, CircBuf, LandedVote, Lockout, VoteInit},
    crate::{authorized_voters::AuthorizedVoters, state::DEFAULT_PRIOR_VOTERS_OFFSET},
    solana_clock::{Clock, Epoch, Slot},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
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

    #[deprecated(
        since = "5.1.0",
        note = "Use `rent.minimum_balance(VoteStateV3::size_of())` directly"
    )]
    pub fn get_rent_exempt_reserve(rent: &Rent) -> u64 {
        rent.minimum_balance(VoteStateV3::size_of())
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // see test_vote_state_size_of.
    }

    pub fn is_uninitialized(&self) -> bool {
        self.authorized_voters.is_empty()
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8]) -> Result<Self, InstructionError> {
        let mut vote_state = Self::default();
        Self::deserialize_into(input, &mut vote_state)?;
        Ok(vote_state)
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided `VoteStateV3`.
    ///
    /// V0_23_5 is not supported. Supported versions: V1_14_11, V3.
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
    /// V0_23_5 is not supported. Supported versions: V1_14_11, V3.
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
            // Variant 0 is not a valid vote state.
            0 => Err(InstructionError::InvalidAccountData),
            // V1_14_11
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

    pub fn current_epoch(&self) -> Epoch {
        self.epoch_credits.last().map_or(0, |v| v.0)
    }

    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteStateV3 to the Rewards program to trade credits for lamports.
    pub fn credits(&self) -> u64 {
        self.epoch_credits.last().map_or(0, |v| v.1)
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        const VERSION_OFFSET: usize = 4;
        const DEFAULT_PRIOR_VOTERS_END: usize = VERSION_OFFSET + DEFAULT_PRIOR_VOTERS_OFFSET;
        data.len() == VoteStateV3::size_of()
            && data[VERSION_OFFSET..DEFAULT_PRIOR_VOTERS_END] != [0; DEFAULT_PRIOR_VOTERS_OFFSET]
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{VoteState1_14_11, VoteStateVersions, MAX_LOCKOUT_HISTORY},
            *,
        },
        arbitrary::Unstructured,
        bincode::serialized_size,
        core::mem::MaybeUninit,
        rand::Rng,
        solana_instruction::error::InstructionError,
    };

    #[test]
    fn test_size_of() {
        let vote_state = VoteStateV3::get_max_sized_vote_state();
        let vote_state = VoteStateVersions::new_v3(vote_state);
        let size = serialized_size(&vote_state).unwrap();
        assert_eq!(VoteStateV3::size_of() as u64, size);
    }

    #[test]
    fn test_minimum_balance() {
        let rent = solana_rent::Rent::default();
        let minimum_balance = rent.minimum_balance(VoteStateV3::size_of());
        // golden, may need updating when vote_state grows
        assert!(minimum_balance as f64 / 10f64.powf(9.0) < 0.04)
    }

    #[test]
    fn test_vote_serialize() {
        let mut buffer: Vec<u8> = vec![0; VoteStateV3::size_of()];
        let mut vote_state = VoteStateV3::default();
        vote_state
            .votes
            .resize(MAX_LOCKOUT_HISTORY, LandedVote::default());
        vote_state.root_slot = Some(1);
        let versioned = VoteStateVersions::new_v3(vote_state);
        assert!(VoteStateV3::serialize(&versioned, &mut buffer[0..4]).is_err());
        VoteStateV3::serialize(&versioned, &mut buffer).unwrap();
        assert_eq!(
            VoteStateV3::deserialize(&buffer).unwrap(),
            versioned.try_convert_to_v3().unwrap()
        );
    }

    #[test]
    fn test_vote_deserialize_into() {
        // base case
        let target_vote_state = VoteStateV3::default();
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v3(target_vote_state.clone())).unwrap();

        let mut test_vote_state = VoteStateV3::default();
        VoteStateV3::deserialize_into(&vote_state_buf, &mut test_vote_state).unwrap();

        assert_eq!(target_vote_state, test_vote_state);

        // variant
        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV3>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let target_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let vote_state_buf = bincode::serialize(&target_vote_state_versions).unwrap();

            // Skip any v4 since they can't convert to v3.
            if let Ok(target_vote_state) = target_vote_state_versions.try_convert_to_v3() {
                let mut test_vote_state = VoteStateV3::default();
                VoteStateV3::deserialize_into(&vote_state_buf, &mut test_vote_state).unwrap();

                assert_eq!(target_vote_state, test_vote_state);
            }
        }
    }

    #[test]
    fn test_vote_deserialize_into_trailing_data() {
        let target_vote_state = VoteStateV3::new_rand_for_tests(Pubkey::new_unique(), 42);
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v3(target_vote_state.clone())).unwrap();

        // Trailing garbage data is ignored.
        let mut buf_with_garbage = vote_state_buf.clone();
        buf_with_garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut test_vote_state = VoteStateV3::default();
        VoteStateV3::deserialize_into(&buf_with_garbage, &mut test_vote_state).unwrap();
        assert_eq!(target_vote_state, test_vote_state);

        // Trailing zeroes are ignored.
        let mut buf_with_zeroes = vote_state_buf;
        buf_with_zeroes.extend_from_slice(&[0u8; 64]);
        let mut test_vote_state = VoteStateV3::default();
        VoteStateV3::deserialize_into(&buf_with_zeroes, &mut test_vote_state).unwrap();
        assert_eq!(target_vote_state, test_vote_state);
    }

    #[test]
    fn test_vote_deserialize_into_error() {
        let target_vote_state = VoteStateV3::new_rand_for_tests(Pubkey::new_unique(), 42);
        let mut vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v3(target_vote_state.clone())).unwrap();
        let len = vote_state_buf.len();
        vote_state_buf.truncate(len - 1);

        let mut test_vote_state = VoteStateV3::default();
        VoteStateV3::deserialize_into(&vote_state_buf, &mut test_vote_state).unwrap_err();
        assert_eq!(test_vote_state, VoteStateV3::default());
    }

    #[test]
    fn test_vote_deserialize_into_error_with_pre_state() {
        // Start with a fully-populated state with heap allocations.
        let mut vote_state = VoteStateV3::new_rand_for_tests(Pubkey::new_unique(), 42);
        vote_state.epoch_credits = vec![(0, 100, 0), (1, 200, 100), (2, 300, 200)];

        // Deserialize truncated buffer — triggers error + DropGuard.
        let mut buf =
            bincode::serialize(&VoteStateVersions::new_v3(VoteStateV3::default())).unwrap();
        buf.truncate(buf.len() - 1);

        VoteStateV3::deserialize_into(&buf, &mut vote_state).unwrap_err();
        // DropGuard should have reset to default despite pre-existing heap data.
        assert_eq!(vote_state, VoteStateV3::default());
    }

    #[test]
    fn test_deserialize_into_uninit_no_reset_on_error() {
        // Contrast with `test_vote_deserialize_into_error` which verifies
        // that `deserialize_into` resets to `T::default()` via DropGuard.
        // `deserialize_into_uninit` does NOT reset — the MaybeUninit may
        // remain partially written and must not be assumed initialized.
        let target = VoteStateV3::new_rand_for_tests(Pubkey::new_unique(), 42);
        let mut buf = bincode::serialize(&VoteStateVersions::new_v3(target)).unwrap();
        buf.truncate(buf.len() - 1);

        let mut test_vote_state = MaybeUninit::uninit();
        let err = VoteStateV3::deserialize_into_uninit(&buf, &mut test_vote_state);
        assert_eq!(err, Err(InstructionError::InvalidAccountData));
        // test_vote_state is NOT guaranteed initialized — must not assume_init.
    }

    #[test]
    fn test_vote_deserialize_into_uninit() {
        // base case
        let target_vote_state = VoteStateV3::default();
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v3(target_vote_state.clone())).unwrap();

        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV3::deserialize_into_uninit(&vote_state_buf, &mut test_vote_state).unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };

        assert_eq!(target_vote_state, test_vote_state);

        // variant
        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV3>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let target_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let vote_state_buf = bincode::serialize(&target_vote_state_versions).unwrap();

            // Skip any v4 since they can't convert to v3.
            if let Ok(target_vote_state) = target_vote_state_versions.try_convert_to_v3() {
                let mut test_vote_state = MaybeUninit::uninit();
                VoteStateV3::deserialize_into_uninit(&vote_state_buf, &mut test_vote_state)
                    .unwrap();
                let test_vote_state = unsafe { test_vote_state.assume_init() };

                assert_eq!(target_vote_state, test_vote_state);
            }
        }
    }

    #[test]
    fn test_vote_deserialize_into_uninit_trailing_data() {
        let target_vote_state = VoteStateV3::new_rand_for_tests(Pubkey::new_unique(), 42);
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v3(target_vote_state.clone())).unwrap();

        // Trailing garbage data is ignored.
        let mut buf_with_garbage = vote_state_buf.clone();
        buf_with_garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV3::deserialize_into_uninit(&buf_with_garbage, &mut test_vote_state).unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };
        assert_eq!(target_vote_state, test_vote_state);

        // Trailing zeroes are ignored.
        let mut buf_with_zeroes = vote_state_buf;
        buf_with_zeroes.extend_from_slice(&[0u8; 64]);
        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV3::deserialize_into_uninit(&buf_with_zeroes, &mut test_vote_state).unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };
        assert_eq!(target_vote_state, test_vote_state);
    }

    #[test]
    fn test_vote_deserialize_into_uninit_nopanic() {
        // base case
        let mut test_vote_state = MaybeUninit::uninit();
        let e = VoteStateV3::deserialize_into_uninit(&[], &mut test_vote_state).unwrap_err();
        assert_eq!(e, InstructionError::InvalidAccountData);

        // variant
        let serialized_len_x4 = serialized_size(&VoteStateV3::default()).unwrap() * 4;
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
            let test_res = VoteStateV3::deserialize_into_uninit(&raw_data, &mut test_vote_state);

            // Test with bincode for consistency.
            let bincode_res = bincode::deserialize::<VoteStateVersions>(&raw_data)
                .map_err(|_| InstructionError::InvalidAccountData)
                .and_then(|versioned| versioned.try_convert_to_v3());

            if test_res.is_err() {
                assert!(bincode_res.is_err());
            } else {
                let test_vote_state = unsafe { test_vote_state.assume_init() };
                assert_eq!(test_vote_state, bincode_res.unwrap());
            }
        }
    }

    #[test]
    fn test_vote_deserialize_into_uninit_ill_sized() {
        // provide 4x the minimum struct size in bytes to ensure we typically touch every field
        let struct_bytes_x4 = std::mem::size_of::<VoteStateV3>() * 4;
        for _ in 0..1000 {
            let raw_data: Vec<u8> = (0..struct_bytes_x4).map(|_| rand::random::<u8>()).collect();
            let mut unstructured = Unstructured::new(&raw_data);

            let original_vote_state_versions =
                VoteStateVersions::arbitrary(&mut unstructured).unwrap();
            let original_buf = bincode::serialize(&original_vote_state_versions).unwrap();

            // Skip any v4 since they can't convert to v3.
            if !matches!(original_vote_state_versions, VoteStateVersions::V4(_)) {
                let mut truncated_buf = original_buf.clone();
                let mut expanded_buf = original_buf.clone();

                truncated_buf.resize(original_buf.len() - 8, 0);
                expanded_buf.resize(original_buf.len() + 8, 0);

                // truncated fails
                let mut test_vote_state = MaybeUninit::uninit();
                let test_res =
                    VoteStateV3::deserialize_into_uninit(&truncated_buf, &mut test_vote_state);
                // `deserialize_into_uninit` will eventually call into
                // `try_convert_to_v3`, so we have alignment in the following map.
                let bincode_res = bincode::deserialize::<VoteStateVersions>(&truncated_buf)
                    .map_err(|_| InstructionError::InvalidAccountData)
                    .and_then(|versioned| versioned.try_convert_to_v3());

                assert!(test_res.is_err());
                assert!(bincode_res.is_err());

                // expanded succeeds
                let mut test_vote_state = MaybeUninit::uninit();
                VoteStateV3::deserialize_into_uninit(&expanded_buf, &mut test_vote_state).unwrap();
                // `deserialize_into_uninit` will eventually call into
                // `try_convert_to_v3`, so we have alignment in the following map.
                let bincode_res = bincode::deserialize::<VoteStateVersions>(&expanded_buf)
                    .map_err(|_| InstructionError::InvalidAccountData)
                    .and_then(|versioned| versioned.try_convert_to_v3());

                let test_vote_state = unsafe { test_vote_state.assume_init() };
                assert_eq!(test_vote_state, bincode_res.unwrap());
            }
        }
    }

    #[test]
    fn test_deserialize_invalid_variant_tags() {
        let mut buf = vec![0u8; VoteStateV3::size_of()];

        // Tag 0 (V0_23_5 — rejected).
        let mut vs = VoteStateV3::default();
        assert_eq!(
            VoteStateV3::deserialize_into(&buf, &mut vs),
            Err(InstructionError::InvalidAccountData)
        );

        // Tag 3 (V4 — rejected by V3 deserializer).
        buf[..4].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            VoteStateV3::deserialize_into(&buf, &mut vs),
            Err(InstructionError::InvalidAccountData)
        );

        // Tag 4 (unknown).
        buf[..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            VoteStateV3::deserialize_into(&buf, &mut vs),
            Err(InstructionError::InvalidAccountData)
        );

        // Tag u32::MAX.
        buf[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            VoteStateV3::deserialize_into(&buf, &mut vs),
            Err(InstructionError::InvalidAccountData)
        );
    }

    #[test]
    fn test_invalid_option_bool_discriminants() {
        let mut vote_state = VoteStateV3::default();
        vote_state.root_slot = Some(42);
        let valid_buf = bincode::serialize(&VoteStateVersions::new_v3(vote_state)).unwrap();

        // root_slot Option discriminant.
        // tag(4) + node_pubkey(32) + authorized_withdrawer(32) + commission(1) +
        // votes_count(8)
        let root_slot_offset = 4 + 32 + 32 + 1 + 8;
        assert_eq!(valid_buf[root_slot_offset], 1); // Some

        {
            let mut buf = valid_buf.clone();
            buf[root_slot_offset] = 2;
            let mut vs = VoteStateV3::default();
            assert_eq!(
                VoteStateV3::deserialize_into(&buf, &mut vs),
                Err(InstructionError::InvalidAccountData)
            );
        }

        // CircBuf is_empty bool discriminant.
        // discriminant(1) + value(8) + auth_voters_count(8) +
        // prior_buf(32*48) + prior_idx(8)
        let is_empty_offset = root_slot_offset + 1 + 8 + 8 + 32 * 48 + 8;
        assert_eq!(valid_buf[is_empty_offset], 1); // true

        {
            let mut buf = valid_buf.clone();
            buf[is_empty_offset] = 2;
            let mut vs = VoteStateV3::default();
            assert_eq!(
                VoteStateV3::deserialize_into(&buf, &mut vs),
                Err(InstructionError::InvalidAccountData)
            );
        }
    }

    #[test]
    fn test_has_latency() {
        // V1_14_11 → V3: all latencies should be 0.
        let mut v1_state = VoteState1_14_11::default();
        v1_state.votes.push_back(Lockout::new(100));
        v1_state.votes.push_back(Lockout::new(200));
        let buf = bincode::serialize(&VoteStateVersions::V1_14_11(Box::new(v1_state))).unwrap();
        let deserialized = VoteStateV3::deserialize(&buf).unwrap();
        assert_eq!(deserialized.votes.len(), 2);
        for vote in &deserialized.votes {
            assert_eq!(vote.latency, 0);
        }

        // V3 with non-zero latency: preserved.
        let mut v3_state = VoteStateV3::default();
        v3_state.votes.push_back(LandedVote {
            latency: 42,
            lockout: Lockout::new(100),
        });
        v3_state.votes.push_back(LandedVote {
            latency: 7,
            lockout: Lockout::new(200),
        });
        let buf = bincode::serialize(&VoteStateVersions::new_v3(v3_state)).unwrap();
        let deserialized = VoteStateV3::deserialize(&buf).unwrap();
        assert_eq!(deserialized.votes[0].latency, 42);
        assert_eq!(deserialized.votes[1].latency, 7);
    }

    #[test]
    fn test_empty_collections_round_trip() {
        // Populated scalar fields, all collections empty.
        let vote_state = VoteStateV3 {
            node_pubkey: Pubkey::new_unique(),
            authorized_withdrawer: Pubkey::new_unique(),
            commission: 50,
            root_slot: Some(100),
            ..VoteStateV3::default()
        };
        let versioned = VoteStateVersions::new_v3(vote_state.clone());
        let buf = bincode::serialize(&versioned).unwrap();
        let deserialized = VoteStateV3::deserialize(&buf).unwrap();
        assert_eq!(vote_state, deserialized);
    }
}
