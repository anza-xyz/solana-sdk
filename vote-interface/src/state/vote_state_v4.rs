#[cfg(feature = "bincode")]
use super::VoteStateVersions;
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi};
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
    frozen_abi(
        api_digest = "ALZS4x22Ga8M6KkLVgdEJu3ZQUUSBkFHAkErmSvFLzUM",
        abi_digest = "CFpc8LMQhpYBsNctM4n9o6rn6BQJ4mcTx6pveGtb7YcM"
    ),
    derive(AbiExample, StableAbi)
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

#[cfg(feature = "frozen-abi")]
impl solana_frozen_abi::rand::prelude::Distribution<VoteStateV4>
    for solana_frozen_abi::rand::distr::StandardUniform
{
    fn sample<R: solana_frozen_abi::rand::Rng + ?Sized>(&self, rng: &mut R) -> VoteStateV4 {
        let bls_pubkey_compressed = Some(std::array::from_fn(|_| rng.random()));
        let votes: VecDeque<_> = (0..rng.random_range(0..1000))
            .map(|_| LandedVote {
                latency: rng.random(),
                lockout: crate::state::Lockout::new(rng.random()),
            })
            .collect();
        let epoch_credits: Vec<_> = (0..rng.random_range(0..1000))
            .map(|_| (rng.random(), rng.random(), rng.random()))
            .collect();

        VoteStateV4 {
            node_pubkey: Pubkey::new_from_array(rng.random()),
            authorized_withdrawer: Pubkey::new_from_array(rng.random()),
            inflation_rewards_collector: Pubkey::new_from_array(rng.random()),
            block_revenue_collector: Pubkey::new_from_array(rng.random()),
            inflation_rewards_commission_bps: rng.random(),
            block_revenue_commission_bps: rng.random(),
            pending_delegator_rewards: rng.random(),
            bls_pubkey_compressed,
            votes,
            root_slot: Some(rng.random()),
            authorized_voters: AuthorizedVoters::new(
                rng.random(),
                Pubkey::new_from_array(rng.random()),
            ),
            epoch_credits,
            last_timestamp: BlockTimestamp {
                slot: rng.random(),
                timestamp: rng.random(),
            },
        }
    }
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
            super::{
                CircBuf, Lockout, VoteState1_14_11, VoteStateV3, VoteStateVersions,
                BLS_PUBLIC_KEY_COMPRESSED_SIZE, MAX_LOCKOUT_HISTORY,
            },
            *,
        },
        arbitrary::Unstructured,
        bincode::serialized_size,
        core::mem::MaybeUninit,
        rand::Rng,
        solana_instruction::error::InstructionError,
        test_case::test_matrix,
    };

    #[test]
    fn test_size_of() {
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
    fn test_new_with_defaults() {
        let vote_pubkey = Pubkey::new_unique();
        let vote_init = VoteInit {
            node_pubkey: Pubkey::new_unique(),
            authorized_voter: Pubkey::new_unique(),
            authorized_withdrawer: Pubkey::new_unique(),
            commission: 50,
        };
        let clock = Clock {
            epoch: 7,
            ..Clock::default()
        };
        let v4 = VoteStateV4::new_with_defaults(&vote_pubkey, &vote_init, &clock);

        assert_eq!(v4.node_pubkey, vote_init.node_pubkey);
        assert_eq!(v4.authorized_withdrawer, vote_init.authorized_withdrawer);
        assert_eq!(v4.inflation_rewards_commission_bps, 5000);
        assert_eq!(v4.inflation_rewards_collector, vote_pubkey);
        assert_eq!(v4.block_revenue_collector, vote_init.node_pubkey);
        assert_eq!(v4.block_revenue_commission_bps, 10_000);
        assert_eq!(v4.pending_delegator_rewards, 0);
        assert_eq!(v4.bls_pubkey_compressed, None);
        assert!(!v4.authorized_voters.is_empty());
    }

    #[test]
    fn test_vote_serialize() {
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
    fn test_vote_deserialize_into() {
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
    fn test_deserialize_into_reuse_across_success_and_failure() {
        let vote_pubkey = Pubkey::new_unique();
        let mut vote_state = VoteStateV4::default();

        // 1. Valid V4 data.
        let v4_a = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 100);
        let buf_a = bincode::serialize(&VoteStateVersions::new_v4(v4_a.clone())).unwrap();
        VoteStateV4::deserialize_into(&buf_a, &mut vote_state, &vote_pubkey).unwrap();
        assert_eq!(vote_state, v4_a);

        // 2. Different valid V4 data.
        let v4_b = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 200);
        let buf_b = bincode::serialize(&VoteStateVersions::new_v4(v4_b.clone())).unwrap();
        VoteStateV4::deserialize_into(&buf_b, &mut vote_state, &vote_pubkey).unwrap();
        assert_eq!(vote_state, v4_b);

        // 3. Invalid data — resets to default.
        let mut bad_buf = buf_b.clone();
        bad_buf.truncate(bad_buf.len() - 1);
        VoteStateV4::deserialize_into(&bad_buf, &mut vote_state, &vote_pubkey).unwrap_err();
        assert_eq!(vote_state, VoteStateV4::default());

        // 4. Valid again after error.
        VoteStateV4::deserialize_into(&buf_a, &mut vote_state, &vote_pubkey).unwrap();
        assert_eq!(vote_state, v4_a);
    }

    #[test]
    fn test_vote_deserialize_into_trailing_data() {
        let vote_pubkey = Pubkey::new_unique();
        let target_vote_state = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 42);
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v4(target_vote_state.clone())).unwrap();

        // Trailing garbage data is ignored.
        let mut buf_with_garbage = vote_state_buf.clone();
        buf_with_garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut test_vote_state = VoteStateV4::default();
        VoteStateV4::deserialize_into(&buf_with_garbage, &mut test_vote_state, &vote_pubkey)
            .unwrap();
        assert_eq!(target_vote_state, test_vote_state);

        // Trailing zeroes are ignored.
        let mut buf_with_zeroes = vote_state_buf;
        buf_with_zeroes.extend_from_slice(&[0u8; 64]);
        let mut test_vote_state = VoteStateV4::default();
        VoteStateV4::deserialize_into(&buf_with_zeroes, &mut test_vote_state, &vote_pubkey)
            .unwrap();
        assert_eq!(target_vote_state, test_vote_state);
    }

    #[test]
    fn test_vote_deserialize_into_error() {
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
    fn test_vote_deserialize_into_error_with_pre_state() {
        let vote_pubkey = Pubkey::new_unique();

        // Start with a fully-populated state with heap allocations.
        let mut vote_state = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 42);
        vote_state.epoch_credits = vec![(0, 100, 0), (1, 200, 100), (2, 300, 200)];

        // Deserialize truncated buffer — triggers error + DropGuard.
        let mut buf =
            bincode::serialize(&VoteStateVersions::new_v4(VoteStateV4::default())).unwrap();
        buf.truncate(buf.len() - 1);

        VoteStateV4::deserialize_into(&buf, &mut vote_state, &vote_pubkey).unwrap_err();
        // DropGuard should have reset to default despite pre-existing heap data.
        assert_eq!(vote_state, VoteStateV4::default());
    }

    #[test]
    fn test_deserialize_into_uninit_no_reset_on_error() {
        // Contrast with `test_vote_deserialize_into_error` which verifies
        // that `deserialize_into` resets to `T::default()` via DropGuard.
        // `deserialize_into_uninit` does NOT reset — the MaybeUninit may
        // remain partially written and must not be assumed initialized.
        let vote_pubkey = Pubkey::new_unique();
        let target = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 42);
        let mut buf = bincode::serialize(&VoteStateVersions::new_v4(target)).unwrap();
        buf.truncate(buf.len() - 1);

        let mut test_vote_state = MaybeUninit::uninit();
        let err = VoteStateV4::deserialize_into_uninit(&buf, &mut test_vote_state, &vote_pubkey);
        assert_eq!(err, Err(InstructionError::InvalidAccountData));
        // test_vote_state is NOT guaranteed initialized — must not assume_init.
    }

    #[test]
    fn test_vote_deserialize_into_uninit() {
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
    fn test_vote_deserialize_into_uninit_trailing_data() {
        let vote_pubkey = Pubkey::new_unique();
        let target_vote_state = VoteStateV4::new_rand_for_tests(Pubkey::new_unique(), 42);
        let vote_state_buf =
            bincode::serialize(&VoteStateVersions::new_v4(target_vote_state.clone())).unwrap();

        // Trailing garbage data is ignored.
        let mut buf_with_garbage = vote_state_buf.clone();
        buf_with_garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV4::deserialize_into_uninit(&buf_with_garbage, &mut test_vote_state, &vote_pubkey)
            .unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };
        assert_eq!(target_vote_state, test_vote_state);

        // Trailing zeroes are ignored.
        let mut buf_with_zeroes = vote_state_buf;
        buf_with_zeroes.extend_from_slice(&[0u8; 64]);
        let mut test_vote_state = MaybeUninit::uninit();
        VoteStateV4::deserialize_into_uninit(&buf_with_zeroes, &mut test_vote_state, &vote_pubkey)
            .unwrap();
        let test_vote_state = unsafe { test_vote_state.assume_init() };
        assert_eq!(target_vote_state, test_vote_state);
    }

    #[test]
    fn test_vote_deserialize_into_uninit_nopanic() {
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
    fn test_vote_deserialize_into_uninit_ill_sized() {
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
    fn test_bls_pubkey_compressed() {
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

    #[test]
    fn test_deserialize_invalid_variant_tags() {
        let vote_pubkey = Pubkey::new_unique();
        let mut buf = vec![0u8; VoteStateV4::size_of()];

        // Tag 0 (V0_23_5 — rejected).
        let mut vs = VoteStateV4::default();
        assert_eq!(
            VoteStateV4::deserialize_into(&buf, &mut vs, &vote_pubkey),
            Err(InstructionError::InvalidAccountData)
        );

        // Tag 4 (unknown).
        buf[..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            VoteStateV4::deserialize_into(&buf, &mut vs, &vote_pubkey),
            Err(InstructionError::InvalidAccountData)
        );

        // Tag u32::MAX.
        buf[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            VoteStateV4::deserialize_into(&buf, &mut vs, &vote_pubkey),
            Err(InstructionError::InvalidAccountData)
        );
    }

    #[test]
    fn test_invalid_option_discriminants() {
        let vote_pubkey = Pubkey::new_unique();
        let vote_state = VoteStateV4 {
            root_slot: Some(42),
            ..VoteStateV4::default()
        };
        let valid_buf = bincode::serialize(&VoteStateVersions::new_v4(vote_state)).unwrap();

        // bls_pubkey_compressed Option discriminant.
        // tag(4) + node_pubkey(32) + authorized_withdrawer(32) +
        // inflation_rewards_collector(32) + block_revenue_collector(32) +
        // commission_bps(2) + block_revenue_bps(2) + pending_rewards(8)
        let bls_offset = 4 + 32 + 32 + 32 + 32 + 2 + 2 + 8;
        assert_eq!(valid_buf[bls_offset], 0); // None

        {
            let mut buf = valid_buf.clone();
            buf[bls_offset] = 2;
            let mut vs = VoteStateV4::default();
            assert_eq!(
                VoteStateV4::deserialize_into(&buf, &mut vs, &vote_pubkey),
                Err(InstructionError::InvalidAccountData)
            );
        }

        // root_slot Option discriminant.
        // bls(1 for None) + votes_count(8)
        let root_slot_offset = bls_offset + 1 + 8;
        assert_eq!(valid_buf[root_slot_offset], 1); // Some

        {
            let mut buf = valid_buf.clone();
            buf[root_slot_offset] = 2;
            let mut vs = VoteStateV4::default();
            assert_eq!(
                VoteStateV4::deserialize_into(&buf, &mut vs, &vote_pubkey),
                Err(InstructionError::InvalidAccountData)
            );
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    #[test_matrix(
        [0u8, 50, 100, 255],
        [0usize, 1, 2]
    )]
    fn test_deserialize_prior_versions_simd_0185(commission: u8, prior_voters_count: usize) {
        let vote_pubkey = Pubkey::new_unique();
        let node_pubkey = Pubkey::new_unique();
        let root_slot = Some(42);
        let epoch_credits = vec![(0, 100, 0), (1, 200, 100)];
        let last_timestamp = BlockTimestamp {
            slot: 999,
            timestamp: 12345,
        };
        let mut prior_voters = CircBuf::default();
        for i in 0..prior_voters_count {
            prior_voters.append((Pubkey::new_unique(), i as u64 * 5, (i as u64 + 1) * 5));
        }

        // SIMD-0185 specifies the following defaults when converting older
        // vote state versions to V4:
        //
        //   inflation_rewards_collector:      vote_pubkey
        //   block_revenue_collector:          old_vote_state.node_pubkey
        //   inflation_rewards_commission_bps: 100 * (old_vote_state.commission as u16)
        //   block_revenue_commission_bps:     10_000 (100%)
        //   pending_delegator_rewards:        0
        //   bls_pubkey_compressed:            None
        let assert_simd_0185_defaults = |v4: &VoteStateV4| {
            assert_eq!(
                v4.inflation_rewards_commission_bps,
                u16::from(commission) * 100
            );
            assert_eq!(v4.block_revenue_commission_bps, 10_000);
            assert_eq!(v4.inflation_rewards_collector, vote_pubkey);
            assert_eq!(v4.block_revenue_collector, node_pubkey);
            assert_eq!(v4.pending_delegator_rewards, 0);
            assert_eq!(v4.bls_pubkey_compressed, None);

            // Assert fields after `prior_voters` survived `skip_prior_voters`.
            assert_eq!(v4.epoch_credits, epoch_credits);
            assert_eq!(v4.last_timestamp, last_timestamp);
        };

        // V1_14_11 → V4
        let v1_state = VoteState1_14_11 {
            node_pubkey,
            commission,
            root_slot,
            epoch_credits: epoch_credits.clone(),
            last_timestamp: last_timestamp.clone(),
            prior_voters: prior_voters.clone(),
            ..VoteState1_14_11::default()
        };
        let buf = bincode::serialize(&VoteStateVersions::V1_14_11(Box::new(v1_state))).unwrap();
        let v4 = VoteStateV4::deserialize(&buf, &vote_pubkey).unwrap();
        assert_simd_0185_defaults(&v4);

        // V3 → V4
        let v3_state = VoteStateV3 {
            node_pubkey,
            commission,
            root_slot,
            epoch_credits: epoch_credits.clone(),
            last_timestamp: last_timestamp.clone(),
            prior_voters: prior_voters.clone(),
            ..VoteStateV3::default()
        };
        let buf = bincode::serialize(&VoteStateVersions::new_v3(v3_state)).unwrap();
        let v4 = VoteStateV4::deserialize(&buf, &vote_pubkey).unwrap();
        assert_simd_0185_defaults(&v4);
    }

    #[test]
    fn test_has_latency() {
        let vote_pubkey = Pubkey::new_unique();

        // V1_14_11 → V4: all latencies should be 0.
        let mut v1_state = VoteState1_14_11::default();
        v1_state.votes.push_back(Lockout::new(100));
        v1_state.votes.push_back(Lockout::new(200));
        let buf = bincode::serialize(&VoteStateVersions::V1_14_11(Box::new(v1_state))).unwrap();
        let deserialized = VoteStateV4::deserialize(&buf, &vote_pubkey).unwrap();
        assert_eq!(deserialized.votes.len(), 2);
        for vote in &deserialized.votes {
            assert_eq!(vote.latency, 0);
        }

        // V4 with non-zero latency: preserved.
        let mut v4_state = VoteStateV4::default();
        v4_state.votes.push_back(LandedVote {
            latency: 42,
            lockout: Lockout::new(100),
        });
        let buf = bincode::serialize(&VoteStateVersions::new_v4(v4_state)).unwrap();
        let deserialized = VoteStateV4::deserialize(&buf, &vote_pubkey).unwrap();
        assert_eq!(deserialized.votes[0].latency, 42);
    }
}
