#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{AbiExample, StableAbi, StableAbiSample};
#[cfg(feature = "wincode")]
use wincode::ZeroCopy;
use {
    super::BLS_PUBLIC_KEY_COMPRESSED_SIZE,
    crate::state::{BlockTimestamp, VoteInitV2, VoteStateV4},
    solana_clock::{Clock, Epoch, Slot},
    solana_instruction_error::InstructionError,
    solana_nullable::{MaybeNull, Nullable},
    solana_pubkey::Pubkey,
    std::{
        cmp::Ordering,
        mem::{offset_of, size_of},
    },
};

/// Discriminate between the different vote state versions.
pub const VOTE_STATE_V5_DISCRIMINANT: u32 = 4;
/// The actual vote state v5 size.  Note that this is actually larger than `size_of::<VoteStateV5>()`.
/// The tail is padded with 0 to allow for adding fields in the future.
pub const VOTE_STATE_V5_SIZE: usize = 951;
/// Maximum number of entries in the various commissions related arrays.
pub const MAX_COMMISSION_CHANGES: usize = 4;
/// Maximum number of entries in the authorized voters array.
pub const MAX_AUTHORIZED_VOTERS: usize = 4;
/// Maximum number of entries in the accumulated lamports array.
pub const MAX_ACCUMULATED_LAMPORTS: usize = 5;

const NONE_LAST_TIMESTAMP: BlockTimestamp = BlockTimestamp {
    slot: u64::MAX,
    timestamp: 0,
};

/// Version 5 of VoteState as defined in
/// [SIMD](https://github.com/solana-foundation/solana-improvement-documents/pull/701).
///
/// Use constructors `from_account_data_ref` and `from_account_data_mut` for zero-copy access
/// when the memory is aligned and `from_account_data_unaligned` for an owned copy when the memory
/// is not aligned.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct VoteStateV5 {
    /// The vote state v5 tag.
    discriminant: u32,
    /// The node that owns this account.
    pub node_pubkey: Pubkey,
    /// The signer for withdrawals.
    pub authorized_withdrawer: Pubkey,
    /// The collector account for inflation rewards.
    pub inflation_rewards_collector: Pubkey,
    /// The collector account for block revenue.
    pub block_revenue_collector: Pubkey,
    /// The location where this validator resides.
    pub location: Location,
    /// Reward amount pending distribution to stake delegators.
    pub pending_delegator_rewards: u64,
    /// Number of entries in `inflation_rewards_commission_bps_epochs` and
    /// `inflation_rewards_commission_bps`.
    inflation_rewards_commission_bps_len: u32,
    /// Number of entries in `block_revenue_commission_bps_epochs` and
    /// `block_revenue_commission_bps`.
    block_revenue_commission_bps_len: u32,
    inflation_rewards_commission_bps_epochs: [Epoch; MAX_COMMISSION_CHANGES],
    inflation_rewards_commission_bps: [Commission; MAX_COMMISSION_CHANGES],
    block_revenue_commission_bps_epochs: [Epoch; MAX_COMMISSION_CHANGES],
    block_revenue_commission_bps: [Commission; MAX_COMMISSION_CHANGES],
    /// Compressed BLS pubkey.
    pub bls_pubkey_compressed: [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
    /// The latest slot that this validator voted in.
    pub latest_vote: MaybeNull<NullableSlot>,
    /// The latest root that this validator has observed.
    pub root_slot: MaybeNull<NullableSlot>,
    /// Number of entries in `authorized_votes`.
    authorized_voters_len: u32,
    /// Number of entries in `accumulated_lamports`.
    accumulated_lamports_len: u32,
    /// List of signers allowed to sign transactions along with the epoch when they became active.
    authorized_voters: [AuthorizedVoter; MAX_AUTHORIZED_VOTERS],
    /// List of lamports that the validator has accumulated in rewards but have not yet been paid out.
    /// Entries are packed from the left with trailing zeros
    accumulated_lamports: [AccumulatedLamports; MAX_ACCUMULATED_LAMPORTS],
    last_timestamp: BlockTimestamp,
    /// Reserved until rank support is introduced; must remain `u64::MAX`.
    pub rank_epoch: MaybeNull<NullableEpoch>,
    /// Reserved until rank support is introduced; must remain `u16::MAX`.
    pub rank: MaybeNull<NullableRank>,
    /// The first bytes of the spec's zeroed tail, which keep the struct free of padding: 618..624
    padding: [u8; 6],
}

#[cfg(feature = "wincode")]
impl VoteStateV5 {
    /// Returns a mutable view returning error if the memory is not aligned.
    ///
    /// WARN: this assumes that the state is valid.  Future accesses may panic if not.
    pub fn from_account_data_unchecked_mut(
        bytes: &mut [u8],
    ) -> Result<&mut Self, InstructionError> {
        Self::_from_account_data_mut(bytes, false)
    }

    /// Returns an immutable view returning error if the memory is not aligned.
    ///
    /// WARN: this assumes that the state is valid.  Future accesses may panic if not.
    pub fn from_account_data_unchecked_ref(bytes: &[u8]) -> Result<&Self, InstructionError> {
        Self::_from_account_data_ref(bytes, false)
    }

    /// Returns a mutable view returning error if the memory is not aligned or state is invalid.
    pub fn from_account_data_mut(bytes: &mut [u8]) -> Result<&mut Self, InstructionError> {
        Self::_from_account_data_mut(bytes, true)
    }

    /// Returns a immutable view returning error if the memory is not aligned or state is invalid.
    pub fn from_account_data_ref(bytes: &[u8]) -> Result<&Self, InstructionError> {
        Self::_from_account_data_ref(bytes, true)
    }

    /// Returns an owned copy when the memory is not aligned.
    pub fn from_account_data_unaligned(bytes: &[u8]) -> Result<Self, InstructionError> {
        if bytes.len() != VOTE_STATE_V5_SIZE {
            return Err(InstructionError::InvalidAccountData);
        }
        let (prefix, tail) = bytes.split_at(size_of::<Self>());
        let state: VoteStateV5 =
            wincode::deserialize(prefix).map_err(|_| InstructionError::InvalidAccountData)?;
        state.validate(tail).map(|()| state)
    }

    /// Writes the full state into `buf`.  `buf` need not be aligned.
    pub fn write_account_data(&self, buf: &mut [u8]) -> Result<(), InstructionError> {
        if buf.len() != VOTE_STATE_V5_SIZE {
            return Err(InstructionError::InvalidArgument);
        }
        let (prefix, tail) = buf.split_at_mut(size_of::<Self>());
        wincode::serialize_into(prefix, self).map_err(|_| InstructionError::InvalidArgument)?;
        tail.fill(0);
        Ok(())
    }

    fn _from_account_data_mut(
        bytes: &mut [u8],
        should_validate: bool,
    ) -> Result<&mut Self, InstructionError> {
        Self::_from_account_data_ref(bytes, should_validate)?;
        ZeroCopy::from_bytes_mut(&mut bytes[..size_of::<Self>()])
            .map_err(|_| InstructionError::InvalidAccountData)
    }

    fn _from_account_data_ref(
        bytes: &[u8],
        should_validate: bool,
    ) -> Result<&Self, InstructionError> {
        if bytes.len() != VOTE_STATE_V5_SIZE {
            return Err(InstructionError::InvalidAccountData);
        }
        let (prefix, tail) = bytes.split_at(size_of::<Self>());
        let state: &VoteStateV5 =
            ZeroCopy::from_bytes(prefix).map_err(|_| InstructionError::InvalidAccountData)?;
        if should_validate {
            state.validate(tail).map(|()| state)
        } else {
            if cfg!(debug_assertions) {
                state.validate(tail).unwrap();
            }
            Ok(state)
        }
    }

    fn validate(&self, zeroed: &[u8]) -> Result<(), InstructionError> {
        if self.is_valid_prefix() && Self::bytes_are_zero(zeroed) {
            Ok(())
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }
}

impl VoteStateV5 {
    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        let little_endian_4u32 = [4, 0, 0, 0];
        data.len() == VOTE_STATE_V5_SIZE && data[..4] == little_endian_4u32
    }

    pub fn new(
        vote_init: &VoteInitV2,
        inflation_rewards_collector: Pubkey,
        block_revenue_collector: Pubkey,
        location: Location,
        clock: &Clock,
    ) -> Self {
        let mut inflation_rewards_commission_bps = [Commission::new(0); MAX_COMMISSION_CHANGES];
        inflation_rewards_commission_bps[0] =
            Commission::new(vote_init.inflation_rewards_commission_bps);
        let mut inflation_rewards_commission_bps_epochs = [0; MAX_COMMISSION_CHANGES];
        inflation_rewards_commission_bps_epochs[0] = clock.epoch;
        let mut block_revenue_commission_bps = [Commission::new(0); MAX_COMMISSION_CHANGES];
        block_revenue_commission_bps[0] = Commission::new(vote_init.block_revenue_commission_bps);
        let mut block_revenue_commission_bps_epochs = [0; MAX_COMMISSION_CHANGES];
        block_revenue_commission_bps_epochs[0] = clock.epoch;
        let mut authorized_voters = std::array::from_fn(|_| AuthorizedVoter::default());
        authorized_voters[0] = AuthorizedVoter {
            epoch: clock.epoch,
            pubkey: vote_init.authorized_voter,
        };
        Self {
            discriminant: VOTE_STATE_V5_DISCRIMINANT,
            node_pubkey: vote_init.node_pubkey,
            authorized_withdrawer: vote_init.authorized_withdrawer,
            inflation_rewards_collector,
            block_revenue_collector,
            location,
            pending_delegator_rewards: 0,
            inflation_rewards_commission_bps_len: 1,
            block_revenue_commission_bps_len: 1,
            inflation_rewards_commission_bps_epochs,
            inflation_rewards_commission_bps,
            block_revenue_commission_bps_epochs,
            block_revenue_commission_bps,
            bls_pubkey_compressed: vote_init.authorized_voter_bls_pubkey,
            latest_vote: MaybeNull::default(),
            root_slot: MaybeNull::default(),
            authorized_voters_len: 1,
            accumulated_lamports_len: 0,
            authorized_voters,
            accumulated_lamports: std::array::from_fn(|_| AccumulatedLamports::default()),
            last_timestamp: NONE_LAST_TIMESTAMP,
            rank_epoch: MaybeNull::default(),
            rank: MaybeNull::default(),
            padding: [0; 6],
        }
    }

    /// Converts valid V4 state, assuming at most four authorized voters.
    pub fn from_vote_state_v4(
        v4: VoteStateV4,
        location: Location,
        epoch: Epoch,
    ) -> Result<Self, InstructionError> {
        let authorized_voters_len = v4.authorized_voters.len();
        let mut authorized_voters = std::array::from_fn(|_| AuthorizedVoter::default());
        for (entry, (&epoch, &pubkey)) in authorized_voters
            .iter_mut()
            .zip(v4.authorized_voters.iter())
        {
            *entry = AuthorizedVoter { epoch, pubkey };
        }

        let accumulated_lamports_len = v4.epoch_credits.len().min(MAX_ACCUMULATED_LAMPORTS);
        let mut accumulated_lamports: [_; MAX_ACCUMULATED_LAMPORTS] =
            std::array::from_fn(|_| AccumulatedLamports::default());
        for (entry, &(epoch, lamports, prev_lamports)) in accumulated_lamports.iter_mut().zip(
            v4.epoch_credits.iter().skip(
                v4.epoch_credits
                    .len()
                    .saturating_sub(MAX_ACCUMULATED_LAMPORTS),
            ),
        ) {
            *entry = AccumulatedLamports {
                epoch,
                lamports,
                prev_lamports,
            };
        }

        let state = Self {
            discriminant: VOTE_STATE_V5_DISCRIMINANT,
            node_pubkey: v4.node_pubkey,
            authorized_withdrawer: v4.authorized_withdrawer,
            inflation_rewards_collector: v4.inflation_rewards_collector,
            block_revenue_collector: v4.block_revenue_collector,
            location,
            pending_delegator_rewards: v4.pending_delegator_rewards,
            inflation_rewards_commission_bps_len: 1,
            block_revenue_commission_bps_len: 1,
            inflation_rewards_commission_bps_epochs: {
                let mut array = [0; MAX_COMMISSION_CHANGES];
                array[0] = epoch.saturating_add(2);
                array
            },
            inflation_rewards_commission_bps: {
                let mut array = [Commission::new(0); MAX_COMMISSION_CHANGES];
                array[0] = Commission::new(v4.inflation_rewards_commission_bps);
                array
            },
            block_revenue_commission_bps_epochs: {
                let mut array = [0; MAX_COMMISSION_CHANGES];
                array[0] = epoch.saturating_add(2);
                array
            },
            block_revenue_commission_bps: {
                let mut array = [Commission::new(0); MAX_COMMISSION_CHANGES];
                array[0] = Commission::new(v4.block_revenue_commission_bps);
                array
            },
            bls_pubkey_compressed: v4
                .bls_pubkey_compressed
                .ok_or(InstructionError::InvalidAccountData)?,
            latest_vote: v4
                .votes
                .back()
                .map(|v| MaybeNull::from(NullableSlot(v.slot())))
                .unwrap_or_default(),
            root_slot: v4
                .root_slot
                .map(|s| MaybeNull::from(NullableSlot(s)))
                .unwrap_or_default(),
            authorized_voters_len: u32::try_from(authorized_voters_len).expect("must fit in u32"),
            accumulated_lamports_len: u32::try_from(accumulated_lamports_len)
                .expect("must fit in u32"),
            authorized_voters,
            accumulated_lamports,
            last_timestamp: v4.last_timestamp.clone(),
            rank_epoch: MaybeNull::default(),
            rank: MaybeNull::default(),
            padding: [0; 6],
        };
        // V4 should always translate to a valid v5.  Just some defense in depth.
        if state.is_valid_prefix() {
            Ok(state)
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }

    pub fn last_timestamp(&self) -> Option<&BlockTimestamp> {
        (self.last_timestamp.slot != u64::MAX).then_some(&self.last_timestamp)
    }

    pub fn set_last_timestamp(&mut self, timestamp: Option<BlockTimestamp>) {
        match timestamp {
            None => self.last_timestamp = NONE_LAST_TIMESTAMP,
            Some(t) => self.last_timestamp = t,
        }
    }

    pub fn inflation_rewards_commission_ref(&self) -> CommissionScheduleRef<'_> {
        CommissionScheduleRef {
            epochs: &self.inflation_rewards_commission_bps_epochs
                [..self.inflation_rewards_commission_bps_len as usize],
            bps: &self.inflation_rewards_commission_bps
                [..self.inflation_rewards_commission_bps_len as usize],
        }
    }

    pub fn inflation_rewards_commission_mut(&mut self) -> CommissionScheduleMut<'_> {
        CommissionScheduleMut {
            epochs: &mut self.inflation_rewards_commission_bps_epochs,
            bps: &mut self.inflation_rewards_commission_bps,
            len: &mut self.inflation_rewards_commission_bps_len,
        }
    }

    pub fn block_revenue_commission_ref(&self) -> CommissionScheduleRef<'_> {
        CommissionScheduleRef {
            epochs: &self.block_revenue_commission_bps_epochs
                [..self.block_revenue_commission_bps_len as usize],
            bps: &self.block_revenue_commission_bps
                [..self.block_revenue_commission_bps_len as usize],
        }
    }

    pub fn block_revenue_commission_mut(&mut self) -> CommissionScheduleMut<'_> {
        CommissionScheduleMut {
            epochs: &mut self.block_revenue_commission_bps_epochs,
            bps: &mut self.block_revenue_commission_bps,
            len: &mut self.block_revenue_commission_bps_len,
        }
    }

    pub fn authorized_voters_ref(&self) -> AuthorizedVotersRef<'_> {
        AuthorizedVotersRef(&self.authorized_voters[..self.authorized_voters_len as usize])
    }

    pub fn authorized_voters_mut(&mut self) -> AuthorizedVotersMut<'_> {
        AuthorizedVotersMut {
            entries: &mut self.authorized_voters,
            len: &mut self.authorized_voters_len,
        }
    }

    pub fn accumulated_lamports_ref(&self) -> AccumulatedLamportsRef<'_> {
        AccumulatedLamportsRef(&self.accumulated_lamports[..self.accumulated_lamports_len as usize])
    }

    pub fn accumulated_lamports_mut(&mut self) -> AccumulatedLamportsMut<'_> {
        AccumulatedLamportsMut {
            entries: &mut self.accumulated_lamports,
            len: &mut self.accumulated_lamports_len,
        }
    }

    #[must_use]
    fn commission_is_valid(len: u32, epochs: &[u64], bps: &[Commission]) -> bool {
        let len = len as usize;
        len <= MAX_COMMISSION_CHANGES
            && Self::commission_schedule_is_valid(&epochs[..len], &bps[..len])
            && epochs[len..].iter().all(|b| b == &0)
            && bps[len..].iter().all(|b| b == &Commission(0))
    }

    #[must_use]
    fn commission_schedule_is_valid(epochs: &[Epoch], bps: &[Commission]) -> bool {
        epochs.len() == bps.len()
            && !epochs.is_empty()
            && epochs.len() <= MAX_COMMISSION_CHANGES
            && epochs.windows(2).all(|w| w[0] < w[1])
    }

    #[must_use]
    fn authorized_voters_is_valid(len: u32, data: &[AuthorizedVoter]) -> bool {
        let len = len as usize;
        !data.is_empty()
            && len <= MAX_AUTHORIZED_VOTERS
            && len <= data.len()
            && data[..len].windows(2).all(|w| w[0].epoch < w[1].epoch)
            && data
                .iter()
                .skip(len)
                .all(|i| i == &AuthorizedVoter::default())
    }

    #[must_use]
    fn accumulated_lamports_is_valid(len: u32, data: &[AccumulatedLamports]) -> bool {
        let len = len as usize;
        len <= MAX_ACCUMULATED_LAMPORTS
            && Self::accumulated_lamports_are_valid(&data[..len])
            && data
                .iter()
                .skip(len)
                .all(|i| i == &AccumulatedLamports::default())
    }

    #[must_use]
    #[cfg(not(target_os = "solana"))]
    fn bytes_are_zero(bytes: &[u8]) -> bool {
        // First compare u64 sized words and then the remaining tail byte by byte.
        let mut words = bytes.chunks_exact(size_of::<u64>());
        let chunks = words.by_ref().fold(0, |acc, word| {
            acc | u64::from_ne_bytes(word.try_into().expect("u64 is 8 bytes"))
        });
        let tail = words.remainder().iter().fold(0, |acc, byte| acc | byte);
        chunks | u64::from(tail) == 0
    }

    #[must_use]
    #[cfg(target_os = "solana")]
    fn bytes_are_zero(bytes: &[u8]) -> bool {
        // The reserved tail is the largest slice checked during validation.
        static ZEROES: [u8; VOTE_STATE_V5_SIZE - size_of::<VoteStateV5>()] =
            [0; VOTE_STATE_V5_SIZE - size_of::<VoteStateV5>()];
        bytes.chunks(ZEROES.len()).all(|chunk| {
            // SAFETY: Both slices contain at least chunk.len() initialized bytes.
            unsafe { solana_program_memory::sol_memcmp(chunk, &ZEROES, chunk.len()) == 0 }
        })
    }

    #[must_use]
    fn accumulated_lamports_are_valid(data: &[AccumulatedLamports]) -> bool {
        data.len() <= MAX_ACCUMULATED_LAMPORTS
            && data
                .iter()
                .filter(|entry| entry.is_alpenglow_migration_marker())
                .count()
                <= 1
            && data.windows(2).all(|w| {
                w[0].is_alpenglow_migration_marker()
                    || w[1].is_alpenglow_migration_marker()
                    || ((w[0].epoch < w[1].epoch)
                        && (w[1].prev_lamports == w[0].lamports)
                        && (w[0].prev_lamports <= w[0].lamports)
                        && w[1].prev_lamports <= w[1].lamports)
            })
    }

    #[must_use]
    fn is_valid_prefix(&self) -> bool {
        self.discriminant == VOTE_STATE_V5_DISCRIMINANT
            && Location::is_valid(self.location.x, self.location.y, self.location.z)
            && Self::commission_is_valid(
                self.inflation_rewards_commission_bps_len,
                &self.inflation_rewards_commission_bps_epochs,
                &self.inflation_rewards_commission_bps,
            )
            && Self::commission_is_valid(
                self.block_revenue_commission_bps_len,
                &self.block_revenue_commission_bps_epochs,
                &self.block_revenue_commission_bps,
            )
            && Self::authorized_voters_is_valid(self.authorized_voters_len, &self.authorized_voters)
            && Self::accumulated_lamports_is_valid(
                self.accumulated_lamports_len,
                &self.accumulated_lamports,
            )
            && Self::bytes_are_zero(&self.padding)
    }
}

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct NullableSlot(pub Slot);

impl Nullable for NullableSlot {
    const NONE: Self = Self(Slot::MAX);
}

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct NullableEpoch(pub Epoch);

impl Nullable for NullableEpoch {
    const NONE: Self = Self(Epoch::MAX);
}

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct NullableRank(pub u16);

impl Nullable for NullableRank {
    const NONE: Self = Self(u16::MAX);
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct AuthorizedVoter {
    pub epoch: u64,
    pub pubkey: Pubkey,
}

/// Stores the commission in basis-points.  It can be set above 100% but will be clamped to 100%
/// for reward calculations.
#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Commission(u16);

impl Commission {
    pub fn new(commission: u16) -> Self {
        Self(commission)
    }

    /// Commissions above 100% do not make sense.
    pub fn get(&self) -> u16 {
        self.0.min(10_000)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct AccumulatedLamports {
    pub epoch: u64,
    pub lamports: u64,
    pub prev_lamports: u64,
}

impl AccumulatedLamports {
    fn is_alpenglow_migration_marker(&self) -> bool {
        self.epoch == u64::MAX && self.lamports == u64::MAX && self.prev_lamports == u64::MAX
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "stable-abi", derive(AbiExample, StableAbi, StableAbiSample))]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
pub struct Location {
    x: i32,
    y: i32,
    z: i32,
}

impl Location {
    pub fn x(&self) -> i32 {
        self.x
    }

    pub fn y(&self) -> i32 {
        self.y
    }

    pub fn z(&self) -> i32 {
        self.z
    }

    pub fn try_new(x: i32, y: i32, z: i32) -> Option<Self> {
        Self::is_valid(x, y, z).then_some(Self { x, y, z })
    }

    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    fn is_valid(x: i32, y: i32, z: i32) -> bool {
        const COORD_MAX: i32 = 6_378_138;
        const SURFACE_DIST2: u64 = 40_680_631_590_769;
        const FLATTENING_CORRECTION: u64 = 442;
        const SURFACE_TOLERANCE: u64 = 12_756_274_000;

        let in_range = |c: i32| (-COORD_MAX..=COORD_MAX).contains(&c);
        if !(in_range(x) && in_range(y) && in_range(z)) {
            return false;
        }
        let square = |c: i32| (c as i64 * c as i64) as u64;
        let z2 = square(z);
        let dist2 = square(x) + square(y) + z2 + ((FLATTENING_CORRECTION * z2) >> 16);
        (SURFACE_DIST2 - SURFACE_TOLERANCE..=SURFACE_DIST2 + SURFACE_TOLERANCE).contains(&dist2)
    }
}

pub struct CommissionScheduleMut<'a> {
    epochs: &'a mut [Epoch],
    bps: &'a mut [Commission],
    len: &'a mut u32,
}

impl<'a> CommissionScheduleMut<'a> {
    pub fn epochs(&self) -> &[Epoch] {
        let len = *self.len as usize;
        &self.epochs[..len]
    }

    pub fn bps(&self) -> &[Commission] {
        let len = *self.len as usize;
        &self.bps[..len]
    }

    /// Records a commission rate starting at `effective_epoch`.
    /// The caller must calculate the effective epoch, including any required delay.
    pub fn update(
        &mut self,
        effective_epoch: Epoch,
        bps: Commission,
    ) -> Result<(), InstructionError> {
        let len = *self.len as usize;
        let last = len.checked_sub(1).expect("must contain at least one entry");
        let latest_epoch = self.epochs[last];
        match effective_epoch.cmp(&latest_epoch) {
            Ordering::Less => return Err(InstructionError::InvalidArgument),
            Ordering::Equal => {
                self.bps[last] = bps;
            }
            Ordering::Greater => match len.cmp(&MAX_COMMISSION_CHANGES) {
                Ordering::Less => {
                    self.epochs[len] = effective_epoch;
                    self.bps[len] = bps;
                    *self.len = self.len.saturating_add(1);
                }
                Ordering::Equal => {
                    self.epochs.rotate_left(1);
                    self.bps.rotate_left(1);
                    self.epochs[last] = effective_epoch;
                    self.bps[last] = bps;
                }
                Ordering::Greater => {
                    panic!("array has too many entries.")
                }
            },
        }
        Ok(())
    }
}

pub struct CommissionScheduleRef<'a> {
    pub epochs: &'a [Epoch],
    pub bps: &'a [Commission],
}

pub struct AccumulatedLamportsRef<'a>(pub &'a [AccumulatedLamports]);

pub struct AccumulatedLamportsMut<'a> {
    entries: &'a mut [AccumulatedLamports],
    len: &'a mut u32,
}

impl<'a> AccumulatedLamportsMut<'a> {
    pub fn entries(&self) -> &[AccumulatedLamports] {
        let len = *self.len as usize;
        &self.entries[..len]
    }

    /// Adds rewards for `epoch`, updating cumulative totals. Epochs cannot
    /// precede the latest non-marker entry. Errors leave the history unchanged.
    pub fn update(&mut self, epoch: Epoch, lamports: u64) -> Result<(), InstructionError> {
        let len = *self.len as usize;
        if len == 0 {
            self.append_entry(AccumulatedLamports {
                epoch,
                lamports,
                prev_lamports: 0,
            });
            return Ok(());
        }

        let latest_entry = &mut self.entries[len.checked_sub(1).expect("checked above")];
        if latest_entry.epoch > epoch && !latest_entry.is_alpenglow_migration_marker() {
            return Err(InstructionError::InvalidArgument);
        }

        if latest_entry.is_alpenglow_migration_marker() {
            let prev_lamports = if len >= 2 {
                let previous = &self.entries[len.checked_sub(2).expect("checked above")];
                if previous.epoch >= epoch {
                    return Err(InstructionError::InvalidArgument);
                }
                previous.lamports
            } else {
                0
            };
            self.append_entry(AccumulatedLamports {
                epoch,
                lamports: lamports.saturating_add(prev_lamports),
                prev_lamports,
            });
            return Ok(());
        }

        if latest_entry.epoch == epoch {
            latest_entry.lamports = latest_entry.lamports.saturating_add(lamports);
            return Ok(());
        }

        debug_assert!(latest_entry.prev_lamports <= latest_entry.lamports);
        if latest_entry.prev_lamports == latest_entry.lamports {
            *latest_entry = AccumulatedLamports {
                epoch,
                lamports: latest_entry.lamports.saturating_add(lamports),
                prev_lamports: latest_entry.prev_lamports,
            };
            return Ok(());
        }

        let new_entry = AccumulatedLamports {
            epoch,
            lamports: latest_entry.lamports.saturating_add(lamports),
            prev_lamports: latest_entry.lamports,
        };
        self.append_entry(new_entry);
        Ok(())
    }

    fn append_entry(&mut self, entry: AccumulatedLamports) {
        let len = *self.len as usize;
        debug_assert!(len <= MAX_ACCUMULATED_LAMPORTS);
        if len < MAX_ACCUMULATED_LAMPORTS {
            self.entries[len] = entry;
            *self.len = self.len.saturating_add(1);
        } else {
            self.entries.rotate_left(1);
            self.entries[len.saturating_sub(1)] = entry;
        }
    }
}

pub struct AuthorizedVotersRef<'a>(pub &'a [AuthorizedVoter]);

pub struct AuthorizedVotersMut<'a> {
    entries: &'a mut [AuthorizedVoter],
    len: &'a mut u32,
}

impl<'a> AuthorizedVotersMut<'a> {
    pub fn entries(&self) -> &[AuthorizedVoter] {
        let len = *self.len as usize;
        &self.entries[..len]
    }

    /// Appends or replaces the latest signer starting at `effective_epoch`.
    /// The caller must calculate the effective epoch, including any required delay.
    pub fn update(
        &mut self,
        effective_epoch: Epoch,
        pubkey: Pubkey,
    ) -> Result<(), InstructionError> {
        let len = *self.len as usize;
        let Some(index) = len.checked_sub(1) else {
            self.entries[0] = AuthorizedVoter {
                epoch: effective_epoch,
                pubkey,
            };
            *self.len = 1;
            return Ok(());
        };
        match self.entries[index].epoch.cmp(&effective_epoch) {
            Ordering::Greater => Err(InstructionError::InvalidArgument),
            Ordering::Equal => {
                self.entries[index].pubkey = pubkey;
                Ok(())
            }
            Ordering::Less => {
                if len == MAX_AUTHORIZED_VOTERS {
                    return Err(InstructionError::InvalidInstructionData);
                }
                self.entries[len] = AuthorizedVoter {
                    epoch: effective_epoch,
                    pubkey,
                };
                *self.len = self.len.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Removes entries with epochs strictly less than `epoch`.
    pub fn purge_before(&mut self, epoch: Epoch) {
        let removed = self.entries().partition_point(|entry| entry.epoch < epoch);
        let len = *self.len as usize;
        let len = len.saturating_sub(removed);
        self.entries.rotate_left(removed);
        self.entries[len..].fill(AuthorizedVoter::default());
        *self.len = len as u32;
    }
}

const _: () = {
    assert!(size_of::<VoteStateV5>() == 624);
    assert!(offset_of!(VoteStateV5, location) == 132);
    assert!(offset_of!(VoteStateV5, pending_delegator_rewards) == 144);
    assert!(offset_of!(VoteStateV5, block_revenue_commission_bps_len) == 156);
    assert!(offset_of!(VoteStateV5, inflation_rewards_commission_bps_epochs) == 160);
    assert!(offset_of!(VoteStateV5, block_revenue_commission_bps_epochs) == 200);
    assert!(offset_of!(VoteStateV5, bls_pubkey_compressed) == 240);
    assert!(offset_of!(VoteStateV5, accumulated_lamports_len) == 308);
    assert!(offset_of!(VoteStateV5, authorized_voters) == 312);
    assert!(offset_of!(VoteStateV5, accumulated_lamports) == 472);
    assert!(offset_of!(VoteStateV5, last_timestamp) == 592);
    assert!(offset_of!(VoteStateV5, rank_epoch) == 608);
    assert!(offset_of!(VoteStateV5, rank) == 616);
    assert!(offset_of!(VoteStateV5, padding) == 618);
    assert!(size_of::<Location>() == 12);
    assert!(size_of::<AuthorizedVoter>() == 40);
    assert!(size_of::<AccumulatedLamports>() == 24);
    assert!(size_of::<BlockTimestamp>() == 16);
};

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use {super::*, bytemuck::Pod};

    #[repr(C, align(8))]
    struct Aligned([u8; VOTE_STATE_V5_SIZE + 8]);

    fn put<T: Pod>(buf: &mut [u8], off: usize, v: T) {
        buf[off..off + size_of::<T>()].copy_from_slice(bytemuck::bytes_of(&v));
    }

    #[test]
    fn zero_bytes_checks_unaligned_words_and_remainders() {
        let tail_len = VOTE_STATE_V5_SIZE - size_of::<VoteStateV5>();
        for offset in 0..8 {
            for len in (0..=17).chain([
                tail_len - 1,
                tail_len,
                tail_len + 1,
                2 * tail_len,
                2 * tail_len + 1,
            ]) {
                let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
                let bytes = &mut storage.0[offset..offset + len];
                assert!(
                    VoteStateV5::bytes_are_zero(bytes),
                    "offset {offset}, length {len}"
                );
                for index in 0..len {
                    for value in [1, 0x80] {
                        bytes[index] = value;
                        assert!(
                            !VoteStateV5::bytes_are_zero(bytes),
                            "offset {offset}, length {len}, index {index}, value {value}"
                        );
                    }
                    bytes[index] = 0;
                }
            }
        }
    }

    fn assert_state_round_trips(state: &VoteStateV5) {
        let mut storage = Aligned([0xff; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        state.write_account_data(data).unwrap();
        assert_eq!(VoteStateV5::from_account_data_ref(data).unwrap(), state);
        assert_eq!(VoteStateV5::from_account_data_mut(data).unwrap(), state);
        assert_eq!(
            &VoteStateV5::from_account_data_unaligned(data).unwrap(),
            state
        );
        let prefix = &data[..size_of::<VoteStateV5>()];
        assert_eq!(wincode::serialize(state).unwrap(), prefix);
        assert_eq!(
            &wincode::deserialize_exact::<VoteStateV5>(prefix).unwrap(),
            state
        );
    }

    #[test]
    fn new_initializes_valid_commissions_and_authorized_voter() {
        let epoch = 42;
        let inflation_rewards_commission_bps = 123;
        let block_revenue_commission_bps = 432;
        let vote_init = VoteInitV2 {
            authorized_voter: Pubkey::new_unique(),
            inflation_rewards_commission_bps,
            block_revenue_commission_bps,
            ..VoteInitV2::default()
        };
        let clock = Clock {
            epoch,
            ..Clock::default()
        };
        let state = VoteStateV5::new(
            &vote_init,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Location::try_new(4051542, 618526, 4870645).unwrap(),
            &clock,
        );
        let mut storage = Aligned([0xff; VOTE_STATE_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_STATE_V5_SIZE];
        state.write_account_data(buf).unwrap();
        let state = VoteStateV5::from_account_data_ref(buf).unwrap();
        assert_eq!(state.inflation_rewards_commission_ref().epochs, &[epoch]);
        assert_eq!(
            state.inflation_rewards_commission_ref().bps,
            &[Commission::new(inflation_rewards_commission_bps)]
        );
        assert_eq!(state.block_revenue_commission_ref().epochs, &[epoch]);
        assert_eq!(
            state.block_revenue_commission_ref().bps,
            &[Commission::new(block_revenue_commission_bps)]
        );
        assert_eq!(
            state.authorized_voters_ref().0,
            &[AuthorizedVoter {
                epoch,
                pubkey: vote_init.authorized_voter,
            }]
        );
    }

    #[test]
    fn last_timestamp_getter_decodes_account_data() {
        for (slot, timestamp) in [(0, 0), (42, -42), (u64::MAX - 1, i64::MAX), (u64::MAX, 0)] {
            let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
            sample(data);
            put(
                data,
                offset_of!(VoteStateV5, last_timestamp) + offset_of!(BlockTimestamp, slot),
                slot,
            );
            put(
                data,
                offset_of!(VoteStateV5, last_timestamp) + offset_of!(BlockTimestamp, timestamp),
                timestamp,
            );
            let expected = (slot != u64::MAX).then_some(BlockTimestamp { slot, timestamp });
            assert_eq!(
                VoteStateV5::from_account_data_ref(data)
                    .unwrap()
                    .last_timestamp(),
                expected.as_ref()
            );
            assert_eq!(
                VoteStateV5::from_account_data_unaligned(data)
                    .unwrap()
                    .last_timestamp(),
                expected.as_ref()
            );
        }
    }

    #[test]
    fn last_timestamp_setter_updates_and_clears_backing_account_data() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(data);
        for expected in [
            Some(BlockTimestamp {
                slot: 0,
                timestamp: 0,
            }),
            Some(BlockTimestamp {
                slot: 42,
                timestamp: i64::MIN,
            }),
            None,
            None,
            Some(BlockTimestamp {
                slot: u64::MAX - 1,
                timestamp: i64::MAX,
            }),
            None,
        ] {
            VoteStateV5::from_account_data_mut(data)
                .unwrap()
                .set_last_timestamp(expected.clone());
            let state = VoteStateV5::from_account_data_ref(data).unwrap();
            assert_eq!(state.last_timestamp(), expected.as_ref());
            assert_eq!(
                state.last_timestamp,
                expected.unwrap_or(BlockTimestamp {
                    slot: u64::MAX,
                    timestamp: 0,
                })
            );
            assert_state_round_trips(state);
        }
    }

    #[test]
    fn conversion_from_v4_preserves_voter_count_order_and_zero_padding() {
        for len in 0..=MAX_AUTHORIZED_VOTERS {
            let mut v4 = VoteStateV4 {
                bls_pubkey_compressed: Some([1; BLS_PUBLIC_KEY_COMPRESSED_SIZE]),
                ..VoteStateV4::default()
            };
            // Insert out of order so the conversion must retain the map's
            // epoch order along with each epoch's original signer.
            for epoch in [42, 39, 41, 40].into_iter().take(len) {
                v4.authorized_voters.insert(epoch, Pubkey::new_unique());
            }
            let expected: Vec<_> = v4
                .authorized_voters
                .iter()
                .map(|(&epoch, &pubkey)| AuthorizedVoter { epoch, pubkey })
                .collect();
            let state = VoteStateV5::from_vote_state_v4(
                v4,
                Location::try_new(4051542, 618526, 4870645).unwrap(),
                42,
            )
            .unwrap();
            assert_eq!(state.authorized_voters_len as usize, len);
            assert_eq!(state.authorized_voters_ref().0, expected);
            assert!(state.authorized_voters[len..]
                .iter()
                .all(|entry| entry == &AuthorizedVoter::default()));

            assert_state_round_trips(&state);
        }
    }

    #[test]
    fn conversion_from_v4_keeps_latest_lamports_in_chronological_order_with_trailing_zeros() {
        let history = [
            (1, 10, 0),
            (2, 20, 10),
            (3, 30, 20),
            (u64::MAX, u64::MAX, u64::MAX), // Alpenglow migration marker.
            (4, 40, 30),
            (5, 50, 40),
            (6, 60, 50),
        ];
        for len in 0..=history.len() {
            let state = VoteStateV5::from_vote_state_v4(
                VoteStateV4 {
                    bls_pubkey_compressed: Some([1; BLS_PUBLIC_KEY_COMPRESSED_SIZE]),
                    epoch_credits: history[..len].to_vec(),
                    ..VoteStateV4::default()
                },
                Location::try_new(4051542, 618526, 4870645).unwrap(),
                42,
            )
            .unwrap();
            let retained = len.min(MAX_ACCUMULATED_LAMPORTS);
            assert_eq!(state.accumulated_lamports_len as usize, retained);
            assert!(state.accumulated_lamports[retained..]
                .iter()
                .all(|entry| entry == &AccumulatedLamports::default()));
            let expected = &history[len - retained..len];
            let actual: Vec<_> = state
                .accumulated_lamports_ref()
                .0
                .iter()
                .map(|entry| (entry.epoch, entry.lamports, entry.prev_lamports))
                .collect();
            assert_eq!(actual, expected);

            let mut storage = Aligned([0xff; VOTE_STATE_V5_SIZE + 8]);
            let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
            state.write_account_data(data).unwrap();
            let start = offset_of!(VoteStateV5, accumulated_lamports);
            assert!(data[start + retained * size_of::<AccumulatedLamports>()
                ..start + size_of::<[AccumulatedLamports; MAX_ACCUMULATED_LAMPORTS]>()]
                .iter()
                .all(|byte| *byte == 0));
            assert_state_round_trips(&state);
        }
    }

    #[test]
    fn conversion_from_v4_rejects_missing_bls_key() {
        let mut v4 = VoteStateV4::default();
        v4.authorized_voters.insert(123, Pubkey::new_unique());
        VoteStateV5::from_vote_state_v4(
            v4,
            Location::try_new(4051542, 618526, 4870645).unwrap(),
            42,
        )
        .unwrap_err();
    }

    fn sample(buf: &mut [u8]) {
        buf.fill(0);
        put(
            buf,
            offset_of!(VoteStateV5, discriminant),
            VOTE_STATE_V5_DISCRIMINANT,
        );
        put(buf, offset_of!(VoteStateV5, node_pubkey), [0x11u8; 32]);
        put(
            buf,
            offset_of!(VoteStateV5, location),
            [4051542i32, 618526, 4870645],
        );
        put(
            buf,
            offset_of!(VoteStateV5, pending_delegator_rewards),
            999u64,
        );
        put(
            buf,
            offset_of!(VoteStateV5, inflation_rewards_commission_bps_len),
            2u32,
        );
        put(
            buf,
            offset_of!(VoteStateV5, block_revenue_commission_bps_len),
            1u32,
        );
        put(
            buf,
            offset_of!(VoteStateV5, inflation_rewards_commission_bps_epochs),
            [5u64, 12],
        );
        put(
            buf,
            offset_of!(VoteStateV5, inflation_rewards_commission_bps),
            [1234u16, 4321],
        );
        put(
            buf,
            offset_of!(VoteStateV5, block_revenue_commission_bps_epochs),
            5u64,
        );
        put(
            buf,
            offset_of!(VoteStateV5, block_revenue_commission_bps),
            5678u16,
        );
        put(buf, offset_of!(VoteStateV5, authorized_voters_len), 2u32);
        put(buf, offset_of!(VoteStateV5, accumulated_lamports_len), 3u32);
        for (i, epoch) in [10u64, 11].into_iter().enumerate() {
            put(
                buf,
                offset_of!(VoteStateV5, authorized_voters)
                    + i * size_of::<AuthorizedVoter>()
                    + offset_of!(AuthorizedVoter, epoch),
                epoch,
            );
        }
        put(
            buf,
            offset_of!(VoteStateV5, accumulated_lamports),
            [[5u64, 10, 0], [6, 20, 10], [7, 30, 20]],
        );
        put(
            buf,
            offset_of!(VoteStateV5, last_timestamp) + offset_of!(BlockTimestamp, slot),
            4242u64,
        );
        put(
            buf,
            offset_of!(VoteStateV5, last_timestamp) + offset_of!(BlockTimestamp, timestamp),
            0i64,
        );
        put(buf, offset_of!(VoteStateV5, rank_epoch), u64::MAX);
        put(buf, offset_of!(VoteStateV5, rank), u16::MAX);
    }

    #[test]
    fn write_account_data_round_trips_at_every_alignment() {
        let mut expected = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let account = &mut expected.0[..VOTE_STATE_V5_SIZE];
        sample(account);
        let mut state = wincode::deserialize::<VoteStateV5>(account).unwrap();
        state.pending_delegator_rewards = 1234;
        state.latest_vote = MaybeNull::from(NullableSlot(5678));
        state.last_timestamp.timestamp = -42;
        state.bls_pubkey_compressed.fill(0xab);
        put(
            account,
            offset_of!(VoteStateV5, pending_delegator_rewards),
            1234u64,
        );
        put(account, offset_of!(VoteStateV5, latest_vote), 5678u64);
        put(
            account,
            offset_of!(VoteStateV5, last_timestamp) + offset_of!(BlockTimestamp, timestamp),
            -42i64,
        );
        let bls_offset = offset_of!(VoteStateV5, bls_pubkey_compressed);
        account[bls_offset..bls_offset + BLS_PUBLIC_KEY_COMPRESSED_SIZE].fill(0xab);
        assert_eq!(
            wincode::serialized_size(&state).unwrap(),
            size_of::<VoteStateV5>() as u64
        );
        assert_eq!(
            wincode::serialize(&state).unwrap(),
            account[..size_of::<VoteStateV5>()]
        );

        for offset in 0..8 {
            let mut output = Aligned([0xff; VOTE_STATE_V5_SIZE + 8]);
            let buf = &mut output.0[offset..offset + VOTE_STATE_V5_SIZE];
            state.write_account_data(buf).unwrap();
            assert_eq!(buf, account);
            buf.fill(0xff);
            let (prefix, tail) = buf.split_at_mut(size_of::<VoteStateV5>());
            wincode::serialize_into(&mut prefix[..], &state).unwrap();
            assert_eq!(prefix, &account[..size_of::<VoteStateV5>()]);
            assert!(tail.iter().all(|&byte| byte == 0xff));
            // The full-account writer also writes the reserved zero tail.
            state.write_account_data(buf).unwrap();
            let decoded = VoteStateV5::from_account_data_unaligned(buf).unwrap();
            assert_eq!(decoded.pending_delegator_rewards, 1234);
            assert_eq!(decoded.latest_vote.get().unwrap().0, 5678);
            assert_eq!(decoded.last_timestamp.timestamp, -42);
            if offset == 0 {
                VoteStateV5::from_account_data_ref(buf).unwrap();
            }
            assert!(output.0[..offset].iter().all(|&byte| byte == 0xff));
            assert!(output.0[offset + VOTE_STATE_V5_SIZE..]
                .iter()
                .all(|&byte| byte == 0xff));
        }
    }

    #[test]
    fn wincode_round_trips_prefixes_in_containers() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let account = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(account);
        let state = VoteStateV5::from_account_data_ref(account).unwrap().clone();
        let mut other = state.clone();
        other.pending_delegator_rewards = 123;
        let states = [state, other];
        let encoded = wincode::serialize(&states).unwrap();
        let prefix_size = size_of::<VoteStateV5>();
        assert_eq!(encoded.len(), 2 * prefix_size);
        assert_eq!(&encoded[..prefix_size], &account[..prefix_size]);
        states[1].write_account_data(account).unwrap();
        assert_eq!(&encoded[prefix_size..], &account[..prefix_size]);
        assert_eq!(
            wincode::deserialize_exact::<[VoteStateV5; 2]>(&encoded).unwrap(),
            states
        );
    }

    #[test]
    fn commission_construction_and_updates_preserve_raw_values_and_clamp_rewards() {
        for bps in [0, 10_000, 10_001, u16::MAX] {
            let state = VoteStateV5::new(
                &VoteInitV2 {
                    inflation_rewards_commission_bps: bps,
                    block_revenue_commission_bps: bps,
                    ..VoteInitV2::default()
                },
                Pubkey::default(),
                Pubkey::default(),
                Location::try_new(4051542, 618526, 4870645).unwrap(),
                &Clock::default(),
            );
            let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
            state.write_account_data(data).unwrap();
            let state = VoteStateV5::from_account_data_mut(data).unwrap();
            for commission in [
                state.inflation_rewards_commission_ref().bps[0],
                state.block_revenue_commission_ref().bps[0],
            ] {
                assert_eq!(commission, Commission::new(bps));
                assert_eq!(commission.get(), bps.min(10_000));
                assert_eq!(wincode::serialize(&commission).unwrap(), bps.to_le_bytes());
            }
            for epoch in 0..MAX_COMMISSION_CHANGES as Epoch {
                state
                    .inflation_rewards_commission_mut()
                    .update(epoch, Commission::new(bps))
                    .unwrap();
                state
                    .block_revenue_commission_mut()
                    .update(epoch, Commission::new(bps))
                    .unwrap();
            }
            let expected = state.clone();
            assert_eq!(VoteStateV5::from_account_data_ref(data).unwrap(), &expected);
            assert_eq!(
                VoteStateV5::from_account_data_unaligned(data).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn write_account_data_rejects_incorrect_sizes_without_writing() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        sample(&mut storage.0[..VOTE_STATE_V5_SIZE]);
        let state = VoteStateV5::from_account_data_ref(&storage.0[..VOTE_STATE_V5_SIZE]).unwrap();
        for len in [
            0,
            size_of::<VoteStateV5>(),
            VOTE_STATE_V5_SIZE - 1,
            VOTE_STATE_V5_SIZE + 1,
        ] {
            let mut output = vec![0xff; len];
            assert_eq!(
                state.write_account_data(&mut output),
                Err(InstructionError::InvalidArgument)
            );
            assert!(output.iter().all(|&byte| byte == 0xff));
        }
    }

    #[test]
    fn decoding_preserves_raw_commissions_and_clamps_rewards() {
        for (len_offset, epochs_offset, bps_offset) in [
            (
                offset_of!(VoteStateV5, inflation_rewards_commission_bps_len),
                offset_of!(VoteStateV5, inflation_rewards_commission_bps_epochs),
                offset_of!(VoteStateV5, inflation_rewards_commission_bps),
            ),
            (
                offset_of!(VoteStateV5, block_revenue_commission_bps_len),
                offset_of!(VoteStateV5, block_revenue_commission_bps_epochs),
                offset_of!(VoteStateV5, block_revenue_commission_bps),
            ),
        ] {
            // Check boundary values in a single active slot, then distinct values
            // in every slot of a full schedule.
            for values in [0u16, 10_000, 10_001, u16::MAX]
                .map(|bps| vec![bps])
                .into_iter()
                .chain(std::iter::once(vec![0, 10_000, 10_001, u16::MAX]))
            {
                let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
                let buf = &mut storage.0[..VOTE_STATE_V5_SIZE];
                sample(buf);
                put(buf, len_offset, values.len() as u32);
                // Keep unused entries zero when shortening the sample schedule.
                put(buf, bps_offset, [0u16; MAX_COMMISSION_CHANGES]);
                put(buf, epochs_offset, [0u64; MAX_COMMISSION_CHANGES]);
                for (index, &bps) in values.iter().enumerate() {
                    put(
                        buf,
                        epochs_offset + index * size_of::<Epoch>(),
                        index as Epoch,
                    );
                    put(buf, bps_offset + index * size_of::<u16>(), bps);
                }

                let state = VoteStateV5::from_account_data_ref(buf).unwrap();
                let schedule =
                    if bps_offset == offset_of!(VoteStateV5, inflation_rewards_commission_bps) {
                        state.inflation_rewards_commission_ref()
                    } else {
                        state.block_revenue_commission_ref()
                    };
                let expected: Vec<_> = values.iter().copied().map(Commission::new).collect();
                assert_eq!(schedule.bps, expected);
                for (commission, bps) in schedule.bps.iter().zip(values) {
                    assert_eq!(commission.get(), bps.min(10_000));
                }
                assert_eq!(&wincode::deserialize::<VoteStateV5>(buf).unwrap(), state);
                VoteStateV5::from_account_data_mut(buf).unwrap();
            }
        }
    }

    #[test]
    fn commission_validation_checks_slice_lengths_and_epoch_order() {
        let bps = [1, 2, 3, 4].map(Commission::new);
        assert!(!VoteStateV5::commission_schedule_is_valid(&[], &[]));
        assert!(!VoteStateV5::commission_schedule_is_valid(&[1], &[]));
        assert!(!VoteStateV5::commission_schedule_is_valid(&[], &bps[..1]));
        assert!(!VoteStateV5::commission_schedule_is_valid(
            &[1, 2],
            &bps[..1]
        ));
        assert!(!VoteStateV5::commission_schedule_is_valid(&[1], &bps[..2]));
        assert!(!VoteStateV5::commission_schedule_is_valid(
            &[0, 1, 2, 3, 4],
            &[Commission::new(0); MAX_COMMISSION_CHANGES + 1],
        ));
        let epochs = [5, 12, 20, 30];
        for len in 1..=MAX_COMMISSION_CHANGES {
            assert!(VoteStateV5::commission_schedule_is_valid(
                &epochs[..len],
                &bps[..len]
            ));
        }
        assert!(VoteStateV5::commission_schedule_is_valid(&[0], &bps[..1]));
        assert!(VoteStateV5::commission_schedule_is_valid(
            &[0, u64::MAX],
            &bps[..2]
        ));
        for epochs in [&[5, 5][..], &[12, 5][..], &[5, 20, 12][..]] {
            assert!(!VoteStateV5::commission_schedule_is_valid(
                epochs,
                &bps[..epochs.len()]
            ));
        }
    }

    #[test]
    fn decoding_rejects_commission_epochs_that_are_not_strictly_increasing() {
        for (len_offset, epochs_offset) in [
            (
                offset_of!(VoteStateV5, inflation_rewards_commission_bps_len),
                offset_of!(VoteStateV5, inflation_rewards_commission_bps_epochs),
            ),
            (
                offset_of!(VoteStateV5, block_revenue_commission_bps_len),
                offset_of!(VoteStateV5, block_revenue_commission_bps_epochs),
            ),
        ] {
            for epochs in [[5u64, 5], [12, 5]] {
                let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
                let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
                sample(data);
                put(data, len_offset, 2u32);
                put(data, epochs_offset, epochs);
                VoteStateV5::from_account_data_ref(data).unwrap_err();
                VoteStateV5::from_account_data_mut(data).unwrap_err();
                VoteStateV5::from_account_data_unaligned(data).unwrap_err();
            }
        }
    }

    #[test]
    fn commission_updates_overwrite_append_roll_over_and_preserve_other_schedule() {
        let updates: &[(Epoch, u16, &[Epoch], &[u16])] = &[
            (10, 111, &[10], &[111]),
            (11, 222, &[10, 11], &[111, 222]),
            (12, 333, &[10, 11, 12], &[111, 222, 333]),
            (13, 444, &[10, 11, 12, 13], &[111, 222, 333, 444]),
            (14, 555, &[11, 12, 13, 14], &[222, 333, 444, 555]),
            (14, 666, &[11, 12, 13, 14], &[222, 333, 444, 666]),
            (15, 777, &[12, 13, 14, 15], &[333, 444, 666, 777]),
        ];
        for inflation in [true, false] {
            let original = VoteStateV5::new(
                &VoteInitV2 {
                    inflation_rewards_commission_bps: 100,
                    block_revenue_commission_bps: 200,
                    ..VoteInitV2::default()
                },
                Pubkey::default(),
                Pubkey::default(),
                Location::try_new(4051542, 618526, 4870645).unwrap(),
                &Clock {
                    epoch: 10,
                    ..Clock::default()
                },
            );
            let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
            original.write_account_data(data).unwrap();
            for &(effective_epoch, bps, expected_epochs, expected_bps) in updates {
                let expected_bps: Vec<_> =
                    expected_bps.iter().copied().map(Commission::new).collect();
                {
                    let state = VoteStateV5::from_account_data_mut(data).unwrap();
                    let mut schedule = if inflation {
                        state.inflation_rewards_commission_mut()
                    } else {
                        state.block_revenue_commission_mut()
                    };
                    schedule
                        .update(effective_epoch, Commission::new(bps))
                        .unwrap();
                    assert_eq!(schedule.epochs(), expected_epochs);
                    assert_eq!(schedule.bps(), expected_bps);
                }
                let state = VoteStateV5::from_account_data_ref(data).unwrap();
                let (schedule, other, original_other, epochs_buffer, bps_buffer) = if inflation {
                    (
                        state.inflation_rewards_commission_ref(),
                        state.block_revenue_commission_ref(),
                        original.block_revenue_commission_ref(),
                        &state.inflation_rewards_commission_bps_epochs,
                        &state.inflation_rewards_commission_bps,
                    )
                } else {
                    (
                        state.block_revenue_commission_ref(),
                        state.inflation_rewards_commission_ref(),
                        original.inflation_rewards_commission_ref(),
                        &state.block_revenue_commission_bps_epochs,
                        &state.block_revenue_commission_bps,
                    )
                };
                assert_eq!(schedule.epochs, expected_epochs);
                assert_eq!(schedule.bps, expected_bps);
                assert_eq!(other.epochs, original_other.epochs);
                assert_eq!(other.bps, original_other.bps);
                assert!(epochs_buffer[expected_epochs.len()..]
                    .iter()
                    .all(|epoch| *epoch == 0));
                assert!(bps_buffer[expected_epochs.len()..]
                    .iter()
                    .all(|bps| *bps == Commission::new(0)));
                assert_eq!(
                    &VoteStateV5::from_account_data_unaligned(data).unwrap(),
                    state
                );
            }
        }
    }

    #[test]
    fn commission_mutable_view_tracks_length_across_updates() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(data);
        let state = VoteStateV5::from_account_data_mut(data).unwrap();
        let mut schedule = state.block_revenue_commission_mut();
        assert_eq!(schedule.epochs(), &[5]);
        assert_eq!(schedule.bps(), &[Commission::new(5678)]);
        schedule.update(6, Commission::new(100)).unwrap();
        schedule.update(7, Commission::new(200)).unwrap();
        assert_eq!(schedule.epochs(), &[5, 6, 7]);
        assert_eq!(schedule.bps(), &[5678, 100, 200].map(Commission::new));
        schedule.update(7, Commission::new(300)).unwrap();
        assert_eq!(schedule.bps(), &[5678, 100, 300].map(Commission::new));
        VoteStateV5::from_account_data_ref(data).unwrap();
    }

    #[test]
    fn commission_update_rejects_older_epochs_without_modifying_account() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(data);
        let original = data.to_vec();
        let result = VoteStateV5::from_account_data_mut(data)
            .unwrap()
            .inflation_rewards_commission_mut()
            .update(0, Commission::new(100));
        assert_eq!(result, Err(InstructionError::InvalidArgument));
        assert_eq!(data, original);
    }

    #[test]
    fn account_views_read_fields_and_mutate_backing_bytes() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(buf);
        let s = VoteStateV5::from_account_data_ref(buf).unwrap();
        assert_eq!(s.discriminant, VOTE_STATE_V5_DISCRIMINANT);
        assert_eq!(s.pending_delegator_rewards, 999);
        assert_eq!(
            s.inflation_rewards_commission_ref().bps,
            &[1234, 4321].map(Commission::new)
        );
        assert_eq!(
            s.block_revenue_commission_ref().bps,
            &[5678].map(Commission::new)
        );
        assert_eq!(s.authorized_voters_ref().0[1].epoch, 11);
        assert_eq!(s.last_timestamp.slot, 4242);

        let s = VoteStateV5::from_account_data_mut(buf).unwrap();
        s.pending_delegator_rewards += 1;
        let location = Location::try_new(-4051542, 618526, 4870645).unwrap();
        s.location = location;
        assert_eq!(
            VoteStateV5::from_account_data_ref(buf).unwrap().location,
            location
        );
        assert_eq!(
            u64::from_le_bytes(
                buf[offset_of!(VoteStateV5, pending_delegator_rewards)
                    ..offset_of!(VoteStateV5, pending_delegator_rewards) + size_of::<u64>()]
                    .try_into()
                    .unwrap()
            ),
            1000
        );
    }

    #[test]
    fn authorized_voters_validation_checks_length_and_epoch_order() {
        let voters = [0, 1, 2, u64::MAX].map(|epoch| AuthorizedVoter {
            epoch,
            pubkey: Pubkey::new_unique(),
        });
        for len in 0..=MAX_AUTHORIZED_VOTERS {
            let mut data = [AuthorizedVoter::default(); MAX_AUTHORIZED_VOTERS];
            data[..len].copy_from_slice(&voters[..len]);
            assert!(VoteStateV5::authorized_voters_is_valid(len as u32, &data));
            assert_eq!(
                VoteStateV5::authorized_voters_is_valid(len as u32, &data[..len]),
                len != 0
            );
            if len < MAX_AUTHORIZED_VOTERS {
                data[len].epoch = 1;
                assert!(!VoteStateV5::authorized_voters_is_valid(len as u32, &data));
                data[len] = AuthorizedVoter {
                    pubkey: Pubkey::new_unique(),
                    ..AuthorizedVoter::default()
                };
                assert!(!VoteStateV5::authorized_voters_is_valid(len as u32, &data));
            }
        }
        let oversized = [0, 1, 2, 3, 4].map(|epoch| AuthorizedVoter {
            epoch,
            pubkey: Pubkey::default(),
        });
        assert!(!VoteStateV5::authorized_voters_is_valid(5, &oversized));
        for len in [MAX_AUTHORIZED_VOTERS as u32 + 1, u32::MAX] {
            assert!(!VoteStateV5::authorized_voters_is_valid(len, &voters));
        }
        assert!(!VoteStateV5::authorized_voters_is_valid(0, &[]));
        assert!(!VoteStateV5::authorized_voters_is_valid(1, &[]));
        assert!(!VoteStateV5::authorized_voters_is_valid(2, &voters[..1]));
        for invalid in [
            &[voters[0], voters[0]][..],
            &[voters[1], voters[0]][..],
            &[voters[0], voters[2], voters[1]][..],
        ] {
            assert!(!VoteStateV5::authorized_voters_is_valid(
                invalid.len() as u32,
                invalid
            ));
        }
    }

    #[test]
    fn accumulated_lamports_validation_checks_length_epoch_order_and_totals() {
        let entries =
            std::array::from_fn::<_, MAX_ACCUMULATED_LAMPORTS, _>(|i| AccumulatedLamports {
                epoch: (i + 1) as Epoch,
                lamports: ((i + 1) * 10) as u64,
                prev_lamports: (i * 10) as u64,
            });
        for len in 0..=MAX_ACCUMULATED_LAMPORTS {
            assert!(VoteStateV5::accumulated_lamports_are_valid(&entries[..len]));
        }
        let oversized: [AccumulatedLamports; MAX_ACCUMULATED_LAMPORTS + 1] =
            std::array::from_fn(|_| AccumulatedLamports::default());
        assert!(!VoteStateV5::accumulated_lamports_are_valid(&oversized));
        for epoch in [entries[0].epoch, entries[0].epoch - 1] {
            let mut invalid = entries;
            invalid[1].epoch = epoch;
            assert!(!VoteStateV5::accumulated_lamports_are_valid(&invalid));
        }
        let mut invalid = entries;
        invalid[1].prev_lamports += 1;
        assert!(!VoteStateV5::accumulated_lamports_are_valid(&invalid));
    }

    #[test]
    fn accumulated_lamports_accepts_a_single_migration_marker_at_any_position() {
        let entries = [
            AccumulatedLamports {
                epoch: 6,
                lamports: 50,
                prev_lamports: 40,
            },
            AccumulatedLamports {
                epoch: 7,
                lamports: 60,
                prev_lamports: 50,
            },
            AccumulatedLamports {
                epoch: u64::MAX,
                lamports: u64::MAX,
                prev_lamports: u64::MAX,
            },
            // Tower and Alpenglow entries can belong to the same epoch.
            AccumulatedLamports {
                epoch: 7,
                lamports: 70,
                prev_lamports: 60,
            },
            AccumulatedLamports {
                epoch: 8,
                lamports: 80,
                prev_lamports: 70,
            },
        ];
        for history in [&entries[2..3], &entries[2..], &entries[..3], &entries[..]] {
            assert!(VoteStateV5::accumulated_lamports_are_valid(history));
            let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
            sample(data);
            let state = VoteStateV5::from_account_data_mut(data).unwrap();
            state
                .accumulated_lamports
                .fill(AccumulatedLamports::default());
            state.accumulated_lamports[..history.len()].clone_from_slice(history);
            state.accumulated_lamports_len = history.len() as u32;
            let state = VoteStateV5::from_account_data_ref(data).unwrap();
            assert_eq!(state.accumulated_lamports_ref().0, history);
            assert_eq!(
                &VoteStateV5::from_account_data_unaligned(data).unwrap(),
                state
            );
        }

        let marker = entries[2];
        assert!(!VoteStateV5::accumulated_lamports_are_valid(&[
            marker, marker
        ]));
        for corrupt in [
            |entry: &mut AccumulatedLamports| entry.epoch = 0,
            |entry: &mut AccumulatedLamports| entry.lamports = 0,
            |entry: &mut AccumulatedLamports| entry.prev_lamports = 0,
        ] {
            let mut invalid = entries;
            corrupt(&mut invalid[2]);
            assert!(!VoteStateV5::accumulated_lamports_are_valid(&invalid));
        }
        for index in [0, 3] {
            let mut invalid = entries;
            invalid[index + 1].prev_lamports += 1;
            assert!(!VoteStateV5::accumulated_lamports_are_valid(&invalid));
            let mut invalid = entries;
            invalid[index].epoch = invalid[index + 1].epoch;
            assert!(!VoteStateV5::accumulated_lamports_are_valid(&invalid));
        }
    }

    #[test]
    fn authorized_voters_updates_append_replace_and_reject_older_epochs_and_overflow() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(data);
        let original = VoteStateV5::from_account_data_ref(data).unwrap().clone();
        let keys = std::array::from_fn::<_, 5, _>(|_| Pubkey::new_unique());
        {
            let state = VoteStateV5::from_account_data_mut(data).unwrap();
            let mut voters = state.authorized_voters_mut();
            assert_eq!(voters.entries().len(), 2);
            voters.update(12, keys[0]).unwrap();
            voters.update(13, keys[1]).unwrap();
            voters.update(13, keys[2]).unwrap(); // Replace the latest voter while full.
            assert_eq!(
                voters.entries(),
                &[
                    original.authorized_voters[0],
                    original.authorized_voters[1],
                    AuthorizedVoter {
                        epoch: 12,
                        pubkey: keys[0]
                    },
                    AuthorizedVoter {
                        epoch: 13,
                        pubkey: keys[2]
                    },
                ]
            );
            let before = voters.entries().to_vec();
            for effective_epoch in [9, 12] {
                assert_eq!(
                    voters.update(effective_epoch, keys[3]),
                    Err(InstructionError::InvalidArgument)
                );
                assert_eq!(voters.entries(), before);
            }
            assert_eq!(
                voters.update(14, keys[3]),
                Err(InstructionError::InvalidInstructionData)
            );
            assert_eq!(voters.entries(), before);
            voters.purge_before(12);
            voters.update(14, keys[3]).unwrap(); // Append after purging makes room.
            assert_eq!(
                voters
                    .entries()
                    .iter()
                    .map(|entry| entry.epoch)
                    .collect::<Vec<_>>(),
                &[12, 13, 14]
            );
            assert_eq!(voters.entries()[2].pubkey, keys[3]);
            assert!(voters.entries[voters.entries().len()..]
                .iter()
                .all(|entry| entry == &AuthorizedVoter::default()));
        }
        let state = VoteStateV5::from_account_data_ref(data).unwrap();
        assert_eq!(state.accumulated_lamports, original.accumulated_lamports);
        assert_eq!(
            state.accumulated_lamports_len,
            original.accumulated_lamports_len
        );
        assert_eq!(
            state.inflation_rewards_commission_ref().epochs,
            original.inflation_rewards_commission_ref().epochs
        );
        assert_eq!(
            state.inflation_rewards_commission_ref().bps,
            original.inflation_rewards_commission_ref().bps
        );
        assert_state_round_trips(state);
    }

    #[test]
    fn authorized_voters_updates_preserve_explicit_effective_epochs() {
        let mut entries = [AuthorizedVoter::default(); MAX_AUTHORIZED_VOTERS];
        let mut len = 0;
        let mut voters = AuthorizedVotersMut {
            entries: &mut entries,
            len: &mut len,
        };
        let initial_pubkey = Pubkey::new_unique();
        voters.update(0, initial_pubkey).unwrap();
        assert_eq!(
            voters.entries(),
            &[AuthorizedVoter {
                epoch: 0,
                pubkey: initial_pubkey,
            }]
        );
        for (effective_epoch, expected_epochs) in [
            (u64::MAX - 2, &[0, u64::MAX - 2][..]),
            (u64::MAX - 1, &[0, u64::MAX - 2, u64::MAX - 1][..]),
            (u64::MAX, &[0, u64::MAX - 2, u64::MAX - 1, u64::MAX][..]),
            (u64::MAX, &[0, u64::MAX - 2, u64::MAX - 1, u64::MAX][..]),
        ] {
            let pubkey = Pubkey::new_unique();
            voters.update(effective_epoch, pubkey).unwrap();
            assert_eq!(
                voters
                    .entries()
                    .iter()
                    .map(|entry| entry.epoch)
                    .collect::<Vec<_>>(),
                expected_epochs
            );
            assert_eq!(voters.entries()[0].pubkey, initial_pubkey);
            assert_eq!(voters.entries().last().unwrap().pubkey, pubkey);
        }
    }

    #[test]
    fn accumulated_lamports_updates_accumulate_reuse_and_roll_over() {
        let mut state = VoteStateV5::new(
            &VoteInitV2::default(),
            Pubkey::default(),
            Pubkey::default(),
            Location::try_new(4051542, 618526, 4870645).unwrap(),
            &Clock::default(),
        );
        let original = state.clone();
        type RewardHistory = [(Epoch, u64, u64)];
        let updates: &[(Epoch, u64, &RewardHistory)] = &[
            (10, 100, &[(10, 100, 0)]),
            (10, 25, &[(10, 125, 0)]),
            (12, 0, &[(10, 125, 0), (12, 125, 125)]),
            (15, 50, &[(10, 125, 0), (15, 175, 125)]),
            (16, 10, &[(10, 125, 0), (15, 175, 125), (16, 185, 175)]),
            (
                17,
                10,
                &[(10, 125, 0), (15, 175, 125), (16, 185, 175), (17, 195, 185)],
            ),
            (
                18,
                10,
                &[
                    (10, 125, 0),
                    (15, 175, 125),
                    (16, 185, 175),
                    (17, 195, 185),
                    (18, 205, 195),
                ],
            ),
            (
                19,
                10,
                &[
                    (15, 175, 125),
                    (16, 185, 175),
                    (17, 195, 185),
                    (18, 205, 195),
                    (19, 215, 205),
                ],
            ),
        ];
        assert!(state.accumulated_lamports_mut().entries().is_empty());
        for &(epoch, amount, expected) in updates {
            {
                let mut history = state.accumulated_lamports_mut();
                history.update(epoch, amount).unwrap();
                let actual: Vec<_> = history
                    .entries()
                    .iter()
                    .map(|entry| (entry.epoch, entry.lamports, entry.prev_lamports))
                    .collect();
                assert_eq!(actual, expected);
                assert!(history.entries[history.entries().len()..]
                    .iter()
                    .all(|entry| entry == &AccumulatedLamports::default()));
            }
            assert_eq!(state.authorized_voters, original.authorized_voters);
            assert_eq!(state.authorized_voters_len, original.authorized_voters_len);
            assert_eq!(
                state.block_revenue_commission_ref().epochs,
                original.block_revenue_commission_ref().epochs
            );
            assert_eq!(
                state.block_revenue_commission_ref().bps,
                original.block_revenue_commission_ref().bps
            );
            assert_state_round_trips(&state);
        }
    }

    #[test]
    fn accumulated_lamports_updates_saturate_totals() {
        for epoch in [7, 8] {
            let mut state = VoteStateV5::from_vote_state_v4(
                VoteStateV4 {
                    bls_pubkey_compressed: Some([1; BLS_PUBLIC_KEY_COMPRESSED_SIZE]),
                    epoch_credits: vec![(7, 100, 90)],
                    ..VoteStateV4::default()
                },
                Location::try_new(4051542, 618526, 4870645).unwrap(),
                7,
            )
            .unwrap();
            state
                .accumulated_lamports_mut()
                .update(epoch, u64::MAX)
                .unwrap();
            let history = state.accumulated_lamports_ref().0;
            assert_eq!(history.len(), if epoch == 7 { 1 } else { 2 });
            let latest = history.last().unwrap();
            assert_eq!(latest.epoch, epoch);
            assert_eq!(latest.lamports, u64::MAX);
            assert_eq!(latest.prev_lamports, if epoch == 7 { 90 } else { 100 });
            assert_state_round_trips(&state);

            state.accumulated_lamports_mut().update(9, 1).unwrap();
            let latest = state.accumulated_lamports_ref().0.last().unwrap();
            assert_eq!(latest.lamports, u64::MAX);
            assert_eq!(latest.prev_lamports, u64::MAX);
            assert_state_round_trips(&state);
        }
    }

    #[test]
    fn authorized_voters_mutable_view_purges_and_clears_unused_entries() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(data);
        {
            let state = VoteStateV5::from_account_data_mut(data).unwrap();
            let mut voters = state.authorized_voters_mut();
            voters.purge_before(u64::MAX);
            assert!(voters.entries().is_empty());
            for effective_epoch in 0..MAX_AUTHORIZED_VOTERS as Epoch {
                voters
                    .update(effective_epoch, Pubkey::new_unique())
                    .unwrap();
            }
            for (epoch, expected) in [
                (0, &[0, 1, 2, 3][..]),
                (1, &[1, 2, 3][..]),
                (3, &[3][..]),
                (4, &[][..]),
            ] {
                voters.purge_before(epoch);
                let actual: Vec<_> = voters.entries().iter().map(|voter| voter.epoch).collect();
                assert_eq!(actual, expected);
                assert!(voters.entries[voters.entries().len()..]
                    .iter()
                    .all(|entry| entry == &AuthorizedVoter::default()));
            }
            voters.update(10, Pubkey::new_unique()).unwrap();
            assert_eq!(voters.entries().len(), 1);
            assert_eq!(voters.entries()[0].epoch, 10);
        }
        let state = VoteStateV5::from_account_data_ref(data).unwrap();
        assert_eq!(
            &VoteStateV5::from_account_data_unaligned(data).unwrap(),
            state
        );
    }

    #[test]
    fn account_views_reject_misaligned_data() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let buf = &mut storage.0[4..4 + VOTE_STATE_V5_SIZE];
        sample(buf);
        VoteStateV5::from_account_data_ref(buf).unwrap_err();
        VoteStateV5::from_account_data_mut(buf).unwrap_err();
    }

    #[test]
    fn unaligned_account_reader_returns_independent_owned_copy() {
        // Exercise aligned data and every possible misalignment.
        for offset in 0..std::mem::align_of::<VoteStateV5>() {
            let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            let buf = &mut storage.0[offset..offset + VOTE_STATE_V5_SIZE];
            sample(buf);
            let mut state = VoteStateV5::from_account_data_unaligned(buf).unwrap();
            assert_eq!(state.discriminant, VOTE_STATE_V5_DISCRIMINANT);
            assert_eq!(state.pending_delegator_rewards, 999);
            assert_eq!(
                state.inflation_rewards_commission_ref().bps,
                &[1234, 4321].map(Commission::new)
            );
            assert_eq!(
                state.block_revenue_commission_ref().bps,
                &[5678].map(Commission::new)
            );
            assert_eq!(state.authorized_voters_ref().0[1].epoch, 11);
            assert_eq!(state.last_timestamp.slot, 4242);
            state.pending_delegator_rewards = 1000;
            assert_eq!(
                u64::from_le_bytes(
                    buf[offset_of!(VoteStateV5, pending_delegator_rewards)
                        ..offset_of!(VoteStateV5, pending_delegator_rewards) + size_of::<u64>()]
                        .try_into()
                        .unwrap()
                ),
                999
            );
            buf.fill(0);
            assert_eq!(state.pending_delegator_rewards, 1000);
        }
    }

    #[test]
    fn account_readers_validate_reserved_bytes() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_STATE_V5_SIZE];
        sample(buf);
        // Cover both the reserved bytes inside the prefix and the external tail.
        for offset in offset_of!(VoteStateV5, padding)..VOTE_STATE_V5_SIZE {
            buf[offset] = 1;
            assert!(
                VoteStateV5::from_account_data_ref(buf).is_err(),
                "shared: byte {offset}"
            );
            assert!(
                VoteStateV5::from_account_data_mut(buf).is_err(),
                "mutable: byte {offset}"
            );
            assert!(
                VoteStateV5::from_account_data_unaligned(buf).is_err(),
                "owned: byte {offset}"
            );
            buf[offset] = 0;
        }
    }

    #[test]
    fn account_readers_accept_nullable_rank_fields() {
        for epoch in [u64::MAX, 0, 42, u64::MAX - 1] {
            for rank in [u16::MAX, 0, 7, u16::MAX - 1] {
                let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
                let data = &mut storage.0[..VOTE_STATE_V5_SIZE];
                sample(data);
                put(data, offset_of!(VoteStateV5, rank_epoch), epoch);
                put(data, offset_of!(VoteStateV5, rank), rank);
                let state = VoteStateV5::from_account_data_ref(data).unwrap();
                assert_eq!(
                    state.rank_epoch.get(),
                    (epoch != u64::MAX).then_some(NullableEpoch(epoch))
                );
                assert_eq!(
                    state.rank.get(),
                    (rank != u16::MAX).then_some(NullableRank(rank))
                );
                assert_state_round_trips(state);
            }
        }
    }

    #[test]
    fn decoders_reject_invalid_account_data() {
        let mut storage = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
        let buf = &mut storage.0[..VOTE_STATE_V5_SIZE];
        type InvalidCase = (&'static str, fn(&mut [u8]));
        let cases: &[InvalidCase] = &[
            ("wrong discriminant", |b| {
                put(b, offset_of!(VoteStateV5, discriminant), 3u32)
            }),
            ("invalid location", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, location) + offset_of!(Location, z),
                    0i32,
                )
            }),
            ("empty commission schedule", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, inflation_rewards_commission_bps_len),
                    0u32,
                )
            }),
            ("oversized commission schedule", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, block_revenue_commission_bps_len),
                    MAX_COMMISSION_CHANGES as u32 + 1,
                )
            }),
            ("nonzero unused commission epoch", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, inflation_rewards_commission_bps_epochs)
                        + 2 * size_of::<Epoch>(),
                    13u64,
                )
            }),
            ("nonzero unused commission value", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, inflation_rewards_commission_bps)
                        + 2 * size_of::<Commission>(),
                    1u16,
                )
            }),
            ("oversized authorized voters", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, authorized_voters_len),
                    MAX_AUTHORIZED_VOTERS as u32 + 1,
                )
            }),
            ("duplicate voter epoch", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, authorized_voters)
                        + size_of::<AuthorizedVoter>()
                        + offset_of!(AuthorizedVoter, epoch),
                    10u64,
                )
            }),
            ("nonzero unused voter", |b| {
                b[offset_of!(VoteStateV5, authorized_voters) + 3 * size_of::<AuthorizedVoter>()] = 1
            }),
            ("oversized reward history", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, accumulated_lamports_len),
                    MAX_ACCUMULATED_LAMPORTS as u32 + 1,
                )
            }),
            ("nonzero unused reward entry", |b| {
                b[offset_of!(VoteStateV5, accumulated_lamports)
                    + 3 * size_of::<AccumulatedLamports>()] = 1
            }),
            ("duplicate reward epoch", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, accumulated_lamports)
                        + offset_of!(AccumulatedLamports, epoch),
                    6u64,
                )
            }),
            ("inconsistent reward totals", |b| {
                put(
                    b,
                    offset_of!(VoteStateV5, accumulated_lamports)
                        + size_of::<AccumulatedLamports>()
                        + offset_of!(AccumulatedLamports, prev_lamports),
                    21u64,
                )
            }),
            ("nonzero reserved tail", |b| b[VOTE_STATE_V5_SIZE - 1] = 1),
        ];
        for (name, mutate) in cases {
            sample(buf);
            VoteStateV5::from_account_data_ref(buf).unwrap();
            mutate(buf);
            assert!(
                VoteStateV5::from_account_data_ref(buf).is_err(),
                "{name}: shared account view"
            );
            assert!(
                VoteStateV5::from_account_data_mut(buf).is_err(),
                "{name}: mutable account view"
            );
            assert!(
                VoteStateV5::from_account_data_unaligned(buf).is_err(),
                "{name}: owned account"
            );
            // Validate the same malformed data at a misaligned address.
            let mut unaligned = Aligned([0; VOTE_STATE_V5_SIZE + 8]);
            unaligned.0[1..1 + VOTE_STATE_V5_SIZE].copy_from_slice(buf);
            assert!(
                VoteStateV5::from_account_data_unaligned(&unaligned.0[1..1 + VOTE_STATE_V5_SIZE])
                    .is_err(),
                "{name}: misaligned owned account"
            );
        }
        for len in [
            0,
            size_of::<VoteStateV5>() - 1,
            size_of::<VoteStateV5>(),
            VOTE_STATE_V5_SIZE - 1,
        ] {
            VoteStateV5::from_account_data_ref(&buf[..len]).unwrap_err();
            VoteStateV5::from_account_data_unaligned(&buf[..len]).unwrap_err();
            VoteStateV5::from_account_data_mut(&mut buf[..len]).unwrap_err();
        }
        sample(&mut storage.0[..VOTE_STATE_V5_SIZE]);
        VoteStateV5::from_account_data_ref(&storage.0).unwrap_err();
        VoteStateV5::from_account_data_unaligned(&storage.0).unwrap_err();
        VoteStateV5::from_account_data_mut(&mut storage.0).unwrap_err();
    }
}
