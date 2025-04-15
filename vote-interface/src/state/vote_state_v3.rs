#[cfg(feature = "bincode")]
use super::VoteStateVersions;
#[cfg(feature = "dev-context-only-utils")]
use arbitrary::Arbitrary;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample};
use {
    super::{
        BlockTimestamp, CircBuf, LandedVote, Lockout, VoteInit, MAX_EPOCH_CREDITS_HISTORY,
        MAX_LOCKOUT_HISTORY, VOTE_CREDITS_GRACE_SLOTS, VOTE_CREDITS_MAXIMUM_PER_SLOT,
    },
    crate::{
        authorized_voters::AuthorizedVoters, error::VoteError, state::DEFAULT_PRIOR_VOTERS_OFFSET,
    },
    solana_clock::{Clock, Epoch, Slot, UnixTimestamp},
    solana_instruction::error::InstructionError,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    std::{collections::VecDeque, fmt::Debug},
};

#[cfg_attr(
    feature = "frozen-abi",
    frozen_abi(digest = "BRwozbypfYXsHqFVj9w3iH5x1ak2NWHqCCn6pr3gHBkG"),
    derive(AbiExample)
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Arbitrary))]
pub struct VoteState {
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

impl VoteState {
    pub fn new(vote_init: &VoteInit, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            commission: vote_init.commission,
            ..VoteState::default()
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
            ..VoteState::default()
        }
    }

    pub fn get_authorized_voter(&self, epoch: Epoch) -> Option<Pubkey> {
        self.authorized_voters.get_authorized_voter(epoch)
    }

    pub fn authorized_voters(&self) -> &AuthorizedVoters {
        &self.authorized_voters
    }

    pub fn prior_voters(&mut self) -> &CircBuf<(Pubkey, Epoch, Epoch)> {
        &self.prior_voters
    }

    pub fn get_rent_exempt_reserve(rent: &Rent) -> u64 {
        rent.minimum_balance(VoteState::size_of())
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // see test_vote_state_size_of.
    }

    // NOTE we retain `bincode::deserialize` for `not(target_os = "solana")` pending testing on mainnet-beta
    // once that testing is done, `VoteState::deserialize_into` may be used for all targets
    // conversion of V0_23_5 to current must be handled specially, however
    // because it inserts a null voter into `authorized_voters`
    // which `VoteStateVersions::is_uninitialized` erroneously reports as initialized
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize(input: &[u8]) -> Result<Self, InstructionError> {
        #[cfg(not(target_os = "solana"))]
        {
            bincode::deserialize::<VoteStateVersions>(input)
                .map(|versioned| versioned.convert_to_current())
                .map_err(|_| InstructionError::InvalidAccountData)
        }
        #[cfg(target_os = "solana")]
        {
            let mut vote_state = Self::default();
            Self::deserialize_into(input, &mut vote_state)?;
            Ok(vote_state)
        }
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided `VoteState`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` reflects the state of the input data. On failure, `vote_state` is
    /// reset to `VoteState::default()`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into(
        input: &[u8],
        vote_state: &mut VoteState,
    ) -> Result<(), InstructionError> {
        // Rebind vote_state to *mut VoteState so that the &mut binding isn't
        // accessible anymore, preventing accidental use after this point.
        //
        // NOTE: switch to ptr::from_mut() once platform-tools moves to rustc >= 1.76
        let vote_state = vote_state as *mut VoteState;

        // Safety: vote_state is valid to_drop (see drop_in_place() docs). After
        // dropping, the pointer is treated as uninitialized and only accessed
        // through ptr::write, which is safe as per drop_in_place docs.
        unsafe {
            std::ptr::drop_in_place(vote_state);
        }

        // This is to reset vote_state to VoteState::default() if deserialize fails or panics.
        struct DropGuard {
            vote_state: *mut VoteState,
        }

        impl Drop for DropGuard {
            fn drop(&mut self) {
                // Safety:
                //
                // Deserialize failed or panicked so at this point vote_state is uninitialized. We
                // must write a new _valid_ value into it or after returning (or unwinding) from
                // this function the caller is left with an uninitialized `&mut VoteState`, which is
                // UB (references must always be valid).
                //
                // This is always safe and doesn't leak memory because deserialize_into_ptr() writes
                // into the fields that heap alloc only when it returns Ok().
                unsafe {
                    self.vote_state.write(VoteState::default());
                }
            }
        }

        let guard = DropGuard { vote_state };

        let res = VoteState::deserialize_into_ptr(input, vote_state);
        if res.is_ok() {
            std::mem::forget(guard);
        }

        res
    }

    /// Deserializes the input `VoteStateVersions` buffer directly into the provided
    /// `MaybeUninit<VoteState>`.
    ///
    /// In a SBPF context, V0_23_5 is not supported, but in non-SBPF, all versions are supported for
    /// compatibility with `bincode::deserialize`.
    ///
    /// On success, `vote_state` is fully initialized and can be converted to `VoteState` using
    /// [MaybeUninit::assume_init]. On failure, `vote_state` may still be uninitialized and must not
    /// be converted to `VoteState`.
    #[cfg(any(target_os = "solana", feature = "bincode"))]
    pub fn deserialize_into_uninit(
        input: &[u8],
        vote_state: &mut std::mem::MaybeUninit<VoteState>,
    ) -> Result<(), InstructionError> {
        VoteState::deserialize_into_ptr(input, vote_state.as_mut_ptr())
    }

    #[cfg(any(target_os = "solana", feature = "bincode"))]
    fn deserialize_into_ptr(
        input: &[u8],
        vote_state: *mut VoteState,
    ) -> Result<(), InstructionError> {
        use vote_state_deserialize::deserialize_vote_state_into;

        let mut cursor = std::io::Cursor::new(input);

        let variant = solana_serialize_utils::cursor::read_u32(&mut cursor)?;
        match variant {
            // V0_23_5. not supported for bpf targets; these should not exist on mainnet
            // supported for non-bpf targets for backwards compatibility
            0 => {
                #[cfg(not(target_os = "solana"))]
                {
                    // Safety: vote_state is valid as it comes from `&mut MaybeUninit<VoteState>` or
                    // `&mut VoteState`. In the first case, the value is uninitialized so we write()
                    // to avoid dropping invalid data; in the latter case, we `drop_in_place()`
                    // before writing so the value has already been dropped and we just write a new
                    // one in place.
                    unsafe {
                        vote_state.write(
                            bincode::deserialize::<VoteStateVersions>(input)
                                .map(|versioned| versioned.convert_to_current())
                                .map_err(|_| InstructionError::InvalidAccountData)?,
                        );
                    }
                    Ok(())
                }
                #[cfg(target_os = "solana")]
                Err(InstructionError::InvalidAccountData)
            }
            // V1_14_11. substantially different layout and data from V0_23_5
            1 => deserialize_vote_state_into(&mut cursor, vote_state, false),
            // Current. the only difference from V1_14_11 is the addition of a slot-latency to each vote
            2 => deserialize_vote_state_into(&mut cursor, vote_state, true),
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

    /// returns commission split as (voter_portion, staker_portion, was_split) tuple
    ///
    ///  if commission calculation is 100% one way or other,
    ///   indicate with false for was_split
    #[deprecated(since = "2.2.0", note = "logic was moved into the agave runtime crate")]
    pub fn commission_split(&self, on: u64) -> (u64, u64, bool) {
        match self.commission.min(100) {
            0 => (0, on, false),
            100 => (on, 0, false),
            split => {
                let on = u128::from(on);
                // Calculate mine and theirs independently and symmetrically instead of
                // using the remainder of the other to treat them strictly equally.
                // This is also to cancel the rewarding if either of the parties
                // should receive only fractional lamports, resulting in not being rewarded at all.
                // Thus, note that we intentionally discard any residual fractional lamports.
                let mine = on
                    .checked_mul(u128::from(split))
                    .expect("multiplication of a u64 and u8 should not overflow")
                    / 100u128;
                let theirs = on
                    .checked_mul(u128::from(
                        100u8
                            .checked_sub(split)
                            .expect("commission cannot be greater than 100"),
                    ))
                    .expect("multiplication of a u64 and u8 should not overflow")
                    / 100u128;

                (mine as u64, theirs as u64, true)
            }
        }
    }

    /// Returns if the vote state contains a slot `candidate_slot`
    pub fn contains_slot(&self, candidate_slot: Slot) -> bool {
        self.votes
            .binary_search_by(|vote| vote.slot().cmp(&candidate_slot))
            .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn get_max_sized_vote_state() -> VoteState {
        use solana_epoch_schedule::MAX_LEADER_SCHEDULE_EPOCH_OFFSET;
        let mut authorized_voters = AuthorizedVoters::default();
        for i in 0..=MAX_LEADER_SCHEDULE_EPOCH_OFFSET {
            authorized_voters.insert(i, Pubkey::new_unique());
        }

        VoteState {
            votes: VecDeque::from(vec![LandedVote::default(); MAX_LOCKOUT_HISTORY]),
            root_slot: Some(u64::MAX),
            epoch_credits: vec![(0, 0, 0); MAX_EPOCH_CREDITS_HISTORY],
            authorized_voters,
            ..Self::default()
        }
    }

    pub fn process_next_vote_slot(
        &mut self,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) {
        // Ignore votes for slots earlier than we already have votes for
        if self
            .last_voted_slot()
            .is_some_and(|last_voted_slot| next_vote_slot <= last_voted_slot)
        {
            return;
        }

        self.pop_expired_votes(next_vote_slot);

        let landed_vote = LandedVote {
            latency: Self::compute_vote_latency(next_vote_slot, current_slot),
            lockout: Lockout::new(next_vote_slot),
        };

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if self.votes.len() == MAX_LOCKOUT_HISTORY {
            let credits = self.credits_for_vote_at_index(0);
            let landed_vote = self.votes.pop_front().unwrap();
            self.root_slot = Some(landed_vote.slot());

            self.increment_credits(epoch, credits);
        }
        self.votes.push_back(landed_vote);
        self.double_lockouts();
    }

    /// increment credits, record credits for last epoch if new epoch
    pub fn increment_credits(&mut self, epoch: Epoch, credits: u64) {
        // increment credits, record by epoch

        // never seen a credit
        if self.epoch_credits.is_empty() {
            self.epoch_credits.push((epoch, 0, 0));
        } else if epoch != self.epoch_credits.last().unwrap().0 {
            let (_, credits, prev_credits) = *self.epoch_credits.last().unwrap();

            if credits != prev_credits {
                // if credits were earned previous epoch
                // append entry at end of list for the new epoch
                self.epoch_credits.push((epoch, credits, credits));
            } else {
                // else just move the current epoch
                self.epoch_credits.last_mut().unwrap().0 = epoch;
            }

            // Remove too old epoch_credits
            if self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
                self.epoch_credits.remove(0);
            }
        }

        self.epoch_credits.last_mut().unwrap().1 =
            self.epoch_credits.last().unwrap().1.saturating_add(credits);
    }

    // Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
    pub fn compute_vote_latency(voted_for_slot: Slot, current_slot: Slot) -> u8 {
        std::cmp::min(current_slot.saturating_sub(voted_for_slot), u8::MAX as u64) as u8
    }

    /// Returns the credits to award for a vote at the given lockout slot index
    pub fn credits_for_vote_at_index(&self, index: usize) -> u64 {
        let latency = self
            .votes
            .get(index)
            .map_or(0, |landed_vote| landed_vote.latency);

        // If latency is 0, this means that the Lockout was created and stored from a software version that did not
        // store vote latencies; in this case, 1 credit is awarded
        if latency == 0 {
            1
        } else {
            match latency.checked_sub(VOTE_CREDITS_GRACE_SLOTS) {
                None | Some(0) => {
                    // latency was <= VOTE_CREDITS_GRACE_SLOTS, so maximum credits are awarded
                    VOTE_CREDITS_MAXIMUM_PER_SLOT as u64
                }

                Some(diff) => {
                    // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
                    // Subtract diff from VOTE_CREDITS_MAXIMUM_PER_SLOT which is the number of credits to award
                    match VOTE_CREDITS_MAXIMUM_PER_SLOT.checked_sub(diff) {
                        // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
                        None | Some(0) => 1,

                        Some(credits) => credits as u64,
                    }
                }
            }
        }
    }

    pub fn nth_recent_lockout(&self, position: usize) -> Option<&Lockout> {
        if position < self.votes.len() {
            let pos = self
                .votes
                .len()
                .checked_sub(position)
                .and_then(|pos| pos.checked_sub(1))?;
            self.votes.get(pos).map(|vote| &vote.lockout)
        } else {
            None
        }
    }

    pub fn last_lockout(&self) -> Option<&Lockout> {
        self.votes.back().map(|vote| &vote.lockout)
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.last_lockout().map(|v| v.slot())
    }

    // Upto MAX_LOCKOUT_HISTORY many recent unexpired
    // vote slots pushed onto the stack.
    pub fn tower(&self) -> Vec<Slot> {
        self.votes.iter().map(|v| v.slot()).collect()
    }

    pub fn current_epoch(&self) -> Epoch {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().0
        }
    }

    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteState to the Rewards program to trade credits for lamports.
    pub fn credits(&self) -> u64 {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().1
        }
    }

    /// Number of "credits" owed to this account from the mining pool on a per-epoch basis,
    ///  starting from credits observed.
    /// Each tuple of (Epoch, u64, u64) is read as (epoch, credits, prev_credits), where
    ///   credits for each epoch is credits - prev_credits; while redundant this makes
    ///   calculating rewards over partial epochs nice and simple
    pub fn epoch_credits(&self) -> &Vec<(Epoch, u64, u64)> {
        &self.epoch_credits
    }

    pub fn set_new_authorized_voter<F>(
        &mut self,
        authorized_pubkey: &Pubkey,
        current_epoch: Epoch,
        target_epoch: Epoch,
        verify: F,
    ) -> Result<(), InstructionError>
    where
        F: Fn(Pubkey) -> Result<(), InstructionError>,
    {
        let epoch_authorized_voter = self.get_and_update_authorized_voter(current_epoch)?;
        verify(epoch_authorized_voter)?;

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if self.authorized_voters.contains(target_epoch) {
            return Err(VoteError::TooSoonToReauthorize.into());
        }

        // Get the latest authorized_voter
        let (latest_epoch, latest_authorized_pubkey) = self
            .authorized_voters
            .last()
            .ok_or(InstructionError::InvalidAccountData)?;

        // If we're not setting the same pubkey as authorized pubkey again,
        // then update the list of prior voters to mark the expiration
        // of the old authorized pubkey
        if latest_authorized_pubkey != authorized_pubkey {
            // Update the epoch ranges of authorized pubkeys that will be expired
            let epoch_of_last_authorized_switch =
                self.prior_voters.last().map(|range| range.2).unwrap_or(0);

            // target_epoch must:
            // 1) Be monotonically increasing due to the clock always
            //    moving forward
            // 2) not be equal to latest epoch otherwise this
            //    function would have returned TooSoonToReauthorize error
            //    above
            if target_epoch <= *latest_epoch {
                return Err(InstructionError::InvalidAccountData);
            }

            // Commit the new state
            self.prior_voters.append((
                *latest_authorized_pubkey,
                epoch_of_last_authorized_switch,
                target_epoch,
            ));
        }

        self.authorized_voters
            .insert(target_epoch, *authorized_pubkey);

        Ok(())
    }

    pub fn get_and_update_authorized_voter(
        &mut self,
        current_epoch: Epoch,
    ) -> Result<Pubkey, InstructionError> {
        let pubkey = self
            .authorized_voters
            .get_and_cache_authorized_voter_for_epoch(current_epoch)
            .ok_or(InstructionError::InvalidAccountData)?;
        self.authorized_voters
            .purge_authorized_voters(current_epoch);
        Ok(pubkey)
    }

    // Pop all recent votes that are not locked out at the next vote slot.  This
    // allows validators to switch forks once their votes for another fork have
    // expired. This also allows validators continue voting on recent blocks in
    // the same fork without increasing lockouts.
    pub fn pop_expired_votes(&mut self, next_vote_slot: Slot) {
        while let Some(vote) = self.last_lockout() {
            if !vote.is_locked_out_at_slot(next_vote_slot) {
                self.votes.pop_back();
            } else {
                break;
            }
        }
    }

    pub fn double_lockouts(&mut self) {
        let stack_depth = self.votes.len();
        for (i, v) in self.votes.iter_mut().enumerate() {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            if stack_depth >
                i.checked_add(v.confirmation_count() as usize)
                    .expect("`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`")
            {
                v.lockout.increase_confirmation_count(1);
            }
        }
    }

    pub fn process_timestamp(
        &mut self,
        slot: Slot,
        timestamp: UnixTimestamp,
    ) -> Result<(), VoteError> {
        if (slot < self.last_timestamp.slot || timestamp < self.last_timestamp.timestamp)
            || (slot == self.last_timestamp.slot
                && BlockTimestamp { slot, timestamp } != self.last_timestamp
                && self.last_timestamp.slot != 0)
        {
            return Err(VoteError::TimestampTooOld);
        }
        self.last_timestamp = BlockTimestamp { slot, timestamp };
        Ok(())
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        const VERSION_OFFSET: usize = 4;
        const DEFAULT_PRIOR_VOTERS_END: usize = VERSION_OFFSET + DEFAULT_PRIOR_VOTERS_OFFSET;
        data.len() == VoteState::size_of()
            && data[VERSION_OFFSET..DEFAULT_PRIOR_VOTERS_END] != [0; DEFAULT_PRIOR_VOTERS_OFFSET]
    }
}

#[cfg(any(target_os = "solana", feature = "bincode"))]
mod vote_state_deserialize {
    use {
        crate::{
            authorized_voters::AuthorizedVoters,
            state::{
                BlockTimestamp, LandedVote, Lockout, VoteState, MAX_EPOCH_CREDITS_HISTORY,
                MAX_ITEMS, MAX_LOCKOUT_HISTORY,
            },
        },
        solana_clock::Epoch,
        solana_instruction::error::InstructionError,
        solana_pubkey::Pubkey,
        solana_serialize_utils::cursor::{
            read_bool, read_i64, read_option_u64, read_pubkey, read_pubkey_into, read_u32,
            read_u64, read_u8,
        },
        std::{collections::VecDeque, io::Cursor, ptr::addr_of_mut},
    };

    pub(super) fn deserialize_vote_state_into(
        cursor: &mut Cursor<&[u8]>,
        vote_state: *mut VoteState,
        has_latency: bool,
    ) -> Result<(), InstructionError> {
        // General safety note: we must use add_or_mut! to access the `vote_state` fields as the value
        // is assumed to be _uninitialized_, so creating references to the state or any of its inner
        // fields is UB.

        read_pubkey_into(
            cursor,
            // Safety: if vote_state is non-null, node_pubkey is guaranteed to be valid too
            unsafe { addr_of_mut!((*vote_state).node_pubkey) },
        )?;
        read_pubkey_into(
            cursor,
            // Safety: if vote_state is non-null, authorized_withdrawer is guaranteed to be valid too
            unsafe { addr_of_mut!((*vote_state).authorized_withdrawer) },
        )?;
        let commission = read_u8(cursor)?;
        let votes = read_votes(cursor, has_latency)?;
        let root_slot = read_option_u64(cursor)?;
        let authorized_voters = read_authorized_voters(cursor)?;
        read_prior_voters_into(cursor, vote_state)?;
        let epoch_credits = read_epoch_credits(cursor)?;
        read_last_timestamp_into(cursor, vote_state)?;

        // Safety: if vote_state is non-null, all the fields are guaranteed to be
        // valid pointers.
        //
        // Heap allocated collections - votes, authorized_voters and epoch_credits -
        // are guaranteed not to leak after this point as the VoteState is fully
        // initialized and will be regularly dropped.
        unsafe {
            addr_of_mut!((*vote_state).commission).write(commission);
            addr_of_mut!((*vote_state).votes).write(votes);
            addr_of_mut!((*vote_state).root_slot).write(root_slot);
            addr_of_mut!((*vote_state).authorized_voters).write(authorized_voters);
            addr_of_mut!((*vote_state).epoch_credits).write(epoch_credits);
        }

        Ok(())
    }

    fn read_votes<T: AsRef<[u8]>>(
        cursor: &mut Cursor<T>,
        has_latency: bool,
    ) -> Result<VecDeque<LandedVote>, InstructionError> {
        let vote_count = read_u64(cursor)? as usize;
        let mut votes = VecDeque::with_capacity(vote_count.min(MAX_LOCKOUT_HISTORY));

        for _ in 0..vote_count {
            let latency = if has_latency { read_u8(cursor)? } else { 0 };

            let slot = read_u64(cursor)?;
            let confirmation_count = read_u32(cursor)?;
            let lockout = Lockout::new_with_confirmation_count(slot, confirmation_count);

            votes.push_back(LandedVote { latency, lockout });
        }

        Ok(votes)
    }

    fn read_authorized_voters<T: AsRef<[u8]>>(
        cursor: &mut Cursor<T>,
    ) -> Result<AuthorizedVoters, InstructionError> {
        let authorized_voter_count = read_u64(cursor)?;
        let mut authorized_voters = AuthorizedVoters::default();

        for _ in 0..authorized_voter_count {
            let epoch = read_u64(cursor)?;
            let authorized_voter = read_pubkey(cursor)?;
            authorized_voters.insert(epoch, authorized_voter);
        }

        Ok(authorized_voters)
    }

    fn read_prior_voters_into<T: AsRef<[u8]>>(
        cursor: &mut Cursor<T>,
        vote_state: *mut VoteState,
    ) -> Result<(), InstructionError> {
        // Safety: if vote_state is non-null, prior_voters is guaranteed to be valid too
        unsafe {
            let prior_voters = addr_of_mut!((*vote_state).prior_voters);
            let prior_voters_buf = addr_of_mut!((*prior_voters).buf) as *mut (Pubkey, Epoch, Epoch);

            for i in 0..MAX_ITEMS {
                let prior_voter = read_pubkey(cursor)?;
                let from_epoch = read_u64(cursor)?;
                let until_epoch = read_u64(cursor)?;

                prior_voters_buf
                    .add(i)
                    .write((prior_voter, from_epoch, until_epoch));
            }

            (*vote_state).prior_voters.idx = read_u64(cursor)? as usize;
            (*vote_state).prior_voters.is_empty = read_bool(cursor)?;
        }
        Ok(())
    }

    fn read_epoch_credits<T: AsRef<[u8]>>(
        cursor: &mut Cursor<T>,
    ) -> Result<Vec<(Epoch, u64, u64)>, InstructionError> {
        let epoch_credit_count = read_u64(cursor)? as usize;
        let mut epoch_credits =
            Vec::with_capacity(epoch_credit_count.min(MAX_EPOCH_CREDITS_HISTORY));

        for _ in 0..epoch_credit_count {
            let epoch = read_u64(cursor)?;
            let credits = read_u64(cursor)?;
            let prev_credits = read_u64(cursor)?;
            epoch_credits.push((epoch, credits, prev_credits));
        }

        Ok(epoch_credits)
    }

    fn read_last_timestamp_into<T: AsRef<[u8]>>(
        cursor: &mut Cursor<T>,
        vote_state: *mut VoteState,
    ) -> Result<(), InstructionError> {
        let slot = read_u64(cursor)?;
        let timestamp = read_i64(cursor)?;

        let last_timestamp = BlockTimestamp { slot, timestamp };

        // Safety: if vote_state is non-null, last_timestamp is guaranteed to be valid too
        unsafe {
            addr_of_mut!((*vote_state).last_timestamp).write(last_timestamp);
        }

        Ok(())
    }
}
