use {
    crate::{
        authorized_voters::AuthorizedVoters,
        state::{
            BlockTimestamp, LandedVote, Lockout, VoteStateV3, MAX_EPOCH_CREDITS_HISTORY, MAX_ITEMS,
            MAX_LOCKOUT_HISTORY,
        },
    },
    solana_clock::Epoch,
    solana_instruction_error::InstructionError,
    solana_pubkey::Pubkey,
    solana_serialize_utils::cursor::{
        read_bool, read_i64, read_option_u64, read_pubkey, read_pubkey_into, read_u32, read_u64,
        read_u8,
    },
    std::{collections::VecDeque, io::Cursor, ptr::addr_of_mut},
};

// This is to reset vote_state to T::default() if deserialize fails or panics.
struct DropGuard<T: Default> {
    vote_state: *mut T,
}

impl<T: Default> Drop for DropGuard<T> {
    fn drop(&mut self) {
        // Safety:
        //
        // Deserialize failed or panicked so at this point vote_state is uninitialized. We
        // must write a new _valid_ value into it or after returning (or unwinding) from
        // this function the caller is left with an uninitialized `&mut T`, which is UB
        // (references must always be valid).
        //
        // This is always safe and doesn't leak memory because deserialize_into_ptr() writes
        // into the fields that heap alloc only when it returns Ok().
        unsafe {
            self.vote_state.write(T::default());
        }
    }
}

pub(crate) fn deserialize_into<T: Default>(
    input: &[u8],
    vote_state: &mut T,
    deserialize_fn: impl FnOnce(&[u8], *mut T) -> Result<(), InstructionError>,
) -> Result<(), InstructionError> {
    // Rebind vote_state to *mut T so that the &mut binding isn't accessible
    // anymore, preventing accidental use after this point.
    //
    // NOTE: switch to ptr::from_mut() once platform-tools moves to rustc >= 1.76
    let vote_state = vote_state as *mut T;

    // Safety: vote_state is valid to_drop (see drop_in_place() docs). After
    // dropping, the pointer is treated as uninitialized and only accessed
    // through ptr::write, which is safe as per drop_in_place docs.
    unsafe {
        std::ptr::drop_in_place(vote_state);
    }

    // This is to reset vote_state to T::default() if deserialize fails or panics.
    let guard = DropGuard { vote_state };

    let res = deserialize_fn(input, vote_state);
    if res.is_ok() {
        std::mem::forget(guard);
    }

    res
}

pub(super) fn deserialize_vote_state_into(
    cursor: &mut Cursor<&[u8]>,
    vote_state: *mut VoteStateV3,
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
    // are guaranteed not to leak after this point as the VoteStateV3 is fully
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
    vote_state: *mut VoteStateV3,
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
    let mut epoch_credits = Vec::with_capacity(epoch_credit_count.min(MAX_EPOCH_CREDITS_HISTORY));

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
    vote_state: *mut VoteStateV3,
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
