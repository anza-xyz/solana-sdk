//! API for retrieving epoch stake information.
//!
//! On-chain programs can use this API to retrieve the total stake for the
//! current epoch or the stake for a specific vote account using the
//! `sol_get_epoch_stake` syscall.
#![cfg_attr(docsrs, feature(doc_cfg))]

use solana_pubkey::Pubkey;

fn get_epoch_stake(var_addr: *const u8) -> u64 {
    #[cfg(target_os = "solana")]
    {
        unsafe { solana_define_syscall::definitions::sol_get_epoch_stake(var_addr) }
    }

    #[cfg(not(target_os = "solana"))]
    {
        core::hint::black_box(var_addr);
        0
    }
}

/// Get the current epoch's total stake.
pub fn get_epoch_total_stake() -> u64 {
    get_epoch_stake(std::ptr::null::<Pubkey>() as *const u8)
}

/// Get the current epoch stake for a given vote address.
///
/// If the provided vote address corresponds to an account that is not a vote
/// account or does not exist, returns `0` for active stake.
pub fn get_epoch_stake_for_vote_account(vote_address: &Pubkey) -> u64 {
    get_epoch_stake(vote_address as *const _ as *const u8)
}
