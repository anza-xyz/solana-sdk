//! API for retrieving the leaders of the current and next slot.
//!
//! On-chain programs can use this API to read the identity and vote account
//! of the block producer for the current slot and for the slot after it,
//! using the `sol_get_leader` syscall defined in [SIMD-0558].
//!
//! [SIMD-0558]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0558-leader-info-syscall.md
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

#[cfg(feature = "bytemuck")]
use bytemuck_derive::{Pod, Zeroable};
use solana_address::Address;

/// The block producers of the current slot and of the slot after it.
///
/// This is the layout written by the `sol_get_leader` syscall.
#[repr(C)]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaderInfo {
    /// Identity of the current slot's leader.
    pub leader_identity: Address,
    /// Vote account of the current slot's leader.
    pub leader_vote: Address,
    /// Identity of the leader of the slot after the current one.
    pub next_leader_identity: Address,
    /// Vote account of the leader of the slot after the current one.
    pub next_leader_vote: Address,
}

impl LeaderInfo {
    /// Size of [`LeaderInfo`] in bytes, as written by the syscall.
    pub const SIZE: usize = 128;
}

const _: () = assert!(core::mem::size_of::<LeaderInfo>() == LeaderInfo::SIZE);
const _: () = assert!(core::mem::align_of::<LeaderInfo>() == 1);

/// Get the leaders of the current slot and of the slot after it.
///
/// Off-chain builds have no runtime to query and return
/// [`LeaderInfo::default`].
pub fn get_leader_info() -> LeaderInfo {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut leader_info = core::mem::MaybeUninit::<LeaderInfo>::uninit();
        // SAFETY: This is sound as sol_get_leader either fills all 128 bytes or aborts the VM
        unsafe {
            solana_define_syscall::definitions::sol_get_leader(leader_info.as_mut_ptr() as *mut u8);
            leader_info.assume_init()
        }
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        LeaderInfo::default()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, core::mem::offset_of};

    #[test]
    fn test_layout_matches_simd_0558() {
        assert_eq!(offset_of!(LeaderInfo, leader_identity), 0);
        assert_eq!(offset_of!(LeaderInfo, leader_vote), 32);
        assert_eq!(offset_of!(LeaderInfo, next_leader_identity), 64);
        assert_eq!(offset_of!(LeaderInfo, next_leader_vote), 96);
    }

    #[test]
    fn test_get_leader_info_off_chain() {
        assert_eq!(get_leader_info(), LeaderInfo::default());
    }
}
