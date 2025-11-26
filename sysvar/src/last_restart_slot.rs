//! Information about the last restart slot (hard fork).
//!
//! The _last restart sysvar_ provides access to the last restart slot kept in the
//! bank fork for the slot on the fork that executes the current transaction.
//! In case there was no fork it returns _0_.
//!
//! [`LastRestartSlot`] implements [`Sysvar::get`] and can be loaded efficiently without
//! passing the sysvar account ID to the program.
//!
//! See also the Solana [SIMD proposal][simd].
//!
//! [simd]: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0047-syscall-and-sysvar-for-last-restart-slot.md
//!
//! # Examples
//!
//! Accessing via on-chain program directly:
//!
//! ```no_run
//! # use solana_account_info::AccountInfo;
//! # use solana_msg::msg;
//! # use solana_sysvar::Sysvar;
//! # use solana_program_error::ProgramResult;
//! # use solana_pubkey::Pubkey;
//! # use solana_last_restart_slot::LastRestartSlot;
//!
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!
//!     let last_restart_slot = LastRestartSlot::get();
//!     msg!("last restart slot: {:?}", last_restart_slot);
//!
//!     Ok(())
//! }
//! ```
//!
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
use crate::{impl_sysvar_get, Sysvar};
pub use {
    solana_last_restart_slot::LastRestartSlot,
    solana_sdk_ids::sysvar::last_restart_slot::{check_id, id, ID},
};

impl Sysvar for LastRestartSlot {
    impl_sysvar_get!(id());
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for LastRestartSlot {}

#[cfg(test)]
mod tests {
    use {super::*, crate::tests::to_bytes, serial_test::serial};

    #[test]
    #[cfg(feature = "bincode")]
    fn test_last_restart_slot_size_matches_bincode() {
        // Prove that LastRestartSlot's in-memory layout matches its bincode serialization.
        let slot = LastRestartSlot::default();
        let in_memory_size = core::mem::size_of::<LastRestartSlot>();
        let bincode_size = bincode::serialized_size(&slot).unwrap() as usize;

        assert_eq!(
            in_memory_size, bincode_size,
            "LastRestartSlot in-memory size ({in_memory_size}) must match bincode size ({bincode_size})",
        );
    }

    #[test]
    #[serial]
    fn test_last_restart_slot_get_uses_sysvar_syscall() {
        let expected = LastRestartSlot {
            last_restart_slot: 9999,
        };
        let data = to_bytes(&expected);
        crate::tests::mock_get_sysvar_syscall(&data);

        let got = LastRestartSlot::get().unwrap();
        assert_eq!(got, expected);
    }
}
