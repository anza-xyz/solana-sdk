//! Configuration for network [rent].
//!
//! [rent]: https://docs.solanalabs.com/implemented-proposals/rent
//!
//! The _rent sysvar_ provides access to the [`Rent`] type, which defines
//! storage rent fees.
//!
//! [`Rent`] implements [`Sysvar::get`] and can be loaded efficiently without
//! passing the sysvar account ID to the program.
//!
//! See also the Solana [documentation on the rent sysvar][sdoc].
//!
//! [sdoc]: https://docs.solanalabs.com/runtime/sysvars#rent
//!
//! # Examples
//!
//! Accessing via on-chain program directly:
//!
//! ```no_run
//! # use solana_account_info::AccountInfo;
//! # use solana_msg::msg;
//! # use solana_sysvar::Sysvar;
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_rent::Rent;
//! # use solana_sdk_ids::sysvar::rent;
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!
//!     let rent = Rent::get()?;
//!     msg!("rent: {:#?}", rent);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = Rent::id();
//! # let l = &mut 1009200;
//! # let d = &mut vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Accessing via on-chain program's parameters:
//!
//! ```
//! # use solana_account_info::{AccountInfo, next_account_info};
//! # use solana_msg::msg;
//! # use solana_sysvar::{Sysvar, SysvarSerialize};
//! # use solana_program_error::{ProgramError, ProgramResult};
//! # use solana_pubkey::Pubkey;
//! # use solana_rent::Rent;
//! # use solana_sdk_ids::sysvar::rent;
//! #
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let rent_account_info = next_account_info(account_info_iter)?;
//!
//!     assert!(rent::check_id(rent_account_info.key));
//!
//!     let rent = Rent::from_account_info(rent_account_info)?;
//!     msg!("rent: {:#?}", rent);
//!
//!     Ok(())
//! }
//! #
//! # use solana_sysvar_id::SysvarId;
//! # let p = Rent::id();
//! # let l = &mut 1009200;
//! # let d = &mut vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Accessing via the RPC client:
//!
//! ```
//! # use solana_example_mocks::solana_account;
//! # use solana_example_mocks::solana_rpc_client;
//! # use solana_account::Account;
//! # use solana_rent::Rent;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_sdk_ids::sysvar::rent;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_rent(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(rent::ID, Account {
//! #       lamports: 1009200,
//! #       data: vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! # });
//! #
//!     let rent = client.get_account(&rent::ID)?;
//!     let data: Rent = bincode::deserialize(&rent.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_rent(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```
#[cfg(feature = "bincode")]
use crate::SysvarSerialize;
use crate::{get_sysvar_via_packed, sysvar_packed_struct, Sysvar};
pub use {
    solana_rent::Rent,
    solana_sdk_ids::sysvar::rent::{check_id, id, ID},
};

sysvar_packed_struct! {
    struct RentPacked(17) {
        lamports_per_byte_year: u64,
        exemption_threshold: [u8; 8], // f64 as little-endian bytes
        burn_percent: u8,
    }
}

impl From<RentPacked> for Rent {
    fn from(p: RentPacked) -> Self {
        Self {
            lamports_per_byte_year: p.lamports_per_byte_year,
            exemption_threshold: f64::from_le_bytes(p.exemption_threshold),
            burn_percent: p.burn_percent,
        }
    }
}

impl Sysvar for Rent {
    fn get() -> Result<Self, solana_program_error::ProgramError> {
        get_sysvar_via_packed::<Self, RentPacked>(&id())
    }
}

#[cfg(feature = "bincode")]
impl SysvarSerialize for Rent {}

#[cfg(test)]
mod tests {
    use {super::*, crate::Sysvar, serial_test::serial};

    #[test]
    fn test_rent_packed_size() {
        assert_eq!(core::mem::size_of::<RentPacked>(), 17);
    }

    #[test]
    #[serial]
    #[cfg(feature = "bincode")]
    fn test_rent_get() {
        use {
            crate::program_stubs::{set_syscall_stubs, SyscallStubs},
            solana_program_entrypoint::SUCCESS,
        };

        let expected = Rent {
            lamports_per_byte_year: 123,
            exemption_threshold: 2.5,
            burn_percent: 7,
        };

        let data = bincode::serialize(&expected).unwrap();
        assert_eq!(data.len(), 17);

        struct MockSyscall {
            data: Vec<u8>,
        }
        impl SyscallStubs for MockSyscall {
            fn sol_get_sysvar(
                &self,
                _sysvar_id_addr: *const u8,
                var_addr: *mut u8,
                offset: u64,
                length: u64,
            ) -> u64 {
                unsafe {
                    let slice = core::slice::from_raw_parts_mut(var_addr, length as usize);
                    slice.copy_from_slice(&self.data[offset as usize..(offset + length) as usize]);
                }
                SUCCESS
            }
        }

        set_syscall_stubs(Box::new(MockSyscall { data }));
        let got = Rent::get().unwrap();
        assert_eq!(got, expected);
    }
}
