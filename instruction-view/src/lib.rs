//! Lightweight types for directing the execution of Solana programs.
//!
//! This crate offers views and zero-copy types to interact with program
//! instructions and accounts. As a result, it reduces compute units
//! consumption. This is achieved by defining types that hold references
//! instead of owning the required data.

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "cpi")]
pub mod cpi;

use {solana_account_view::AccountView, solana_address::Address};

/// Information about an instruction.
#[derive(Debug, Clone)]
pub struct InstructionView<'a, 'b, 'c, 'd>
where
    'a: 'b,
{
    /// Address of the program.
    pub program_id: &'c Address,

    /// Data expected by the program instruction.
    pub data: &'d [u8],

    /// Metadata describing account privileges that should be passed to the program.
    pub accounts: &'b [AccountRole<'a>],
}

/// Describes the role of an account during instruction execution.
///
/// When constructing an [`InstructionView`], a list of all accounts that may be
/// signer, read or written during the execution of that instruction must be supplied.
/// Any account that may be mutated by the program during execution, either its
/// data or metadata such as held lamports, must be writable.
///
/// Note that because the Solana runtime schedules parallel transaction
/// execution around which accounts are writable, care should be taken that only
/// accounts which actually may be mutated are specified as writable.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct AccountRole<'a> {
    /// Address of the account.
    pub address: &'a Address,

    /// Indicates whether the account is writable or not.
    pub is_writable: bool,

    /// Indicates whether the account signed the instruction or not.
    pub is_signer: bool,
}

impl<'a> AccountRole<'a> {
    /// Creates a new `AccountPrivilege`.
    #[inline(always)]
    pub const fn new(address: &'a Address, is_writable: bool, is_signer: bool) -> Self {
        Self {
            address,
            is_writable,
            is_signer,
        }
    }

    /// Creates a new read-only `AccountPrivilege`.
    #[inline(always)]
    pub const fn readonly(address: &'a Address) -> Self {
        Self::new(address, false, false)
    }

    /// Creates a new writable `AccountPrivilege`.
    #[inline(always)]
    pub const fn writable(address: &'a Address) -> Self {
        Self::new(address, true, false)
    }

    /// Creates a new read-only and signer `AccountPrivilege`.
    #[inline(always)]
    pub const fn readonly_signer(address: &'a Address) -> Self {
        Self::new(address, false, true)
    }

    /// Creates a new writable and signer `AccountPrivilege`.
    #[inline(always)]
    pub const fn writable_signer(address: &'a Address) -> Self {
        Self::new(address, true, true)
    }
}

impl<'a> From<&'a AccountView> for AccountRole<'a> {
    fn from(account: &'a AccountView) -> Self {
        AccountRole::new(
            account.address(),
            account.is_writable(),
            account.is_signer(),
        )
    }
}
