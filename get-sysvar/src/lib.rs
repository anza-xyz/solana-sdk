//! Access to the `sol_get_sysvar` syscall, used to fetch sysvar data from the runtime.
//!
//! On-chain calls go directly to the syscall. Off-chain calls are routed through a
//! stub which test harnesses can install with [`set_get_sysvar_stub`] to serve mock
//! sysvar data.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(not(target_os = "solana"), feature = "std"))]
extern crate std;

use {solana_address::Address, solana_program_error::ProgramError};

#[cfg(all(not(target_os = "solana"), feature = "std"))]
mod stubs;

#[cfg(all(not(target_os = "solana"), feature = "std"))]
pub use stubs::{clear_get_sysvar_stub, set_get_sysvar_stub, GetSysvarStub};

/// Syscall success code.
//
// Defined in solana-program-entrypoint as [`SUCCESS`](https://github.com/anza-xyz/solana-sdk/blob/program-entrypoint@v2.2.1/program-entrypoint/src/lib.rs#L35).
const SUCCESS: u64 = 0;
/// Return value indicating that the  `offset + length` is greater than the length of
/// the sysvar data.
//
// Defined in the Agave syscalls crate as [`OFFSET_LENGTH_EXCEEDS_SYSVAR`](https://github.com/anza-xyz/agave/blob/v4.0.2/syscalls/src/sysvar.rs#L180).
const OFFSET_LENGTH_EXCEEDS_SYSVAR: u64 = 1;

/// Return value indicating that the sysvar was not found.
//
// Defined in the Agave syscalls crate as [`SYSVAR_NOT_FOUND`](https://github.com/anza-xyz/agave/blob/v4.0.2/syscalls/src/sysvar.rs#L179).
const SYSVAR_NOT_FOUND: u64 = 2;

/// Handler for retrieving a slice of sysvar data from the `sol_get_sysvar`
/// syscall.
pub fn get_sysvar(
    dst: &mut [u8],
    sysvar_id: &Address,
    offset: u64,
    length: u64,
) -> Result<(), ProgramError> {
    // Check that the provided destination buffer is large enough to hold the requested data
    if dst.len() < length as usize {
        return Err(ProgramError::InvalidArgument);
    }

    let sysvar_id = sysvar_id as *const _ as *const u8;
    let var_addr = dst as *mut _ as *mut u8;

    match sol_get_sysvar(sysvar_id, var_addr, offset, length) {
        SUCCESS => Ok(()),
        OFFSET_LENGTH_EXCEEDS_SYSVAR => Err(ProgramError::InvalidArgument),
        _ => Err(ProgramError::UnsupportedSysvar),
    }
}

/// Internal helper for retrieving sysvar data directly into a raw buffer.
///
/// # Safety
///
/// This function bypasses the slice-length check that `get_sysvar` performs.
/// The caller must ensure that `var_addr` points to a writable buffer of at
/// least `length` bytes. This is typically used with `MaybeUninit` to load
/// compact representations of sysvars.
#[doc(hidden)]
pub unsafe fn get_sysvar_unchecked(
    var_addr: *mut u8,
    sysvar_id: *const u8,
    offset: u64,
    length: u64,
) -> Result<(), ProgramError> {
    match sol_get_sysvar(sysvar_id, var_addr, offset, length) {
        SUCCESS => Ok(()),
        OFFSET_LENGTH_EXCEEDS_SYSVAR => Err(ProgramError::InvalidArgument),
        SYSVAR_NOT_FOUND => Err(ProgramError::UnsupportedSysvar),
        // Unexpected errors are folded into `UnsupportedSysvar`.
        _ => Err(ProgramError::UnsupportedSysvar),
    }
}

// Dispatch to the syscall backend available for this target and feature set
fn sol_get_sysvar(sysvar_id: *const u8, var_addr: *mut u8, offset: u64, length: u64) -> u64 {
    // On-chain programs call the runtime syscall directly
    #[cfg(target_os = "solana")]
    unsafe {
        solana_define_syscall::definitions::sol_get_sysvar(sysvar_id, var_addr, offset, length)
    }

    // Off-chain std builds route through the host-test stub registry
    #[cfg(all(not(target_os = "solana"), feature = "std"))]
    {
        stubs::sol_get_sysvar(sysvar_id, var_addr, offset, length)
    }

    // Off-chain no-std builds have neither runtime syscalls nor host stubs.
    #[cfg(all(not(target_os = "solana"), not(feature = "std")))]
    {
        let _ = (sysvar_id, var_addr, offset, length);
        solana_program_error::UNSUPPORTED_SYSVAR
    }
}
