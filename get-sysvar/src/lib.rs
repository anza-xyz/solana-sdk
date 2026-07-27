//! Access to the `sol_get_sysvar` syscall, used to fetch sysvar data from the runtime.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

use {solana_address::Address, solana_program_error::ProgramError};

// Stable `$crate` paths for `impl_get_sysvar!`, which expands downstream.
#[doc(hidden)]
pub mod __private {
    pub use solana_program_error::ProgramError;

    /// Syscall success code.
    //
    // Defined in solana-program-entrypoint as [`SUCCESS`](https://github.com/anza-xyz/solana-sdk/blob/program-entrypoint@v2.2.1/program-entrypoint/src/lib.rs#L35).
    pub const SUCCESS: u64 = 0;
    /// Return value indicating that the  `offset + length` is greater than the length of
    /// the sysvar data.
    //
    // Defined in the Agave syscalls crate as [`OFFSET_LENGTH_EXCEEDS_SYSVAR`](https://github.com/anza-xyz/agave/blob/v4.0.2/syscalls/src/sysvar.rs#L180).
    pub const OFFSET_LENGTH_EXCEEDS_SYSVAR: u64 = 1;

    /// Return value indicating that the sysvar was not found.
    //
    // Defined in the Agave syscalls crate as [`SYSVAR_NOT_FOUND`](https://github.com/anza-xyz/agave/blob/v4.0.2/syscalls/src/sysvar.rs#L179).
    pub const SYSVAR_NOT_FOUND: u64 = 2;

    /// Wrapper for the `sol_get_sysvar` syscall.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `sysvar_id` points to a valid sysvar address, and that `var_addr` points
    /// to a writable buffer of at least `length` bytes.
    #[inline(always)]
    pub unsafe fn sol_get_sysvar(
        sysvar_id: *const u8,
        var_addr: *mut u8,
        offset: u64,
        length: u64,
    ) -> u64 {
        // On-chain programs call the runtime syscall directly
        #[cfg(target_os = "solana")]
        unsafe {
            solana_define_syscall::definitions::sol_get_sysvar(sysvar_id, var_addr, offset, length)
        }

        // Off-chain builds have no solana runtime syscall to call
        #[cfg(not(target_os = "solana"))]
        {
            let _ = (sysvar_id, var_addr, offset, length); // warning suppression
            solana_program_error::UNSUPPORTED_SYSVAR
        }
    }
}

/// Interface for loading a sysvar directly from the runtime.
pub trait GetSysvar: Sized {
    /// Load the sysvar directly from the runtime.
    ///
    /// This is the preferred way to load a sysvar. Calling this method does not
    /// incur any deserialization overhead, and does not require the sysvar
    /// account to be passed to the program.
    ///
    /// Not all sysvars support this method. If not, it returns
    /// [`ProgramError::UnsupportedSysvar`].
    #[inline(always)]
    fn get() -> Result<Self, ProgramError> {
        Err(ProgramError::UnsupportedSysvar)
    }
}

/// Handler for retrieving a slice of sysvar data from the `sol_get_sysvar`
/// syscall.
pub fn get_sysvar(
    dst: &mut [u8],
    sysvar_id: &Address,
    offset: u64,
    length: u64,
) -> Result<(), ProgramError> {
    // Check that the provided destination buffer is large enough to hold
    // the requested data.
    if dst.len() < length as usize {
        return Err(ProgramError::InvalidArgument);
    }

    let sysvar_id = sysvar_id as *const _ as *const u8;
    let var_addr = dst as *mut _ as *mut u8;

    // SAFETY: `dst` is a valid buffer of at least `length` bytes.
    unsafe { get_sysvar_unchecked(var_addr, sysvar_id, offset, length) }
}

/// Helper for retrieving sysvar data directly into a raw buffer.
///
/// # Safety
///
/// This function bypasses the slice-length check that `get_sysvar` performs.
/// The caller must ensure that `var_addr` points to a writable buffer of at
/// least `length` bytes. This is typically used with `MaybeUninit` to load
/// compact representations of sysvars.
#[doc(hidden)]
#[inline(always)]
pub unsafe fn get_sysvar_unchecked(
    var_addr: *mut u8,
    sysvar_id: *const u8,
    offset: u64,
    length: u64,
) -> Result<(), ProgramError> {
    match __private::sol_get_sysvar(sysvar_id, var_addr, offset, length) {
        __private::SUCCESS => Ok(()),
        __private::OFFSET_LENGTH_EXCEEDS_SYSVAR => Err(ProgramError::InvalidArgument),
        __private::SYSVAR_NOT_FOUND => Err(ProgramError::UnsupportedSysvar),
        // Unexpected errors are folded into `UnsupportedSysvar`.
        _ => Err(ProgramError::UnsupportedSysvar),
    }
}

/// Implements [`GetSysvar::get`] for runtime-backed sysvars.
#[macro_export]
macro_rules! impl_get_sysvar {
    // Variant for sysvars with trailing bytes (padding). Loads bincode-serialized
    // data (size - padding bytes). Only supports sysvars where padding is at the end
    // of the layout. Caller must supply the correct number of padding bytes.
    ($sysvar_id:expr, $padding:literal) => {
        #[inline(always)]
        fn get() -> Result<Self, $crate::__private::ProgramError> {
            let mut var = core::mem::MaybeUninit::<Self>::uninit();
            let var_addr = var.as_mut_ptr() as *mut u8;
            // SAFETY: The allocation is valid for `size_of::<Self>()` but it
            // loads `(size - padding)` bytes from the syscall, which matches bincode
            // serialization.
            let result = unsafe {
                $crate::__private::sol_get_sysvar(
                    &$sysvar_id as *const _ as *const u8,
                    var_addr,
                    0,
                    core::mem::size_of::<Self>().saturating_sub($padding) as u64,
                )
            };

            match result {
                $crate::__private::SUCCESS => {
                    // SAFETY: The syscall initialized all non-padding bytes of `Self`;
                    // the remaining bytes are trailing padding.
                    Ok(unsafe { var.assume_init() })
                }
                $crate::__private::OFFSET_LENGTH_EXCEEDS_SYSVAR => {
                    Err($crate::__private::ProgramError::InvalidArgument)
                }
                $crate::__private::SYSVAR_NOT_FOUND => {
                    Err($crate::__private::ProgramError::UnsupportedSysvar)
                }
                // Unexpected errors are folded into `UnsupportedSysvar`.
                _ => Err($crate::__private::ProgramError::UnsupportedSysvar),
            }
        }
    };
    // Variant for sysvars without padding (struct size matches bincode size).
    ($sysvar_id:expr) => {
        $crate::impl_get_sysvar!($sysvar_id, 0);
    };
}
