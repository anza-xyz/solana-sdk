#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// We re-export the `format!` macro from `alloc` for use in the `msg!` macro
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub use alloc::format;

/// Print a message to the log.
///
/// Supports simple strings as well as Rust [format strings][fs]. When passed a
/// single expression it will be passed directly to [`sol_log`]. The expression
/// must have type `&str`, and is typically used for logging static strings.
/// When passed something other than an expression, particularly
/// a sequence of expressions, the tokens will be passed through the
/// [`format!`] macro before being logged with `sol_log`.
///
/// [fs]: https://doc.rust-lang.org/alloc/fmt/
/// [`format!`]: https://doc.rust-lang.org/alloc/fmt/fn.format.html
///
/// Note that Rust's formatting machinery is relatively CPU-intensive
/// for constrained environments like the Solana VM.
///
/// # Examples
///
/// ```
/// use solana_msg::msg;
///
/// // The fast form
/// msg!("verifying multisig");
///
/// // With formatting
/// let err = "not enough signers";
/// msg!("multisig failed: {}", err);
/// ```
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! msg {
    ($msg:expr) => {
        $crate::sol_log($msg)
    };
    ($($arg:tt)*) => ($crate::sol_log(&$crate::format!($($arg)*)));
}

#[cfg(target_os = "solana")]
pub mod syscalls;

/// Print a string to the log.
#[inline]
pub fn sol_log(message: &str) {
    #[cfg(target_os = "solana")]
    unsafe {
        syscalls::sol_log_(message.as_ptr(), message.len() as u64);
    }

    #[cfg(all(not(target_os = "solana"), feature = "std"))]
    std::println!("{message}");

    #[cfg(all(not(target_os = "solana"), not(feature = "std")))]
    core::hint::black_box(message);
}
