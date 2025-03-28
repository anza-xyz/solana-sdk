//! Solana precompiled programs.

#![cfg(feature = "full")]

#[deprecated(since = "2.1.0", note = "Use `solana-precompile-error` crate instead.")]
pub use solana_precompile_error::PrecompileError;
#[allow(deprecated)]
pub use solana_precompiles::{
    get_precompile, get_precompiles, is_precompile, verify_if_precompile, Precompile, Verify,
};
