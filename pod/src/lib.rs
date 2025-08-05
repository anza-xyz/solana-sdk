//! Crate containing `Pod` types and `bytemuck` utilities used in SPL

pub mod bytemuck;
pub mod error;
pub mod list;
pub mod option;
pub mod optional_keys;
pub mod pod_length;
pub mod primitives;
pub mod slice;

// Export current sdk types for downstream users building with a different sdk
// version
pub use {solana_program_error, solana_program_option, solana_pubkey};
