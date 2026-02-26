//! Crate containing `Pod` types and `bytemuck` utilities used in SPL

#[cfg(feature = "bytemuck")]
pub mod bytemuck;
pub mod option;
pub mod optional_keys;
pub mod primitives;

// Export current sdk types for downstream users building with a different sdk
// version
pub use {solana_address, solana_program_error, solana_program_option};
