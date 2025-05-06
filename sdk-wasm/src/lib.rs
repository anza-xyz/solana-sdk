#![cfg(target_arch = "wasm32")]
pub use {
    solana_program::*,
    solana_sdk::{
        // These imports exist in both solana_sdk and solana_program, so we use
        // direct imports to suppress ambiguous re-export warnings.
        declare_deprecated_id,
        declare_id,
        entrypoint,
        entrypoint_deprecated,
        example_mocks,
        feature,
        hash,
        program_utils,
        pubkey,
        *,
    },
};
