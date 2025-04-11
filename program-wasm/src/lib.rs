//! solana-program Javascript interface
#![cfg(target_arch = "wasm32")]
#[deprecated(since = "2.2.0", note = "Use solana_instruction::wasm instead.")]
pub use solana_instruction::wasm as instructions;
// These imports exist in both solana_sdk and solana_program, so we use
// direct imports to suppress ambiguous re-export warnings.
pub use solana_sdk::entrypoint_deprecated;
use {::log::Level, wasm_bindgen::prelude::*};
pub use {
    solana_program::*,
    solana_sdk::{
        declare_deprecated_id, declare_id, entrypoint, example_mocks, feature, hash, program_utils,
        pubkey, *,
    },
};

// This module is intentionally left empty. The wasm system instruction impl can be
// found in the `solana-system-interface` crate.
pub mod system_instruction {}

/// Initialize Javascript logging and panic handler
#[wasm_bindgen]
pub fn solana_program_init() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
        console_log::init_with_level(Level::Info).unwrap();
    });
}

pub fn display_to_jsvalue<T: std::fmt::Display>(display: T) -> JsValue {
    display.to_string().into()
}
