//! solana-program Javascript interface
#![cfg(target_arch = "wasm32")]

use log::Level;
pub use {
    solana_hash::*,
    solana_instruction::*,
    solana_keypair::*,
    solana_pubkey::*,
    solana_transaction::*,
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

pub mod hash;
pub mod instruction;
pub mod keypair;
pub mod message;
pub mod pubkey;
pub mod transaction;

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
