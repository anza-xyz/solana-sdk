//! solana-program Javascript interface
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg(target_arch = "wasm32")]

use {
    log::Level,
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

pub mod address;
pub mod hash;
pub mod instruction;
pub mod keypair;
pub mod message;
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

/// Simple macro for implementing conversion functions between wrapper types and
/// wrapped types.
mod conversion {
    macro_rules! impl_inner_conversion {
        ($Wrapper:ty, $Inner:ty) => {
            impl From<$Inner> for $Wrapper {
                fn from(inner: $Inner) -> Self {
                    Self { inner }
                }
            }
            impl std::ops::Deref for $Wrapper {
                type Target = $Inner;
                fn deref(&self) -> &Self::Target {
                    &self.inner
                }
            }
        };
    }
    pub(crate) use impl_inner_conversion;
}
