use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Message(pub solana_message::Message);
