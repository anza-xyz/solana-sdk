use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Message(pub(crate) solana_message::Message);

impl Message {
    pub fn new(inner: solana_message::Message) -> Self {
        Self(inner)
    }
}
