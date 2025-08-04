use {crate::address::Address, solana_signer::Signer, wasm_bindgen::prelude::*};

#[wasm_bindgen]
#[derive(Debug)]
pub struct Keypair {
    pub(crate) inner: solana_keypair::Keypair,
}

crate::conversion::impl_inner_conversion!(Keypair, solana_keypair::Keypair);

#[allow(non_snake_case)]
#[wasm_bindgen]
impl Keypair {
    /// Create a new `Keypair `
    #[wasm_bindgen(constructor)]
    pub fn constructor() -> Self {
        solana_keypair::Keypair::new().into()
    }

    /// Convert a `Keypair` to a `Uint8Array`
    pub fn toBytes(&self) -> Box<[u8]> {
        self.inner.to_bytes().into()
    }

    /// Recover a `Keypair` from a `Uint8Array`
    pub fn fromBytes(bytes: &[u8]) -> Result<Self, JsValue> {
        solana_keypair::Keypair::try_from(bytes)
            .map(Into::into)
            .map_err(|e| e.to_string().into())
    }

    /// Return the `Address` for this `Keypair`
    #[wasm_bindgen(js_name = pubkey)]
    pub fn js_pubkey(&self) -> Address {
        self.inner.pubkey().into()
    }
}
