use {crate::pubkey::Pubkey, solana_signer::Signer, wasm_bindgen::prelude::*};

#[wasm_bindgen]
#[derive(Debug)]
pub struct Keypair(pub(crate) solana_keypair::Keypair);

#[allow(non_snake_case)]
#[wasm_bindgen]
impl Keypair {
    /// Create a new `Keypair `
    #[wasm_bindgen(constructor)]
    pub fn constructor() -> Self {
        Self(solana_keypair::Keypair::new())
    }

    /// Convert a `Keypair` to a `Uint8Array`
    pub fn toBytes(&self) -> Box<[u8]> {
        self.0.to_bytes().into()
    }

    /// Recover a `Keypair` from a `Uint8Array`
    pub fn fromBytes(bytes: &[u8]) -> Result<Self, JsValue> {
        solana_keypair::Keypair::try_from(bytes)
            .map(Self)
            .map_err(|e| e.to_string().into())
    }

    /// Return the `Pubkey` for this `Keypair`
    #[wasm_bindgen(js_name = pubkey)]
    pub fn js_pubkey(&self) -> Pubkey {
        Pubkey(self.0.pubkey())
    }
}
