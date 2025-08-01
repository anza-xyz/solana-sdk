//! `Transaction` Javascript interface
#![allow(non_snake_case)]
use {
    crate::{
        address::Address, hash::Hash, instruction::Instruction, keypair::Keypair, message::Message,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// wasm-bindgen version of the Transaction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Transaction struct.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Default, Eq, Clone)]
pub struct Transaction {
    pub(crate) inner: solana_transaction::Transaction,
}

impl Transaction {
    pub fn new(inner: solana_transaction::Transaction) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &solana_transaction::Transaction {
        &self.inner
    }
}

#[wasm_bindgen]
impl Transaction {
    /// Create a new `Transaction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(instructions: Vec<Instruction>, payer: Option<Address>) -> Self {
        let instructions = instructions
            .into_iter()
            .map(|x| x.inner)
            .collect::<Vec<_>>();
        Self::new(solana_transaction::Transaction::new_with_payer(
            &instructions,
            payer.map(|x| x.inner).as_ref(),
        ))
    }

    /// Return a message containing all data that should be signed.
    #[wasm_bindgen(js_name = message)]
    pub fn js_message(&self) -> Message {
        Message::new(self.inner.message.clone())
    }

    /// Return the serialized message data to sign.
    pub fn messageData(&self) -> Box<[u8]> {
        self.inner.message_data().into()
    }

    /// Verify the transaction
    #[wasm_bindgen(js_name = verify)]
    pub fn js_verify(&self) -> Result<(), JsValue> {
        self.inner
            .verify()
            .map_err(|x| std::string::ToString::to_string(&x).into())
    }

    pub fn partialSign(&mut self, keypair: &Keypair, recent_blockhash: &Hash) {
        self.inner
            .partial_sign(&[&keypair.inner], recent_blockhash.inner);
    }

    pub fn isSigned(&self) -> bool {
        self.inner.is_signed()
    }

    pub fn toBytes(&self) -> Box<[u8]> {
        bincode::serialize(&self.inner).unwrap().into()
    }

    pub fn fromBytes(bytes: &[u8]) -> Result<Self, JsValue> {
        bincode::deserialize::<solana_transaction::Transaction>(bytes)
            .map(Self::new)
            .map_err(|x| std::string::ToString::to_string(&x).into())
    }
}
