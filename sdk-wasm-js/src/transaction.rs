//! `Transaction` Javascript interface
#![allow(non_snake_case)]
use {
    crate::{
        hash::Hash, instruction::Instruction, keypair::Keypair, message::Message, pubkey::Pubkey,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// wasm-bindgen version of the Transaction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Transaction struct.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Default, Eq, Clone)]
pub struct Transaction(pub(crate) solana_transaction::Transaction);

#[wasm_bindgen]
impl Transaction {
    /// Create a new `Transaction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(instructions: Vec<Instruction>, payer: Option<Pubkey>) -> Self {
        let instructions = instructions.into_iter().map(|x| x.0).collect::<Vec<_>>();
        Transaction(solana_transaction::Transaction::new_with_payer(
            &instructions,
            payer.map(|x| x.0).as_ref(),
        ))
    }

    /// Return a message containing all data that should be signed.
    #[wasm_bindgen(js_name = message)]
    pub fn js_message(&self) -> Message {
        Message(self.0.message.clone())
    }

    /// Return the serialized message data to sign.
    pub fn messageData(&self) -> Box<[u8]> {
        self.0.message_data().into()
    }

    /// Verify the transaction
    #[wasm_bindgen(js_name = verify)]
    pub fn js_verify(&self) -> Result<(), JsValue> {
        self.0
            .verify()
            .map_err(|x| std::string::ToString::to_string(&x).into())
    }

    pub fn partialSign(&mut self, keypair: &Keypair, recent_blockhash: &Hash) {
        self.0.partial_sign(&[&keypair.0], recent_blockhash.0);
    }

    pub fn isSigned(&self) -> bool {
        self.0.is_signed()
    }

    pub fn toBytes(&self) -> Box<[u8]> {
        bincode::serialize(&self.0).unwrap().into()
    }

    pub fn fromBytes(bytes: &[u8]) -> Result<Self, JsValue> {
        bincode::deserialize::<solana_transaction::Transaction>(bytes)
            .map(Self)
            .map_err(|x| std::string::ToString::to_string(&x).into())
    }
}
