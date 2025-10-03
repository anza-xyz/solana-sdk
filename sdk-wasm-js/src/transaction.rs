//! `Transaction` Javascript interface
#![allow(non_snake_case)]
use {
    crate::{
        address::Address, hash::Hash, instruction::Instruction, keypair::Keypair, message::Message,
    },
    js_sys::Uint8Array,
    solana_packet::PACKET_DATA_SIZE,
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

const MAX_TRANSACTION_SIZE: usize = PACKET_DATA_SIZE;

/// wasm-bindgen version of the Transaction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Transaction struct.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Default, Eq, Clone)]
pub struct Transaction {
    pub(crate) inner: solana_transaction::Transaction,
}

crate::conversion::impl_inner_conversion!(Transaction, solana_transaction::Transaction);

#[wasm_bindgen]
impl Transaction {
    /// Create a new `Transaction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(instructions: Vec<Instruction>, payer: Option<Address>) -> Self {
        let instructions = instructions
            .into_iter()
            .map(|x| x.inner)
            .collect::<Vec<_>>();
        solana_transaction::Transaction::new_with_payer(
            &instructions,
            payer.map(|x| x.inner).as_ref(),
        )
        .into()
    }

    /// Return a message containing all data that should be signed.
    #[wasm_bindgen(js_name = message)]
    pub fn js_message(&self) -> Message {
        self.inner.message.clone().into()
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

    pub fn fromBytes(uint8_array: Uint8Array) -> Result<Self, JsValue> {
        if uint8_array.length() as usize > MAX_TRANSACTION_SIZE {
            return Err(std::format!(
                "Transaction size too large: {} > {}",
                uint8_array.length(),
                MAX_TRANSACTION_SIZE
            )
            .into());
        }

        let bytes_vec = uint8_array.to_vec();

        bincode::deserialize::<solana_transaction::Transaction>(&bytes_vec)
            .map(Into::into)
            .map_err(|x| std::string::ToString::to_string(&x).into())
    }
}
