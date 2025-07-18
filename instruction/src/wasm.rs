//! The `Instructions` struct is a legacy workaround
//! from when wasm-bindgen lacked Vec<T> support
//! (ref: https://github.com/rustwasm/wasm-bindgen/issues/111)
#![allow(non_snake_case)]
use {
    crate::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    wasm_bindgen::prelude::*,
};

#[wasm_bindgen]
#[derive(Default)]
pub struct Instructions {
    instructions: std::vec::Vec<Instruction>,
}

#[wasm_bindgen]
impl Instructions {
    #[wasm_bindgen(constructor)]
    pub fn constructor() -> Instructions {
        Instructions::default()
    }

    pub fn push(&mut self, instruction: Instruction) {
        self.instructions.push(instruction);
    }
}

impl From<Instructions> for std::vec::Vec<Instruction> {
    fn from(instructions: Instructions) -> Self {
        instructions.instructions
    }
}

#[wasm_bindgen]
impl Instruction {
    /// Create a new `Instruction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(program_id: Pubkey) -> Self {
        Instruction::new_with_bytes(program_id, &[], std::vec::Vec::new())
    }

    pub fn setData(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    pub fn addAccount(&mut self, account_meta: AccountMeta) {
        self.accounts.push(account_meta);
    }
}

#[wasm_bindgen]
impl AccountMeta {
    /// Create a new writable `AccountMeta`
    pub fn newWritable(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta::new(pubkey, is_signer)
    }

    /// Create a new readonly `AccountMeta`
    pub fn newReadonly(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta::new_readonly(pubkey, is_signer)
    }
}
