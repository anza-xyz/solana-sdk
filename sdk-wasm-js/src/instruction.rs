//! The `Instructions` struct is a legacy workaround
//! from when wasm-bindgen lacked Vec<T> support
//! (ref: https://github.com/rustwasm/wasm-bindgen/issues/111)
#![allow(non_snake_case)]

use {crate::address::Address, wasm_bindgen::prelude::*};

/// wasm-bindgen version of the Instruction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Instruction struct.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Instruction(pub(crate) solana_instruction::Instruction);

#[wasm_bindgen]
impl Instruction {
    /// Create a new `Instruction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(program_id: Address) -> Self {
        Instruction(solana_instruction::Instruction::new_with_bytes(
            program_id.0,
            &[],
            std::vec::Vec::new(),
        ))
    }

    pub fn setData(&mut self, data: &[u8]) {
        self.0.data = data.to_vec();
    }

    pub fn addAccount(&mut self, account_meta: AccountMeta) {
        self.0.accounts.push(account_meta.0);
    }
}

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountMeta(pub(crate) solana_instruction::AccountMeta);

#[wasm_bindgen]
impl AccountMeta {
    /// Create a new writable `AccountMeta`
    pub fn newWritable(address: Address, is_signer: bool) -> Self {
        AccountMeta(solana_instruction::AccountMeta::new(address.0, is_signer))
    }

    /// Create a new readonly `AccountMeta`
    pub fn newReadonly(address: Address, is_signer: bool) -> Self {
        AccountMeta(solana_instruction::AccountMeta::new_readonly(
            address.0, is_signer,
        ))
    }
}
