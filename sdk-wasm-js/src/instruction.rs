//! The `Instructions` struct is a legacy workaround
//! from when wasm-bindgen lacked Vec<T> support
//! (ref: https://github.com/rustwasm/wasm-bindgen/issues/111)
#![allow(non_snake_case)]

use {
    crate::address::Address, js_sys::Uint8Array, solana_packet::PACKET_DATA_SIZE,
    wasm_bindgen::prelude::*,
};

const MAX_INSTRUCTION_DATA_LEN: usize = PACKET_DATA_SIZE;

/// wasm-bindgen version of the Instruction struct.
/// This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
/// is fixed. This must not diverge from the regular non-wasm Instruction struct.
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Instruction {
    pub(crate) inner: solana_instruction::Instruction,
}

crate::conversion::impl_inner_conversion!(Instruction, solana_instruction::Instruction);

#[wasm_bindgen]
impl Instruction {
    /// Create a new `Instruction`
    #[wasm_bindgen(constructor)]
    pub fn constructor(program_id: Address) -> Self {
        solana_instruction::Instruction::new_with_bytes(program_id.inner, &[], std::vec::Vec::new())
            .into()
    }

    pub fn setData(&mut self, data: Uint8Array) -> Result<(), JsValue> {
        if data.length() as usize > MAX_INSTRUCTION_DATA_LEN {
            return Err(std::format!(
                "Instruction data too large: {} > {}",
                data.length(),
                MAX_INSTRUCTION_DATA_LEN
            )
            .into());
        }

        self.inner.data = data.to_vec();
        Ok(())
    }

    pub fn addAccount(&mut self, account_meta: AccountMeta) {
        self.inner.accounts.push(account_meta.inner);
    }
}

#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountMeta {
    pub(crate) inner: solana_instruction::AccountMeta,
}

crate::conversion::impl_inner_conversion!(AccountMeta, solana_instruction::AccountMeta);

#[wasm_bindgen]
impl AccountMeta {
    /// Create a new writable `AccountMeta`
    pub fn newWritable(address: Address, is_signer: bool) -> Self {
        solana_instruction::AccountMeta::new(address.inner, is_signer).into()
    }

    /// Create a new readonly `AccountMeta`
    pub fn newReadonly(address: Address, is_signer: bool) -> Self {
        solana_instruction::AccountMeta::new_readonly(address.inner, is_signer).into()
    }
}
