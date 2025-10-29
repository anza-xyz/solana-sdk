//! `SystemInstruction` Javascript interface
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg(target_arch = "wasm32")]
#![allow(non_snake_case)]
pub use solana_sdk_wasm_js::{
    address::Address, hash::Hash, instruction::Instruction, keypair::Keypair, solana_program_init,
    transaction::Transaction,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MyProgramInstruction;

fn my_program_instruction(program_id: &solana_address::Address) -> solana_instruction::Instruction {
    solana_instruction::Instruction {
        program_id: *program_id,
        accounts: vec![],
        data: vec![],
    }
}

#[wasm_bindgen]
impl MyProgramInstruction {
    #[wasm_bindgen(constructor)]
    pub fn constructor(program_id: &Address) -> Instruction {
        my_program_instruction(program_id).into()
    }
}
