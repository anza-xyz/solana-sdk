//! `SystemInstruction` Javascript interface
#![cfg(target_arch = "wasm32")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(non_snake_case)]
use {
    solana_sdk_wasm_js::{address::Address, instruction::Instruction},
    solana_system_interface::instruction::{
        advance_nonce_account, allocate, allocate_with_seed, assign, assign_with_seed,
        authorize_nonce_account, create_account, create_account_with_seed, create_nonce_account,
        transfer, transfer_with_seed, withdraw_nonce_account,
    },
    wasm_bindgen::prelude::*,
};

#[wasm_bindgen]
pub struct SystemInstruction;

#[wasm_bindgen]
impl SystemInstruction {
    pub fn createAccount(
        from: &Address,
        to: &Address,
        lamports: u64,
        space: u64,
        owner: &Address,
    ) -> Instruction {
        create_account(from, to, lamports, space, owner).into()
    }

    pub fn createAccountWithSeed(
        from: &Address,
        to: &Address,
        base: &Address,
        seed: &str,
        lamports: u64,
        space: u64,
        owner: &Address,
    ) -> Instruction {
        create_account_with_seed(from, to, base, seed, lamports, space, owner).into()
    }

    pub fn assign(address: &Address, owner: &Address) -> Instruction {
        assign(address, owner).into()
    }

    pub fn assignWithSeed(
        address: &Address,
        base: &Address,
        seed: &str,
        owner: &Address,
    ) -> Instruction {
        assign_with_seed(address, base, seed, owner).into()
    }

    pub fn transfer(from: &Address, to: &Address, lamports: u64) -> Instruction {
        transfer(from, to, lamports).into()
    }

    pub fn transferWithSeed(
        from: &Address,
        from_base: &Address,
        from_seed: String,
        from_owner: &Address,
        to: &Address,
        lamports: u64,
    ) -> Instruction {
        transfer_with_seed(from, from_base, from_seed, from_owner, to, lamports).into()
    }

    pub fn allocate(address: &Address, space: u64) -> Instruction {
        allocate(address, space).into()
    }

    pub fn allocateWithSeed(
        address: &Address,
        base: &Address,
        seed: &str,
        space: u64,
        owner: &Address,
    ) -> Instruction {
        allocate_with_seed(address, base, seed, space, owner).into()
    }

    pub fn createNonceAccount(
        from: &Address,
        nonce: &Address,
        authority: &Address,
        lamports: u64,
    ) -> js_sys::Array {
        let instructions = create_nonce_account(from, nonce, authority, lamports);
        instructions
            .into_iter()
            .map(|x| JsValue::from(Instruction::from(x)))
            .collect()
    }

    pub fn advanceNonceAccount(nonce: &Address, authorized: &Address) -> Instruction {
        advance_nonce_account(nonce, authorized).into()
    }

    pub fn withdrawNonceAccount(
        nonce: &Address,
        authorized: &Address,
        to: &Address,
        lamports: u64,
    ) -> Instruction {
        withdraw_nonce_account(nonce, authorized, to, lamports).into()
    }

    pub fn authorizeNonceAccount(
        nonce: &Address,
        authorized: &Address,
        new_authority: &Address,
    ) -> Instruction {
        authorize_nonce_account(nonce, authorized, new_authority).into()
    }
}
