//! Instructions for the non-upgradable BPF loader.
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "stable-abi")]
use solana_frozen_abi_macro::{frozen_abi, StableAbi, StableAbiSample};
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};
#[cfg(any(feature = "bincode", feature = "wincode"))]
use {
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_sdk_ids::sysvar::rent,
};

#[cfg_attr(
    feature = "stable-abi",
    frozen_abi(
        abi_digest = "C8z9CxbjNT9UwGVkCkubvUsZH7ZUJPNkNn9TmRp6ZsPC",
        abi_serializer = ["bincode", "wincode"],
        test_roundtrip = "eq_and_wire"
    ),
    derive(StableAbi, StableAbiSample)
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LoaderInstruction {
    /// Write program data into an account
    ///
    /// # Account references
    ///   0. [WRITE, SIGNER] Account to write to
    Write {
        /// Offset at which to write the given bytes
        offset: u32,

        /// Serialized program data
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        bytes: Vec<u8>,
    },

    /// Finalize an account loaded with program data for execution
    ///
    /// The exact preparation steps is loader specific but on success the loader must set the executable
    /// bit of the account.
    ///
    /// # Account references
    ///   0. [WRITE, SIGNER] The account to prepare for execution
    ///   1. [] Rent sysvar
    Finalize,
}

#[cfg(all(feature = "bincode", not(feature = "wincode")))]
#[inline(always)]
fn create_instruction(
    program_id: Pubkey,
    data: &LoaderInstruction,
    accounts: Vec<AccountMeta>,
) -> Instruction {
    Instruction::new_with_bincode(program_id, data, accounts)
}

#[cfg(feature = "wincode")]
#[inline(always)]
fn create_instruction(
    program_id: Pubkey,
    data: &LoaderInstruction,
    accounts: Vec<AccountMeta>,
) -> Instruction {
    Instruction::new_with_wincode(program_id, data, accounts)
}

#[deprecated(since = "2.2.0", note = "Use loader-v4 instead")]
#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn write(
    account_pubkey: &Pubkey,
    program_id: &Pubkey,
    offset: u32,
    bytes: Vec<u8>,
) -> Instruction {
    let account_metas = vec![AccountMeta::new(*account_pubkey, true)];
    create_instruction(
        *program_id,
        &LoaderInstruction::Write { offset, bytes },
        account_metas,
    )
}

#[deprecated(since = "2.2.0", note = "Use loader-v4 instead")]
#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn finalize(account_pubkey: &Pubkey, program_id: &Pubkey) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*account_pubkey, true),
        AccountMeta::new_readonly(rent::id(), false),
    ];
    create_instruction(*program_id, &LoaderInstruction::Finalize, account_metas)
}

#[cfg(all(test, feature = "bincode", feature = "wincode"))]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_builders_match_bincode_encoding() {
        let account = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        for (ix, expected) in [
            (
                write(&account, &program_id, 7, vec![9, 8, 7]),
                LoaderInstruction::Write {
                    offset: 7,
                    bytes: vec![9, 8, 7],
                },
            ),
            (finalize(&account, &program_id), LoaderInstruction::Finalize),
        ] {
            assert_eq!(ix.program_id, program_id);
            assert_eq!(ix.data, bincode::serialize(&expected).unwrap());
        }
    }
}
