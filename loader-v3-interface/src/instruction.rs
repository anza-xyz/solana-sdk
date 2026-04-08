//! Instructions for the upgradable BPF loader.

#[cfg(feature = "bincode")]
use {
    crate::{get_program_data_address, state::UpgradeableLoaderState},
    solana_instruction::{error::InstructionError, AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_sdk_ids::{bpf_loader_upgradeable::id, loader_v4, sysvar},
    solana_system_interface::instruction as system_instruction,
};

/// Minimum number of bytes for an `ExtendProgram` instruction.
///
/// After the SIMD-0431 feature gate is activated, `ExtendProgram` will
/// reject requests smaller than this value, unless the program data
/// account is within this many bytes of the max permitted data length of
/// an account: 10 MiB.
pub const MINIMUM_EXTEND_PROGRAM_BYTES: u32 = 10_240;

#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UpgradeableLoaderInstruction {
    /// Initialize a Buffer account.
    ///
    /// A Buffer account is an intermediary that once fully populated is used
    /// with the `DeployWithMaxDataLen` instruction to populate the program's
    /// ProgramData account.
    ///
    /// The `InitializeBuffer` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party may initialize the account.
    ///
    /// # Account references
    ///   0. `[writable]` source account to initialize.
    ///   1. `[]` Buffer authority, optional, if omitted then the buffer will be
    ///      immutable.
    InitializeBuffer,

    /// Write program data into a Buffer account.
    ///
    /// # Account references
    ///   0. `[writable]` Buffer account to write program data to.
    ///   1. `[signer]` Buffer authority
    Write {
        /// Offset at which to write the given bytes.
        offset: u32,
        /// Serialized program data
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        bytes: Vec<u8>,
    },

    /// Deploy an executable program.
    ///
    /// A program consists of a Program and ProgramData account pair.
    ///   - The Program account's address will serve as the program id for any
    ///     instructions that execute this program.
    ///   - The ProgramData account will remain mutable by the loader only and
    ///     holds the program data and authority information.  The ProgramData
    ///     account's address is derived from the Program account's address and
    ///     created by the DeployWithMaxDataLen instruction.
    ///
    /// The ProgramData address is derived from the Program account's address as
    /// follows:
    ///
    /// ```
    /// # use solana_pubkey::Pubkey;
    /// # use solana_sdk_ids::bpf_loader_upgradeable;
    /// # let program_address = &[];
    /// let (program_data_address, _) = Pubkey::find_program_address(
    ///      &[program_address],
    ///      &bpf_loader_upgradeable::id()
    ///  );
    /// ```
    ///
    /// The `DeployWithMaxDataLen` instruction does not require the ProgramData
    /// account be a signer and therefore MUST be included within the same
    /// Transaction as the system program's `CreateAccount` instruction that
    /// creates the Program account. Otherwise another party may initialize the
    /// account.
    ///
    /// # Account references
    ///   0. `[writable, signer]` The payer account that will pay to create the
    ///      ProgramData account.
    ///   1. `[writable]` The uninitialized ProgramData account.
    ///   2. `[writable]` The uninitialized Program account.
    ///   3. `[writable]` The Buffer account where the program data has been
    ///      written.
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[]` System program (`solana_sdk_ids::system_program::id()`).
    ///   7. `[signer]` The program's authority
    ///
    /// An additional parameter can be serialized at the end of this
    /// instruction. Consider this `close_buffer: bool`.
    /// * If `true`:
    ///   * The buffer account's authority must match the program's authority.
    ///   * The buffer account will be closed and its lamports transferred to
    ///     the payer.
    /// * If `false`:
    ///   * The buffer account's authority *does not* have to match the
    ///     program's authority.
    ///   * The buffer remains unchanged for potential reuse.
    DeployWithMaxDataLen {
        /// Maximum length that the program can be upgraded to.
        max_data_len: usize,
    },

    /// Upgrade a program.
    ///
    /// A program can be updated as long as the program's authority has not been
    /// set to `None`.
    ///
    /// The Buffer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt, any additional lamports left over
    /// will be transferred to the spill account, leaving the Buffer account
    /// balance at zero.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The Program account.
    ///   2. `[writable]` The Buffer account where the program data has been
    ///      written.
    ///   3. `[writable]` The spill account.
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[signer]` The program's authority.
    ///
    /// An additional parameter can be serialized at the end of this
    /// instruction. Consider this `close_buffer: bool`.
    /// * If `true`:
    ///   * The buffer account's authority must match the program's authority.
    ///   * The buffer account will be closed and its lamports transferred to
    ///     the payer.
    /// * If `false`:
    ///   * The buffer account's authority *does not* have to match the
    ///     program's authority.
    ///   * The buffer remains unchanged for potential reuse.
    Upgrade,

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.  To permanently make the buffer immutable or disable program
    /// updates omit the new authority.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[]` The new authority, optional, if omitted then the program will
    ///      not be upgradeable.
    SetAuthority,

    /// Closes an account owned by the upgradeable loader of all lamports and
    /// withdraws all the lamports
    ///
    /// # Account references
    ///   0. `[writable]` The account to close, if closing a program must be the
    ///      ProgramData account.
    ///   1. `[writable]` The account to deposit the closed account's lamports.
    ///   2. `[signer]` The account's authority, Optional, required for
    ///      initialized accounts.
    ///   3. `[writable]` The associated Program account if the account to close
    ///      is a ProgramData account.
    Close,

    /// Extend a program's ProgramData account by the specified number of bytes.
    /// Only upgradeable programs can be extended.
    ///
    /// After the SIMD-0431 feature gate is activated, `additional_bytes`
    /// must be at least [`MINIMUM_EXTEND_PROGRAM_BYTES`] (10 KiB).
    /// The minimum does not apply when the program data account is
    /// within [`MINIMUM_EXTEND_PROGRAM_BYTES`] of the max permitted
    /// data length of an account: 10 MiB.
    ///
    /// The payer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt. If the ProgramData account
    /// balance is already sufficient to cover the rent exemption cost
    /// for the extended bytes, the payer account is not required.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The ProgramData account's associated Program account.
    ///   2. `[]` System program (`solana_sdk::system_program::id()`), optional, used to transfer
    ///      lamports from the payer to the ProgramData account.
    ///   3. `[writable, signer]` The payer account, optional, that will pay
    ///      necessary rent exemption costs for the increased storage size.
    ExtendProgram {
        /// Number of bytes to extend the program data.
        additional_bytes: u32,
    },

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.
    ///
    /// This instruction differs from SetAuthority in that the new authority is a
    /// required signer.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[signer]` The new authority.
    SetAuthorityChecked,

    /// Migrate the program to loader-v4.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The Program account.
    ///   2. `[signer]` The current authority.
    Migrate,

    /// Extend a program's ProgramData account by the specified number of bytes.
    /// Only upgradeable programs can be extended.
    ///
    /// This instruction differs from ExtendProgram in that the authority is a
    /// required signer.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The ProgramData account's associated Program account.
    ///   2. `[signer]` The authority.
    ///   3. `[]` System program (`solana_sdk::system_program::id()`), optional, used to transfer
    ///      lamports from the payer to the ProgramData account.
    ///   4. `[signer]` The payer account, optional, that will pay necessary rent exemption costs
    ///      for the increased storage size.
    ExtendProgramChecked {
        /// Number of bytes to extend the program data.
        additional_bytes: u32,
    },
}

// 4-byte discriminator + 8-byte usize
#[cfg(feature = "bincode")]
const SIZE_OF_DEPLOY_WITH_MAX_DATA_LEN: usize = 12;
// 4-byte discriminator
#[cfg(feature = "bincode")]
const SIZE_OF_UPGRADE: usize = 4;

#[cfg(feature = "bincode")]
fn deserialize_trailing_bool(bytes: &[u8], offset: usize) -> Result<bool, InstructionError> {
    if bytes.len() < offset {
        return Err(InstructionError::InvalidInstructionData);
    }
    match bytes.get(offset) {
        None | Some(1) => Ok(true), // <-- Defaults to `true`
        Some(0) => Ok(false),
        Some(_) => Err(InstructionError::InvalidInstructionData),
    }
}

/// Deserialize the optional trailing `close_buffer: bool` from a
/// `DeployWithMaxDataLen` instruction.
///
/// Per SIMD-0430, the absence of this byte defaults to `true`.
#[cfg(feature = "bincode")]
pub fn deserialize_deploy_close_buffer(instruction_data: &[u8]) -> Result<bool, InstructionError> {
    deserialize_trailing_bool(instruction_data, SIZE_OF_DEPLOY_WITH_MAX_DATA_LEN)
}

/// Deserialize the optional trailing `close_buffer: bool` from an
/// `Upgrade` instruction.
///
/// Per SIMD-0430, the absence of this byte defaults to `true`.
#[cfg(feature = "bincode")]
pub fn deserialize_upgrade_close_buffer(instruction_data: &[u8]) -> Result<bool, InstructionError> {
    deserialize_trailing_bool(instruction_data, SIZE_OF_UPGRADE)
}

#[cfg(feature = "bincode")]
fn serialize_with_trailing_bool(
    instruction: &UpgradeableLoaderInstruction,
    value: bool,
) -> Vec<u8> {
    let mut data = bincode::serialize(instruction).unwrap();
    data.push(value.into());
    data
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to initialize a Buffer account.
pub fn create_buffer(
    payer_address: &Pubkey,
    buffer_address: &Pubkey,
    authority_address: &Pubkey,
    lamports: u64,
    program_len: usize,
) -> Result<Vec<Instruction>, InstructionError> {
    Ok(vec![
        system_instruction::create_account(
            payer_address,
            buffer_address,
            lamports,
            UpgradeableLoaderState::size_of_buffer(program_len) as u64,
            &id(),
        ),
        Instruction::new_with_bincode(
            id(),
            &UpgradeableLoaderInstruction::InitializeBuffer,
            vec![
                AccountMeta::new(*buffer_address, false),
                AccountMeta::new_readonly(*authority_address, false),
            ],
        ),
    ])
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to write a chunk of program data to a
/// buffer account.
pub fn write(
    buffer_address: &Pubkey,
    authority_address: &Pubkey,
    offset: u32,
    bytes: Vec<u8>,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::Write { offset, bytes },
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*authority_address, true),
        ],
    )
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to deploy a program with a specified
/// maximum program length.  The maximum length must be large enough to
/// accommodate any future upgrades.
pub fn deploy_with_max_program_len(
    payer_address: &Pubkey,
    program_address: &Pubkey,
    buffer_address: &Pubkey,
    upgrade_authority_address: &Pubkey,
    program_lamports: u64,
    max_data_len: usize,
    close_buffer: bool,
) -> Result<Vec<Instruction>, InstructionError> {
    let programdata_address = get_program_data_address(program_address);
    let bytes = serialize_with_trailing_bool(
        &UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len },
        close_buffer,
    );
    Ok(vec![
        system_instruction::create_account(
            payer_address,
            program_address,
            program_lamports,
            UpgradeableLoaderState::size_of_program() as u64,
            &id(),
        ),
        Instruction::new_with_bytes(
            id(),
            &bytes,
            vec![
                AccountMeta::new(*payer_address, true),
                AccountMeta::new(programdata_address, false),
                AccountMeta::new(*program_address, false),
                AccountMeta::new(*buffer_address, false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
                AccountMeta::new_readonly(sysvar::clock::id(), false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
                AccountMeta::new_readonly(*upgrade_authority_address, true),
            ],
        ),
    ])
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to upgrade a program.
pub fn upgrade(
    program_address: &Pubkey,
    buffer_address: &Pubkey,
    authority_address: &Pubkey,
    spill_address: &Pubkey,
    close_buffer: bool,
) -> Instruction {
    let programdata_address = get_program_data_address(program_address);
    let bytes = serialize_with_trailing_bool(&UpgradeableLoaderInstruction::Upgrade, close_buffer);
    Instruction::new_with_bytes(
        id(),
        &bytes,
        vec![
            AccountMeta::new(programdata_address, false),
            AccountMeta::new(*program_address, false),
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new(*spill_address, false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(*authority_address, true),
        ],
    )
}

pub fn is_upgrade_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 3 == instruction_data[0]
}

pub fn is_set_authority_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 4 == instruction_data[0]
}

pub fn is_close_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 5 == instruction_data[0]
}

pub fn is_set_authority_checked_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 7 == instruction_data[0]
}

pub fn is_migrate_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 8 == instruction_data[0]
}

pub fn is_extend_program_checked_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 9 == instruction_data[0]
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to set a buffers's authority.
pub fn set_buffer_authority(
    buffer_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthority,
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*current_authority_address, true),
            AccountMeta::new_readonly(*new_authority_address, false),
        ],
    )
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to set a buffers's authority. If using this instruction, the new authority
/// must sign.
pub fn set_buffer_authority_checked(
    buffer_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthorityChecked,
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*current_authority_address, true),
            AccountMeta::new_readonly(*new_authority_address, true),
        ],
    )
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to set a program's authority.
pub fn set_upgrade_authority(
    program_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: Option<&Pubkey>,
) -> Instruction {
    let programdata_address = get_program_data_address(program_address);

    let mut metas = vec![
        AccountMeta::new(programdata_address, false),
        AccountMeta::new_readonly(*current_authority_address, true),
    ];
    if let Some(address) = new_authority_address {
        metas.push(AccountMeta::new_readonly(*address, false));
    }
    Instruction::new_with_bincode(id(), &UpgradeableLoaderInstruction::SetAuthority, metas)
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to set a program's authority. If using this instruction, the new authority
/// must sign.
pub fn set_upgrade_authority_checked(
    program_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: &Pubkey,
) -> Instruction {
    let programdata_address = get_program_data_address(program_address);

    let metas = vec![
        AccountMeta::new(programdata_address, false),
        AccountMeta::new_readonly(*current_authority_address, true),
        AccountMeta::new_readonly(*new_authority_address, true),
    ];
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthorityChecked,
        metas,
    )
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to close a buffer account
pub fn close(
    close_address: &Pubkey,
    recipient_address: &Pubkey,
    authority_address: &Pubkey,
) -> Instruction {
    close_any(
        close_address,
        recipient_address,
        Some(authority_address),
        None,
    )
}

#[cfg(feature = "bincode")]
/// Returns the instructions required to close program, buffer, or uninitialized account
pub fn close_any(
    close_address: &Pubkey,
    recipient_address: &Pubkey,
    authority_address: Option<&Pubkey>,
    program_address: Option<&Pubkey>,
) -> Instruction {
    let mut metas = vec![
        AccountMeta::new(*close_address, false),
        AccountMeta::new(*recipient_address, false),
    ];
    if let Some(authority_address) = authority_address {
        metas.push(AccountMeta::new_readonly(*authority_address, true));
    }
    if let Some(program_address) = program_address {
        metas.push(AccountMeta::new(*program_address, false));
    }
    Instruction::new_with_bincode(id(), &UpgradeableLoaderInstruction::Close, metas)
}

#[cfg(feature = "bincode")]
/// Returns the instruction required to extend the size of a program's
/// executable data account.
///
/// After SIMD-0431 activation, `additional_bytes` must be at least
/// [`MINIMUM_EXTEND_PROGRAM_BYTES`] unless the account is near the
/// max permitted data length of an account: 10 MiB.
pub fn extend_program(
    program_address: &Pubkey,
    payer_address: Option<&Pubkey>,
    additional_bytes: u32,
) -> Instruction {
    let program_data_address = get_program_data_address(program_address);
    let mut metas = vec![
        AccountMeta::new(program_data_address, false),
        AccountMeta::new(*program_address, false),
    ];
    if let Some(payer_address) = payer_address {
        metas.push(AccountMeta::new_readonly(
            solana_sdk_ids::system_program::id(),
            false,
        ));
        metas.push(AccountMeta::new(*payer_address, true));
    }
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::ExtendProgram { additional_bytes },
        metas,
    )
}

/// Returns the instructions required to migrate a program to loader-v4.
#[cfg(feature = "bincode")]
pub fn migrate_program(
    programdata_address: &Pubkey,
    program_address: &Pubkey,
    authority: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*programdata_address, false),
        AccountMeta::new(*program_address, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new_readonly(loader_v4::id(), false),
    ];

    Instruction::new_with_bincode(id(), &UpgradeableLoaderInstruction::Migrate, accounts)
}

/// Returns the instruction required to extend the size of a program's
/// executable data account
#[cfg(feature = "bincode")]
pub fn extend_program_checked(
    program_address: &Pubkey,
    authority_address: &Pubkey,
    payer_address: Option<&Pubkey>,
    additional_bytes: u32,
) -> Instruction {
    let program_data_address = get_program_data_address(program_address);
    let mut metas = vec![
        AccountMeta::new(program_data_address, false),
        AccountMeta::new(*program_address, false),
        AccountMeta::new(*authority_address, true),
    ];
    if let Some(payer_address) = payer_address {
        metas.push(AccountMeta::new_readonly(
            solana_sdk_ids::system_program::id(),
            false,
        ));
        metas.push(AccountMeta::new(*payer_address, true));
    }
    Instruction::new_with_bincode(
        id(),
        &UpgradeableLoaderInstruction::ExtendProgramChecked { additional_bytes },
        metas,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_is_instruction<F>(
        is_instruction_fn: F,
        expected_instruction: UpgradeableLoaderInstruction,
    ) where
        F: Fn(&[u8]) -> bool,
    {
        let result = is_instruction_fn(
            &bincode::serialize(&UpgradeableLoaderInstruction::InitializeBuffer).unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::InitializeBuffer
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &bincode::serialize(&UpgradeableLoaderInstruction::Write {
                offset: 0,
                bytes: vec![],
            })
            .unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::Write {
                offset: _,
                bytes: _,
            }
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &bincode::serialize(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                max_data_len: 0,
            })
            .unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: _ }
        );
        assert_eq!(expected_result, result);

        let result =
            is_instruction_fn(&bincode::serialize(&UpgradeableLoaderInstruction::Upgrade).unwrap());
        let expected_result = matches!(expected_instruction, UpgradeableLoaderInstruction::Upgrade);
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &bincode::serialize(&UpgradeableLoaderInstruction::SetAuthority).unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::SetAuthority
        );
        assert_eq!(expected_result, result);

        let result =
            is_instruction_fn(&bincode::serialize(&UpgradeableLoaderInstruction::Close).unwrap());
        let expected_result = matches!(expected_instruction, UpgradeableLoaderInstruction::Close);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_is_set_authority_instruction() {
        assert!(!is_set_authority_instruction(&[]));
        assert_is_instruction(
            is_set_authority_instruction,
            UpgradeableLoaderInstruction::SetAuthority {},
        );
    }

    #[test]
    fn test_is_set_authority_checked_instruction() {
        assert!(!is_set_authority_checked_instruction(&[]));
        assert_is_instruction(
            is_set_authority_checked_instruction,
            UpgradeableLoaderInstruction::SetAuthorityChecked {},
        );
    }

    #[test]
    fn test_is_upgrade_instruction() {
        assert!(!is_upgrade_instruction(&[]));
        assert_is_instruction(
            is_upgrade_instruction,
            UpgradeableLoaderInstruction::Upgrade {},
        );
    }

    #[test]
    fn test_is_migrate_instruction() {
        assert!(!is_migrate_instruction(&[]));
        assert_is_instruction(
            is_migrate_instruction,
            UpgradeableLoaderInstruction::Migrate {},
        );
    }

    #[test]
    fn test_is_extend_program_checked_instruction() {
        assert!(!is_extend_program_checked_instruction(&[]));
        assert_is_instruction(
            is_extend_program_checked_instruction,
            UpgradeableLoaderInstruction::ExtendProgramChecked {
                additional_bytes: 0,
            },
        );
    }

    // -- SIMD-0430 tests --

    #[test]
    fn test_simd_0430_instruction_sizes() {
        // Gut-check that the constants stay in sync.

        assert_eq!(
            bincode::serialized_size(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                max_data_len: usize::MAX
            })
            .unwrap() as usize,
            SIZE_OF_DEPLOY_WITH_MAX_DATA_LEN,
        );
        assert_eq!(
            bincode::serialized_size(&UpgradeableLoaderInstruction::Upgrade).unwrap() as usize,
            SIZE_OF_UPGRADE,
        );
    }

    #[test]
    fn test_simd_0430_ignore_trailing_bytes() {
        // Make sure we can still deserialize with bincode, ignoring trailing
        // bytes by default.

        // -- DeployWithMaxDataLen --
        let max_data_len = usize::MAX;
        let mut bytes = bincode::serialize(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
            max_data_len,
        })
        .unwrap();
        bytes.extend_from_slice(&[0xFF; 16]);
        let deserialized: UpgradeableLoaderInstruction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(
            deserialized,
            UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len },
        );

        // -- Upgrade --
        let mut bytes = bincode::serialize(&UpgradeableLoaderInstruction::Upgrade).unwrap();
        bytes.extend_from_slice(&[0xFF; 16]);
        let deserialized: UpgradeableLoaderInstruction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized, UpgradeableLoaderInstruction::Upgrade,);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_simd_0430_close_buffer_no_trailing_bytes() {
        // Legacy instructions without trailing bytes should default to `true`.

        // -- DeployWithMaxDataLen --
        let bytes = bincode::serialize(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
            max_data_len: 1000,
        })
        .unwrap();
        assert_eq!(bytes.len(), SIZE_OF_DEPLOY_WITH_MAX_DATA_LEN);
        assert_eq!(deserialize_deploy_close_buffer(&bytes).unwrap(), true);

        // -- Upgrade --
        let bytes = bincode::serialize(&UpgradeableLoaderInstruction::Upgrade).unwrap();
        assert_eq!(bytes.len(), SIZE_OF_UPGRADE);
        assert_eq!(deserialize_upgrade_close_buffer(&bytes).unwrap(), true);
    }

    #[test]
    fn test_simd_0430_close_buffer_valid_trailing_bytes() {
        // The `close_buffer: bool` deserializer should be able to read a valid
        // trailing `bool`.

        for close_buffer in [true, false] {
            // -- DeployWithMaxDataLen --
            let bytes = serialize_with_trailing_bool(
                &UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: 1000 },
                close_buffer,
            );
            assert_eq!(
                deserialize_deploy_close_buffer(&bytes).unwrap(),
                close_buffer,
            );

            // -- Upgrade --
            let bytes =
                serialize_with_trailing_bool(&UpgradeableLoaderInstruction::Upgrade, close_buffer);
            assert_eq!(
                deserialize_upgrade_close_buffer(&bytes).unwrap(),
                close_buffer,
            );
        }

        // It should still work with extra bytes after the `bool`.
        let garbage_data = &[0xDE, 0xAD, 0xBE, 0xEF];
        for close_buffer in [true, false] {
            // -- DeployWithMaxDataLen --
            let mut bytes = serialize_with_trailing_bool(
                &UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: 1000 },
                close_buffer,
            );
            bytes.extend_from_slice(garbage_data);
            assert_eq!(
                deserialize_deploy_close_buffer(&bytes).unwrap(),
                close_buffer,
            );

            // -- Upgrade --
            let mut bytes =
                serialize_with_trailing_bool(&UpgradeableLoaderInstruction::Upgrade, close_buffer);
            bytes.extend_from_slice(garbage_data);
            assert_eq!(
                deserialize_upgrade_close_buffer(&bytes).unwrap(),
                close_buffer,
            );
        }
    }

    #[test]
    fn test_simd_0430_close_buffer_invalid_trailing_bytes() {
        // The `close_buffer: bool` deserializer should REJECT an invalid
        // `bool`.

        for invalid_byte in [2, 42, 0xFF] {
            // -- DeployWithMaxDataLen --
            let mut bytes =
                bincode::serialize(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                    max_data_len: 1000,
                })
                .unwrap();
            bytes.push(invalid_byte);
            assert_eq!(
                deserialize_deploy_close_buffer(&bytes),
                Err(InstructionError::InvalidInstructionData),
            );

            // -- Upgrade --
            let mut bytes = bincode::serialize(&UpgradeableLoaderInstruction::Upgrade).unwrap();
            bytes.push(invalid_byte);
            assert_eq!(
                deserialize_upgrade_close_buffer(&bytes),
                Err(InstructionError::InvalidInstructionData),
            );
        }
    }

    #[test]
    fn test_simd_0430_close_buffer_not_enough_bytes() {
        // The `close_buffer: bool` deserializer should REJECT a payload with
        // not enough bytes.

        // -- DeployWithMaxDataLen --
        let bytes = &[0xFF; SIZE_OF_DEPLOY_WITH_MAX_DATA_LEN - 1];
        assert_eq!(
            deserialize_deploy_close_buffer(bytes),
            Err(InstructionError::InvalidInstructionData),
        );

        // -- Upgrade --
        let bytes = &[0xFF; SIZE_OF_UPGRADE - 1];
        assert_eq!(
            deserialize_upgrade_close_buffer(bytes),
            Err(InstructionError::InvalidInstructionData),
        );
    }
}
