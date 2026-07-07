//! Instructions for the upgradable BPF loader.

#[cfg(feature = "wincode")]
use {
    crate::{get_program_data_address, state::UpgradeableLoaderState},
    core::mem::MaybeUninit,
    solana_instruction::{error::InstructionError, AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_sdk_ids::{bpf_loader_upgradeable::id, sysvar},
    solana_system_interface::instruction as system_instruction,
    wincode::{
        config::ConfigCore,
        error::invalid_bool_encoding,
        io::{Reader, Writer},
        ReadResult, SchemaRead, SchemaWrite, TypeMeta, WriteResult,
    },
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
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
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
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[]` System program (`solana_sdk_ids::system_program::id()`).
    ///   7. `[signer]` The program's authority
    DeployWithMaxDataLen {
        /// Maximum length that the program can be upgraded to.
        max_data_len: usize,
        /// SIMD-0430: Whether to close the buffer account after deployment.
        ///
        /// Optional on the wire: when the trailing byte is absent, this
        /// decodes to `true`.
        #[cfg_attr(feature = "wincode", wincode(with = "OptionalTrailingBool<true>"))]
        close_buffer: bool,
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
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   3. `[writable]` The spill account.
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[signer]` The program's authority.
    Upgrade {
        /// SIMD-0430: Whether to close the buffer account after upgrade.
        ///
        /// Optional on the wire: when the trailing byte is absent, this
        /// decodes to `true`.
        #[cfg_attr(feature = "wincode", wincode(with = "OptionalTrailingBool<true>"))]
        close_buffer: bool,
    },

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
    Close {
        /// SIMD-0432: Whether to tombstone the program account instead of
        /// reclaiming its address.
        ///
        /// Optional on the wire: when the trailing byte is absent, this
        /// decodes to `false`.
        #[cfg_attr(feature = "wincode", wincode(with = "OptionalTrailingBool<false>"))]
        tombstone: bool,
    },

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
}

/// A wincode schema for a `bool` that may be absent from the end of the
/// wire payload. On write, the byte is always emitted. On read, an
/// exhausted reader yields `DEFAULT`.
#[cfg(feature = "wincode")]
pub struct OptionalTrailingBool<const DEFAULT: bool>;

#[cfg(feature = "wincode")]
unsafe impl<'de, C: ConfigCore, const DEFAULT: bool> SchemaRead<'de, C>
    for OptionalTrailingBool<DEFAULT>
{
    type Dst = bool;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let value = match reader.take_byte() {
            Ok(0) => false,
            Ok(1) => true,
            Ok(byte) => return Err(invalid_bool_encoding(byte)),
            Err(_) => DEFAULT,
        };
        dst.write(value);
        Ok(())
    }
}

#[cfg(feature = "wincode")]
unsafe impl<C: ConfigCore, const DEFAULT: bool> SchemaWrite<C> for OptionalTrailingBool<DEFAULT> {
    type Src = bool;

    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 1,
        zero_copy: false,
    };

    fn size_of(_src: &Self::Src) -> WriteResult<usize> {
        Ok(1)
    }

    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        writer.write(&[u8::from(*src)])?;
        Ok(())
    }
}

#[cfg(feature = "wincode")]
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
        Instruction::new_with_wincode(
            id(),
            &UpgradeableLoaderInstruction::InitializeBuffer,
            vec![
                AccountMeta::new(*buffer_address, false),
                AccountMeta::new_readonly(*authority_address, false),
            ],
        ),
    ])
}

#[cfg(feature = "wincode")]
/// Returns the instructions required to write a chunk of program data to a
/// buffer account.
pub fn write(
    buffer_address: &Pubkey,
    authority_address: &Pubkey,
    offset: u32,
    bytes: Vec<u8>,
) -> Instruction {
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::Write { offset, bytes },
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*authority_address, true),
        ],
    )
}

#[cfg(feature = "wincode")]
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
    Ok(vec![
        system_instruction::create_account(
            payer_address,
            program_address,
            program_lamports,
            UpgradeableLoaderState::size_of_program() as u64,
            &id(),
        ),
        Instruction::new_with_wincode(
            id(),
            &UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                max_data_len,
                close_buffer,
            },
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

#[cfg(feature = "wincode")]
/// Returns the instructions required to upgrade a program.
pub fn upgrade(
    program_address: &Pubkey,
    buffer_address: &Pubkey,
    authority_address: &Pubkey,
    spill_address: &Pubkey,
    close_buffer: bool,
) -> Instruction {
    let programdata_address = get_program_data_address(program_address);
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::Upgrade { close_buffer },
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

#[cfg(feature = "wincode")]
/// Returns the instructions required to set a buffers's authority.
pub fn set_buffer_authority(
    buffer_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthority,
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*current_authority_address, true),
            AccountMeta::new_readonly(*new_authority_address, false),
        ],
    )
}

#[cfg(feature = "wincode")]
/// Returns the instructions required to set a buffers's authority. If using this instruction, the new authority
/// must sign.
pub fn set_buffer_authority_checked(
    buffer_address: &Pubkey,
    current_authority_address: &Pubkey,
    new_authority_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthorityChecked,
        vec![
            AccountMeta::new(*buffer_address, false),
            AccountMeta::new_readonly(*current_authority_address, true),
            AccountMeta::new_readonly(*new_authority_address, true),
        ],
    )
}

#[cfg(feature = "wincode")]
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
    Instruction::new_with_wincode(id(), &UpgradeableLoaderInstruction::SetAuthority, metas)
}

#[cfg(feature = "wincode")]
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
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::SetAuthorityChecked,
        metas,
    )
}

#[cfg(feature = "wincode")]
/// Returns the instructions required to close a buffer account
pub fn close(
    close_address: &Pubkey,
    recipient_address: &Pubkey,
    authority_address: &Pubkey,
    tombstone: bool,
) -> Instruction {
    close_any(
        close_address,
        recipient_address,
        Some(authority_address),
        None,
        tombstone,
    )
}

#[cfg(feature = "wincode")]
/// Returns the instructions required to close program, buffer, or uninitialized account
pub fn close_any(
    close_address: &Pubkey,
    recipient_address: &Pubkey,
    authority_address: Option<&Pubkey>,
    program_address: Option<&Pubkey>,
    tombstone: bool,
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
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::Close { tombstone },
        metas,
    )
}

#[cfg(feature = "wincode")]
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
    Instruction::new_with_wincode(
        id(),
        &UpgradeableLoaderInstruction::ExtendProgram { additional_bytes },
        metas,
    )
}

#[cfg(all(test, feature = "wincode"))]
mod tests {
    use {super::*, test_case::test_case};

    fn assert_is_instruction<F>(
        is_instruction_fn: F,
        expected_instruction: UpgradeableLoaderInstruction,
    ) where
        F: Fn(&[u8]) -> bool,
    {
        let result = is_instruction_fn(
            &wincode::serialize(&UpgradeableLoaderInstruction::InitializeBuffer).unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::InitializeBuffer
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &wincode::serialize(&UpgradeableLoaderInstruction::Write {
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
            &wincode::serialize(&UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                max_data_len: 0,
                close_buffer: true,
            })
            .unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::DeployWithMaxDataLen { .. }
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &wincode::serialize(&UpgradeableLoaderInstruction::Upgrade { close_buffer: true })
                .unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::Upgrade { .. }
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &wincode::serialize(&UpgradeableLoaderInstruction::SetAuthority).unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::SetAuthority
        );
        assert_eq!(expected_result, result);

        let result = is_instruction_fn(
            &wincode::serialize(&UpgradeableLoaderInstruction::Close { tombstone: false }).unwrap(),
        );
        let expected_result = matches!(
            expected_instruction,
            UpgradeableLoaderInstruction::Close { .. }
        );
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
            UpgradeableLoaderInstruction::Upgrade { close_buffer: true },
        );
    }

    /// Verify that wincode produces the exact same bytes as bincode for
    /// every instruction variant, and that both round-trip correctly.
    #[test_case(UpgradeableLoaderInstruction::InitializeBuffer)]
    #[test_case(UpgradeableLoaderInstruction::Write { offset: 42, bytes: vec![1, 2, 3, 4, 5] })]
    #[test_case(UpgradeableLoaderInstruction::Write { offset: 0, bytes: vec![] })]
    #[test_case(UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: 1_000_000, close_buffer: true })]
    #[test_case(UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: 0, close_buffer: false })]
    #[test_case(UpgradeableLoaderInstruction::Upgrade { close_buffer: true })]
    #[test_case(UpgradeableLoaderInstruction::Upgrade { close_buffer: false })]
    #[test_case(UpgradeableLoaderInstruction::SetAuthority)]
    #[test_case(UpgradeableLoaderInstruction::Close { tombstone: false })]
    #[test_case(UpgradeableLoaderInstruction::Close { tombstone: true })]
    #[test_case(UpgradeableLoaderInstruction::ExtendProgram { additional_bytes: 10_240 })]
    #[test_case(UpgradeableLoaderInstruction::ExtendProgram { additional_bytes: 0 })]
    #[test_case(UpgradeableLoaderInstruction::SetAuthorityChecked)]
    fn wire_compat_bincode_vs_wincode(instr: UpgradeableLoaderInstruction) {
        let bincode_bytes = bincode::serialize(&instr).unwrap();
        let wincode_bytes = wincode::serialize(&instr).unwrap();
        assert_eq!(bincode_bytes, wincode_bytes);

        let from_bincode: UpgradeableLoaderInstruction =
            bincode::deserialize(&bincode_bytes).unwrap();
        let from_wincode: UpgradeableLoaderInstruction =
            wincode::deserialize(&wincode_bytes).unwrap();
        assert_eq!(from_bincode, instr);
        assert_eq!(from_wincode, instr);
    }

    /// Legacy `DeployWithMaxDataLen` payloads omit the trailing
    /// `close_buffer` byte; wincode must decode these to `close_buffer: true`.
    #[test]
    fn legacy_deploy_decodes_close_buffer_as_true() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // Discriminator
        data.extend_from_slice(&42u64.to_le_bytes()); // max_data_len
        let decoded: UpgradeableLoaderInstruction = wincode::deserialize(&data).unwrap();
        assert_eq!(
            decoded,
            UpgradeableLoaderInstruction::DeployWithMaxDataLen {
                max_data_len: 42,
                close_buffer: true, // <-- Default value
            }
        );
    }

    /// Legacy `Upgrade` payloads omit the trailing `close_buffer` byte;
    /// wincode must decode these to `close_buffer: true`.
    #[test]
    fn legacy_upgrade_decodes_close_buffer_as_true() {
        let data = 3u32.to_le_bytes(); // Discriminator
        let decoded: UpgradeableLoaderInstruction = wincode::deserialize(&data).unwrap();
        assert_eq!(
            decoded,
            UpgradeableLoaderInstruction::Upgrade {
                close_buffer: true, // <-- Default value
            }
        );
    }

    /// Legacy `Close` payloads omit the trailing `tombstone` byte; wincode
    /// must decode these to `tombstone: false`.
    #[test]
    fn legacy_close_decodes_tombstone_as_false() {
        let data = 5u32.to_le_bytes(); // Discriminator
        let decoded: UpgradeableLoaderInstruction = wincode::deserialize(&data).unwrap();
        assert_eq!(
            decoded,
            UpgradeableLoaderInstruction::Close {
                tombstone: false, // <-- Default value
            }
        );
    }

    /// `OptionalTrailingBool` must reject a trailing byte that is not `0` or `1`.
    #[test]
    fn invalid_optional_trailing_bool_byte_errors() {
        let assert_invalid_trailing_bool = |data: &[u8]| {
            let err = wincode::deserialize::<UpgradeableLoaderInstruction>(data).unwrap_err();
            assert!(
                matches!(err, wincode::ReadError::InvalidBoolEncoding(2)),
                "expected InvalidBoolEncoding(2), got {err:?}",
            );
        };

        // `DeployWithMaxDataLen`
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // Discriminator
        data.extend_from_slice(&42u64.to_le_bytes()); // max_data_len
        data.push(2);
        assert_invalid_trailing_bool(&data);

        // `Upgrade`
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes()); // Discriminator
        data.push(2);
        assert_invalid_trailing_bool(&data);

        // `Close`
        let mut data = Vec::new();
        data.extend_from_slice(&5u32.to_le_bytes()); // Discriminator
        data.push(2);
        assert_invalid_trailing_bool(&data);
    }
}
