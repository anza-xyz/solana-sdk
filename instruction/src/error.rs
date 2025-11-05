use core::fmt;
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{AbiEnumVisitor, AbiExample};
#[cfg(feature = "std")]
use {
    num_traits::ToPrimitive,
    std::string::{String, ToString},
};

/// Builtin return values occupy the upper 32 bits
const BUILTIN_BIT_SHIFT: usize = 32;
macro_rules! to_builtin {
    ($error:expr) => {
        ($error as u64) << BUILTIN_BIT_SHIFT
    };
}

pub const CUSTOM_ZERO: u64 = to_builtin!(1);
pub const INVALID_ARGUMENT: u64 = to_builtin!(2);
pub const INVALID_INSTRUCTION_DATA: u64 = to_builtin!(3);
pub const INVALID_ACCOUNT_DATA: u64 = to_builtin!(4);
pub const ACCOUNT_DATA_TOO_SMALL: u64 = to_builtin!(5);
pub const INSUFFICIENT_FUNDS: u64 = to_builtin!(6);
pub const INCORRECT_PROGRAM_ID: u64 = to_builtin!(7);
pub const MISSING_REQUIRED_SIGNATURES: u64 = to_builtin!(8);
pub const ACCOUNT_ALREADY_INITIALIZED: u64 = to_builtin!(9);
pub const UNINITIALIZED_ACCOUNT: u64 = to_builtin!(10);
pub const NOT_ENOUGH_ACCOUNT_KEYS: u64 = to_builtin!(11);
pub const ACCOUNT_BORROW_FAILED: u64 = to_builtin!(12);
pub const MAX_SEED_LENGTH_EXCEEDED: u64 = to_builtin!(13);
pub const INVALID_SEEDS: u64 = to_builtin!(14);
pub const BORSH_IO_ERROR: u64 = to_builtin!(15);
pub const ACCOUNT_NOT_RENT_EXEMPT: u64 = to_builtin!(16);
pub const UNSUPPORTED_SYSVAR: u64 = to_builtin!(17);
pub const ILLEGAL_OWNER: u64 = to_builtin!(18);
pub const MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED: u64 = to_builtin!(19);
pub const INVALID_ACCOUNT_DATA_REALLOC: u64 = to_builtin!(20);
pub const MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED: u64 = to_builtin!(21);
pub const BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS: u64 = to_builtin!(22);
pub const INVALID_ACCOUNT_OWNER: u64 = to_builtin!(23);
pub const ARITHMETIC_OVERFLOW: u64 = to_builtin!(24);
pub const IMMUTABLE: u64 = to_builtin!(25);
pub const INCORRECT_AUTHORITY: u64 = to_builtin!(26);
// Warning: Any new error codes added here must also be:
// - Added to the below conversions
// - Added as an equivalent to ProgramError and InstructionError
// - Be featurized in the BPF loader to return `InstructionError::InvalidError`
//   until the feature is activated
// - Added to the `Deserialize` implementation, which is done by hand

/// Reasons the runtime might have rejected an instruction.
///
/// Members of this enum must not be removed, but new ones can be added.
/// Also, it is crucial that meta-information if any that comes along with
/// an error be consistent across software versions.  For example, it is
/// dangerous to include error strings from 3rd party crates because they could
/// change at any time and changes to them are difficult to detect.
#[cfg(feature = "std")]
#[cfg_attr(feature = "frozen-abi", derive(AbiExample, AbiEnumVisitor))]
#[cfg_attr(feature = "serde", derive(serde_derive::Serialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InstructionError {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom(u32),

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError(String),

    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added
}

#[cfg(all(feature = "std", feature = "serde"))]
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::single_match,
    clippy::redundant_static_lifetimes
)]
const _: () = {
    use std::{fmt::Formatter, marker::PhantomData, string::String};
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::de::Deserialize<'de> for InstructionError {
        fn deserialize<__D>(__deserializer: __D) -> Result<InstructionError, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            match None::<&InstructionError> {
                Some(InstructionError::Custom { 0: __v0 }) => {}
                Some(InstructionError::BorshIoError { 0: __v0 }) => {}
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::GenericError;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidArgument;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidInstructionData;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidAccountData;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountDataTooSmall;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InsufficientFunds;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::IncorrectProgramId;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MissingRequiredSignature;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountAlreadyInitialized;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::UninitializedAccount;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::UnbalancedInstruction;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ModifiedProgramId;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExternalAccountLamportSpend;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExternalAccountDataModified;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ReadonlyLamportChange;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ReadonlyDataModified;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::DuplicateAccountIndex;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExecutableModified;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::RentEpochModified;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::NotEnoughAccountKeys;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountDataSizeChanged;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountNotExecutable;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountBorrowFailed;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountBorrowOutstanding;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::DuplicateAccountOutOfSync;
                }
                _ => {}
            }
            match None {
                Some((__v0,)) => {
                    let _ = InstructionError::Custom(__v0);
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidError;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExecutableDataModified;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExecutableLamportChange;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ExecutableAccountNotRentExempt;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::UnsupportedProgramId;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::CallDepth;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MissingAccount;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ReentrancyNotAllowed;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MaxSeedLengthExceeded;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidSeeds;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidRealloc;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ComputationalBudgetExceeded;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::PrivilegeEscalation;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ProgramEnvironmentSetupFailure;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ProgramFailedToComplete;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ProgramFailedToCompile;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::Immutable;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::IncorrectAuthority;
                }
                _ => {}
            }
            match None {
                Some((__v0,)) => {
                    let _ = InstructionError::BorshIoError(__v0);
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::AccountNotRentExempt;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::InvalidAccountOwner;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::ArithmeticOverflow;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::UnsupportedSysvar;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::IllegalOwner;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MaxAccountsDataAllocationsExceeded;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MaxAccountsExceeded;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::MaxInstructionTraceLengthExceeded;
                }
                _ => {}
            }
            match None {
                Some(()) => {
                    let _ = InstructionError::BuiltinProgramsMustConsumeComputeUnits;
                }
                _ => {}
            }
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __field3,
                __field4,
                __field5,
                __field6,
                __field7,
                __field8,
                __field9,
                __field10,
                __field11,
                __field12,
                __field13,
                __field14,
                __field15,
                __field16,
                __field17,
                __field18,
                __field19,
                __field20,
                __field21,
                __field22,
                __field23,
                __field24,
                __field25,
                __field26,
                __field27,
                __field28,
                __field29,
                __field30,
                __field31,
                __field32,
                __field33,
                __field34,
                __field35,
                __field36,
                __field37,
                __field38,
                __field39,
                __field40,
                __field41,
                __field42,
                __field43,
                __field44,
                __field45,
                __field46,
                __field47,
                __field48,
                __field49,
                __field50,
                __field51,
                __field52,
                __field53,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                    Formatter::write_str(__formatter, "variant identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => Ok(__Field::__field0),
                        1u64 => Ok(__Field::__field1),
                        2u64 => Ok(__Field::__field2),
                        3u64 => Ok(__Field::__field3),
                        4u64 => Ok(__Field::__field4),
                        5u64 => Ok(__Field::__field5),
                        6u64 => Ok(__Field::__field6),
                        7u64 => Ok(__Field::__field7),
                        8u64 => Ok(__Field::__field8),
                        9u64 => Ok(__Field::__field9),
                        10u64 => Ok(__Field::__field10),
                        11u64 => Ok(__Field::__field11),
                        12u64 => Ok(__Field::__field12),
                        13u64 => Ok(__Field::__field13),
                        14u64 => Ok(__Field::__field14),
                        15u64 => Ok(__Field::__field15),
                        16u64 => Ok(__Field::__field16),
                        17u64 => Ok(__Field::__field17),
                        18u64 => Ok(__Field::__field18),
                        19u64 => Ok(__Field::__field19),
                        20u64 => Ok(__Field::__field20),
                        21u64 => Ok(__Field::__field21),
                        22u64 => Ok(__Field::__field22),
                        23u64 => Ok(__Field::__field23),
                        24u64 => Ok(__Field::__field24),
                        25u64 => Ok(__Field::__field25),
                        26u64 => Ok(__Field::__field26),
                        27u64 => Ok(__Field::__field27),
                        28u64 => Ok(__Field::__field28),
                        29u64 => Ok(__Field::__field29),
                        30u64 => Ok(__Field::__field30),
                        31u64 => Ok(__Field::__field31),
                        32u64 => Ok(__Field::__field32),
                        33u64 => Ok(__Field::__field33),
                        34u64 => Ok(__Field::__field34),
                        35u64 => Ok(__Field::__field35),
                        36u64 => Ok(__Field::__field36),
                        37u64 => Ok(__Field::__field37),
                        38u64 => Ok(__Field::__field38),
                        39u64 => Ok(__Field::__field39),
                        40u64 => Ok(__Field::__field40),
                        41u64 => Ok(__Field::__field41),
                        42u64 => Ok(__Field::__field42),
                        43u64 => Ok(__Field::__field43),
                        44u64 => Ok(__Field::__field44),
                        45u64 => Ok(__Field::__field45),
                        46u64 => Ok(__Field::__field46),
                        47u64 => Ok(__Field::__field47),
                        48u64 => Ok(__Field::__field48),
                        49u64 => Ok(__Field::__field49),
                        50u64 => Ok(__Field::__field50),
                        51u64 => Ok(__Field::__field51),
                        52u64 => Ok(__Field::__field52),
                        53u64 => Ok(__Field::__field53),
                        _ => Err(_serde::de::Error::invalid_value(
                            _serde::de::Unexpected::Unsigned(__value),
                            &"variant index 0 <= i < 54",
                        )),
                    }
                }
                fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "GenericError" => Ok(__Field::__field0),
                        "InvalidArgument" => Ok(__Field::__field1),
                        "InvalidInstructionData" => Ok(__Field::__field2),
                        "InvalidAccountData" => Ok(__Field::__field3),
                        "AccountDataTooSmall" => Ok(__Field::__field4),
                        "InsufficientFunds" => Ok(__Field::__field5),
                        "IncorrectProgramId" => Ok(__Field::__field6),
                        "MissingRequiredSignature" => Ok(__Field::__field7),
                        "AccountAlreadyInitialized" => Ok(__Field::__field8),
                        "UninitializedAccount" => Ok(__Field::__field9),
                        "UnbalancedInstruction" => Ok(__Field::__field10),
                        "ModifiedProgramId" => Ok(__Field::__field11),
                        "ExternalAccountLamportSpend" => Ok(__Field::__field12),
                        "ExternalAccountDataModified" => Ok(__Field::__field13),
                        "ReadonlyLamportChange" => Ok(__Field::__field14),
                        "ReadonlyDataModified" => Ok(__Field::__field15),
                        "DuplicateAccountIndex" => Ok(__Field::__field16),
                        "ExecutableModified" => Ok(__Field::__field17),
                        "RentEpochModified" => Ok(__Field::__field18),
                        "NotEnoughAccountKeys" => Ok(__Field::__field19),
                        "AccountDataSizeChanged" => Ok(__Field::__field20),
                        "AccountNotExecutable" => Ok(__Field::__field21),
                        "AccountBorrowFailed" => Ok(__Field::__field22),
                        "AccountBorrowOutstanding" => Ok(__Field::__field23),
                        "DuplicateAccountOutOfSync" => Ok(__Field::__field24),
                        "Custom" => Ok(__Field::__field25),
                        "InvalidError" => Ok(__Field::__field26),
                        "ExecutableDataModified" => Ok(__Field::__field27),
                        "ExecutableLamportChange" => Ok(__Field::__field28),
                        "ExecutableAccountNotRentExempt" => Ok(__Field::__field29),
                        "UnsupportedProgramId" => Ok(__Field::__field30),
                        "CallDepth" => Ok(__Field::__field31),
                        "MissingAccount" => Ok(__Field::__field32),
                        "ReentrancyNotAllowed" => Ok(__Field::__field33),
                        "MaxSeedLengthExceeded" => Ok(__Field::__field34),
                        "InvalidSeeds" => Ok(__Field::__field35),
                        "InvalidRealloc" => Ok(__Field::__field36),
                        "ComputationalBudgetExceeded" => Ok(__Field::__field37),
                        "PrivilegeEscalation" => Ok(__Field::__field38),
                        "ProgramEnvironmentSetupFailure" => Ok(__Field::__field39),
                        "ProgramFailedToComplete" => Ok(__Field::__field40),
                        "ProgramFailedToCompile" => Ok(__Field::__field41),
                        "Immutable" => Ok(__Field::__field42),
                        "IncorrectAuthority" => Ok(__Field::__field43),
                        "BorshIoError" => Ok(__Field::__field44),
                        "AccountNotRentExempt" => Ok(__Field::__field45),
                        "InvalidAccountOwner" => Ok(__Field::__field46),
                        "ArithmeticOverflow" => Ok(__Field::__field47),
                        "UnsupportedSysvar" => Ok(__Field::__field48),
                        "IllegalOwner" => Ok(__Field::__field49),
                        "MaxAccountsDataAllocationsExceeded" => Ok(__Field::__field50),
                        "MaxAccountsExceeded" => Ok(__Field::__field51),
                        "MaxInstructionTraceLengthExceeded" => Ok(__Field::__field52),
                        "BuiltinProgramsMustConsumeComputeUnits" => Ok(__Field::__field53),
                        _ => Err(_serde::de::Error::unknown_variant(__value, VARIANTS)),
                    }
                }
                fn visit_bytes<__E>(self, __value: &[u8]) -> Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"GenericError" => Ok(__Field::__field0),
                        b"InvalidArgument" => Ok(__Field::__field1),
                        b"InvalidInstructionData" => Ok(__Field::__field2),
                        b"InvalidAccountData" => Ok(__Field::__field3),
                        b"AccountDataTooSmall" => Ok(__Field::__field4),
                        b"InsufficientFunds" => Ok(__Field::__field5),
                        b"IncorrectProgramId" => Ok(__Field::__field6),
                        b"MissingRequiredSignature" => Ok(__Field::__field7),
                        b"AccountAlreadyInitialized" => Ok(__Field::__field8),
                        b"UninitializedAccount" => Ok(__Field::__field9),
                        b"UnbalancedInstruction" => Ok(__Field::__field10),
                        b"ModifiedProgramId" => Ok(__Field::__field11),
                        b"ExternalAccountLamportSpend" => Ok(__Field::__field12),
                        b"ExternalAccountDataModified" => Ok(__Field::__field13),
                        b"ReadonlyLamportChange" => Ok(__Field::__field14),
                        b"ReadonlyDataModified" => Ok(__Field::__field15),
                        b"DuplicateAccountIndex" => Ok(__Field::__field16),
                        b"ExecutableModified" => Ok(__Field::__field17),
                        b"RentEpochModified" => Ok(__Field::__field18),
                        b"NotEnoughAccountKeys" => Ok(__Field::__field19),
                        b"AccountDataSizeChanged" => Ok(__Field::__field20),
                        b"AccountNotExecutable" => Ok(__Field::__field21),
                        b"AccountBorrowFailed" => Ok(__Field::__field22),
                        b"AccountBorrowOutstanding" => Ok(__Field::__field23),
                        b"DuplicateAccountOutOfSync" => Ok(__Field::__field24),
                        b"Custom" => Ok(__Field::__field25),
                        b"InvalidError" => Ok(__Field::__field26),
                        b"ExecutableDataModified" => Ok(__Field::__field27),
                        b"ExecutableLamportChange" => Ok(__Field::__field28),
                        b"ExecutableAccountNotRentExempt" => Ok(__Field::__field29),
                        b"UnsupportedProgramId" => Ok(__Field::__field30),
                        b"CallDepth" => Ok(__Field::__field31),
                        b"MissingAccount" => Ok(__Field::__field32),
                        b"ReentrancyNotAllowed" => Ok(__Field::__field33),
                        b"MaxSeedLengthExceeded" => Ok(__Field::__field34),
                        b"InvalidSeeds" => Ok(__Field::__field35),
                        b"InvalidRealloc" => Ok(__Field::__field36),
                        b"ComputationalBudgetExceeded" => Ok(__Field::__field37),
                        b"PrivilegeEscalation" => Ok(__Field::__field38),
                        b"ProgramEnvironmentSetupFailure" => Ok(__Field::__field39),
                        b"ProgramFailedToComplete" => Ok(__Field::__field40),
                        b"ProgramFailedToCompile" => Ok(__Field::__field41),
                        b"Immutable" => Ok(__Field::__field42),
                        b"IncorrectAuthority" => Ok(__Field::__field43),
                        b"BorshIoError" => Ok(__Field::__field44),
                        b"AccountNotRentExempt" => Ok(__Field::__field45),
                        b"InvalidAccountOwner" => Ok(__Field::__field46),
                        b"ArithmeticOverflow" => Ok(__Field::__field47),
                        b"UnsupportedSysvar" => Ok(__Field::__field48),
                        b"IllegalOwner" => Ok(__Field::__field49),
                        b"MaxAccountsDataAllocationsExceeded" => Ok(__Field::__field50),
                        b"MaxAccountsExceeded" => Ok(__Field::__field51),
                        b"MaxInstructionTraceLengthExceeded" => Ok(__Field::__field52),
                        b"BuiltinProgramsMustConsumeComputeUnits" => Ok(__Field::__field53),
                        _ => {
                            let __value = &String::from_utf8_lossy(__value);
                            Err(_serde::de::Error::unknown_variant(__value, VARIANTS))
                        }
                    }
                }
            }
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: PhantomData<InstructionError>,
                lifetime: PhantomData<&'de ()>,
            }
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = InstructionError;
                fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                    Formatter::write_str(__formatter, "enum InstructionError")
                }
                fn visit_enum<__A>(self, __data: __A) -> Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match _serde::de::EnumAccess::variant(__data)? {
                        (__Field::__field0, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::GenericError)
                        }
                        (__Field::__field1, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidArgument)
                        }
                        (__Field::__field2, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidInstructionData)
                        }
                        (__Field::__field3, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidAccountData)
                        }
                        (__Field::__field4, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountDataTooSmall)
                        }
                        (__Field::__field5, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InsufficientFunds)
                        }
                        (__Field::__field6, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::IncorrectProgramId)
                        }
                        (__Field::__field7, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MissingRequiredSignature)
                        }
                        (__Field::__field8, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountAlreadyInitialized)
                        }
                        (__Field::__field9, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::UninitializedAccount)
                        }
                        (__Field::__field10, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::UnbalancedInstruction)
                        }
                        (__Field::__field11, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ModifiedProgramId)
                        }
                        (__Field::__field12, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExternalAccountLamportSpend)
                        }
                        (__Field::__field13, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExternalAccountDataModified)
                        }
                        (__Field::__field14, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ReadonlyLamportChange)
                        }
                        (__Field::__field15, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ReadonlyDataModified)
                        }
                        (__Field::__field16, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::DuplicateAccountIndex)
                        }
                        (__Field::__field17, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExecutableModified)
                        }
                        (__Field::__field18, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::RentEpochModified)
                        }
                        (__Field::__field19, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::NotEnoughAccountKeys)
                        }
                        (__Field::__field20, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountDataSizeChanged)
                        }
                        (__Field::__field21, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountNotExecutable)
                        }
                        (__Field::__field22, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountBorrowFailed)
                        }
                        (__Field::__field23, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountBorrowOutstanding)
                        }
                        (__Field::__field24, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::DuplicateAccountOutOfSync)
                        }
                        (__Field::__field25, __variant) => Result::map(
                            _serde::de::VariantAccess::newtype_variant::<u32>(__variant),
                            InstructionError::Custom,
                        ),
                        (__Field::__field26, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidError)
                        }
                        (__Field::__field27, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExecutableDataModified)
                        }
                        (__Field::__field28, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExecutableLamportChange)
                        }
                        (__Field::__field29, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ExecutableAccountNotRentExempt)
                        }
                        (__Field::__field30, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::UnsupportedProgramId)
                        }
                        (__Field::__field31, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::CallDepth)
                        }
                        (__Field::__field32, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MissingAccount)
                        }
                        (__Field::__field33, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ReentrancyNotAllowed)
                        }
                        (__Field::__field34, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MaxSeedLengthExceeded)
                        }
                        (__Field::__field35, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidSeeds)
                        }
                        (__Field::__field36, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidRealloc)
                        }
                        (__Field::__field37, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ComputationalBudgetExceeded)
                        }
                        (__Field::__field38, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::PrivilegeEscalation)
                        }
                        (__Field::__field39, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ProgramEnvironmentSetupFailure)
                        }
                        (__Field::__field40, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ProgramFailedToComplete)
                        }
                        (__Field::__field41, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ProgramFailedToCompile)
                        }
                        (__Field::__field42, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::Immutable)
                        }
                        (__Field::__field43, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::IncorrectAuthority)
                        }
                        (__Field::__field44, __variant) => {
                            // START CUSTOM CODE: FALL BACK TO AN EMPTY STRING
                            Ok(InstructionError::BorshIoError(
                                _serde::de::VariantAccess::newtype_variant::<String>(__variant)
                                    .unwrap_or_default(),
                            ))
                            // END CUSTOM CODE
                        }
                        (__Field::__field45, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::AccountNotRentExempt)
                        }
                        (__Field::__field46, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::InvalidAccountOwner)
                        }
                        (__Field::__field47, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::ArithmeticOverflow)
                        }
                        (__Field::__field48, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::UnsupportedSysvar)
                        }
                        (__Field::__field49, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::IllegalOwner)
                        }
                        (__Field::__field50, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MaxAccountsDataAllocationsExceeded)
                        }
                        (__Field::__field51, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MaxAccountsExceeded)
                        }
                        (__Field::__field52, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::MaxInstructionTraceLengthExceeded)
                        }
                        (__Field::__field53, __variant) => {
                            _serde::de::VariantAccess::unit_variant(__variant)?;
                            Ok(InstructionError::BuiltinProgramsMustConsumeComputeUnits)
                        }
                    }
                }
            }
            #[doc(hidden)]
            const VARIANTS: &'static [&'static str] = &[
                "GenericError",
                "InvalidArgument",
                "InvalidInstructionData",
                "InvalidAccountData",
                "AccountDataTooSmall",
                "InsufficientFunds",
                "IncorrectProgramId",
                "MissingRequiredSignature",
                "AccountAlreadyInitialized",
                "UninitializedAccount",
                "UnbalancedInstruction",
                "ModifiedProgramId",
                "ExternalAccountLamportSpend",
                "ExternalAccountDataModified",
                "ReadonlyLamportChange",
                "ReadonlyDataModified",
                "DuplicateAccountIndex",
                "ExecutableModified",
                "RentEpochModified",
                "NotEnoughAccountKeys",
                "AccountDataSizeChanged",
                "AccountNotExecutable",
                "AccountBorrowFailed",
                "AccountBorrowOutstanding",
                "DuplicateAccountOutOfSync",
                "Custom",
                "InvalidError",
                "ExecutableDataModified",
                "ExecutableLamportChange",
                "ExecutableAccountNotRentExempt",
                "UnsupportedProgramId",
                "CallDepth",
                "MissingAccount",
                "ReentrancyNotAllowed",
                "MaxSeedLengthExceeded",
                "InvalidSeeds",
                "InvalidRealloc",
                "ComputationalBudgetExceeded",
                "PrivilegeEscalation",
                "ProgramEnvironmentSetupFailure",
                "ProgramFailedToComplete",
                "ProgramFailedToCompile",
                "Immutable",
                "IncorrectAuthority",
                "BorshIoError",
                "AccountNotRentExempt",
                "InvalidAccountOwner",
                "ArithmeticOverflow",
                "UnsupportedSysvar",
                "IllegalOwner",
                "MaxAccountsDataAllocationsExceeded",
                "MaxAccountsExceeded",
                "MaxInstructionTraceLengthExceeded",
                "BuiltinProgramsMustConsumeComputeUnits",
            ];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "InstructionError",
                VARIANTS,
                __Visitor {
                    marker: PhantomData::<InstructionError>,
                    lifetime: PhantomData,
                },
            )
        }
    }
};

#[cfg(feature = "std")]
impl std::error::Error for InstructionError {}

#[cfg(feature = "std")]
impl fmt::Display for InstructionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InstructionError::GenericError => f.write_str("generic instruction error"),
            InstructionError::InvalidArgument => f.write_str("invalid program argument"),
            InstructionError::InvalidInstructionData => f.write_str("invalid instruction data"),
            InstructionError::InvalidAccountData => {
                f.write_str("invalid account data for instruction")
            }
            InstructionError::AccountDataTooSmall => {
                f.write_str("account data too small for instruction")
            }
            InstructionError::InsufficientFunds => {
                f.write_str("insufficient funds for instruction")
            }
            InstructionError::IncorrectProgramId => {
                f.write_str("incorrect program id for instruction")
            }
            InstructionError::MissingRequiredSignature => {
                f.write_str("missing required signature for instruction")
            }
            InstructionError::AccountAlreadyInitialized => {
                f.write_str("instruction requires an uninitialized account")
            }
            InstructionError::UninitializedAccount => {
                f.write_str("instruction requires an initialized account")
            }
            InstructionError::UnbalancedInstruction => {
                f.write_str("sum of account balances before and after instruction do not match")
            }
            InstructionError::ModifiedProgramId => {
                f.write_str("instruction illegally modified the program id of an account")
            }
            InstructionError::ExternalAccountLamportSpend => {
                f.write_str("instruction spent from the balance of an account it does not own")
            }
            InstructionError::ExternalAccountDataModified => {
                f.write_str("instruction modified data of an account it does not own")
            }
            InstructionError::ReadonlyLamportChange => {
                f.write_str("instruction changed the balance of a read-only account")
            }
            InstructionError::ReadonlyDataModified => {
                f.write_str("instruction modified data of a read-only account")
            }
            InstructionError::DuplicateAccountIndex => {
                f.write_str("instruction contains duplicate accounts")
            }
            InstructionError::ExecutableModified => {
                f.write_str("instruction changed executable bit of an account")
            }
            InstructionError::RentEpochModified => {
                f.write_str("instruction modified rent epoch of an account")
            }
            InstructionError::NotEnoughAccountKeys => {
                f.write_str("insufficient account keys for instruction")
            }
            InstructionError::AccountDataSizeChanged => f.write_str(
                "program other than the account's owner changed the size of the account data",
            ),
            InstructionError::AccountNotExecutable => {
                f.write_str("instruction expected an executable account")
            }
            InstructionError::AccountBorrowFailed => f.write_str(
                "instruction tries to borrow reference for an account which is already borrowed",
            ),
            InstructionError::AccountBorrowOutstanding => {
                f.write_str("instruction left account with an outstanding borrowed reference")
            }
            InstructionError::DuplicateAccountOutOfSync => {
                f.write_str("instruction modifications of multiply-passed account differ")
            }
            InstructionError::Custom(num) => {
                write!(f, "custom program error: {num:#x}")
            }
            InstructionError::InvalidError => f.write_str("program returned invalid error code"),
            InstructionError::ExecutableDataModified => {
                f.write_str("instruction changed executable accounts data")
            }
            InstructionError::ExecutableLamportChange => {
                f.write_str("instruction changed the balance of an executable account")
            }
            InstructionError::ExecutableAccountNotRentExempt => {
                f.write_str("executable accounts must be rent exempt")
            }
            InstructionError::UnsupportedProgramId => f.write_str("Unsupported program id"),
            InstructionError::CallDepth => {
                f.write_str("Cross-program invocation call depth too deep")
            }
            InstructionError::MissingAccount => {
                f.write_str("An account required by the instruction is missing")
            }
            InstructionError::ReentrancyNotAllowed => {
                f.write_str("Cross-program invocation reentrancy not allowed for this instruction")
            }
            InstructionError::MaxSeedLengthExceeded => {
                f.write_str("Length of the seed is too long for address generation")
            }
            InstructionError::InvalidSeeds => {
                f.write_str("Provided seeds do not result in a valid address")
            }
            InstructionError::InvalidRealloc => f.write_str("Failed to reallocate account data"),
            InstructionError::ComputationalBudgetExceeded => {
                f.write_str("Computational budget exceeded")
            }
            InstructionError::PrivilegeEscalation => {
                f.write_str("Cross-program invocation with unauthorized signer or writable account")
            }
            InstructionError::ProgramEnvironmentSetupFailure => {
                f.write_str("Failed to create program execution environment")
            }
            InstructionError::ProgramFailedToComplete => f.write_str("Program failed to complete"),
            InstructionError::ProgramFailedToCompile => f.write_str("Program failed to compile"),
            InstructionError::Immutable => f.write_str("Account is immutable"),
            InstructionError::IncorrectAuthority => f.write_str("Incorrect authority provided"),
            InstructionError::BorshIoError(s) => {
                write!(f, "Failed to serialize or deserialize account data: {s}",)
            }
            InstructionError::AccountNotRentExempt => {
                f.write_str("An account does not have enough lamports to be rent-exempt")
            }
            InstructionError::InvalidAccountOwner => f.write_str("Invalid account owner"),
            InstructionError::ArithmeticOverflow => f.write_str("Program arithmetic overflowed"),
            InstructionError::UnsupportedSysvar => f.write_str("Unsupported sysvar"),
            InstructionError::IllegalOwner => f.write_str("Provided owner is not allowed"),
            InstructionError::MaxAccountsDataAllocationsExceeded => f.write_str(
                "Accounts data allocations exceeded the maximum allowed per transaction",
            ),
            InstructionError::MaxAccountsExceeded => f.write_str("Max accounts exceeded"),
            InstructionError::MaxInstructionTraceLengthExceeded => {
                f.write_str("Max instruction trace length exceeded")
            }
            InstructionError::BuiltinProgramsMustConsumeComputeUnits => {
                f.write_str("Builtin programs must consume compute units")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<T> From<T> for InstructionError
where
    T: ToPrimitive,
{
    fn from(error: T) -> Self {
        let error = error.to_u64().unwrap_or(0xbad_c0de);
        match error {
            CUSTOM_ZERO => Self::Custom(0),
            INVALID_ARGUMENT => Self::InvalidArgument,
            INVALID_INSTRUCTION_DATA => Self::InvalidInstructionData,
            INVALID_ACCOUNT_DATA => Self::InvalidAccountData,
            ACCOUNT_DATA_TOO_SMALL => Self::AccountDataTooSmall,
            INSUFFICIENT_FUNDS => Self::InsufficientFunds,
            INCORRECT_PROGRAM_ID => Self::IncorrectProgramId,
            MISSING_REQUIRED_SIGNATURES => Self::MissingRequiredSignature,
            ACCOUNT_ALREADY_INITIALIZED => Self::AccountAlreadyInitialized,
            UNINITIALIZED_ACCOUNT => Self::UninitializedAccount,
            NOT_ENOUGH_ACCOUNT_KEYS => Self::NotEnoughAccountKeys,
            ACCOUNT_BORROW_FAILED => Self::AccountBorrowFailed,
            MAX_SEED_LENGTH_EXCEEDED => Self::MaxSeedLengthExceeded,
            INVALID_SEEDS => Self::InvalidSeeds,
            BORSH_IO_ERROR => Self::BorshIoError("Unknown".to_string()),
            ACCOUNT_NOT_RENT_EXEMPT => Self::AccountNotRentExempt,
            UNSUPPORTED_SYSVAR => Self::UnsupportedSysvar,
            ILLEGAL_OWNER => Self::IllegalOwner,
            MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED => Self::MaxAccountsDataAllocationsExceeded,
            INVALID_ACCOUNT_DATA_REALLOC => Self::InvalidRealloc,
            MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED => Self::MaxInstructionTraceLengthExceeded,
            BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS => {
                Self::BuiltinProgramsMustConsumeComputeUnits
            }
            INVALID_ACCOUNT_OWNER => Self::InvalidAccountOwner,
            ARITHMETIC_OVERFLOW => Self::ArithmeticOverflow,
            IMMUTABLE => Self::Immutable,
            INCORRECT_AUTHORITY => Self::IncorrectAuthority,
            _ => {
                // A valid custom error has no bits set in the upper 32
                if error >> BUILTIN_BIT_SHIFT == 0 {
                    Self::Custom(error as u32)
                } else {
                    Self::InvalidError
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum LamportsError {
    /// arithmetic underflowed
    ArithmeticUnderflow,
    /// arithmetic overflowed
    ArithmeticOverflow,
}

#[cfg(feature = "std")]
impl std::error::Error for LamportsError {}

impl fmt::Display for LamportsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ArithmeticUnderflow => f.write_str("Arithmetic underflowed"),
            Self::ArithmeticOverflow => f.write_str("Arithmetic overflowed"),
        }
    }
}

#[cfg(feature = "std")]
impl From<LamportsError> for InstructionError {
    fn from(error: LamportsError) -> Self {
        match error {
            LamportsError::ArithmeticOverflow => InstructionError::ArithmeticOverflow,
            LamportsError::ArithmeticUnderflow => InstructionError::ArithmeticOverflow,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use {super::InstructionError, std::string::ToString};

    #[test]
    fn deserialize() {
        serde_json::from_str::<InstructionError>(r#""InvalidError2""#).unwrap_err();
        serde_json::from_str::<InstructionError>(r#"{"InvalidError2": null}"#).unwrap_err();
        serde_json::from_str::<InstructionError>(r#"{}"#).unwrap_err();
        serde_json::from_str::<InstructionError>(r#""Custom""#).unwrap_err();

        assert_eq!(
            InstructionError::BorshIoError("".to_string()),
            serde_json::from_str::<InstructionError>(r#""BorshIoError""#).unwrap()
        );
        assert_eq!(
            InstructionError::BorshIoError("42".to_string()),
            serde_json::from_str::<InstructionError>(r#"{"BorshIoError": "42"}"#).unwrap()
        );
        assert_eq!(
            InstructionError::InvalidError,
            serde_json::from_str::<InstructionError>(r#"{"InvalidError": null}"#).unwrap()
        );
    }

    #[test]
    fn deserialize_bincode() {
        bincode::deserialize::<InstructionError>(&[100, 0, 0, 0]).unwrap_err();

        assert_eq!(
            InstructionError::BorshIoError("".to_string()),
            bincode::deserialize(&[44, 0, 0, 0]).unwrap(),
        );
        assert_eq!(
            InstructionError::BorshIoError("42".to_string()),
            bincode::deserialize(&[44, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, b'4', b'2',]).unwrap()
        );
        assert_eq!(
            InstructionError::InvalidError,
            bincode::deserialize(&[26, 0, 0, 0]).unwrap(),
        );
    }

    #[test]
    fn serialize() {
        assert_eq!(
            serde_json::to_string(&InstructionError::BorshIoError("42".to_string())).unwrap(),
            r#"{"BorshIoError":"42"}"#
        );
        assert_eq!(
            serde_json::to_string(&InstructionError::InvalidError).unwrap(),
            r#""InvalidError""#
        );
    }
}
