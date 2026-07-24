//! The [`ProgramError`] type and related definitions.

#![allow(clippy::arithmetic_side_effects)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#[cfg(feature = "borsh")]
use borsh::io::Error as BorshIoError;
use core::{convert::TryFrom, fmt, mem::MaybeUninit};
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};

pub type ProgramResult = core::result::Result<(), ProgramError>;

/// Builtin return values occupy the upper 32 bits
pub const BUILTIN_BIT_SHIFT: usize = 32;
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
// - Added as a `ProgramError` variant with the code as its discriminant,
//   and made the new upper bound of the builtin range in `From<u64>`
// - Added as an equivalent to ProgramError and InstructionError
// - Be featurized in the BPF loader to return `InstructionError::InvalidError`
//   until the feature is activated

/// Reasons the program may fail
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProgramError {
    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom(u32) = 1,
    InvalidArgument = 2,
    InvalidInstructionData = 3,
    InvalidAccountData = 4,
    AccountDataTooSmall = 5,
    InsufficientFunds = 6,
    IncorrectProgramId = 7,
    MissingRequiredSignature = 8,
    AccountAlreadyInitialized = 9,
    UninitializedAccount = 10,
    NotEnoughAccountKeys = 11,
    AccountBorrowFailed = 12,
    MaxSeedLengthExceeded = 13,
    InvalidSeeds = 14,
    BorshIoError = 15,
    AccountNotRentExempt = 16,
    UnsupportedSysvar = 17,
    IllegalOwner = 18,
    MaxAccountsDataAllocationsExceeded = 19,
    InvalidRealloc = 20,
    MaxInstructionTraceLengthExceeded = 21,
    BuiltinProgramsMustConsumeComputeUnits = 22,
    InvalidAccountOwner = 23,
    ArithmeticOverflow = 24,
    Immutable = 25,
    IncorrectAuthority = 26,
}

impl core::error::Error for ProgramError {}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProgramError::Custom(num) => write!(f,"Custom program error: {num:#x}"),
            ProgramError::InvalidArgument
             => f.write_str("The arguments provided to a program instruction were invalid"),
            ProgramError::InvalidInstructionData
             => f.write_str("An instruction's data contents was invalid"),
            ProgramError::InvalidAccountData
             => f.write_str("An account's data contents was invalid"),
            ProgramError::AccountDataTooSmall
             => f.write_str("An account's data was too small"),
            ProgramError::InsufficientFunds
             => f.write_str("An account's balance was too small to complete the instruction"),
            ProgramError::IncorrectProgramId
             => f.write_str("The account did not have the expected program id"),
            ProgramError::MissingRequiredSignature
             => f.write_str("A signature was required but not found"),
            ProgramError::AccountAlreadyInitialized
             => f.write_str("An initialize instruction was sent to an account that has already been initialized"),
            ProgramError::UninitializedAccount
             => f.write_str("An attempt to operate on an account that hasn't been initialized"),
            ProgramError::NotEnoughAccountKeys
             => f.write_str("The instruction expected additional account keys"),
            ProgramError::AccountBorrowFailed
             => f.write_str("Failed to borrow a reference to account data, already borrowed"),
            ProgramError::MaxSeedLengthExceeded
             => f.write_str("Length of the seed is too long for address generation"),
            ProgramError::InvalidSeeds
             => f.write_str("Provided seeds do not result in a valid address"),
            ProgramError::BorshIoError =>  f.write_str("IO Error"),
            ProgramError::AccountNotRentExempt
             => f.write_str("An account does not have enough lamports to be rent-exempt"),
            ProgramError::UnsupportedSysvar
             => f.write_str("Unsupported sysvar"),
            ProgramError::IllegalOwner
             => f.write_str("Provided owner is not allowed"),
            ProgramError::MaxAccountsDataAllocationsExceeded
             => f.write_str("Accounts data allocations exceeded the maximum allowed per transaction"),
            ProgramError::InvalidRealloc
             => f.write_str("Account data reallocation was invalid"),
            ProgramError::MaxInstructionTraceLengthExceeded
             => f.write_str("Instruction trace length exceeded the maximum allowed per transaction"),
            ProgramError::BuiltinProgramsMustConsumeComputeUnits
             => f.write_str("Builtin programs must consume compute units"),
            ProgramError::InvalidAccountOwner
             => f.write_str("Invalid account owner"),
            ProgramError::ArithmeticOverflow
             => f.write_str("Program arithmetic overflowed"),
            ProgramError::Immutable
             => f.write_str("Account is immutable"),
            ProgramError::IncorrectAuthority
             => f.write_str("Incorrect authority provided"),
        }
    }
}

/// A trait for converting a program's specific error type to a `&str`.
///
/// Can be used with `ProgramError::to_str::<E>()` to get an error string
/// belonging to a specific program's error if the variant is
/// `ProgramError::Custom(...)`, or generic strings from the contained
/// `ProgramError` for all other variants.
///
/// The `ProgramError::to_str::<E>()` function also requires implementing
/// `TryFrom<u32>` on an error type, which can be done easily using
/// `num_enum::TryFromPrimitive`.
pub trait ToStr {
    fn to_str(&self) -> &'static str;
}

impl ProgramError {
    /// Get an appropriate error string given a program error and an expected
    /// error type, if the error implements `TryFrom<u32>` and `ToStr`.
    ///
    /// # Example
    ///
    /// ```
    /// #[derive(num_enum::TryFromPrimitive)]
    /// #[repr(u32)]
    /// enum MyError {
    ///     A,
    ///     B,
    /// }
    ///
    /// impl solana_program_error::ToStr for MyError {
    ///     fn to_str(&self) -> &'static str {
    ///         match self {
    ///             MyError::A => "Message for A",
    ///             MyError::B => "Some other message for B",
    ///         }
    ///     }
    /// }
    ///
    /// let program_error = solana_program_error::ProgramError::Custom(1);
    /// assert_eq!("Some other message for B", program_error.to_str::<MyError>());
    /// ```
    pub fn to_str<E>(&self) -> &'static str
    where
        E: 'static + ToStr + TryFrom<u32>,
    {
        match self {
            Self::Custom(error) => {
                if let Ok(custom_error) = E::try_from(*error) {
                    custom_error.to_str()
                } else {
                    "Error: Unknown"
                }
            }
            Self::InvalidArgument => "Error: InvalidArgument",
            Self::InvalidInstructionData => "Error: InvalidInstructionData",
            Self::InvalidAccountData => "Error: InvalidAccountData",
            Self::AccountDataTooSmall => "Error: AccountDataTooSmall",
            Self::InsufficientFunds => "Error: InsufficientFunds",
            Self::IncorrectProgramId => "Error: IncorrectProgramId",
            Self::MissingRequiredSignature => "Error: MissingRequiredSignature",
            Self::AccountAlreadyInitialized => "Error: AccountAlreadyInitialized",
            Self::UninitializedAccount => "Error: UninitializedAccount",
            Self::NotEnoughAccountKeys => "Error: NotEnoughAccountKeys",
            Self::AccountBorrowFailed => "Error: AccountBorrowFailed",
            Self::MaxSeedLengthExceeded => "Error: MaxSeedLengthExceeded",
            Self::InvalidSeeds => "Error: InvalidSeeds",
            Self::BorshIoError => "Error: BorshIoError",
            Self::AccountNotRentExempt => "Error: AccountNotRentExempt",
            Self::UnsupportedSysvar => "Error: UnsupportedSysvar",
            Self::IllegalOwner => "Error: IllegalOwner",
            Self::MaxAccountsDataAllocationsExceeded => "Error: MaxAccountsDataAllocationsExceeded",
            Self::InvalidRealloc => "Error: InvalidRealloc",
            Self::MaxInstructionTraceLengthExceeded => "Error: MaxInstructionTraceLengthExceeded",
            Self::BuiltinProgramsMustConsumeComputeUnits => {
                "Error: BuiltinProgramsMustConsumeComputeUnits"
            }
            Self::InvalidAccountOwner => "Error: InvalidAccountOwner",
            Self::ArithmeticOverflow => "Error: ArithmeticOverflow",
            Self::Immutable => "Error: Immutable",
            Self::IncorrectAuthority => "Error: IncorrectAuthority",
        }
    }
}

impl From<ProgramError> for u64 {
    fn from(error: ProgramError) -> Self {
        match error {
            ProgramError::Custom(error) => {
                if error == 0 {
                    CUSTOM_ZERO
                } else {
                    error as u64
                }
            }
            _ => {
                // SAFETY: `ProgramError` is `repr(u8)`, so the discriminant
                // of every variant is stored as a `u8` in its first byte.
                let discriminant = unsafe { *(&error as *const ProgramError as *const u8) };
                (discriminant as u64) << BUILTIN_BIT_SHIFT
            }
        }
    }
}

impl From<u64> for ProgramError {
    fn from(error: u64) -> Self {
        match error {
            CUSTOM_ZERO => Self::Custom(0),
            // Builtin errors encode their discriminant in the upper 32 bits
            // and have nothing in the lower 32.
            INVALID_ARGUMENT..=INCORRECT_AUTHORITY if error as u32 == 0 => {
                let discriminant = (error >> BUILTIN_BIT_SHIFT) as u8;
                // SAFETY: `ProgramError` is `repr(u8)` and `discriminant` is
                // the tag of one of its fieldless variants, so writing it to
                // the first byte produces a valid value; the remaining bytes
                // are padding for these variants.
                unsafe {
                    let mut value = MaybeUninit::<ProgramError>::uninit();
                    value.as_mut_ptr().cast::<u8>().write(discriminant);
                    value.assume_init()
                }
            }
            _ => Self::Custom(error as u32),
        }
    }
}

#[cfg(feature = "borsh")]
impl From<BorshIoError> for ProgramError {
    fn from(_error: BorshIoError) -> Self {
        Self::BorshIoError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exhaustive on purpose: adding a variant without updating the
    // conversions (and this test) fails to compile here.
    fn builtin_code(error: &ProgramError) -> u64 {
        match error {
            ProgramError::Custom(_) => CUSTOM_ZERO,
            ProgramError::InvalidArgument => INVALID_ARGUMENT,
            ProgramError::InvalidInstructionData => INVALID_INSTRUCTION_DATA,
            ProgramError::InvalidAccountData => INVALID_ACCOUNT_DATA,
            ProgramError::AccountDataTooSmall => ACCOUNT_DATA_TOO_SMALL,
            ProgramError::InsufficientFunds => INSUFFICIENT_FUNDS,
            ProgramError::IncorrectProgramId => INCORRECT_PROGRAM_ID,
            ProgramError::MissingRequiredSignature => MISSING_REQUIRED_SIGNATURES,
            ProgramError::AccountAlreadyInitialized => ACCOUNT_ALREADY_INITIALIZED,
            ProgramError::UninitializedAccount => UNINITIALIZED_ACCOUNT,
            ProgramError::NotEnoughAccountKeys => NOT_ENOUGH_ACCOUNT_KEYS,
            ProgramError::AccountBorrowFailed => ACCOUNT_BORROW_FAILED,
            ProgramError::MaxSeedLengthExceeded => MAX_SEED_LENGTH_EXCEEDED,
            ProgramError::InvalidSeeds => INVALID_SEEDS,
            ProgramError::BorshIoError => BORSH_IO_ERROR,
            ProgramError::AccountNotRentExempt => ACCOUNT_NOT_RENT_EXEMPT,
            ProgramError::UnsupportedSysvar => UNSUPPORTED_SYSVAR,
            ProgramError::IllegalOwner => ILLEGAL_OWNER,
            ProgramError::MaxAccountsDataAllocationsExceeded => {
                MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED
            }
            ProgramError::InvalidRealloc => INVALID_ACCOUNT_DATA_REALLOC,
            ProgramError::MaxInstructionTraceLengthExceeded => {
                MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED
            }
            ProgramError::BuiltinProgramsMustConsumeComputeUnits => {
                BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS
            }
            ProgramError::InvalidAccountOwner => INVALID_ACCOUNT_OWNER,
            ProgramError::ArithmeticOverflow => ARITHMETIC_OVERFLOW,
            ProgramError::Immutable => IMMUTABLE,
            ProgramError::IncorrectAuthority => INCORRECT_AUTHORITY,
        }
    }

    #[test]
    fn test_builtin_conversions_round_trip() {
        let variants = [
            ProgramError::Custom(0),
            ProgramError::InvalidArgument,
            ProgramError::InvalidInstructionData,
            ProgramError::InvalidAccountData,
            ProgramError::AccountDataTooSmall,
            ProgramError::InsufficientFunds,
            ProgramError::IncorrectProgramId,
            ProgramError::MissingRequiredSignature,
            ProgramError::AccountAlreadyInitialized,
            ProgramError::UninitializedAccount,
            ProgramError::NotEnoughAccountKeys,
            ProgramError::AccountBorrowFailed,
            ProgramError::MaxSeedLengthExceeded,
            ProgramError::InvalidSeeds,
            ProgramError::BorshIoError,
            ProgramError::AccountNotRentExempt,
            ProgramError::UnsupportedSysvar,
            ProgramError::IllegalOwner,
            ProgramError::MaxAccountsDataAllocationsExceeded,
            ProgramError::InvalidRealloc,
            ProgramError::MaxInstructionTraceLengthExceeded,
            ProgramError::BuiltinProgramsMustConsumeComputeUnits,
            ProgramError::InvalidAccountOwner,
            ProgramError::ArithmeticOverflow,
            ProgramError::Immutable,
            ProgramError::IncorrectAuthority,
        ];
        for error in variants {
            let code = builtin_code(&error);
            assert_eq!(u64::from(error.clone()), code);
            assert_eq!(ProgramError::from(code), error);
        }
    }

    #[test]
    fn test_custom_conversions_round_trip() {
        assert_eq!(u64::from(ProgramError::Custom(0)), CUSTOM_ZERO);
        assert_eq!(ProgramError::from(CUSTOM_ZERO), ProgramError::Custom(0));
        for code in [1u64, 42, u32::MAX as u64] {
            assert_eq!(u64::from(ProgramError::Custom(code as u32)), code);
            assert_eq!(ProgramError::from(code), ProgramError::Custom(code as u32));
        }
    }

    #[test]
    fn test_unknown_codes_convert_to_custom() {
        for (code, expected) in [
            ((1u64 << BUILTIN_BIT_SHIFT) | 5, 5),
            ((2u64 << BUILTIN_BIT_SHIFT) | 7, 7),
            (27u64 << BUILTIN_BIT_SHIFT, 0),
            // 0x102 truncates to 2 as u8; must not decode as InvalidArgument
            (0x102u64 << BUILTIN_BIT_SHIFT, 0),
            (u64::MAX, u32::MAX),
        ] {
            assert_eq!(ProgramError::from(code), ProgramError::Custom(expected));
        }
    }
}
