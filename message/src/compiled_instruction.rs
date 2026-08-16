#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::{frozen_abi, AbiExample, StableAbi, StableAbiSample};
use {alloc::vec::Vec, solana_address::Address, solana_sanitize::Sanitize};
#[cfg(feature = "wincode")]
use {
    solana_short_vec::ShortU16,
    wincode::{containers, SchemaRead, SchemaWrite},
};

/// A compact encoding of an instruction.
///
/// A `CompiledInstruction` is a component of a multi-instruction [`Message`],
/// which is the core of a Solana transaction. It is created during the
/// construction of `Message`. Most users will not interact with it directly.
///
/// [`Message`]: crate::Message
#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiExample, StableAbi, StableAbiSample),
    frozen_abi(
        abi_digest = "ANAoDM13eiKa3WRnfiwYi8jcgaEgC32xHWyA8xVAkUGV",
        abi_serializer = ["bincode", "wincode"],
        test_roundtrip = "eq_and_wire"
    )
)]
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "wincode", derive(SchemaWrite, SchemaRead))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompiledInstruction {
    /// Index into the transaction keys array indicating the program account that executes this instruction.
    pub program_id_index: u8,
    /// Ordered indices into the transaction keys array indicating which accounts to pass to the program.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    #[cfg_attr(feature = "wincode", wincode(with = "containers::Vec<_, ShortU16>"))]
    pub accounts: Vec<u8>,
    /// The program input data.
    #[cfg_attr(feature = "serde", serde(with = "solana_short_vec"))]
    #[cfg_attr(feature = "wincode", wincode(with = "containers::Vec<_, ShortU16>"))]
    pub data: Vec<u8>,
}

impl Sanitize for CompiledInstruction {}

impl CompiledInstruction {
    #[cfg(feature = "wincode")]
    /// Create a new instruction from a value, encoded with [`wincode`].
    ///
    /// This is the infallible version of [`CompiledInstruction::try_new`], and will
    /// panic if serialization fails.
    pub fn new<T: wincode::Serialize<Src = T>>(
        program_ids_index: u8,
        data: &T,
        accounts: Vec<u8>,
    ) -> Self {
        Self::try_new(program_ids_index, data, accounts)
            .expect("Failed to serialize instruction data")
    }

    #[cfg(feature = "wincode")]
    /// Fallibly create a new instruction from a value, encoded with [`wincode`].
    ///
    /// [`wincode`]: https://docs.rs/wincode/latest/wincode/
    pub fn try_new<T: wincode::Serialize<Src = T>>(
        program_ids_index: u8,
        data: &T,
        accounts: Vec<u8>,
    ) -> Result<Self, wincode::Error> {
        let data = wincode::serialize(data)?;
        Ok(Self {
            program_id_index: program_ids_index,
            accounts,
            data,
        })
    }

    pub fn new_from_raw_parts(program_id_index: u8, data: Vec<u8>, accounts: Vec<u8>) -> Self {
        Self {
            program_id_index,
            accounts,
            data,
        }
    }

    pub fn program_id<'a>(&self, tx_accounts: &'a [Address]) -> &'a Address {
        &tx_accounts[self.program_id_index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "wincode")]
    mod wincode_tests {
        use super::*;

        struct FailingWincode;
        unsafe impl wincode::SchemaWrite<wincode::config::DefaultConfig> for FailingWincode {
            type Src = Self;

            fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
                Err(wincode::WriteError::Custom("intentional failure"))
            }

            fn write(
                _writer: impl wincode::io::Writer,
                _src: &Self::Src,
            ) -> wincode::WriteResult<()> {
                Err(wincode::WriteError::Custom("intentional failure"))
            }
        }

        #[test]
        fn test_try_new_failure() {
            let result = CompiledInstruction::try_new(0, &FailingWincode, alloc::vec![]);
            assert!(result.is_err());
        }

        #[test]
        #[should_panic(expected = "Failed to serialize instruction data")]
        fn test_new_panic() {
            CompiledInstruction::new(0, &FailingWincode, alloc::vec![]);
        }

        #[derive(wincode::SchemaWrite)]
        struct SuccessWincode {
            value: u64,
        }

        #[test]
        fn test_new_success() {
            let data = SuccessWincode { value: 42 };
            let instr = CompiledInstruction::new(0, &data, alloc::vec![]);
            let expected_data = wincode::serialize(&data).unwrap();
            assert_eq!(instr.data, expected_data);

            let try_instr = CompiledInstruction::try_new(0, &data, alloc::vec![]).unwrap();
            assert_eq!(try_instr.data, expected_data);
        }
    }
}
