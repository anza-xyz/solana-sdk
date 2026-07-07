use solana_pubkey::Pubkey;
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};

/// Upgradeable loader account states
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UpgradeableLoaderState {
    /// Account is not initialized.
    Uninitialized,
    /// A Buffer account.
    Buffer {
        /// Authority address
        authority_address: Option<Pubkey>,
        // The raw program data follows this serialized structure in the
        // account's data.
    },
    /// An Program account.
    Program {
        /// Address of the ProgramData account.
        programdata_address: Pubkey,
    },
    // A ProgramData account.
    ProgramData {
        /// Slot that the program was last modified.
        slot: u64,
        /// Address of the Program's upgrade authority.
        upgrade_authority_address: Option<Pubkey>,
        // The raw program data follows this serialized structure in the
        // account's data.
    },
}
impl UpgradeableLoaderState {
    /// Size of a serialized program account.
    pub const fn size_of_uninitialized() -> usize {
        4 // see test_state_size_of_uninitialized
    }

    /// Size of a buffer account's serialized metadata.
    pub const fn size_of_buffer_metadata() -> usize {
        37 // see test_state_size_of_buffer_metadata
    }

    /// Size of a programdata account's serialized metadata.
    pub const fn size_of_programdata_metadata() -> usize {
        45 // see test_state_size_of_programdata_metadata
    }

    /// Size of a serialized program account.
    pub const fn size_of_program() -> usize {
        36 // see test_state_size_of_program
    }

    /// Size of a serialized buffer account.
    pub const fn size_of_buffer(program_len: usize) -> usize {
        Self::size_of_buffer_metadata().saturating_add(program_len)
    }

    /// Size of a serialized programdata account.
    pub const fn size_of_programdata(program_len: usize) -> usize {
        Self::size_of_programdata_metadata().saturating_add(program_len)
    }
}

#[cfg(all(test, feature = "wincode"))]
mod tests {
    use {super::*, test_case::test_case};

    #[test]
    fn test_state_size_of_uninitialized() {
        let state = UpgradeableLoaderState::Uninitialized;
        let size = wincode::serialized_size(&state).unwrap();
        assert_eq!(UpgradeableLoaderState::size_of_uninitialized() as u64, size);
    }

    #[test]
    fn test_state_size_of_buffer_metadata() {
        let state = UpgradeableLoaderState::Buffer {
            authority_address: Some(Pubkey::default()),
        };
        let size = wincode::serialized_size(&state).unwrap();
        assert_eq!(
            UpgradeableLoaderState::size_of_buffer_metadata() as u64,
            size
        );
    }

    #[test]
    fn test_state_size_of_programdata_metadata() {
        let state = UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(Pubkey::default()),
            slot: 0,
        };
        let size = wincode::serialized_size(&state).unwrap();
        assert_eq!(
            UpgradeableLoaderState::size_of_programdata_metadata() as u64,
            size
        );
    }

    #[test]
    fn test_state_size_of_program() {
        let state = UpgradeableLoaderState::Program {
            programdata_address: Pubkey::default(),
        };
        let size = wincode::serialized_size(&state).unwrap();
        assert_eq!(UpgradeableLoaderState::size_of_program() as u64, size);
    }

    /// Verify that wincode produces the exact same bytes as bincode for
    /// every state variant, and that both round-trip correctly.
    #[test_case(UpgradeableLoaderState::Uninitialized)]
    #[test_case(UpgradeableLoaderState::Buffer { authority_address: Some(Pubkey::default()) })]
    #[test_case(UpgradeableLoaderState::Buffer { authority_address: None })]
    #[test_case(UpgradeableLoaderState::Program { programdata_address: Pubkey::default() })]
    #[test_case(UpgradeableLoaderState::ProgramData { slot: 123_456_789, upgrade_authority_address: Some(Pubkey::default()) })]
    #[test_case(UpgradeableLoaderState::ProgramData { slot: 0, upgrade_authority_address: None })]
    fn wire_compat_bincode_vs_wincode(state: UpgradeableLoaderState) {
        let bincode_bytes = bincode::serialize(&state).unwrap();
        let wincode_bytes = wincode::serialize(&state).unwrap();
        assert_eq!(bincode_bytes, wincode_bytes);

        let from_bincode: UpgradeableLoaderState = bincode::deserialize(&bincode_bytes).unwrap();
        let from_wincode: UpgradeableLoaderState = wincode::deserialize(&wincode_bytes).unwrap();
        assert_eq!(from_bincode, state);
        assert_eq!(from_wincode, state);
    }
}
