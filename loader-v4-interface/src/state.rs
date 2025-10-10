use solana_pubkey::Pubkey;

#[repr(u32)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LoaderV4Status {
    /// Program is in maintenance
    Retracted,
    /// Program is ready to be executed
    Deployed,
    /// Same as `Deployed`, but can not be retracted anymore
    Finalized,
}

/// LoaderV4 account states
#[repr(C)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct LoaderV4State {
    /// Deployment status.
    pub status: LoaderV4Status,
    /// Length of the executable in bytes.
    pub executable_length: u32,
    /// Slot in which the program was last deployed, retracted or initialized.
    pub slot: u64,
    /// Address of signer which can send program management instructions.
    pub authority_address: Pubkey,
    // The raw program data follows this serialized structure in the
    // account's data.
}

impl LoaderV4State {
    /// Size of a serialized program account.
    pub const fn program_data_offset() -> usize {
        std::mem::size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, memoffset::offset_of};

    #[test]
    fn test_layout() {
        assert_eq!(offset_of!(LoaderV4State, status), 0x00);
        assert_eq!(offset_of!(LoaderV4State, executable_length), 0x04);
        assert_eq!(offset_of!(LoaderV4State, slot), 0x08);
        assert_eq!(offset_of!(LoaderV4State, authority_address), 0x10);
        assert_eq!(LoaderV4State::program_data_offset(), 0x30);
    }
}
