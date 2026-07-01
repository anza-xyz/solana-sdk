//! Serde `Serialize` implementations for [`Account`] and [`AccountSharedData`].

use {
    crate::{Account, AccountSharedData},
    serde::ser::{Serialize, Serializer},
};

// mod because we need 'Account' below to have the name 'Account' to match expected serialization
mod account_serialize {
    #[cfg(feature = "frozen-abi")]
    use solana_frozen_abi_macro::{frozen_abi, AbiExample};
    use {
        crate::ReadableAccount,
        serde::{ser::Serializer, Serialize},
        solana_clock::Epoch,
        solana_pubkey::Pubkey,
    };
    #[repr(C)]
    #[cfg_attr(
        feature = "frozen-abi",
        derive(AbiExample),
        frozen_abi(digest = "62EqVoynUFvuui7DVfqWCvZP7bxKGJGioeSBnWrdjRME")
    )]
    #[derive(serde_derive::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Account<'a> {
        lamports: u64,
        #[serde(with = "serde_bytes")]
        // a slice so we don't have to make a copy just to serialize this
        data: &'a [u8],
        owner: &'a Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    }

    /// allows us to implement serialize on AccountSharedData that is equivalent to Account::serialize without making a copy of the Vec<u8>
    pub fn serialize_account<S>(
        account: &impl ReadableAccount,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let temp = Account {
            lamports: account.lamports(),
            data: account.data(),
            owner: account.owner(),
            executable: account.executable(),
            rent_epoch: account.rent_epoch(),
        };
        temp.serialize(serializer)
    }
}

impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        account_serialize::serialize_account(self, serializer)
    }
}

impl Serialize for AccountSharedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        account_serialize::serialize_account(self, serializer)
    }
}
