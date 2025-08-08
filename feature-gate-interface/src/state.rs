#[cfg(feature = "bincode")]
use {
    solana_account::{AccountSharedData, ReadableAccount, WritableAccount},
    solana_account_info::AccountInfo,
    solana_program_error::ProgramError,
    solana_sdk_ids::feature::id,
};

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Feature {
    pub activated_at: Option<u64>,
}

impl Feature {
    pub const fn size_of() -> usize {
        9 // see test_feature_size_of.
    }

    #[cfg(feature = "bincode")]
    pub fn from_account_info(account_info: &AccountInfo) -> Result<Self, ProgramError> {
        if *account_info.owner != id() {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if account_info.data_len() < Feature::size_of() {
            return Err(ProgramError::InvalidAccountData);
        }
        bincode::deserialize(&account_info.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)
    }
}

#[cfg(feature = "bincode")]
pub fn from_account<T: ReadableAccount>(account: &T) -> Option<Feature> {
    if account.owner() != &id() || account.data().len() < Feature::size_of() {
        None
    } else {
        bincode::deserialize(account.data()).ok()
    }
}

#[cfg(feature = "bincode")]
pub fn to_account(feature: &Feature, account: &mut AccountSharedData) -> Option<()> {
    bincode::serialize_into(account.data_as_mut_slice(), feature).ok()
}

#[cfg(feature = "bincode")]
pub fn create_account(feature: &Feature, lamports: u64) -> AccountSharedData {
    let data_len = Feature::size_of().max(bincode::serialized_size(feature).unwrap() as usize);
    let mut account = AccountSharedData::new(lamports, data_len, &id());
    to_account(feature, &mut account).unwrap();
    account
}

#[cfg(test)]
mod test {
    use {super::*, solana_pubkey::Pubkey};

    #[test]
    fn test_feature_size_of() {
        assert_eq!(Feature::size_of() as u64, {
            let feature = Feature {
                activated_at: Some(0),
            };
            bincode::serialized_size(&feature).unwrap()
        });
        assert!(
            Feature::size_of() >= bincode::serialized_size(&Feature::default()).unwrap() as usize
        );
        assert_eq!(Feature::default(), Feature { activated_at: None });

        let features = [
            Feature {
                activated_at: Some(0),
            },
            Feature {
                activated_at: Some(u64::MAX),
            },
        ];
        for feature in &features {
            assert_eq!(
                Feature::size_of(),
                bincode::serialized_size(feature).unwrap() as usize
            );
        }
    }

    #[test]
    fn feature_from_account_info_none() {
        let key = Pubkey::new_unique();
        let mut lamports = 42;

        let mut good_data = vec![0; Feature::size_of()];
        let mut small_data = vec![0; Feature::size_of() - 1]; // Too small

        assert_eq!(
            Feature::from_account_info(&AccountInfo::new(
                &key,
                false,
                false,
                &mut lamports,
                &mut good_data,
                &id(),
                false,
            )),
            Ok(Feature { activated_at: None })
        );
        assert_eq!(
            Feature::from_account_info(&AccountInfo::new(
                &key,
                false,
                false,
                &mut lamports,
                &mut small_data, // Too small
                &id(),
                false,
            )),
            Err(ProgramError::InvalidAccountData),
        );
        assert_eq!(
            Feature::from_account_info(&AccountInfo::new(
                &key,
                false,
                false,
                &mut lamports,
                &mut good_data,
                &Pubkey::new_unique(), // Wrong owner
                false,
            )),
            Err(ProgramError::InvalidAccountOwner),
        );
    }

    #[test]
    fn feature_deserialize_none() {
        assert_eq!(
            from_account(&AccountSharedData::new(42, Feature::size_of(), &id())),
            Some(Feature { activated_at: None })
        );
        assert_eq!(
            from_account(&AccountSharedData::new(
                42,
                Feature::size_of() - 1, // Too small
                &id()
            )),
            None,
        );
        assert_eq!(
            from_account(&AccountSharedData::new(
                42,
                Feature::size_of(),
                &Pubkey::new_unique(), // Wrong owner
            )),
            None,
        );
    }
}
