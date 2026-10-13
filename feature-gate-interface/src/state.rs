// Imported anonymously: either name would be wrong under the other feature, and the two
// traits share method names, so the account writers below stay codec-agnostic.
#[cfg(all(feature = "bincode", not(feature = "wincode")))]
use solana_account::state_traits::StateMut as _;
#[cfg(feature = "wincode")]
use solana_account::state_traits::StateMutWincode as _;
#[cfg(any(feature = "bincode", feature = "wincode"))]
use {
    solana_account::{AccountSharedData, ReadableAccount},
    solana_account_info::AccountInfo,
    solana_program_error::ProgramError,
    solana_sdk_ids::feature::id,
};

#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[cfg_attr(feature = "wincode", derive(wincode::SchemaRead, wincode::SchemaWrite))]
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Feature {
    pub activated_at: Option<u64>,
}

impl Feature {
    pub const fn size_of() -> usize {
        9 // see test_feature_size_of.
    }

    #[cfg(any(feature = "bincode", feature = "wincode"))]
    pub fn from_account_info(account_info: &AccountInfo) -> Result<Self, ProgramError> {
        if *account_info.owner != id() {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if account_info.data_len() < Feature::size_of() {
            return Err(ProgramError::InvalidAccountData);
        }
        deserialize(&account_info.data.borrow()).ok_or(ProgramError::InvalidAccountData)
    }
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn from_account<T: ReadableAccount>(account: &T) -> Option<Feature> {
    if account.owner() != &id() || account.data().len() < Feature::size_of() {
        None
    } else {
        deserialize(account.data())
    }
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn to_account(feature: &Feature, account: &mut AccountSharedData) -> Option<()> {
    account.set_state(feature).ok()
}

#[cfg(any(feature = "bincode", feature = "wincode"))]
pub fn create_account(feature: &Feature, lamports: u64) -> AccountSharedData {
    // `size_of()` is the larger of the two encoded lengths (9 for `Some`, 1 for `None`),
    // as `test_feature_size_of` asserts, so it is the account length for every `Feature`.
    AccountSharedData::new_data_with_space(lamports, feature, Feature::size_of(), &id()).unwrap()
}

// The writers above go through `StateMut`/`StateMutWincode`, but those are only
// implemented for `Account`/`AccountSharedData`: `from_account` is generic over
// `ReadableAccount` and `from_account_info` takes an `AccountInfo`, so both read through
// raw bytes here instead.
#[cfg(feature = "wincode")]
fn deserialize(data: &[u8]) -> Option<Feature> {
    wincode::deserialize(data).ok()
}

#[cfg(all(not(feature = "wincode"), feature = "bincode"))]
fn deserialize(data: &[u8]) -> Option<Feature> {
    bincode::deserialize(data).ok()
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

    /// `wincode` shadows `bincode` in the account accessors above, so the two encodings
    /// must agree byte-for-byte for feature accounts to stay readable under either codec.
    #[cfg(all(feature = "bincode", feature = "wincode"))]
    #[test]
    fn wire_compat_bincode_vs_wincode() {
        for feature in [
            Feature { activated_at: None },
            Feature {
                activated_at: Some(0),
            },
            Feature {
                activated_at: Some(1),
            },
            Feature {
                activated_at: Some(u64::MAX),
            },
        ] {
            let bincode_bytes = bincode::serialize(&feature).unwrap();
            let wincode_bytes = wincode::serialize(&feature).unwrap();
            assert_eq!(bincode_bytes, wincode_bytes);
            assert_eq!(
                bincode::serialized_size(&feature).unwrap(),
                wincode::serialized_size(&feature).unwrap()
            );
            // Each codec reads what the other wrote.
            assert_eq!(
                bincode::deserialize::<Feature>(&wincode_bytes).unwrap(),
                feature
            );
            assert_eq!(
                wincode::deserialize::<Feature>(&bincode_bytes).unwrap(),
                feature
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
    fn feature_create_account_round_trip() {
        for feature in [
            Feature { activated_at: None },
            Feature {
                activated_at: Some(u64::MAX),
            },
        ] {
            let account = create_account(&feature, 42);
            assert_eq!(account.lamports(), 42);
            assert_eq!(account.owner(), &id());
            // Every `Feature` gets a `size_of()`-byte account, `None` included.
            assert_eq!(account.data().len(), Feature::size_of());
            assert_eq!(from_account(&account), Some(feature));
        }
    }

    /// The readers gate on `len() < size_of()`, a lower bound, so data longer than
    /// [`Feature::size_of`] must still parse. This pins the tolerant semantics.
    #[test]
    fn feature_deserialize_ignores_trailing_bytes() {
        let feature = Feature {
            activated_at: Some(42),
        };
        let mut account = AccountSharedData::new(1, Feature::size_of() + 8, &id());
        assert_eq!(to_account(&feature, &mut account), Some(()));

        // The codec that is not compiled into the readers above agrees.
        #[cfg(all(feature = "bincode", feature = "wincode"))]
        assert_eq!(
            bincode::deserialize::<Feature>(account.data()).unwrap(),
            feature
        );

        assert_eq!(from_account(&account), Some(feature));
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
