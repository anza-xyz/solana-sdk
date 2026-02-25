//! Optional addresses that can be used a `Pod`s
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use {
    bytemuck_derive::{Pod, Zeroable},
    solana_address::Address,
    solana_program_error::ProgramError,
    solana_program_option::COption,
    solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey,
};
#[cfg(feature = "serde-traits")]
use {
    core::{convert::TryFrom, fmt, str::FromStr},
    serde::de::{Error, Unexpected, Visitor},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
};

/// A Pubkey that encodes `None` as all `0`, meant to be usable as a `Pod` type,
/// similar to all `NonZero*` number types from the `bytemuck` library.
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
#[repr(transparent)]
pub struct OptionalNonZeroPubkey(pub Address);
impl TryFrom<Option<Address>> for OptionalNonZeroPubkey {
    type Error = ProgramError;
    fn try_from(p: Option<Address>) -> Result<Self, Self::Error> {
        match p {
            None => Ok(Self(Address::default())),
            Some(pubkey) => {
                if pubkey == Address::default() {
                    Err(ProgramError::InvalidArgument)
                } else {
                    Ok(Self(pubkey))
                }
            }
        }
    }
}
impl TryFrom<COption<Address>> for OptionalNonZeroPubkey {
    type Error = ProgramError;
    fn try_from(p: COption<Address>) -> Result<Self, Self::Error> {
        match p {
            COption::None => Ok(Self(Address::default())),
            COption::Some(pubkey) => {
                if pubkey == Address::default() {
                    Err(ProgramError::InvalidArgument)
                } else {
                    Ok(Self(pubkey))
                }
            }
        }
    }
}
impl From<OptionalNonZeroPubkey> for Option<Address> {
    fn from(p: OptionalNonZeroPubkey) -> Self {
        if p.0 == Address::default() {
            None
        } else {
            Some(p.0)
        }
    }
}
impl From<OptionalNonZeroPubkey> for COption<Address> {
    fn from(p: OptionalNonZeroPubkey) -> Self {
        if p.0 == Address::default() {
            COption::None
        } else {
            COption::Some(p.0)
        }
    }
}

#[cfg(feature = "serde-traits")]
impl Serialize for OptionalNonZeroPubkey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0 == Address::default() {
            s.serialize_none()
        } else {
            s.serialize_some(&self.0.to_string())
        }
    }
}

#[cfg(feature = "serde-traits")]
/// Visitor for deserializing `OptionalNonZeroPubkey`
struct OptionalNonZeroPubkeyVisitor;

#[cfg(feature = "serde-traits")]
impl Visitor<'_> for OptionalNonZeroPubkeyVisitor {
    type Value = OptionalNonZeroPubkey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Pubkey in base58 or `null`")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let pkey = Address::from_str(v)
            .map_err(|_| Error::invalid_value(Unexpected::Str(v), &"value string"))?;

        OptionalNonZeroPubkey::try_from(Some(pkey))
            .map_err(|_| Error::custom("Failed to convert from pubkey"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        OptionalNonZeroPubkey::try_from(None).map_err(|e| Error::custom(e.to_string()))
    }
}

#[cfg(feature = "serde-traits")]
impl<'de> Deserialize<'de> for OptionalNonZeroPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OptionalNonZeroPubkeyVisitor)
    }
}

/// An `ElGamalPubkey` that encodes `None` as all `0`, meant to be usable as a
/// `Pod` type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
#[repr(transparent)]
pub struct OptionalNonZeroElGamalPubkey(PodElGamalPubkey);
impl OptionalNonZeroElGamalPubkey {
    /// Checks equality between an `OptionalNonZeroElGamalPubkey` and an
    /// `ElGamalPubkey` when interpreted as bytes.
    pub fn equals(&self, other: &PodElGamalPubkey) -> bool {
        &self.0 == other
    }
}
impl TryFrom<Option<PodElGamalPubkey>> for OptionalNonZeroElGamalPubkey {
    type Error = ProgramError;
    fn try_from(p: Option<PodElGamalPubkey>) -> Result<Self, Self::Error> {
        match p {
            None => Ok(Self(PodElGamalPubkey::default())),
            Some(elgamal_pubkey) => {
                if elgamal_pubkey == PodElGamalPubkey::default() {
                    Err(ProgramError::InvalidArgument)
                } else {
                    Ok(Self(elgamal_pubkey))
                }
            }
        }
    }
}
impl From<OptionalNonZeroElGamalPubkey> for Option<PodElGamalPubkey> {
    fn from(p: OptionalNonZeroElGamalPubkey) -> Self {
        if p.0 == PodElGamalPubkey::default() {
            None
        } else {
            Some(p.0)
        }
    }
}

#[cfg(feature = "serde-traits")]
impl Serialize for OptionalNonZeroElGamalPubkey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0 == PodElGamalPubkey::default() {
            s.serialize_none()
        } else {
            s.serialize_some(&self.0.to_string())
        }
    }
}

#[cfg(feature = "serde-traits")]
struct OptionalNonZeroElGamalPubkeyVisitor;

#[cfg(feature = "serde-traits")]
impl Visitor<'_> for OptionalNonZeroElGamalPubkeyVisitor {
    type Value = OptionalNonZeroElGamalPubkey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an ElGamal public key as base64 or `null`")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let elgamal_pubkey: PodElGamalPubkey = FromStr::from_str(v).map_err(Error::custom)?;
        OptionalNonZeroElGamalPubkey::try_from(Some(elgamal_pubkey)).map_err(Error::custom)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(OptionalNonZeroElGamalPubkey::default())
    }
}

#[cfg(feature = "serde-traits")]
impl<'de> Deserialize<'de> for OptionalNonZeroElGamalPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OptionalNonZeroElGamalPubkeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::bytemuck::pod_from_bytes,
        base64::{prelude::BASE64_STANDARD, Engine},
        solana_address::ADDRESS_BYTES,
    };

    #[test]
    fn test_pod_non_zero_option() {
        assert_eq!(
            Some(Address::new_from_array([1; ADDRESS_BYTES])),
            Option::<Address>::from(
                *pod_from_bytes::<OptionalNonZeroPubkey>(&[1; ADDRESS_BYTES]).unwrap()
            )
        );
        assert_eq!(
            None,
            Option::<Address>::from(
                *pod_from_bytes::<OptionalNonZeroPubkey>(&[0; ADDRESS_BYTES]).unwrap()
            )
        );
        assert_eq!(
            pod_from_bytes::<OptionalNonZeroPubkey>(&[]).unwrap_err(),
            ProgramError::InvalidArgument
        );
        assert_eq!(
            pod_from_bytes::<OptionalNonZeroPubkey>(&[0; 1]).unwrap_err(),
            ProgramError::InvalidArgument
        );
        assert_eq!(
            pod_from_bytes::<OptionalNonZeroPubkey>(&[1; 1]).unwrap_err(),
            ProgramError::InvalidArgument
        );
    }

    #[cfg(feature = "serde-traits")]
    #[test]
    fn test_pod_non_zero_option_serde_some() {
        let optional_non_zero_pubkey_some =
            OptionalNonZeroPubkey(Address::new_from_array([1; ADDRESS_BYTES]));
        let serialized_some = serde_json::to_string(&optional_non_zero_pubkey_some).unwrap();
        assert_eq!(
            &serialized_some,
            "\"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\""
        );

        let deserialized_some =
            serde_json::from_str::<OptionalNonZeroPubkey>(&serialized_some).unwrap();
        assert_eq!(optional_non_zero_pubkey_some, deserialized_some);
    }

    #[cfg(feature = "serde-traits")]
    #[test]
    fn test_pod_non_zero_option_serde_none() {
        let optional_non_zero_pubkey_none =
            OptionalNonZeroPubkey(Address::new_from_array([0; ADDRESS_BYTES]));
        let serialized_none = serde_json::to_string(&optional_non_zero_pubkey_none).unwrap();
        assert_eq!(&serialized_none, "null");

        let deserialized_none =
            serde_json::from_str::<OptionalNonZeroPubkey>(&serialized_none).unwrap();
        assert_eq!(optional_non_zero_pubkey_none, deserialized_none);
    }

    const OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN: usize = 32;

    // Unfortunately, the `solana-zk-sdk` does not expose a constructor interface
    // to construct `PodRistrettoPoint` from bytes. As a work-around, encode the
    // bytes as base64 string and then convert the string to a
    // `PodElGamalCiphertext`.
    //
    // The constructor will be added (and this function removed) with
    // `solana-zk-sdk` 2.1.
    fn elgamal_pubkey_from_bytes(bytes: &[u8]) -> PodElGamalPubkey {
        let string = BASE64_STANDARD.encode(bytes);
        core::str::FromStr::from_str(&string).unwrap()
    }

    #[test]
    fn test_pod_non_zero_elgamal_option() {
        assert_eq!(
            Some(elgamal_pubkey_from_bytes(
                &[1; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN]
            )),
            Option::<PodElGamalPubkey>::from(OptionalNonZeroElGamalPubkey(
                elgamal_pubkey_from_bytes(&[1; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN])
            ))
        );
        assert_eq!(
            None,
            Option::<PodElGamalPubkey>::from(OptionalNonZeroElGamalPubkey(
                elgamal_pubkey_from_bytes(&[0; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN])
            ))
        );

        assert_eq!(
            OptionalNonZeroElGamalPubkey(elgamal_pubkey_from_bytes(
                &[1; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN]
            )),
            *pod_from_bytes::<OptionalNonZeroElGamalPubkey>(
                &[1; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN]
            )
            .unwrap()
        );
        assert!(pod_from_bytes::<OptionalNonZeroElGamalPubkey>(&[]).is_err());
    }

    #[cfg(feature = "serde-traits")]
    #[test]
    fn test_pod_non_zero_elgamal_option_serde_some() {
        let optional_non_zero_elgamal_pubkey_some = OptionalNonZeroElGamalPubkey(
            elgamal_pubkey_from_bytes(&[1; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN]),
        );
        let serialized_some =
            serde_json::to_string(&optional_non_zero_elgamal_pubkey_some).unwrap();
        assert_eq!(
            &serialized_some,
            "\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\""
        );

        let deserialized_some =
            serde_json::from_str::<OptionalNonZeroElGamalPubkey>(&serialized_some).unwrap();
        assert_eq!(optional_non_zero_elgamal_pubkey_some, deserialized_some);
    }

    #[cfg(feature = "serde-traits")]
    #[test]
    fn test_pod_non_zero_elgamal_option_serde_none() {
        let optional_non_zero_elgamal_pubkey_none = OptionalNonZeroElGamalPubkey(
            elgamal_pubkey_from_bytes(&[0; OPTIONAL_NONZERO_ELGAMAL_PUBKEY_LEN]),
        );
        let serialized_none =
            serde_json::to_string(&optional_non_zero_elgamal_pubkey_none).unwrap();
        assert_eq!(&serialized_none, "null");

        let deserialized_none =
            serde_json::from_str::<OptionalNonZeroElGamalPubkey>(&serialized_none).unwrap();
        assert_eq!(optional_non_zero_elgamal_pubkey_none, deserialized_none);
    }
}
