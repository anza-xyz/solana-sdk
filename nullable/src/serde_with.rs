//! [`serde_with`] integration for [`MaybeNull`].
//!
//! Provides blanket [`SerializeAs`] and [`DeserializeAs`] implementations so
//! that any `serde_with` adapter can be composed with `MaybeNull<T>` using the
//! `Option<Strategy>` pattern.
//!
//! ```rust
//! # pub mod solana_address {
//! #     #[derive(PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
//! #     pub struct Address([u8; 32]);
//! #     impl solana_nullable::Nullable for Address {
//! #         const NONE: Self = Address([0u8; 32]);
//! #     }
//! #     impl core::str::FromStr for Address {
//! #         type Err = String;
//! #         fn from_str(s: &str) -> Result<Self, Self::Err> {
//! #             Ok(Address([0u8; 32]))
//! #         }
//! #     }
//! #     impl core::fmt::Display for Address {
//! #         fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//! #             Ok(())
//! #         }
//! #     }
//! # }
//!
//! use {
//!     serde_derive::{Deserialize, Serialize},
//!     serde_with::{serde_as, DisplayFromStr},
//!     solana_address::Address,
//!     solana_nullable::MaybeNull,
//! };
//!
//! #[serde_as]
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct {
//!     #[serde_as(as = "Option<DisplayFromStr>")]
//!     pub field: MaybeNull<Address>,
//! }
//!
//! // Or without the proc macro:
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct2 {
//!     #[serde(with = "serde_with::As::<Option<DisplayFromStr>>")]
//!     pub field: MaybeNull<Address>,
//! }
//! ```

use {
    crate::{MaybeNull, Nullable},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    serde_with::{de::DeserializeAsWrap, ser::SerializeAsWrap, DeserializeAs, SerializeAs},
};

impl<T, U> SerializeAs<MaybeNull<T>> for Option<U>
where
    T: Nullable,
    U: SerializeAs<T>,
{
    fn serialize_as<S>(source: &MaybeNull<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        source
            .as_ref()
            .map(SerializeAsWrap::<T, U>::new)
            .serialize(serializer)
    }
}

impl<'de, T, U> DeserializeAs<'de, MaybeNull<T>> for Option<U>
where
    T: Nullable,
    U: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<MaybeNull<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<DeserializeAsWrap<T, U>>::deserialize(deserializer)?
            .map(DeserializeAsWrap::into_inner)
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::Nullable,
        alloc::string::ToString,
        serde_derive::{Deserialize, Serialize},
        serde_with::{serde_as, DisplayFromStr},
    };

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Id(u32);

    impl Nullable for Id {
        const NONE: Self = Id(0);
    }

    impl core::fmt::Display for Id {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl core::str::FromStr for Id {
        type Err = core::num::ParseIntError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Id(s.parse()?))
        }
    }

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde_as(as = "Option<DisplayFromStr>")]
        pub value: MaybeNull<Id>,
    }

    #[test]
    fn serialize_some_as_display_string() {
        let s = TestStruct {
            value: MaybeNull::from(Id(42)),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":"42"}"#);
    }

    #[test]
    fn serialize_none_as_null() {
        let s = TestStruct {
            value: MaybeNull::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":null}"#);
    }

    #[test]
    fn deserialize_string_to_some() {
        let json = r#"{"value":"42"}"#;
        let s: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(s.value, MaybeNull::from(Id(42)));
    }

    #[test]
    fn deserialize_null_to_none() {
        let json = r#"{"value":null}"#;
        let s: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(s.value, MaybeNull::default());
    }

    #[test]
    fn deserialize_none_marker_in_some_is_rejected() {
        // "0" parses to Id(0) which is the NONE marker
        let json = r#"{"value":"0"}"#;
        let err = serde_json::from_str::<TestStruct>(json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("None-equivalent"));
    }

    #[test]
    fn deserialize_malformed_string_propagates_error() {
        let json = r#"{"value":"not_a_number"}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());
    }

    #[test]
    fn deserialize_wrong_json_type_propagates_error() {
        let json = r#"{"value":42}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());
    }

    #[test]
    fn roundtrip_some() {
        let original = TestStruct {
            value: MaybeNull::from(Id(99)),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn deserialize_missing_field_is_error() {
        // Without #[serde(default)], a missing key is an error, not null.
        let json = r#"{}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());
    }

    #[test]
    fn roundtrip_none() {
        let original = TestStruct {
            value: MaybeNull::default(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    // Verify it works with serde(with) syntax too
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestWithSyntax {
        #[serde(with = "serde_with::As::<Option<DisplayFromStr>>")]
        pub value: MaybeNull<Id>,
    }

    #[test]
    fn serde_with_syntax_serialize_some() {
        let s = TestWithSyntax {
            value: MaybeNull::from(Id(7)),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":"7"}"#);
    }

    #[test]
    fn serde_with_syntax_serialize_none() {
        let s = TestWithSyntax {
            value: MaybeNull::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":null}"#);
    }

    #[test]
    fn serde_with_syntax_deserialize_some() {
        let json = r#"{"value":"7"}"#;
        let s: TestWithSyntax = serde_json::from_str(json).unwrap();
        assert_eq!(s.value, MaybeNull::from(Id(7)));
    }

    #[test]
    fn serde_with_syntax_deserialize_null() {
        let json = r#"{"value":null}"#;
        let s: TestWithSyntax = serde_json::from_str(json).unwrap();
        assert_eq!(s.value, MaybeNull::default());
    }

    // Verify a custom adapter works (not just DisplayFromStr)
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Score(u32);

    impl Nullable for Score {
        const NONE: Self = Score(0);
    }

    /// Custom adapter serializes Score as doubled value
    struct DoubledScore;

    impl SerializeAs<Score> for DoubledScore {
        fn serialize_as<S>(source: &Score, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_u32(source.0.saturating_mul(2))
        }
    }

    impl<'de> DeserializeAs<'de, Score> for DoubledScore {
        fn deserialize_as<D>(deserializer: D) -> Result<Score, D::Error>
        where
            D: Deserializer<'de>,
        {
            let v = u32::deserialize(deserializer)?;
            Ok(Score(v / 2))
        }
    }

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct CustomAdapterStruct {
        #[serde_as(as = "Option<DoubledScore>")]
        pub value: MaybeNull<Score>,
    }

    #[test]
    fn custom_adapter_serialize_some() {
        let s = CustomAdapterStruct {
            value: MaybeNull::from(Score(21)),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":42}"#);
    }

    #[test]
    fn custom_adapter_serialize_none() {
        let s = CustomAdapterStruct {
            value: MaybeNull::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"value":null}"#);
    }

    #[test]
    fn custom_adapter_deserialize_some() {
        let json = r#"{"value":42}"#;
        let s: CustomAdapterStruct = serde_json::from_str(json).unwrap();
        assert_eq!(
            s,
            CustomAdapterStruct {
                value: MaybeNull::from(Score(21)),
            }
        );
    }

    #[test]
    fn custom_adapter_deserialize_null() {
        let json = r#"{"value":null}"#;
        let s: CustomAdapterStruct = serde_json::from_str(json).unwrap();
        assert_eq!(
            s,
            CustomAdapterStruct {
                value: MaybeNull::default(),
            }
        );
    }

    #[test]
    fn custom_adapter_rejects_none_marker_after_transform() {
        // DoubledScore deserializes 1 as Score(1/2) = Score(0) which is NONE.
        // The blanket impl must reject this even though the raw JSON value is valid.
        let json = r#"{"value":1}"#;
        let err = serde_json::from_str::<CustomAdapterStruct>(json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("None-equivalent"));
    }
}
