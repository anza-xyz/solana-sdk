//! Generic `Option`-like wrapper for types that can reserve a designated null
//! value without adding a tag byte.
//!
//! For example, a 64-bit unsigned integer can designate `0` as a `None` value.
//! This is equivalent to
//! [`Option<NonZeroU64>`](https://doc.rust-lang.org/std/num/type.NonZeroU64.html)
//! and provides the same memory layout optimization.

use crate::Nullable;
#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, Zeroable};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};
#[cfg(feature = "borsh")]
use {
    alloc::format,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
};

/// A wrapper that can be used as an `Option<T>` without requiring extra space
/// to indicate whether the value is `Some` or `None`.
///
/// This can be used when a specific value of `T` indicates that its value is
/// `None`.
#[repr(transparent)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MaybeNull<T: Nullable>(T);

/// # Safety
///
/// `MaybeNull<T>` where `T: ZeroCopy` is trivially zero-copy.
#[cfg(feature = "wincode")]
unsafe impl<T, C> wincode::config::ZeroCopy<C> for MaybeNull<T>
where
    C: wincode::config::ConfigCore,
    T: Nullable + wincode::config::ZeroCopy<C>,
{
}

impl<T: Nullable> Default for MaybeNull<T> {
    fn default() -> Self {
        Self(T::NONE)
    }
}

impl<T: Nullable> MaybeNull<T> {
    /// Returns the contained value as an `Option`.
    #[inline]
    pub fn get(self) -> Option<T> {
        if self.0.is_none() {
            None
        } else {
            Some(self.0)
        }
    }

    /// Returns a reference to the contained value as an `Option`.
    #[inline]
    pub fn as_ref(&self) -> Option<&T> {
        if self.0.is_none() {
            None
        } else {
            Some(&self.0)
        }
    }

    /// Returns a mutable reference to the contained value as an `Option`.
    #[inline]
    pub fn as_mut(&mut self) -> Option<&mut T> {
        if self.0.is_none() {
            None
        } else {
            Some(&mut self.0)
        }
    }

    /// Maps a `MaybeNull<T>` to an `Option<T>` by copying the contents of the option.
    #[inline]
    pub fn copied(&self) -> Option<T>
    where
        T: Copy,
    {
        self.as_ref().copied()
    }

    /// Maps a `MaybeNull<T>` to an `Option<T>` by cloning the contents of the option.
    #[inline]
    pub fn cloned(&self) -> Option<T>
    where
        T: Clone,
    {
        self.as_ref().cloned()
    }
}

impl<T: Nullable> From<T> for MaybeNull<T> {
    fn from(value: T) -> Self {
        MaybeNull(value)
    }
}

impl<T: Nullable> From<MaybeNull<T>> for Option<T> {
    fn from(value: MaybeNull<T>) -> Self {
        value.get()
    }
}

impl<T: Nullable> TryFrom<Option<T>> for MaybeNull<T> {
    type Error = MaybeNullError;

    fn try_from(value: Option<T>) -> Result<Self, Self::Error> {
        match value {
            Some(value) if value.is_none() => Err(MaybeNullError::NoneValueInSome),
            Some(value) => Ok(MaybeNull(value)),
            None => Ok(MaybeNull(T::NONE)),
        }
    }
}

/// Error type for invalid `MaybeNull` conversions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaybeNullError {
    /// Attempted to wrap a none-equivalent value in `Some`.
    NoneValueInSome,
}

impl core::fmt::Display for MaybeNullError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoneValueInSome => {
                write!(f, "cannot wrap None-equivalent value in Some")
            }
        }
    }
}

/// ## Safety
///
/// `MaybeNull` is a transparent wrapper around a bytemuck `Pod` type `T` with
/// identical data representation.
#[cfg(feature = "bytemuck")]
unsafe impl<T: Nullable + Pod> Pod for MaybeNull<T> {}

/// ## Safety
///
/// `MaybeNull` is a transparent wrapper around a bytemuck `Pod` type `T` with
/// identical data representation.
#[cfg(feature = "bytemuck")]
unsafe impl<T: Nullable + Zeroable> Zeroable for MaybeNull<T> {}

#[cfg(feature = "serde")]
impl<T> Serialize for MaybeNull<T>
where
    T: Nullable + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.is_none() {
            serializer.serialize_none()
        } else {
            serializer.serialize_some(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for MaybeNull<T>
where
    T: Nullable + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let option = Option::<T>::deserialize(deserializer)?;
        match option {
            Some(value) if value.is_none() => Err(serde::de::Error::custom(
                "Invalid MaybeNull encoding: Some(value) cannot equal the None marker.",
            )),
            Some(value) => Ok(MaybeNull(value)),
            None => Ok(MaybeNull(T::NONE)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Nullable for u64 {
        const NONE: Self = 0;
    }

    #[test]
    fn test_try_from_option() {
        let some = Some(42u64);
        assert_eq!(MaybeNull::try_from(some).unwrap(), MaybeNull(42u64));

        let none: Option<u64> = None;
        assert_eq!(MaybeNull::try_from(none).unwrap(), MaybeNull::from(0u64));

        let invalid = Some(0u64);
        assert_eq!(
            MaybeNull::try_from(invalid).unwrap_err(),
            MaybeNullError::NoneValueInSome,
        );
    }

    #[test]
    fn test_from_maybe_null() {
        let some = MaybeNull::from(42u64);
        let none = MaybeNull::from(0u64);

        assert_eq!(Option::<u64>::from(some), Some(42));
        assert_eq!(Option::<u64>::from(none), None);
    }

    #[test]
    fn test_default() {
        let def = MaybeNull::<u64>::default();
        assert_eq!(def, MaybeNull(0u64));
        assert_eq!(def.get(), None);
    }

    #[test]
    fn test_copied() {
        let some = MaybeNull::from(42u64);
        assert_eq!(some.copied(), Some(42));

        let none = MaybeNull::from(0u64);
        assert_eq!(none.copied(), None);
    }

    #[test]
    fn test_nullable_predicates() {
        assert!(u64::NONE.is_none());
        assert!(!u64::NONE.is_some());
        assert!(8u64.is_some());
        assert!(!8u64.is_none());
    }

    #[test]
    fn test_as_ref() {
        let some = MaybeNull::from(8u64);
        assert_eq!(some.as_ref(), Some(&8u64));

        let none = MaybeNull::from(u64::NONE);
        assert_eq!(none.as_ref(), None);
    }

    #[test]
    fn test_as_mut() {
        let mut some = MaybeNull::from(3u64);
        assert!(some.as_mut().is_some());
        *some.as_mut().unwrap() = 4;
        assert_eq!(some.get(), Some(4));

        let mut none = MaybeNull::from(0u64);
        assert!(none.as_mut().is_none());
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestNonCopyNullable([u8; 4]);

    impl Nullable for TestNonCopyNullable {
        const NONE: Self = Self([0u8; 4]);
    }

    #[test]
    fn test_cloned_with_non_copy_nullable() {
        let some = MaybeNull::from(TestNonCopyNullable([1, 2, 3, 4]));
        assert_eq!(some.cloned(), Some(TestNonCopyNullable([1, 2, 3, 4])));

        let none = MaybeNull::from(TestNonCopyNullable::NONE);
        assert_eq!(none.cloned(), None);
    }

    #[cfg(feature = "borsh")]
    mod borsh_tests {
        use {super::*, alloc::vec};

        #[test]
        fn test_borsh_roundtrip_u64() {
            let some = MaybeNull::from(42u64);
            let none = MaybeNull::from(0u64);

            let some_bytes = borsh::to_vec(&some).unwrap();
            let none_bytes = borsh::to_vec(&none).unwrap();

            assert_eq!(some_bytes, 42u64.to_le_bytes().to_vec());
            assert_eq!(none_bytes, vec![0; 8]);
            assert_eq!(
                borsh::from_slice::<MaybeNull<u64>>(&some_bytes).unwrap(),
                some
            );
            assert_eq!(
                borsh::from_slice::<MaybeNull<u64>>(&none_bytes).unwrap(),
                none
            );
            assert!(borsh::from_slice::<MaybeNull<u64>>(&[]).is_err());
        }
    }

    #[cfg(feature = "wincode")]
    mod wincode_tests {
        use {super::*, wincode::ZeroCopy};

        #[test]
        fn test_wincode_maybe_null_roundtrip_and_size() {
            let some = MaybeNull::from(9u64);
            let none = MaybeNull::from(0u64);

            let some_bytes = wincode::serialize(&some).unwrap();
            let none_bytes = wincode::serialize(&none).unwrap();

            assert_eq!(some_bytes.len(), core::mem::size_of::<u64>());
            assert_eq!(none_bytes.len(), core::mem::size_of::<u64>());
            assert_eq!(some_bytes.as_slice(), &9u64.to_le_bytes());
            assert_eq!(none_bytes.as_slice(), &0u64.to_le_bytes());

            let some_roundtrip: MaybeNull<u64> = wincode::deserialize(&some_bytes).unwrap();
            let none_roundtrip: MaybeNull<u64> = wincode::deserialize(&none_bytes).unwrap();
            assert_eq!(some_roundtrip, some);
            assert_eq!(none_roundtrip, none);

            let some_zero_copy = MaybeNull::<u64>::from_bytes(&some_bytes).unwrap();
            let none_zero_copy = MaybeNull::<u64>::from_bytes(&none_bytes).unwrap();
            assert_eq!(some_zero_copy, &some);
            assert_eq!(none_zero_copy, &none);
        }

        #[test]
        fn test_wincode_maybe_null_rejects_truncated_input() {
            assert!(wincode::deserialize::<MaybeNull<u64>>(&[]).is_err());
            assert!(wincode::deserialize::<MaybeNull<u64>>(&[0; 7]).is_err());
        }
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use {super::*, alloc::string::ToString};

        #[test]
        fn test_serde_u64_some() {
            let some = MaybeNull::from(7u64);
            let serialized = serde_json::to_string(&some).unwrap();
            assert_eq!(serialized, "7");
            let deserialized = serde_json::from_str::<MaybeNull<u64>>(&serialized).unwrap();
            assert_eq!(deserialized, some);
        }

        #[test]
        fn test_serde_u64_none() {
            let deserialized = serde_json::from_str::<MaybeNull<u64>>("null").unwrap();
            assert_eq!(deserialized, MaybeNull::from(0));
        }

        #[test]
        fn test_serde_u64_none_marker_error_message() {
            let err = serde_json::from_str::<MaybeNull<u64>>("0").unwrap_err();
            let message = err.to_string();
            assert!(message.contains("MaybeNull encoding"));
            assert!(message.contains("None marker"));
        }

        #[test]
        fn test_serde_u64_reject_invalid_input() {
            assert!(serde_json::from_str::<MaybeNull<u64>>("\"abc\"").is_err());
            assert!(serde_json::from_str::<MaybeNull<u64>>("{}").is_err());
        }
    }

    #[cfg(feature = "bytemuck")]
    mod bytemuck_tests {
        use super::*;

        #[test]
        fn test_maybe_null_u64() {
            let some = MaybeNull::from(42u64);
            assert_eq!(some.get(), Some(42));

            let none = MaybeNull::from(0u64);
            assert_eq!(none.get(), None);

            let bytes = 42u64.to_le_bytes();
            let value: &MaybeNull<u64> = bytemuck::from_bytes(&bytes);
            assert_eq!(*value, MaybeNull::from(42u64));

            let zero_bytes = 0u64.to_le_bytes();
            let value: &MaybeNull<u64> = bytemuck::from_bytes(&zero_bytes);
            assert_eq!(*value, MaybeNull::from(0u64));
            assert_eq!(value.get(), None);
        }

        #[test]
        fn test_maybe_null_from_bytes_errors() {
            assert!(bytemuck::try_from_bytes::<MaybeNull<u64>>(&[]).is_err());
            assert!(bytemuck::try_from_bytes::<MaybeNull<u64>>(&[0; 1]).is_err());
        }
    }
}
