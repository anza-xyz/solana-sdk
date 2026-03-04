//! Generic `Option` that can be used as a `Pod` for types that can have
//! a designated `None` value without adding a tag byte.
//!
//! For example, a 64-bit unsigned integer can designate `0` as a `None` value.
//! This would be equivalent to
//! [`Option<NonZeroU64>`](https://doc.rust-lang.org/std/num/type.NonZeroU64.html)
//! and provide the same memory layout optimization.

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

/// Trait for types that can be `None`.
///
/// This trait is used to indicate that a type can be `None` according to a
/// specific value.
pub trait Nullable: PartialEq + Sized {
    /// Value that represents `None` for the type.
    const NONE: Self;

    /// Indicates whether the value is `None` or not.
    fn is_none(&self) -> bool {
        self == &Self::NONE
    }

    /// Indicates whether the value is `Some`` value of type `T`` or not.
    fn is_some(&self) -> bool {
        !self.is_none()
    }
}

/// A "pod-enabled" type that can be used as an `Option<T>` without
/// requiring extra space to indicate if the value is `Some` or `None`.
///
/// This can be used when a specific value of `T` indicates that its
/// value is `None`.
#[repr(transparent)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PodOption<T: Nullable>(T);

impl<T: Nullable> Default for PodOption<T> {
    fn default() -> Self {
        Self(T::NONE)
    }
}

impl<T: Nullable> PodOption<T> {
    /// Returns the contained value as an `Option`.
    #[inline]
    pub fn get(self) -> Option<T> {
        if self.0.is_none() {
            None
        } else {
            Some(self.0)
        }
    }

    /// Returns the contained value as an `Option`.
    #[inline]
    pub fn as_ref(&self) -> Option<&T> {
        if self.0.is_none() {
            None
        } else {
            Some(&self.0)
        }
    }

    /// Returns the contained value as a mutable `Option`.
    #[inline]
    pub fn as_mut(&mut self) -> Option<&mut T> {
        if self.0.is_none() {
            None
        } else {
            Some(&mut self.0)
        }
    }

    /// Maps a `PodOption<T>` to an `Option<T>` by copying the contents of the option.
    #[inline]
    pub fn copied(&self) -> Option<T>
    where
        T: Copy,
    {
        self.as_ref().copied()
    }

    /// Maps a `PodOption<T>` to an `Option<T>` by cloning the contents of the option.
    #[inline]
    pub fn cloned(&self) -> Option<T>
    where
        T: Clone,
    {
        self.as_ref().cloned()
    }
}

impl<T: Nullable> From<T> for PodOption<T> {
    fn from(value: T) -> Self {
        PodOption(value)
    }
}

impl<T: Nullable> From<PodOption<T>> for Option<T> {
    fn from(value: PodOption<T>) -> Self {
        value.get()
    }
}

impl<T: Nullable> TryFrom<Option<T>> for PodOption<T> {
    type Error = PodOptionError;

    fn try_from(value: Option<T>) -> Result<Self, Self::Error> {
        match value {
            Some(value) if value.is_none() => Err(PodOptionError::NoneValueInSome),
            Some(value) => Ok(PodOption(value)),
            None => Ok(PodOption(T::NONE)),
        }
    }
}

/// Error type for invalid `PodOption` conversions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PodOptionError {
    /// Attempted to wrap a none-equivalent value in `Some`.
    NoneValueInSome,
}

impl core::fmt::Display for PodOptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoneValueInSome => {
                write!(f, "cannot wrap none-equivalent value in Some")
            }
        }
    }
}

/// ## Safety
///
/// `PodOption` is a transparent wrapper around a `Pod` type `T` with identical
/// data representation.
#[cfg(feature = "bytemuck")]
unsafe impl<T: Nullable + Pod> Pod for PodOption<T> {}

/// ## Safety
///
/// `PodOption` is a transparent wrapper around a `Pod` type `T` with identical
/// data representation.
#[cfg(feature = "bytemuck")]
unsafe impl<T: Nullable + Zeroable> Zeroable for PodOption<T> {}

#[cfg(feature = "serde")]
impl<T> Serialize for PodOption<T>
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
impl<'de, T> Deserialize<'de> for PodOption<T>
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
                "Invalid PodOption encoding: Some(value) cannot equal the none marker.",
            )),
            Some(value) => Ok(PodOption(value)),
            None => Ok(PodOption(T::NONE)),
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
        assert_eq!(PodOption::try_from(some).unwrap(), PodOption(42u64));

        let none: Option<u64> = None;
        assert_eq!(PodOption::try_from(none).unwrap(), PodOption::from(0u64));

        let invalid = Some(0u64);
        assert_eq!(
            PodOption::try_from(invalid).unwrap_err(),
            PodOptionError::NoneValueInSome,
        );
    }

    #[test]
    fn test_from_pod_option() {
        let some = PodOption::from(42u64);
        let none = PodOption::from(0u64);

        assert_eq!(Option::<u64>::from(some), Some(42));
        assert_eq!(Option::<u64>::from(none), None);
    }

    #[test]
    fn test_default() {
        let def = PodOption::<u64>::default();
        assert_eq!(def, PodOption(0u64));
        assert_eq!(def.get(), None);
    }

    #[test]
    fn test_copied() {
        let some = PodOption::from(42u64);
        assert_eq!(some.copied(), Some(42));

        let none = PodOption::from(0u64);
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
        let some = PodOption::from(8u64);
        assert_eq!(some.as_ref(), Some(&8u64));

        let none = PodOption::from(u64::NONE);
        assert_eq!(none.as_ref(), None);
    }

    #[test]
    fn test_as_mut() {
        let mut some = PodOption::from(3u64);
        assert!(some.as_mut().is_some());
        *some.as_mut().unwrap() = 4;
        assert_eq!(some.get(), Some(4));

        let mut none = PodOption::from(0u64);
        assert!(none.as_mut().is_none());
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestNonCopyNullable([u8; 4]);

    impl Nullable for TestNonCopyNullable {
        const NONE: Self = Self([0u8; 4]);
    }

    #[test]
    fn test_cloned_with_non_copy_nullable() {
        let some = PodOption::from(TestNonCopyNullable([1, 2, 3, 4]));
        assert_eq!(some.cloned(), Some(TestNonCopyNullable([1, 2, 3, 4])));

        let none = PodOption::from(TestNonCopyNullable::NONE);
        assert_eq!(none.cloned(), None);
    }

    #[cfg(feature = "borsh")]
    mod borsh_tests {
        use {super::*, alloc::vec};

        #[test]
        fn test_borsh_roundtrip_u64() {
            let some = PodOption::from(42u64);
            let none = PodOption::from(0u64);

            let some_bytes = borsh::to_vec(&some).unwrap();
            let none_bytes = borsh::to_vec(&none).unwrap();

            assert_eq!(some_bytes, 42u64.to_le_bytes().to_vec());
            assert_eq!(none_bytes, vec![0; 8]);
            assert_eq!(
                borsh::from_slice::<PodOption<u64>>(&some_bytes).unwrap(),
                some
            );
            assert_eq!(
                borsh::from_slice::<PodOption<u64>>(&none_bytes).unwrap(),
                none
            );
            assert!(borsh::from_slice::<PodOption<u64>>(&[]).is_err());
        }
    }

    #[cfg(feature = "wincode")]
    mod wincode_tests {
        use super::*;

        #[test]
        fn test_wincode_pod_option_roundtrip_and_size() {
            let some = PodOption::from(9u64);
            let none = PodOption::from(0u64);

            let some_bytes = wincode::serialize(&some).unwrap();
            let none_bytes = wincode::serialize(&none).unwrap();

            assert_eq!(some_bytes.len(), core::mem::size_of::<u64>());
            assert_eq!(none_bytes.len(), core::mem::size_of::<u64>());
            assert_eq!(some_bytes.as_slice(), &9u64.to_le_bytes());
            assert_eq!(none_bytes.as_slice(), &0u64.to_le_bytes());

            let some_roundtrip: PodOption<u64> = wincode::deserialize(&some_bytes).unwrap();
            let none_roundtrip: PodOption<u64> = wincode::deserialize(&none_bytes).unwrap();
            assert_eq!(some_roundtrip, some);
            assert_eq!(none_roundtrip, none);
        }

        #[test]
        fn test_wincode_pod_option_rejects_truncated_input() {
            assert!(wincode::deserialize::<PodOption<u64>>(&[]).is_err());
            assert!(wincode::deserialize::<PodOption<u64>>(&[0; 7]).is_err());
        }
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use {super::*, alloc::string::ToString};

        #[test]
        fn test_serde_u64_some() {
            let some = PodOption::from(7u64);
            let serialized = serde_json::to_string(&some).unwrap();
            assert_eq!(serialized, "7");
            let deserialized = serde_json::from_str::<PodOption<u64>>(&serialized).unwrap();
            assert_eq!(deserialized, some);
        }

        #[test]
        fn test_serde_u64_none() {
            let deserialized = serde_json::from_str::<PodOption<u64>>("null").unwrap();
            assert_eq!(deserialized, PodOption::from(0));
        }

        #[test]
        fn test_serde_u64_none_marker_error_message() {
            let err = serde_json::from_str::<PodOption<u64>>("0").unwrap_err();
            let message = err.to_string();
            assert!(message.contains("PodOption encoding"));
            assert!(message.contains("none marker"));
        }

        #[test]
        fn test_serde_u64_reject_invalid_input() {
            assert!(serde_json::from_str::<PodOption<u64>>("\"abc\"").is_err());
            assert!(serde_json::from_str::<PodOption<u64>>("{}").is_err());
        }
    }

    #[cfg(feature = "bytemuck")]
    mod bytemuck_tests {
        use super::*;

        #[test]
        fn test_pod_option_u64() {
            let some = PodOption::from(42u64);
            assert_eq!(some.get(), Some(42));

            let none = PodOption::from(0u64);
            assert_eq!(none.get(), None);

            let bytes = 42u64.to_le_bytes();
            let value: &PodOption<u64> = bytemuck::from_bytes(&bytes);
            assert_eq!(*value, PodOption::from(42u64));

            let zero_bytes = 0u64.to_le_bytes();
            let value: &PodOption<u64> = bytemuck::from_bytes(&zero_bytes);
            assert_eq!(*value, PodOption::from(0u64));
            assert_eq!(value.get(), None);
        }

        #[test]
        fn test_pod_from_bytes_errors() {
            assert!(bytemuck::try_from_bytes::<PodOption<u64>>(&[]).is_err());
            assert!(bytemuck::try_from_bytes::<PodOption<u64>>(&[0; 1]).is_err());
        }
    }
}
