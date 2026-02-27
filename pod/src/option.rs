//! Generic `Option` that can be used as a `Pod` for types that can have
//! a designated `None` value.
//!
//! For example, a 64-bit unsigned integer can designate `0` as a `None` value.
//! This would be equivalent to
//! [`Option<NonZeroU64>`](https://doc.rust-lang.org/std/num/type.NonZeroU64.html)
//! and provide the same memory layout optimization.

#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, Zeroable};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "borsh")]
use {
    alloc::format,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
};
use {
    solana_address::{Address, ADDRESS_BYTES},
    solana_program_error::ProgramError,
    solana_program_option::COption,
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

impl<T: Nullable> From<PodOption<T>> for COption<T> {
    fn from(value: PodOption<T>) -> Self {
        if value.0.is_none() {
            COption::None
        } else {
            COption::Some(value.0)
        }
    }
}

impl<T: Nullable> TryFrom<Option<T>> for PodOption<T> {
    type Error = ProgramError;

    fn try_from(value: Option<T>) -> Result<Self, Self::Error> {
        match value {
            Some(value) if value.is_none() => Err(ProgramError::InvalidArgument),
            Some(value) => Ok(PodOption(value)),
            None => Ok(PodOption(T::NONE)),
        }
    }
}

impl<T: Nullable> TryFrom<COption<T>> for PodOption<T> {
    type Error = ProgramError;

    fn try_from(value: COption<T>) -> Result<Self, Self::Error> {
        match value {
            COption::Some(value) if value.is_none() => Err(ProgramError::InvalidArgument),
            COption::Some(value) => Ok(PodOption(value)),
            COption::None => Ok(PodOption(T::NONE)),
        }
    }
}

/// Implementation of `Nullable` for `Address`.
impl Nullable for Address {
    const NONE: Self = Address::new_from_array([0u8; ADDRESS_BYTES]);
}

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

    const ID: Address = Address::new_from_array([8; ADDRESS_BYTES]);

    #[test]
    fn test_try_from_option() {
        let some_address = Some(ID);
        assert_eq!(PodOption::try_from(some_address).unwrap(), PodOption(ID));

        let none_address = None;
        assert_eq!(
            PodOption::try_from(none_address).unwrap(),
            PodOption::from(Address::NONE)
        );

        let invalid_option = Some(Address::NONE);
        let err = PodOption::try_from(invalid_option).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
    }

    #[test]
    fn test_try_from_coption_reject_some_zero_address() {
        let invalid_option = COption::Some(Address::NONE);
        let err = PodOption::try_from(invalid_option).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
    }

    #[test]
    fn test_from_pod_option() {
        let some = PodOption::from(ID);
        let none = PodOption::from(Address::NONE);

        assert_eq!(Option::<Address>::from(some), Some(ID));
        assert_eq!(Option::<Address>::from(none), None);
        assert_eq!(COption::<Address>::from(some), COption::Some(ID));
        assert_eq!(COption::<Address>::from(none), COption::None);
    }

    #[test]
    fn test_default() {
        let def = PodOption::<Address>::default();
        assert_eq!(def, None.try_into().unwrap());
    }

    #[test]
    fn test_copied() {
        let some_address = PodOption::from(ID);
        assert_eq!(some_address.copied(), Some(ID));

        let none_address = PodOption::from(Address::NONE);
        assert_eq!(none_address.copied(), None);
    }

    #[test]
    fn test_as_mut() {
        let mut some = PodOption::from(Address::new_from_array([3; ADDRESS_BYTES]));
        assert!(some.as_mut().is_some());
        *some.as_mut().unwrap() = Address::new_from_array([4; ADDRESS_BYTES]);
        assert_eq!(
            some.get(),
            Some(Address::new_from_array([4; ADDRESS_BYTES]))
        );

        let mut none = PodOption::from(Address::NONE);
        assert!(none.as_mut().is_none());
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestNonCopyNullable([u8; 4]);

    impl Nullable for TestNonCopyNullable {
        const NONE: Self = Self([0u8; 4]);
    }

    impl Nullable for u64 {
        const NONE: Self = 0;
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
        fn test_borsh_roundtrip_and_encoding() {
            let some = PodOption::from(Address::new_from_array([1; ADDRESS_BYTES]));
            let none = PodOption::from(Address::NONE);

            let some_bytes = borsh::to_vec(&some).unwrap();
            let none_bytes = borsh::to_vec(&none).unwrap();

            assert_eq!(some_bytes, vec![1; ADDRESS_BYTES]);
            assert_eq!(none_bytes, vec![0; ADDRESS_BYTES]);
            assert_eq!(
                borsh::from_slice::<PodOption<Address>>(&some_bytes).unwrap(),
                some
            );
            assert_eq!(
                borsh::from_slice::<PodOption<Address>>(&none_bytes).unwrap(),
                none
            );
            assert!(borsh::from_slice::<PodOption<Address>>(&[]).is_err());
        }
    }

    #[cfg(feature = "serde")]
    mod serde_tests {
        use {super::*, alloc::string::ToString};

        #[test]
        fn test_serde_some() {
            let some = PodOption::from(Address::new_from_array([1; ADDRESS_BYTES]));
            let serialized = serde_json::to_string(&some).unwrap();
            assert_eq!(
                &serialized,
                "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]"
            );
            let deserialized = serde_json::from_str::<PodOption<Address>>(&serialized).unwrap();
            assert_eq!(some, deserialized);
        }

        #[test]
        fn test_serde_none() {
            let none = PodOption::from(Address::new_from_array([0; ADDRESS_BYTES]));
            let serialized = serde_json::to_string(&none).unwrap();
            assert_eq!(&serialized, "null");
            let deserialized = serde_json::from_str::<PodOption<Address>>(&serialized).unwrap();
            assert_eq!(none, deserialized);
        }

        #[test]
        fn test_serde_reject_zero_address_bytes() {
            let zero_bytes = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
            assert!(serde_json::from_str::<PodOption<Address>>(zero_bytes).is_err());
        }

        #[test]
        fn test_serde_reject_invalid_address_string() {
            assert!(serde_json::from_str::<PodOption<Address>>("\"not_an_address\"").is_err());
        }

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
        use {
            super::*,
            crate::bytemuck::{pod_from_bytes, pod_slice_from_bytes},
            alloc::vec::Vec,
        };

        #[test]
        fn test_pod_option_address() {
            let some_address = PodOption::from(ID);
            assert_eq!(some_address.get(), Some(ID));

            let none_address = PodOption::from(Address::default());
            assert_eq!(none_address.get(), None);

            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(ID.as_ref());
            data.extend_from_slice(&[0u8; 32]);

            let values = pod_slice_from_bytes::<PodOption<Address>>(&data).unwrap();
            assert_eq!(values[0], PodOption::from(ID));
            assert_eq!(values[1], PodOption::from(Address::default()));
        }

        #[test]
        fn test_pod_from_bytes() {
            assert_eq!(
                Option::<Address>::from(
                    *pod_from_bytes::<PodOption<Address>>(&[1; ADDRESS_BYTES]).unwrap()
                ),
                Some(Address::new_from_array([1; ADDRESS_BYTES])),
            );
            assert_eq!(
                Option::<Address>::from(
                    *pod_from_bytes::<PodOption<Address>>(&[0; ADDRESS_BYTES]).unwrap()
                ),
                None,
            );
            assert_eq!(
                pod_from_bytes::<PodOption<Address>>(&[]).unwrap_err(),
                ProgramError::InvalidArgument
            );
            assert_eq!(
                pod_from_bytes::<PodOption<Address>>(&[0; 1]).unwrap_err(),
                ProgramError::InvalidArgument
            );
            assert_eq!(
                pod_from_bytes::<PodOption<Address>>(&[1; 1]).unwrap_err(),
                ProgramError::InvalidArgument
            );
        }
    }
}
