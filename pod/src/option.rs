//! Generic `Option` that can be used as a `Pod` for types that can have
//! a designated `None` value.
//!
//! For example, a 64-bit unsigned integer can designate `0` as a `None` value.
//! This would be equivalent to
//! [`Option<NonZeroU64>`](https://doc.rust-lang.org/std/num/type.NonZeroU64.html)
//! and provide the same memory layout optimization.

#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, Zeroable};
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "bytemuck")]
    use crate::bytemuck::pod_slice_from_bytes;
    const ID: Address = Address::from_str_const("TestSysvar111111111111111111111111111111111");

    #[cfg(feature = "bytemuck")]
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

        let option_pubkey = Some(ID);
        let pod_option_pubkey: PodOption<Address> = option_pubkey.try_into().unwrap();
        assert_eq!(pod_option_pubkey, PodOption::from(ID));
        assert_eq!(
            pod_option_pubkey,
            PodOption::try_from(option_pubkey).unwrap()
        );

        let coption_pubkey = COption::Some(ID);
        let pod_option_pubkey: PodOption<Address> = coption_pubkey.try_into().unwrap();
        assert_eq!(pod_option_pubkey, PodOption::from(ID));
        assert_eq!(
            pod_option_pubkey,
            PodOption::try_from(coption_pubkey).unwrap()
        );
    }

    #[test]
    fn test_try_from_option() {
        let some_pubkey = Some(ID);
        assert_eq!(PodOption::try_from(some_pubkey).unwrap(), PodOption(ID));

        let none_pubkey = None;
        assert_eq!(
            PodOption::try_from(none_pubkey).unwrap(),
            PodOption::from(Address::NONE)
        );

        let invalid_option = Some(Address::NONE);
        let err = PodOption::try_from(invalid_option).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
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
}
