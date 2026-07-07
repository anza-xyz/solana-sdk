//! Unaligned primitive wrapper types for zero-copy data structures.
//! These wrappers preserve a stable byte layout for primitive values without
//! introducing alignment requirements from the native integer types.

#[cfg(feature = "bytemuck")]
use bytemuck_derive::{Pod, Zeroable};
use core::cmp::PartialEq;
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};
#[cfg(feature = "borsh")]
use {
    alloc::string::ToString,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
};

/// The standard `bool` is not naturally zero-copy, define an unaligned replacement.
///
/// Any nonzero value is interpreted as `true`; only `0` is interpreted as `false`.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "bool", into = "bool"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct Bool(pub u8);
impl Bool {
    pub const fn from_bool(b: bool) -> Self {
        Self(if b { 1 } else { 0 })
    }
}

impl From<bool> for Bool {
    fn from(b: bool) -> Self {
        Self::from_bool(b)
    }
}

impl From<&bool> for Bool {
    fn from(b: &bool) -> Self {
        Self(if *b { 1 } else { 0 })
    }
}

impl From<&Bool> for bool {
    fn from(b: &Bool) -> Self {
        b.0 != 0
    }
}

impl From<Bool> for bool {
    fn from(b: Bool) -> Self {
        b.0 != 0
    }
}

/// Simple macro for implementing conversion functions between unaligned
/// integers and standard integers.
///
/// When using standard integer types in a struct, it might be required
/// to add padding to match their alignment requirements. Unaligned types
/// avoid this since their alignment requirement is `1`.
#[macro_export]
macro_rules! impl_int_conversion {
    ($P:ty, $I:ty) => {
        const _: () = assert!(core::mem::align_of::<$P>() == 1);
        const _: () = assert!(core::mem::size_of::<$P>() == core::mem::size_of::<$I>());

        impl $P {
            #[inline(always)]
            pub const fn from_primitive(n: $I) -> Self {
                Self(n.to_le_bytes())
            }

            #[inline(always)]
            pub fn checked_add(self, rhs: impl Into<$I>) -> Option<Self> {
                let s: $I = self.into();
                let other: $I = rhs.into();
                s.checked_add(other).map(Self::from)
            }

            #[inline(always)]
            pub fn checked_div(self, rhs: impl Into<$I>) -> Option<Self> {
                let s: $I = self.into();
                let other: $I = rhs.into();
                s.checked_div(other).map(Self::from)
            }

            #[inline(always)]
            pub fn checked_mul(self, rhs: impl Into<$I>) -> Option<Self> {
                let s: $I = self.into();
                let other: $I = rhs.into();
                s.checked_mul(other).map(Self::from)
            }

            #[inline(always)]
            pub fn checked_rem(self, rhs: impl Into<$I>) -> Option<Self> {
                let s: $I = self.into();
                let other: $I = rhs.into();
                s.checked_rem(other).map(Self::from)
            }

            #[inline(always)]
            pub fn checked_sub(self, rhs: impl Into<$I>) -> Option<Self> {
                let s: $I = self.into();
                let other: $I = rhs.into();
                s.checked_sub(other).map(Self::from)
            }

            #[inline(always)]
            pub fn saturating_add(self, rhs: impl Into<$I>) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                Self::from(s.saturating_add(other))
            }

            #[inline(always)]
            pub fn saturating_div(self, rhs: impl Into<$I>) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "saturating_div follows primitive integer behavior and panics on division by zero"
                )]
                Self::from(s.saturating_div(other))
            }

            #[inline(always)]
            pub fn saturating_mul(self, rhs: impl Into<$I>) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                Self::from(s.saturating_mul(other))
            }

            #[inline(always)]
            pub fn saturating_sub(self, rhs: impl Into<$I>) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                Self::from(s.saturating_sub(other))
            }
        }
        impl From<$I> for $P {
            fn from(n: $I) -> Self {
                Self::from_primitive(n)
            }
        }
        impl From<$P> for $I {
            fn from(unaligned: $P) -> Self {
                Self::from_le_bytes(unaligned.0)
            }
        }
        impl core::ops::Add<$I> for $P {
            type Output = Self;

            #[inline(always)]
            fn add(self, rhs: $I) -> Self {
                let s: $I = self.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "add follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s + rhs)
            }
        }
         impl core::ops::Add<$P> for $P {
            type Output = Self;

            #[inline(always)]
            fn add(self, rhs: $P) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "add follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s + other)
            }
        }
        impl core::ops::Div<$I> for $P {
            type Output = Self;

            #[inline(always)]
            fn div(self, rhs: $I) -> Self {
                let s: $I = self.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "div follows primitive integer behavior and panics on division by zero"
                )]
                Self::from(s / rhs)
            }
        }
        impl core::ops::Div<$P> for $P {
            type Output = Self;

            #[inline(always)]
            fn div(self, rhs: $P) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "div follows primitive integer behavior and panics on division by zero"
                )]
                Self::from(s / other)
            }
        }
        impl core::ops::Mul<$I> for $P {
            type Output = Self;

            #[inline(always)]
            fn mul(self, rhs: $I) -> Self {
                let s: $I = self.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "mul follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s * rhs)
            }
        }
        impl core::ops::Mul<$P> for $P {
            type Output = Self;

            #[inline(always)]
            fn mul(self, rhs: $P) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "mul follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s * other)
            }
        }
        impl core::ops::Rem<$I> for $P {
            type Output = Self;

            #[inline(always)]
            fn rem(self, rhs: $I) -> Self {
                let s: $I = self.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "rem follows primitive integer behavior and panics on division by zero"
                )]
                Self::from(s % rhs)
            }
        }
        impl core::ops::Rem<$P> for $P {
            type Output = Self;

            #[inline(always)]
            fn rem(self, rhs: $P) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "rem follows primitive integer behavior and panics on division by zero"
                )]
                Self::from(s % other)
            }
        }
        impl core::ops::Sub<$I> for $P {
            type Output = Self;

            #[inline(always)]
            fn sub(self, rhs: $I) -> Self {
                let s: $I = self.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "sub follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s - rhs)
            }
        }
        impl core::ops::Sub<$P> for $P {
            type Output = Self;

            #[inline(always)]
            fn sub(self, rhs: $P) -> Self {
                let s: $I = self.into();
                let other: $I = rhs.into();
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "sub follows primitive integer behavior and wraps on overflow"
                )]
                Self::from(s - other)
            }
        }
        impl core::ops::AddAssign<$I> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "add_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn add_assign(&mut self, rhs: $I) {
                *self = *self + rhs;
            }
        }
        impl core::ops::AddAssign<$P> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "add_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn add_assign(&mut self, rhs: $P) {
                *self = *self + rhs;
            }
        }
        impl core::ops::DivAssign<$I> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "div_assign follows primitive integer behavior and panics on division by zero"
            )]
            #[inline(always)]
            fn div_assign(&mut self, rhs: $I) {
                *self = *self / rhs;
            }
        }
        impl core::ops::DivAssign<$P> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "div_assign follows primitive integer behavior and panics on division by zero"
            )]
            #[inline(always)]
            fn div_assign(&mut self, rhs: $P) {
                *self = *self / rhs;
            }
        }
        impl core::ops::MulAssign<$I> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "mul_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn mul_assign(&mut self, rhs: $I) {
                *self = *self * rhs;
            }
        }
        impl core::ops::MulAssign<$P> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "mul_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn mul_assign(&mut self, rhs: $P) {
                *self = *self * rhs;
            }
        }
        impl core::ops::RemAssign<$I> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "rem_assign follows primitive integer behavior and panics on division by zero"
            )]
            #[inline(always)]
            fn rem_assign(&mut self, rhs: $I) {
                *self = *self % rhs;
            }
        }
        impl core::ops::RemAssign<$P> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "rem_assign follows primitive integer behavior and panics on division by zero"
            )]
            #[inline(always)]
            fn rem_assign(&mut self, rhs: $P) {
                *self = *self % rhs;
            }
        }
        impl core::ops::SubAssign<$I> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "sub_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn sub_assign(&mut self, rhs: $I) {
                *self = *self - rhs;
            }
        }
        impl core::ops::SubAssign<$P> for $P {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "sub_assign follows primitive integer behavior and wraps on overflow"
            )]
            #[inline(always)]
            fn sub_assign(&mut self, rhs: $P) {
                *self = *self - rhs;
            }
        }
        impl core::cmp::PartialOrd<$P> for $P {
            #[inline(always)]
            fn partial_cmp(&self, other: &$P) -> Option<core::cmp::Ordering> {
                let s: $I = (*self).into();
                let o: $I = (*other).into();
                s.partial_cmp(&o)
            }
        }
    };
}

/// Unaligned `u16` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u16", into = "u16"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct U16(pub [u8; 2]);
impl_int_conversion!(U16, u16);

/// Unaligned `i16` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "i16", into = "i16"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct I16(pub [u8; 2]);
impl_int_conversion!(I16, i16);

/// Unaligned `u32` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u32", into = "u32"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct U32(pub [u8; 4]);
impl_int_conversion!(U32, u32);

/// Unaligned `u64` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u64", into = "u64"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct U64(pub [u8; 8]);
impl_int_conversion!(U64, u64);

/// Unaligned `i64` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "i64", into = "i64"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct I64([u8; 8]);
impl_int_conversion!(I64, i64);

/// Unaligned `u128` type that can be embedded in bytemuck `Pod` types.
#[cfg(not(target_arch = "bpf"))]
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(
    feature = "borsh",
    derive(BorshDeserialize, BorshSerialize, BorshSchema)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u128", into = "u128"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct U128(pub [u8; 16]);
#[cfg(not(target_arch = "bpf"))]
impl_int_conversion!(U128, u128);

/// Implements the `TryFrom<usize>` and `From<T> for usize` conversions for an
/// unaligned integer type.
macro_rules! impl_usize_conversion {
    ($UnalignedType:ty, $PrimitiveType:ty) => {
        impl TryFrom<usize> for $UnalignedType {
            type Error = core::num::TryFromIntError;

            fn try_from(val: usize) -> Result<Self, Self::Error> {
                let primitive_val = <$PrimitiveType>::try_from(val)?;
                Ok(primitive_val.into())
            }
        }

        impl From<$UnalignedType> for usize {
            fn from(unaligned_val: $UnalignedType) -> Self {
                let primitive_val = <$PrimitiveType>::from(unaligned_val);
                Self::try_from(primitive_val)
                    .expect("value out of range for usize on this platform")
            }
        }
    };
}

impl_usize_conversion!(U16, u16);
impl_usize_conversion!(U32, u32);
impl_usize_conversion!(U64, u64);
#[cfg(not(target_arch = "bpf"))]
impl_usize_conversion!(U128, u128);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_bool() {
        assert!(bytemuck::try_from_bytes::<Bool>(&[]).is_err());
        assert!(bytemuck::try_from_bytes::<Bool>(&[0, 0]).is_err());

        for i in 0..=u8::MAX {
            assert_eq!(i != 0, bool::from(*bytemuck::from_bytes::<Bool>(&[i])));
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_bool_serde() {
        let unaligned_false: Bool = false.into();
        let unaligned_true: Bool = true.into();

        let serialized_false = serde_json::to_string(&unaligned_false).unwrap();
        let serialized_true = serde_json::to_string(&unaligned_true).unwrap();
        assert_eq!(&serialized_false, "false");
        assert_eq!(&serialized_true, "true");

        let deserialized_false = serde_json::from_str::<Bool>(&serialized_false).unwrap();
        let deserialized_true = serde_json::from_str::<Bool>(&serialized_true).unwrap();
        assert_eq!(unaligned_false, deserialized_false);
        assert_eq!(unaligned_true, deserialized_true);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_u16() {
        assert!(bytemuck::try_from_bytes::<U16>(&[]).is_err());
        assert_eq!(1u16, u16::from(*bytemuck::from_bytes::<U16>(&[1, 0])));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_u16_serde() {
        let unaligned_u16: U16 = u16::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u16).unwrap();
        assert_eq!(&serialized, "65535");

        let deserialized = serde_json::from_str::<U16>(&serialized).unwrap();
        assert_eq!(unaligned_u16, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_i16() {
        assert!(bytemuck::try_from_bytes::<I16>(&[]).is_err());
        assert_eq!(-1i16, i16::from(*bytemuck::from_bytes::<I16>(&[255, 255])));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_i16_serde() {
        let unaligned_i16: I16 = i16::MAX.into();
        let serialized = serde_json::to_string(&unaligned_i16).unwrap();
        assert_eq!(&serialized, "32767");

        let deserialized = serde_json::from_str::<I16>(&serialized).unwrap();
        assert_eq!(unaligned_i16, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_u64() {
        assert!(bytemuck::try_from_bytes::<U64>(&[]).is_err());
        assert_eq!(
            1u64,
            u64::from(*bytemuck::from_bytes::<U64>(&[1, 0, 0, 0, 0, 0, 0, 0]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_u64_serde() {
        let unaligned_u64: U64 = u64::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u64).unwrap();
        assert_eq!(&serialized, "18446744073709551615");

        let deserialized = serde_json::from_str::<U64>(&serialized).unwrap();
        assert_eq!(unaligned_u64, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_i64() {
        assert!(bytemuck::try_from_bytes::<I64>(&[]).is_err());
        assert_eq!(
            -1i64,
            i64::from(*bytemuck::from_bytes::<I64>(&[
                255, 255, 255, 255, 255, 255, 255, 255
            ]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_i64_serde() {
        let unaligned_i64: I64 = i64::MAX.into();

        let serialized = serde_json::to_string(&unaligned_i64).unwrap();
        assert_eq!(&serialized, "9223372036854775807");

        let deserialized = serde_json::from_str::<I64>(&serialized).unwrap();
        assert_eq!(unaligned_i64, deserialized);
    }

    #[cfg(not(target_arch = "bpf"))]
    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_u128() {
        assert!(bytemuck::try_from_bytes::<U128>(&[]).is_err());
        assert_eq!(
            1u128,
            u128::from(*bytemuck::from_bytes::<U128>(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]))
        );
    }

    #[cfg(not(target_arch = "bpf"))]
    #[cfg(feature = "serde")]
    #[test]
    fn test_u128_serde() {
        let unaligned_u128: U128 = u128::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u128).unwrap();
        assert_eq!(&serialized, "340282366920938463463374607431768211455");

        let deserialized = serde_json::from_str::<U128>(&serialized).unwrap();
        assert_eq!(unaligned_u128, deserialized);
    }

    macro_rules! test_usize_roundtrip {
        ($test_name:ident, $UnalignedType:ty, $max:expr) => {
            #[test]
            fn $test_name() {
                // zero
                let unaligned = <$UnalignedType>::try_from(0usize).unwrap();
                assert_eq!(usize::from(unaligned), 0);

                // mid-range
                let unaligned = <$UnalignedType>::try_from(42usize).unwrap();
                assert_eq!(usize::from(unaligned), 42);

                // max
                let max = $max as usize;
                let unaligned = <$UnalignedType>::try_from(max).unwrap();
                assert_eq!(usize::from(unaligned), max);
            }
        };
    }

    test_usize_roundtrip!(test_usize_roundtrip_u16, U16, u16::MAX);
    test_usize_roundtrip!(test_usize_roundtrip_u32, U32, u32::MAX);
    test_usize_roundtrip!(test_usize_roundtrip_u64, U64, u64::MAX);
    #[cfg(not(target_arch = "bpf"))]
    test_usize_roundtrip!(test_usize_roundtrip_u128, U128, u128::MAX);

    #[cfg(feature = "wincode")]
    mod wincode_tests {
        use {super::*, test_case::test_case};

        #[test_case(Bool::from_bool(true))]
        #[test_case(Bool::from_bool(false))]
        #[test_case(U16::from_primitive(u16::MAX))]
        #[test_case(I16::from_primitive(i16::MIN))]
        #[test_case(U32::from_primitive(u32::MAX))]
        #[test_case(U64::from_primitive(u64::MAX))]
        #[test_case(I64::from_primitive(i64::MIN))]
        #[cfg(not(target_arch = "bpf"))]
        #[test_case(U128::from_primitive(u128::MAX))]
        fn wincode_roundtrip<
            T: PartialEq
                + core::fmt::Debug
                + wincode::ZeroCopy
                + for<'de> wincode::SchemaRead<'de, wincode::config::DefaultConfig, Dst = T>
                + wincode::SchemaWrite<wincode::config::DefaultConfig, Src = T>,
        >(
            value: T,
        ) {
            let size = wincode::serialized_size(&value).unwrap() as usize;
            let mut bytes = [0u8; 32];
            assert!(size <= bytes.len());
            wincode::serialize_into(&mut bytes[..size], &value).unwrap();

            let deserialized: T = wincode::deserialize(&bytes[..size]).unwrap();
            assert_eq!(value, deserialized);

            let zero_copy_ref = <T as wincode::ZeroCopy>::from_bytes(&bytes[..size]).unwrap();
            assert_eq!(&value, zero_copy_ref);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ArithmeticMethod {
        CheckedAdd,
        CheckedDiv,
        CheckedMul,
        CheckedRem,
        CheckedSub,
        SaturatingAdd,
        SaturatingDiv,
        SaturatingMul,
        SaturatingSub,
        Add,
        Div,
        Mul,
        Rem,
        Sub,
        AddAssign,
        DivAssign,
        MulAssign,
        RemAssign,
        SubAssign,
        PartialOrd,
    }

    macro_rules! test_arithmetic_methods {
        ($test_name:ident, $UnalignedType:ty, $PrimitiveType:ty, $min:expr, $max:expr) => {
            #[test_case::test_case(ArithmeticMethod::CheckedAdd ; "checked_add")]
            #[test_case::test_case(ArithmeticMethod::CheckedDiv ; "checked_div")]
            #[test_case::test_case(ArithmeticMethod::CheckedMul ; "checked_mul")]
            #[test_case::test_case(ArithmeticMethod::CheckedRem ; "checked_rem")]
            #[test_case::test_case(ArithmeticMethod::CheckedSub ; "checked_sub")]
            #[test_case::test_case(ArithmeticMethod::SaturatingAdd ; "saturating_add")]
            #[test_case::test_case(ArithmeticMethod::SaturatingDiv ; "saturating_div")]
            #[test_case::test_case(ArithmeticMethod::SaturatingMul ; "saturating_mul")]
            #[test_case::test_case(ArithmeticMethod::SaturatingSub ; "saturating_sub")]
            #[test_case::test_case(ArithmeticMethod::Add ; "add")]
            #[test_case::test_case(ArithmeticMethod::Div ; "div")]
            #[test_case::test_case(ArithmeticMethod::Mul ; "mul")]
            #[test_case::test_case(ArithmeticMethod::Rem ; "rem")]
            #[test_case::test_case(ArithmeticMethod::Sub ; "sub")]
            #[test_case::test_case(ArithmeticMethod::AddAssign ; "add_assign")]
            #[test_case::test_case(ArithmeticMethod::DivAssign ; "div_assign")]
            #[test_case::test_case(ArithmeticMethod::MulAssign ; "mul_assign")]
            #[test_case::test_case(ArithmeticMethod::RemAssign ; "rem_assign")]
            #[test_case::test_case(ArithmeticMethod::SubAssign ; "sub_assign")]
            #[test_case::test_case(ArithmeticMethod::PartialOrd ; "partial_ord")]
            #[allow(clippy::arithmetic_side_effects)]
            fn $test_name(method: ArithmeticMethod) {
                let min = <$UnalignedType>::from_primitive($min);
                let max = <$UnalignedType>::from_primitive($max);
                let zero = 0 as $PrimitiveType;
                let one = 1 as $PrimitiveType;
                let two = 2 as $PrimitiveType;
                let twenty_one = 21 as $PrimitiveType;
                let forty = 40 as $PrimitiveType;
                let forty_one = 41 as $PrimitiveType;
                let forty_two = 42 as $PrimitiveType;
                let forty_three = 43 as $PrimitiveType;
                let forty_four = 44 as $PrimitiveType;
                let eighty_four = 84 as $PrimitiveType;

                match method {
                    ArithmeticMethod::CheckedAdd => {
                        assert_eq!(max.checked_add(one), None);
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty).checked_add(one),
                            Some(<$UnalignedType>::from_primitive(forty_one))
                        );
                    }
                    ArithmeticMethod::CheckedDiv => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(eighty_four).checked_div(two),
                            Some(<$UnalignedType>::from_primitive(forty_two))
                        );
                        assert_eq!(
                            <$UnalignedType>::from_primitive(eighty_four).checked_div(zero),
                            None
                        );
                    }
                    ArithmeticMethod::CheckedMul => {
                        assert_eq!(max.checked_mul(two), None);
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty_two).checked_mul(two),
                            Some(<$UnalignedType>::from_primitive(eighty_four))
                        );
                    }
                    ArithmeticMethod::CheckedRem => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty_four).checked_rem(forty_three),
                            Some(<$UnalignedType>::from_primitive(one))
                        );
                    }
                    ArithmeticMethod::CheckedSub => {
                        assert_eq!(min.checked_sub(one), None);
                        assert_eq!(
                            max.checked_sub(max),
                            Some(<$UnalignedType>::from_primitive(zero))
                        );
                    }
                    ArithmeticMethod::SaturatingAdd => {
                        assert_eq!(max.saturating_add(one), max);
                        assert_eq!(
                            <$UnalignedType>::from_primitive(zero).saturating_add(one),
                            <$UnalignedType>::from_primitive(one)
                        );
                    }
                    ArithmeticMethod::SaturatingDiv => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(eighty_four).saturating_div(two),
                            <$UnalignedType>::from_primitive(forty_two)
                        );
                    }
                    ArithmeticMethod::SaturatingMul => {
                        assert_eq!(max.saturating_mul(two), max);
                    }
                    ArithmeticMethod::SaturatingSub => {
                        assert_eq!(min.saturating_sub(one), min);
                    }
                    ArithmeticMethod::Add => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty) + two,
                            <$UnalignedType>::from_primitive(forty_two)
                        );
                    }
                    ArithmeticMethod::Div => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(eighty_four) / two,
                            <$UnalignedType>::from_primitive(forty_two)
                        );
                    }
                    ArithmeticMethod::Mul => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(twenty_one) * two,
                            <$UnalignedType>::from_primitive(forty_two)
                        );
                    }
                    ArithmeticMethod::Rem => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty_four) % forty_three,
                            <$UnalignedType>::from_primitive(one)
                        );
                    }
                    ArithmeticMethod::Sub => {
                        assert_eq!(
                            <$UnalignedType>::from_primitive(forty_four) - two,
                            <$UnalignedType>::from_primitive(forty_two)
                        );
                    }
                    ArithmeticMethod::AddAssign => {
                        let mut value = <$UnalignedType>::from_primitive(forty);
                        value += two;
                        assert_eq!(value, <$UnalignedType>::from_primitive(forty_two));
                    }
                    ArithmeticMethod::DivAssign => {
                        let mut value = <$UnalignedType>::from_primitive(eighty_four);
                        value /= two;
                        assert_eq!(value, <$UnalignedType>::from_primitive(forty_two));
                    }
                    ArithmeticMethod::MulAssign => {
                        let mut value = <$UnalignedType>::from_primitive(twenty_one);
                        value *= two;
                        assert_eq!(value, <$UnalignedType>::from_primitive(forty_two));
                    }
                    ArithmeticMethod::RemAssign => {
                        let mut value = <$UnalignedType>::from_primitive(forty_four);
                        value %= forty_three;
                        assert_eq!(value, <$UnalignedType>::from_primitive(one));
                    }
                    ArithmeticMethod::SubAssign => {
                        let mut value = <$UnalignedType>::from_primitive(forty_four);
                        value -= two;
                        assert_eq!(value, <$UnalignedType>::from_primitive(forty_two));
                    }
                    ArithmeticMethod::PartialOrd => {
                        assert!(
                            <$UnalignedType>::from_primitive(forty_one)
                                < <$UnalignedType>::from_primitive(forty_two)
                        );
                        assert!(max > min);
                    }
                }
            }
        };
    }

    test_arithmetic_methods!(test_arithmetic_methods_u16, U16, u16, u16::MIN, u16::MAX);
    test_arithmetic_methods!(test_arithmetic_methods_i16, I16, i16, i16::MIN, i16::MAX);
    test_arithmetic_methods!(test_arithmetic_methods_u32, U32, u32, u32::MIN, u32::MAX);
    test_arithmetic_methods!(test_arithmetic_methods_u64, U64, u64, u64::MIN, u64::MAX);
    test_arithmetic_methods!(test_arithmetic_methods_i64, I64, i64, i64::MIN, i64::MAX);
    #[cfg(not(target_arch = "bpf"))]
    test_arithmetic_methods!(
        test_arithmetic_methods_u128,
        U128,
        u128,
        u128::MIN,
        u128::MAX
    );
}
