//! Unaligned primitive wrapper types for zero-copy data structures.
//! These wrappers preserve a stable byte layout for primitive values without
//! introducing alignment requirements from the native integer types.

#[cfg(feature = "bytemuck")]
use bytemuck_derive::{Pod, Zeroable};
#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(feature = "wincode")]
use wincode::{SchemaRead, SchemaWrite};
#[cfg(feature = "borsh")]
use {
    alloc::string::ToString,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
};

/// The standard `bool` is not a `bytemuck::Pod`, define an unaligned replacement.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "bool", into = "bool"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct UnalignedBool(pub u8);
impl UnalignedBool {
    pub const fn from_bool(b: bool) -> Self {
        Self(if b { 1 } else { 0 })
    }
}

impl From<bool> for UnalignedBool {
    fn from(b: bool) -> Self {
        Self::from_bool(b)
    }
}

impl From<&bool> for UnalignedBool {
    fn from(b: &bool) -> Self {
        Self(if *b { 1 } else { 0 })
    }
}

impl From<&UnalignedBool> for bool {
    fn from(b: &UnalignedBool) -> Self {
        b.0 != 0
    }
}

impl From<UnalignedBool> for bool {
    fn from(b: UnalignedBool) -> Self {
        b.0 != 0
    }
}

/// Simple macro for implementing conversion functions between unaligned
/// integers and standard integers.
///
/// The standard integer types can cause alignment issues when placed in a
/// `bytemuck::Pod`, so these replacements are usable in all bytemuck `Pod`
/// types.
#[macro_export]
macro_rules! impl_int_conversion {
    ($P:ty, $I:ty) => {
        impl $P {
            pub const fn from_primitive(n: $I) -> Self {
                Self(n.to_le_bytes())
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
pub struct UnalignedU16(pub [u8; 2]);
impl_int_conversion!(UnalignedU16, u16);

/// Unaligned `i16` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "i16", into = "i16"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct UnalignedI16(pub [u8; 2]);
impl_int_conversion!(UnalignedI16, i16);

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
pub struct UnalignedU32(pub [u8; 4]);
impl_int_conversion!(UnalignedU32, u32);

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
pub struct UnalignedU64(pub [u8; 8]);
impl_int_conversion!(UnalignedU64, u64);

/// Unaligned `i64` type that can be embedded in bytemuck `Pod` types.
#[cfg_attr(feature = "wincode", derive(SchemaRead, SchemaWrite))]
#[cfg_attr(feature = "wincode", wincode(assert_zero_copy))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "i64", into = "i64"))]
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(transparent)]
pub struct UnalignedI64([u8; 8]);
impl_int_conversion!(UnalignedI64, i64);

/// Unaligned `u128` type that can be embedded in bytemuck `Pod` types.
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
pub struct UnalignedU128(pub [u8; 16]);
impl_int_conversion!(UnalignedU128, u128);

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

impl_usize_conversion!(UnalignedU16, u16);
impl_usize_conversion!(UnalignedU32, u32);
impl_usize_conversion!(UnalignedU64, u64);
impl_usize_conversion!(UnalignedU128, u128);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_bool() {
        assert!(bytemuck::try_from_bytes::<UnalignedBool>(&[]).is_err());
        assert!(bytemuck::try_from_bytes::<UnalignedBool>(&[0, 0]).is_err());

        for i in 0..=u8::MAX {
            assert_eq!(
                i != 0,
                bool::from(*bytemuck::from_bytes::<UnalignedBool>(&[i]))
            );
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_bool_serde() {
        let unaligned_false: UnalignedBool = false.into();
        let unaligned_true: UnalignedBool = true.into();

        let serialized_false = serde_json::to_string(&unaligned_false).unwrap();
        let serialized_true = serde_json::to_string(&unaligned_true).unwrap();
        assert_eq!(&serialized_false, "false");
        assert_eq!(&serialized_true, "true");

        let deserialized_false = serde_json::from_str::<UnalignedBool>(&serialized_false).unwrap();
        let deserialized_true = serde_json::from_str::<UnalignedBool>(&serialized_true).unwrap();
        assert_eq!(unaligned_false, deserialized_false);
        assert_eq!(unaligned_true, deserialized_true);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_u16() {
        assert!(bytemuck::try_from_bytes::<UnalignedU16>(&[]).is_err());
        assert_eq!(
            1u16,
            u16::from(*bytemuck::from_bytes::<UnalignedU16>(&[1, 0]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_u16_serde() {
        let unaligned_u16: UnalignedU16 = u16::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u16).unwrap();
        assert_eq!(&serialized, "65535");

        let deserialized = serde_json::from_str::<UnalignedU16>(&serialized).unwrap();
        assert_eq!(unaligned_u16, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_i16() {
        assert!(bytemuck::try_from_bytes::<UnalignedI16>(&[]).is_err());
        assert_eq!(
            -1i16,
            i16::from(*bytemuck::from_bytes::<UnalignedI16>(&[255, 255]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_i16_serde() {
        let unaligned_i16: UnalignedI16 = i16::MAX.into();
        let serialized = serde_json::to_string(&unaligned_i16).unwrap();
        assert_eq!(&serialized, "32767");

        let deserialized = serde_json::from_str::<UnalignedI16>(&serialized).unwrap();
        assert_eq!(unaligned_i16, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_u64() {
        assert!(bytemuck::try_from_bytes::<UnalignedU64>(&[]).is_err());
        assert_eq!(
            1u64,
            u64::from(*bytemuck::from_bytes::<UnalignedU64>(&[
                1, 0, 0, 0, 0, 0, 0, 0
            ]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_u64_serde() {
        let unaligned_u64: UnalignedU64 = u64::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u64).unwrap();
        assert_eq!(&serialized, "18446744073709551615");

        let deserialized = serde_json::from_str::<UnalignedU64>(&serialized).unwrap();
        assert_eq!(unaligned_u64, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_i64() {
        assert!(bytemuck::try_from_bytes::<UnalignedI64>(&[]).is_err());
        assert_eq!(
            -1i64,
            i64::from(*bytemuck::from_bytes::<UnalignedI64>(&[
                255, 255, 255, 255, 255, 255, 255, 255
            ]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_i64_serde() {
        let unaligned_i64: UnalignedI64 = i64::MAX.into();

        let serialized = serde_json::to_string(&unaligned_i64).unwrap();
        assert_eq!(&serialized, "9223372036854775807");

        let deserialized = serde_json::from_str::<UnalignedI64>(&serialized).unwrap();
        assert_eq!(unaligned_i64, deserialized);
    }

    #[cfg(feature = "bytemuck")]
    #[test]
    fn test_unaligned_u128() {
        assert!(bytemuck::try_from_bytes::<UnalignedU128>(&[]).is_err());
        assert_eq!(
            1u128,
            u128::from(*bytemuck::from_bytes::<UnalignedU128>(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_unaligned_u128_serde() {
        let unaligned_u128: UnalignedU128 = u128::MAX.into();

        let serialized = serde_json::to_string(&unaligned_u128).unwrap();
        assert_eq!(&serialized, "340282366920938463463374607431768211455");

        let deserialized = serde_json::from_str::<UnalignedU128>(&serialized).unwrap();
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

    test_usize_roundtrip!(test_usize_roundtrip_u16, UnalignedU16, u16::MAX);
    test_usize_roundtrip!(test_usize_roundtrip_u32, UnalignedU32, u32::MAX);
    test_usize_roundtrip!(test_usize_roundtrip_u64, UnalignedU64, u64::MAX);
    test_usize_roundtrip!(test_usize_roundtrip_u128, UnalignedU128, u128::MAX);

    #[cfg(feature = "wincode")]
    mod wincode_tests {
        use {super::*, test_case::test_case};

        #[test_case(UnalignedBool::from_bool(true))]
        #[test_case(UnalignedBool::from_bool(false))]
        #[test_case(UnalignedU16::from_primitive(u16::MAX))]
        #[test_case(UnalignedI16::from_primitive(i16::MIN))]
        #[test_case(UnalignedU32::from_primitive(u32::MAX))]
        #[test_case(UnalignedU64::from_primitive(u64::MAX))]
        #[test_case(UnalignedI64::from_primitive(i64::MIN))]
        #[test_case(UnalignedU128::from_primitive(u128::MAX))]
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
}
