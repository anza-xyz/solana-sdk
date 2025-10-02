use {
    crate::{
        error::PodSliceError,
        primitives::{PodU128, PodU16, PodU32, PodU64},
    },
    bytemuck::Pod,
};

/// Marker trait for converting to/from Pod `uint`'s and `usize`
pub trait PodLength: Pod + Into<usize> + TryFrom<usize, Error = PodSliceError> {}

/// Blanket implementation to automatically implement `PodLength` for any type
/// that satisfies the required bounds.
impl<T> PodLength for T where T: Pod + Into<usize> + TryFrom<usize, Error = PodSliceError> {}

/// Implements the `TryFrom<usize>` and `From<T> for usize` conversions for a Pod integer type
macro_rules! impl_pod_length_for {
    ($PodType:ty, $PrimitiveType:ty) => {
        impl TryFrom<usize> for $PodType {
            type Error = PodSliceError;

            fn try_from(val: usize) -> Result<Self, Self::Error> {
                let primitive_val = <$PrimitiveType>::try_from(val)?;
                Ok(primitive_val.into())
            }
        }

        impl From<$PodType> for usize {
            fn from(pod_val: $PodType) -> Self {
                let primitive_val = <$PrimitiveType>::from(pod_val);
                Self::try_from(primitive_val)
                    .expect("value out of range for usize on this platform")
            }
        }
    };
}

impl_pod_length_for!(PodU16, u16);
impl_pod_length_for!(PodU32, u32);
impl_pod_length_for!(PodU64, u64);
impl_pod_length_for!(PodU128, u128);
