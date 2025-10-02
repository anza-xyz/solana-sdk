//! wrappers for `bytemuck` functions

use {crate::error::SplPodError, bytemuck::Pod};

/// On-chain size of a `Pod` type
pub const fn pod_get_packed_len<T: Pod>() -> usize {
    std::mem::size_of::<T>()
}

/// Convert a `Pod` into a slice of bytes (zero copy)
pub fn pod_bytes_of<T: Pod>(t: &T) -> &[u8] {
    bytemuck::bytes_of(t)
}

/// Convert a slice of bytes into a `Pod` (zero copy)
pub fn pod_from_bytes<T: Pod>(bytes: &[u8]) -> Result<&T, SplPodError> {
    Ok(bytemuck::try_from_bytes(bytes)?)
}

/// Maybe convert a slice of bytes into a `Pod` (zero copy)
///
/// Returns `None` if the slice is empty, or else `Err` if input length is not
/// equal to `pod_get_packed_len::<T>()`.
/// This function exists primarily because `Option<T>` is not a `Pod`.
pub fn pod_maybe_from_bytes<T: Pod>(bytes: &[u8]) -> Result<Option<&T>, SplPodError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(bytemuck::try_from_bytes(bytes).map(Some)?)
    }
}

/// Convert a slice of bytes into a mutable `Pod` (zero copy)
pub fn pod_from_bytes_mut<T: Pod>(bytes: &mut [u8]) -> Result<&mut T, SplPodError> {
    Ok(bytemuck::try_from_bytes_mut(bytes)?)
}

/// Convert a slice of bytes into a `Pod` slice (zero copy)
pub fn pod_slice_from_bytes<T: Pod>(bytes: &[u8]) -> Result<&[T], SplPodError> {
    Ok(bytemuck::try_cast_slice(bytes)?)
}

/// Convert a slice of bytes into a mutable `Pod` slice (zero copy)
pub fn pod_slice_from_bytes_mut<T: Pod>(bytes: &mut [u8]) -> Result<&mut [T], SplPodError> {
    Ok(bytemuck::try_cast_slice_mut(bytes)?)
}

/// Convert a `Pod` slice into a single slice of bytes
pub fn pod_slice_to_bytes<T: Pod>(slice: &[T]) -> &[u8] {
    bytemuck::cast_slice(slice)
}
