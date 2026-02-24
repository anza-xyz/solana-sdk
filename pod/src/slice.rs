//! Special types for working with slices of `Pod`s

use {
    crate::{
        list::{ListView, ListViewMut, ListViewReadOnly},
        primitives::PodU32,
    },
    bytemuck::Pod,
    solana_program_error::ProgramError,
};

#[deprecated(
    since = "0.6.0",
    note = "This struct will be removed in the next major release (1.0.0). Please use `ListView` instead."
)]
/// Special type for using a slice of `Pod`s in a zero-copy way
#[allow(deprecated)]
pub struct PodSlice<'data, T: Pod> {
    inner: ListViewReadOnly<'data, T, PodU32>,
}

#[allow(deprecated)]
impl<'data, T: Pod> PodSlice<'data, T> {
    /// Unpack the buffer into a slice
    pub fn unpack<'a>(data: &'a [u8]) -> Result<Self, ProgramError>
    where
        'a: 'data,
    {
        let inner = ListView::<T, PodU32>::unpack(data)?;
        Ok(Self { inner })
    }

    /// Get the slice data
    pub fn data(&self) -> &[T] {
        let len = self.inner.len();
        &self.inner.data[..len]
    }

    /// Get the amount of bytes used by `num_items`
    pub fn size_of(num_items: usize) -> Result<usize, ProgramError> {
        ListView::<T, PodU32>::size_of(num_items)
    }
}

#[deprecated(
    since = "0.6.0",
    note = "This struct will be removed in the next major release (1.0.0). Please use `ListView` instead."
)]
/// Special type for using a slice of mutable `Pod`s in a zero-copy way.
/// Uses `ListView` under the hood.
pub struct PodSliceMut<'data, T: Pod> {
    inner: ListViewMut<'data, T, PodU32>,
}

#[allow(deprecated)]
impl<'data, T: Pod> PodSliceMut<'data, T> {
    /// Unpack the mutable buffer into a mutable slice
    pub fn unpack<'a>(data: &'a mut [u8]) -> Result<Self, ProgramError>
    where
        'a: 'data,
    {
        let inner = ListView::<T, PodU32>::unpack_mut(data)?;
        Ok(Self { inner })
    }

    /// Unpack the mutable buffer into a mutable slice, and initialize the
    /// slice to 0-length
    pub fn init<'a>(data: &'a mut [u8]) -> Result<Self, ProgramError>
    where
        'a: 'data,
    {
        let inner = ListView::<T, PodU32>::init(data)?;
        Ok(Self { inner })
    }

    /// Add another item to the slice
    pub fn push(&mut self, t: T) -> Result<(), ProgramError> {
        self.inner.push(t)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use {
        super::*,
        crate::{bytemuck::pod_slice_to_bytes, error::PodSliceError},
        bytemuck_derive::{Pod, Zeroable},
    };

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
    struct TestStruct {
        test_field: u8,
        test_pubkey: [u8; 32],
    }

    const LENGTH_SIZE: usize = core::mem::size_of::<PodU32>();

    #[test]
    fn test_pod_slice() {
        let test_field_bytes = [0];
        let test_pubkey_bytes = [1; 32];
        let len_bytes = [2, 0, 0, 0];

        // Slice will contain 2 `TestStruct`
        let mut data_bytes = [0; 66];
        data_bytes[0..1].copy_from_slice(&test_field_bytes);
        data_bytes[1..33].copy_from_slice(&test_pubkey_bytes);
        data_bytes[33..34].copy_from_slice(&test_field_bytes);
        data_bytes[34..66].copy_from_slice(&test_pubkey_bytes);

        let mut pod_slice_bytes = [0; 70];
        pod_slice_bytes[0..4].copy_from_slice(&len_bytes);
        pod_slice_bytes[4..70].copy_from_slice(&data_bytes);

        let pod_slice = PodSlice::<TestStruct>::unpack(&pod_slice_bytes).unwrap();
        let pod_slice_data = pod_slice.data();

        assert_eq!(pod_slice.inner.len(), 2);
        assert_eq!(pod_slice_to_bytes(pod_slice.data()), data_bytes);
        assert_eq!(pod_slice_data[0].test_field, test_field_bytes[0]);
        assert_eq!(pod_slice_data[0].test_pubkey, test_pubkey_bytes);
        assert_eq!(PodSlice::<TestStruct>::size_of(1).unwrap(), 37);
    }

    #[test]
    fn test_pod_slice_buffer_too_large() {
        // Length is 1. We pass one test struct with 6 trailing bytes to
        // trigger BufferTooLarge.
        let data_len = LENGTH_SIZE + core::mem::size_of::<TestStruct>() + 6;
        let mut pod_slice_bytes = vec![1; data_len];
        pod_slice_bytes[0..4].copy_from_slice(&[1, 0, 0, 0]);
        let err = PodSlice::<TestStruct>::unpack(&pod_slice_bytes)
            .err()
            .unwrap();
        assert!(matches!(err, ProgramError::InvalidArgument));
    }

    #[test]
    fn test_pod_slice_buffer_larger_than_length_value() {
        // If the buffer is longer than the u32 length value declares, it
        // should still unpack successfully, as long as the length of the rest
        // of the buffer can be divided by `size_of::<T>`.
        let length: u32 = 12;
        let length_le = length.to_le_bytes();

        // First set up the data to have room for extra items.
        let data_len = PodSlice::<TestStruct>::size_of(length as usize + 2).unwrap();
        let mut data = vec![0; data_len];

        // Now write the bogus length - which is smaller - into the first 4
        // bytes.
        data[..LENGTH_SIZE].copy_from_slice(&length_le);

        let pod_slice = PodSlice::<TestStruct>::unpack(&data).unwrap();
        let pod_slice_len = pod_slice.inner.len() as u32;
        let data = pod_slice.data();
        let data_vec = data.to_vec();

        assert_eq!(pod_slice_len, length);
        assert_eq!(data.len(), length as usize);
        assert_eq!(data_vec.len(), length as usize);
    }

    #[test]
    fn test_pod_slice_buffer_too_small() {
        // 1 `TestStruct` + length = 37 bytes
        // we pass 36 to trigger BufferTooSmall
        let pod_slice_bytes = [1; 36];
        let err = PodSlice::<TestStruct>::unpack(&pod_slice_bytes)
            .err()
            .unwrap();
        assert!(matches!(err, ProgramError::InvalidArgument));
    }

    #[test]
    fn test_pod_slice_buffer_shorter_than_length_value() {
        // If the buffer is shorter than the u32 length value declares, we
        // should get a BufferTooSmall error.
        let length: u32 = 12;
        let length_le = length.to_le_bytes();
        for num_items in 0..length {
            // First set up the data to have `num_elements` items.
            let data_len = PodSlice::<TestStruct>::size_of(num_items as usize).unwrap();
            let mut data = vec![0; data_len];

            // Now write the bogus length - which is larger - into the first 4
            // bytes.
            data[..LENGTH_SIZE].copy_from_slice(&length_le);

            // Expect an error on unpacking.
            let err = PodSlice::<TestStruct>::unpack(&data).err().unwrap();
            assert_eq!(
                err,
                PodSliceError::BufferTooSmall.into(),
                "Expected an `PodSliceError::BufferTooSmall` error"
            );
        }
    }

    #[test]
    fn test_pod_slice_mut() {
        // slice can fit 2 `TestStruct`
        let mut pod_slice_bytes = [0; 70];
        // set length to 1, so we have room to push 1 more item
        let len_bytes = [1, 0, 0, 0];
        pod_slice_bytes[0..4].copy_from_slice(&len_bytes);

        let mut pod_slice = PodSliceMut::<TestStruct>::unpack(&mut pod_slice_bytes).unwrap();

        assert_eq!(pod_slice.inner.len(), 1);
        pod_slice.push(TestStruct::default()).unwrap();
        assert_eq!(pod_slice.inner.len(), 2);

        let err = pod_slice
            .push(TestStruct::default())
            .expect_err("Expected an `PodSliceError::BufferTooSmall` error");
        assert_eq!(err, PodSliceError::BufferTooSmall.into());
    }
}
