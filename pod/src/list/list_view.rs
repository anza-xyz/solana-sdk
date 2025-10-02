//! `ListView`, a compact, zero-copy array wrapper.

use {
    crate::{
        bytemuck::{
            pod_from_bytes, pod_from_bytes_mut, pod_slice_from_bytes, pod_slice_from_bytes_mut,
        },
        error::SplPodError,
        list::{list_view_mut::ListViewMut, list_view_read_only::ListViewReadOnly},
        pod_length::PodLength,
        primitives::PodU32,
    },
    bytemuck::Pod,
    std::{
        marker::PhantomData,
        mem::{align_of, size_of},
        ops::Range,
    },
};

/// An API for interpreting a raw buffer (`&[u8]`) as a variable-length collection of Pod elements.
///
/// `ListView` provides a safe, zero-copy, `Vec`-like interface for a slice of
/// `Pod` data that resides in an external, pre-allocated `&[u8]` buffer.
/// It does not own the buffer itself, but acts as a view over it, which can be
/// read-only (`ListViewReadOnly`) or mutable (`ListViewMut`).
///
/// This is useful in environments where allocations are restricted or expensive,
/// such as Solana programs, allowing for efficient reads and manipulation of
/// dynamic-length data structures.
///
/// ## Memory Layout
///
/// The structure assumes the underlying byte buffer is formatted as follows:
/// 1.  **Length**: A length field of type `L` at the beginning of the buffer,
///     indicating the number of currently active elements in the collection.
///     Defaults to `PodU32`. The implementation uses padding to ensure that the
///     data is correctly aligned for any `Pod` type.
/// 2.  **Padding**: Optional padding bytes to ensure proper alignment of the data.
/// 3.  **Data**: The remaining part of the buffer, which is treated as a slice
///     of `T` elements. The capacity of the collection is the number of `T`
///     elements that can fit into this data portion.
pub struct ListView<T: Pod, L: PodLength = PodU32>(PhantomData<(T, L)>);

struct Layout {
    length_range: Range<usize>,
    data_range: Range<usize>,
}

impl<T: Pod, L: PodLength> ListView<T, L> {
    /// Calculate the total byte size for a `ListView` holding `num_items`.
    /// This includes the length prefix, padding, and data.
    pub fn size_of(num_items: usize) -> Result<usize, SplPodError> {
        let header_padding = Self::header_padding()?;
        size_of::<T>()
            .checked_mul(num_items)
            .and_then(|curr| curr.checked_add(size_of::<L>()))
            .and_then(|curr| curr.checked_add(header_padding))
            .ok_or(SplPodError::CalculationFailure)
    }

    /// Unpack a read-only buffer into a `ListViewReadOnly`
    pub fn unpack(buf: &[u8]) -> Result<ListViewReadOnly<T, L>, SplPodError> {
        let layout = Self::calculate_layout(buf.len())?;

        // Slice the buffer to get the length prefix and the data.
        // The layout calculation provides the correct ranges, accounting for any
        // padding between the length and the data.
        //
        // buf: [ L L L L | P P | D D D D D D D D ...]
        //       <----->         <------------------>
        //      len_bytes            data_bytes
        let len_bytes = &buf[layout.length_range];
        let data_bytes = &buf[layout.data_range];

        let length = pod_from_bytes::<L>(len_bytes)?;
        let data = pod_slice_from_bytes::<T>(data_bytes)?;
        let capacity = data.len();

        if (*length).into() > capacity {
            return Err(SplPodError::BufferTooSmall);
        }

        Ok(ListViewReadOnly {
            length,
            data,
            capacity,
        })
    }

    /// Unpack the mutable buffer into a mutable `ListViewMut`
    pub fn unpack_mut(buf: &mut [u8]) -> Result<ListViewMut<T, L>, SplPodError> {
        let view = Self::build_mut_view(buf)?;
        if (*view.length).into() > view.capacity {
            return Err(SplPodError::BufferTooSmall);
        }
        Ok(view)
    }

    /// Initialize a buffer: sets `length = 0` and returns a mutable `ListViewMut`.
    pub fn init(buf: &mut [u8]) -> Result<ListViewMut<T, L>, SplPodError> {
        let view = Self::build_mut_view(buf)?;
        *view.length = L::try_from(0)?;
        Ok(view)
    }

    /// Internal helper to build a mutable view without validation or initialization.
    #[inline]
    fn build_mut_view(buf: &mut [u8]) -> Result<ListViewMut<T, L>, SplPodError> {
        let layout = Self::calculate_layout(buf.len())?;

        // Split the buffer to get the length prefix and the data.
        // buf: [ L L L L | P P | D D D D D D D D ...]
        //       <---- head ---> <--- tail --------->
        let (header_bytes, data_bytes) = buf.split_at_mut(layout.data_range.start);
        // header: [ L L L L | P P ]
        //           <----->
        //          len_bytes
        let len_bytes = &mut header_bytes[layout.length_range];

        // Cast the bytes to typed data
        let length = pod_from_bytes_mut::<L>(len_bytes)?;
        let data = pod_slice_from_bytes_mut::<T>(data_bytes)?;
        let capacity = data.len();

        Ok(ListViewMut {
            length,
            data,
            capacity,
        })
    }

    /// Calculate the byte ranges for the length and data sections of the buffer
    #[inline]
    fn calculate_layout(buf_len: usize) -> Result<Layout, SplPodError> {
        let len_field_end = size_of::<L>();
        let header_padding = Self::header_padding()?;
        let data_start = len_field_end.saturating_add(header_padding);

        if buf_len < data_start {
            return Err(SplPodError::BufferTooSmall);
        }

        Ok(Layout {
            length_range: 0..len_field_end,
            data_range: data_start..buf_len,
        })
    }

    /// Calculate the padding required to align the data part of the buffer.
    ///
    /// The goal is to ensure that the data field `T` starts at a memory offset
    /// that is a multiple of its alignment requirement.
    #[inline]
    fn header_padding() -> Result<usize, SplPodError> {
        // Enforce that the length prefix type `L` itself does not have alignment requirements
        if align_of::<L>() != 1 {
            return Err(SplPodError::InvalidLengthTypeAlignment);
        }

        let length_size = size_of::<L>();
        let data_align = align_of::<T>();

        // No padding is needed for alignments of 0 or 1
        if data_align == 0 || data_align == 1 {
            return Ok(0);
        }

        // Find how many bytes `length_size` extends past an alignment boundary
        #[allow(clippy::arithmetic_side_effects)]
        let remainder = length_size.wrapping_rem(data_align);

        // If already aligned (remainder is 0), no padding is needed.
        // Otherwise, calculate the distance to the next alignment boundary.
        if remainder == 0 {
            Ok(0)
        } else {
            Ok(data_align.wrapping_sub(remainder))
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            list::List,
            primitives::{PodU128, PodU16, PodU32, PodU64},
        },
        bytemuck_derive::{Pod as DerivePod, Zeroable},
    };

    #[test]
    fn test_size_of_no_padding() {
        // Case 1: T has align 1, so no padding is ever needed.
        // 10 items * 1 byte/item + 4 bytes for length = 14
        assert_eq!(ListView::<u8, PodU32>::size_of(10).unwrap(), 14);

        // Case 2: size_of<L> is a multiple of align_of<T>, so no padding needed.
        // T = u32 (size 4, align 4), L = PodU32 (size 4). 4 % 4 == 0.
        // 10 items * 4 bytes/item + 4 bytes for length = 44
        assert_eq!(ListView::<u32>::size_of(10).unwrap(), 44);

        // Case 3: 0 items. Size should just be size_of<L> + padding.
        // Padding is 0 here.
        // 0 items * 4 bytes/item + 4 bytes for length = 4
        assert_eq!(ListView::<u32>::size_of(0).unwrap(), 4);
    }

    #[test]
    fn test_size_of_with_padding() {
        // Case 1: Padding is required.
        // T = u64 (size 8, align 8), L = PodU32 (size 4).
        // Padding required to align data to 8 bytes is 4. (4 + 4 = 8)
        // (10 items * 8 bytes/item) + 4 bytes for length + 4 bytes for padding = 88
        assert_eq!(ListView::<u64, PodU32>::size_of(10).unwrap(), 88);

        #[repr(C, align(16))]
        #[derive(DerivePod, Zeroable, Copy, Clone)]
        struct Align16(u128);

        // Case 2: Custom struct with high alignment.
        // size 16, align 16
        // L = PodU64 (size 8).
        // Padding required to align data to 16 bytes is 8. (8 + 8 = 16)
        // (10 items * 16 bytes/item) + 8 bytes for length + 8 bytes for padding = 176
        assert_eq!(ListView::<Align16>::size_of(10).unwrap(), 176);

        // Case 3: 0 items with padding.
        // Size should be size_of<L> + padding.
        // L = PodU32 (size 4), T = u64 (align 8). Padding is 4.
        // Total size = 4 + 4 = 8
        assert_eq!(ListView::<u64, PodU32>::size_of(0).unwrap(), 8);
    }

    #[test]
    fn test_size_of_overflow() {
        // Case 1: Multiplication overflows.
        // `size_of::<u16>() * usize::MAX` will overflow.
        let err = ListView::<u16, PodU32>::size_of(usize::MAX).unwrap_err();
        assert_eq!(err, SplPodError::CalculationFailure);

        // Case 2: Multiplication does not overflow, but subsequent addition does.
        // `size_of::<u8>() * usize::MAX` does not overflow, but adding `size_of<L>` will.
        let err = ListView::<u8, PodU32>::size_of(usize::MAX).unwrap_err();
        assert_eq!(err, SplPodError::CalculationFailure);
    }

    #[test]
    fn test_fails_with_non_aligned_length_type() {
        // A custom `PodLength` type with an alignment of 4
        #[repr(C, align(4))]
        #[derive(Debug, Copy, Clone, Zeroable, DerivePod)]
        struct TestPodU32(u32);

        // Implement the traits for `PodLength`
        impl From<TestPodU32> for usize {
            fn from(val: TestPodU32) -> Self {
                val.0 as usize
            }
        }
        impl TryFrom<usize> for TestPodU32 {
            type Error = SplPodError;
            fn try_from(val: usize) -> Result<Self, Self::Error> {
                Ok(Self(u32::try_from(val)?))
            }
        }

        let mut buf = [0u8; 100];

        let err_size_of = ListView::<u8, TestPodU32>::size_of(10).unwrap_err();
        assert_eq!(err_size_of, SplPodError::InvalidLengthTypeAlignment);

        let err_unpack = ListView::<u8, TestPodU32>::unpack(&buf).unwrap_err();
        assert_eq!(err_unpack, SplPodError::InvalidLengthTypeAlignment);

        let err_init = ListView::<u8, TestPodU32>::init(&mut buf).unwrap_err();
        assert_eq!(err_init, SplPodError::InvalidLengthTypeAlignment);
    }

    #[test]
    fn test_padding_calculation() {
        // `u8` has an alignment of 1, so no padding is ever needed.
        assert_eq!(ListView::<u8, PodU32>::header_padding().unwrap(), 0);

        // Zero-Sized Types like `()` have size 0 and align 1, requiring no padding.
        assert_eq!(ListView::<(), PodU64>::header_padding().unwrap(), 0);

        // When length and data have the same alignment.
        assert_eq!(ListView::<u16, PodU16>::header_padding().unwrap(), 0);
        assert_eq!(ListView::<u32, PodU32>::header_padding().unwrap(), 0);
        assert_eq!(ListView::<u64, PodU64>::header_padding().unwrap(), 0);

        // When data alignment is smaller than or perfectly divides the length size.
        assert_eq!(ListView::<u16, PodU64>::header_padding().unwrap(), 0); // 8 % 2 = 0
        assert_eq!(ListView::<u32, PodU64>::header_padding().unwrap(), 0); // 8 % 4 = 0

        // When padding IS needed.
        assert_eq!(ListView::<u32, PodU16>::header_padding().unwrap(), 2); // size_of<PodU16> is 2. To align to 4, need 2 bytes.
        assert_eq!(ListView::<u64, PodU16>::header_padding().unwrap(), 6); // size_of<PodU16> is 2. To align to 8, need 6 bytes.
        assert_eq!(ListView::<u64, PodU32>::header_padding().unwrap(), 4); // size_of<PodU32> is 4. To align to 8, need 4 bytes.

        // Test with custom, higher alignments.
        #[repr(C, align(8))]
        #[derive(DerivePod, Zeroable, Copy, Clone)]
        struct Align8(u64);

        // Test against different length types
        assert_eq!(ListView::<Align8, PodU16>::header_padding().unwrap(), 6); // 2 + 6 = 8
        assert_eq!(ListView::<Align8, PodU32>::header_padding().unwrap(), 4); // 4 + 4 = 8
        assert_eq!(ListView::<Align8, PodU64>::header_padding().unwrap(), 0); // 8 is already aligned

        #[repr(C, align(16))]
        #[derive(DerivePod, Zeroable, Copy, Clone)]
        struct Align16(u128);

        assert_eq!(ListView::<Align16, PodU16>::header_padding().unwrap(), 14); // 2 + 14 = 16
        assert_eq!(ListView::<Align16, PodU32>::header_padding().unwrap(), 12); // 4 + 12 = 16
        assert_eq!(ListView::<Align16, PodU64>::header_padding().unwrap(), 8); // 8 + 8 = 16
    }

    #[test]
    fn test_unpack_success_no_padding() {
        // T = u32 (align 4), L = PodU32 (size 4, align 4). No padding needed.
        let length: u32 = 2;
        let capacity: usize = 3;
        let item_size = size_of::<u32>();
        let len_size = size_of::<PodU32>();
        let buf_size = len_size + capacity * item_size;
        let mut buf = vec![0u8; buf_size];

        let pod_len: PodU32 = length.into();
        buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

        let data_start = len_size;
        let items = [100u32, 200u32];
        let items_bytes = bytemuck::cast_slice(&items);
        buf[data_start..(data_start + items_bytes.len())].copy_from_slice(items_bytes);

        let view_ro = ListView::<u32, PodU32>::unpack(&buf).unwrap();
        assert_eq!(view_ro.len(), length as usize);
        assert_eq!(view_ro.capacity(), capacity);
        assert_eq!(*view_ro, items[..]);

        let view_mut = ListView::<u32, PodU32>::unpack_mut(&mut buf).unwrap();
        assert_eq!(view_mut.len(), length as usize);
        assert_eq!(view_mut.capacity(), capacity);
        assert_eq!(*view_mut, items[..]);
    }

    #[test]
    fn test_unpack_success_with_padding() {
        // T = u64 (align 8), L = PodU32 (size 4, align 4). Needs 4 bytes padding.
        let padding = ListView::<u64, PodU32>::header_padding().unwrap();
        assert_eq!(padding, 4);

        let length: u32 = 2;
        let capacity: usize = 2;
        let item_size = size_of::<u64>();
        let len_size = size_of::<PodU32>();
        let buf_size = len_size + padding + capacity * item_size;
        let mut buf = vec![0u8; buf_size];

        let pod_len: PodU32 = length.into();
        buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

        // Data starts after length and padding
        let data_start = len_size + padding;
        let items = [100u64, 200u64];
        let items_bytes = bytemuck::cast_slice(&items);
        buf[data_start..(data_start + items_bytes.len())].copy_from_slice(items_bytes);

        let view_ro = ListView::<u64, PodU32>::unpack(&buf).unwrap();
        assert_eq!(view_ro.len(), length as usize);
        assert_eq!(view_ro.capacity(), capacity);
        assert_eq!(*view_ro, items[..]);

        let view_mut = ListView::<u64, PodU32>::unpack_mut(&mut buf).unwrap();
        assert_eq!(view_mut.len(), length as usize);
        assert_eq!(view_mut.capacity(), capacity);
        assert_eq!(*view_mut, items[..]);
    }

    #[test]
    fn test_unpack_success_zero_length() {
        let capacity: usize = 5;
        let item_size = size_of::<u32>();
        let len_size = size_of::<PodU32>();
        let buf_size = len_size + capacity * item_size;
        let mut buf = vec![0u8; buf_size];

        let pod_len: PodU32 = 0u32.into();
        buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

        let view_ro = ListView::<u32, PodU32>::unpack(&buf).unwrap();
        assert_eq!(view_ro.len(), 0);
        assert_eq!(view_ro.capacity(), capacity);
        assert!(view_ro.is_empty());
        assert_eq!(&*view_ro, &[] as &[u32]);

        let view_mut = ListView::<u32, PodU32>::unpack_mut(&mut buf).unwrap();
        assert_eq!(view_mut.len(), 0);
        assert_eq!(view_mut.capacity(), capacity);
        assert!(view_mut.is_empty());
        assert_eq!(&*view_mut, &[] as &[u32]);
    }

    #[test]
    fn test_unpack_success_full_capacity() {
        let length: u64 = 3;
        let capacity: usize = 3;
        let item_size = size_of::<u64>();
        let len_size = size_of::<PodU64>();
        let buf_size = len_size + capacity * item_size;
        let mut buf = vec![0u8; buf_size];

        let pod_len: PodU64 = length.into();
        buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

        let data_start = len_size;
        let items = [1u64, 2u64, 3u64];
        let items_bytes = bytemuck::cast_slice(&items);
        buf[data_start..].copy_from_slice(items_bytes);

        let view_ro = ListView::<u64>::unpack(&buf).unwrap();
        assert_eq!(view_ro.len(), length as usize);
        assert_eq!(view_ro.capacity(), capacity);
        assert_eq!(*view_ro, items[..]);

        let view_mut = ListView::<u64>::unpack_mut(&mut buf).unwrap();
        assert_eq!(view_mut.len(), length as usize);
        assert_eq!(view_mut.capacity(), capacity);
        assert_eq!(*view_mut, items[..]);
    }

    #[test]
    fn test_unpack_fail_buffer_too_small_for_header() {
        // T = u64 (align 8), L = PodU32 (size 4). Header size is 8.
        let header_size = ListView::<u64, PodU32>::size_of(0).unwrap();
        assert_eq!(header_size, 8);

        // Provide a buffer smaller than the required header
        let mut buf = vec![0u8; header_size - 1]; // 7 bytes

        let err = ListView::<u64, PodU32>::unpack(&buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);

        let err = ListView::<u64, PodU32>::unpack_mut(&mut buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);
    }

    #[test]
    fn test_unpack_fail_declared_length_exceeds_capacity() {
        let declared_length: u32 = 4;
        let capacity: usize = 3; // buffer can only hold 3
        let item_size = size_of::<u32>();
        let len_size = size_of::<PodU32>();
        let buf_size = len_size + capacity * item_size;
        let mut buf = vec![0u8; buf_size];

        // Write a length that is bigger than capacity
        let pod_len: PodU32 = declared_length.into();
        buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

        let err = ListView::<u32, PodU32>::unpack(&buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);

        let err = ListView::<u32, PodU32>::unpack_mut(&mut buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);
    }

    #[test]
    fn test_unpack_fail_data_part_not_multiple_of_item_size() {
        let len_size = size_of::<PodU32>();

        // data part is 5 bytes, not a multiple of item_size (4)
        let buf_size = len_size + 5;
        let mut buf = vec![0u8; buf_size];

        // bytemuck::try_cast_slice returns an alignment error, which we map to InvalidArgument

        let err = ListView::<u32, PodU32>::unpack(&buf).unwrap_err();
        assert_eq!(err, SplPodError::PodCast);

        let err = ListView::<u32, PodU32>::unpack_mut(&mut buf).unwrap_err();
        assert_eq!(err, SplPodError::PodCast);
    }

    #[test]
    fn test_unpack_empty_buffer() {
        let mut buf = [];
        let err = ListView::<u32, PodU32>::unpack(&buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);

        let err = ListView::<u32, PodU32>::unpack_mut(&mut buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);
    }

    #[test]
    fn test_init_success_no_padding() {
        // T = u32 (align 4), L = PodU32 (size 4). No padding needed.
        let capacity: usize = 5;
        let len_size = size_of::<PodU32>();
        let buf_size = ListView::<u32, PodU32>::size_of(capacity).unwrap();
        let mut buf = vec![0xFFu8; buf_size]; // Pre-fill to ensure init zeroes it

        let view = ListView::<u32, PodU32>::init(&mut buf).unwrap();

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), capacity);
        assert!(view.is_empty());

        // Check that the underlying buffer's length was actually zeroed
        let length_bytes = &buf[0..len_size];
        assert_eq!(length_bytes, &[0u8; 4]);
    }

    #[test]
    fn test_init_success_with_padding() {
        // T = u64 (align 8), L = PodU32 (size 4). Needs 4 bytes padding.
        let capacity: usize = 3;
        let len_size = size_of::<PodU32>();
        let buf_size = ListView::<u64, PodU32>::size_of(capacity).unwrap();
        let mut buf = vec![0xFFu8; buf_size]; // Pre-fill to ensure init zeroes it

        let view = ListView::<u64, PodU32>::init(&mut buf).unwrap();

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), capacity);
        assert!(view.is_empty());

        // Check that the underlying buffer's length was actually zeroed
        let length_bytes = &buf[0..len_size];
        assert_eq!(length_bytes, &[0u8; 4]);
        // The padding bytes may or may not be zeroed, we don't assert on them.
    }

    #[test]
    fn test_init_success_zero_capacity() {
        // Test initializing a buffer that can only hold the header.
        // T = u64 (align 8), L = PodU32 (size 4). Header size is 8.
        let buf_size = ListView::<u64, PodU32>::size_of(0).unwrap();
        assert_eq!(buf_size, 8);
        let mut buf = vec![0xFFu8; buf_size];

        let view = ListView::<u64, PodU32>::init(&mut buf).unwrap();

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), 0);
        assert!(view.is_empty());

        // Check that the underlying buffer's length was actually zeroed
        let len_size = size_of::<PodU32>();
        let length_bytes = &buf[0..len_size];
        assert_eq!(length_bytes, &[0u8; 4]);
    }

    #[test]
    fn test_init_fail_buffer_too_small() {
        // Header requires 4 bytes (size_of<PodU32>)
        let mut buf = vec![0u8; 3];
        let err = ListView::<u32, PodU32>::init(&mut buf).unwrap_err();
        assert_eq!(err, SplPodError::BufferTooSmall);

        // With padding, header requires 8 bytes (4 for len, 4 for pad)
        let mut buf_padded = vec![0u8; 7];
        let err_padded = ListView::<u64, PodU32>::init(&mut buf_padded).unwrap_err();
        assert_eq!(err_padded, SplPodError::BufferTooSmall);
    }

    #[test]
    fn test_init_success_default_length_type() {
        // This test uses the default L=PodU32 length type by omitting it.
        // T = u32 (align 4), L = PodU32 (size 4). No padding needed as 4 % 4 == 0.
        let capacity = 5;
        let len_size = size_of::<PodU32>(); // Default L is PodU32
        let buf_size = ListView::<u32>::size_of(capacity).unwrap();
        let mut buf = vec![0xFFu8; buf_size]; // Pre-fill to ensure init zeroes it

        let view = ListView::<u32>::init(&mut buf).unwrap();

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), capacity);
        assert!(view.is_empty());

        // Check that the underlying buffer's length (a u32) was actually zeroed
        let length_bytes = &buf[0..len_size];
        assert_eq!(length_bytes, &[0u8; 4]);
    }

    macro_rules! test_list_view_for_length_type {
        ($test_name:ident, $LengthType:ty) => {
            #[test]
            fn $test_name() {
                type T = u64;

                let padding = ListView::<T, $LengthType>::header_padding().unwrap();
                let length_usize = 2usize;
                let capacity = 3;

                let item_size = size_of::<T>();
                let len_size = size_of::<$LengthType>();
                let buf_size = len_size + padding + capacity * item_size;
                let mut buf = vec![0u8; buf_size];

                // Write length
                let pod_len = <$LengthType>::try_from(length_usize).unwrap();
                buf[0..len_size].copy_from_slice(bytemuck::bytes_of(&pod_len));

                // Write data
                let data_start = len_size + padding;
                let items = [1000 as T, 2000 as T];
                let items_bytes = bytemuck::cast_slice(&items);
                buf[data_start..(data_start + items_bytes.len())].copy_from_slice(items_bytes);

                // Test read-only view
                let view_ro = ListView::<T, $LengthType>::unpack(&buf).unwrap();
                assert_eq!(view_ro.len(), length_usize);
                assert_eq!(view_ro.capacity(), capacity);
                assert_eq!(*view_ro, items[..]);

                // Test mutable view
                let mut buf_mut = buf.clone();
                let view_mut = ListView::<T, $LengthType>::unpack_mut(&mut buf_mut).unwrap();
                assert_eq!(view_mut.len(), length_usize);
                assert_eq!(view_mut.capacity(), capacity);
                assert_eq!(*view_mut, items[..]);

                // Test init
                let mut init_buf = vec![0xFFu8; buf_size];
                let init_view = ListView::<T, $LengthType>::init(&mut init_buf).unwrap();
                assert_eq!(init_view.len(), 0);
                assert_eq!(init_view.capacity(), capacity);
                assert_eq!(<$LengthType>::try_from(0usize).unwrap(), *init_view.length);
            }
        };
    }

    test_list_view_for_length_type!(list_view_with_pod_u16, PodU16);
    test_list_view_for_length_type!(list_view_with_pod_u32, PodU32);
    test_list_view_for_length_type!(list_view_with_pod_u64, PodU64);
    test_list_view_for_length_type!(list_view_with_pod_u128, PodU128);
}
