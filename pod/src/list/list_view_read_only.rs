//! `ListViewReadOnly`, a read-only, compact, zero-copy array wrapper.

use {
    crate::{list::list_trait::List, pod_length::PodLength, primitives::PodU32},
    bytemuck::Pod,
    core::ops::Deref,
};

#[derive(Debug)]
pub struct ListViewReadOnly<'data, T: Pod, L: PodLength = PodU32> {
    pub(crate) length: &'data L,
    pub(crate) data: &'data [T],
    pub(crate) capacity: usize,
}

impl<T: Pod, L: PodLength> List for ListViewReadOnly<'_, T, L> {
    type Item = T;
    type Length = L;

    fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T: Pod, L: PodLength> Deref for ListViewReadOnly<'_, T, L> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        let len = (*self.length).into();
        &self.data[..len]
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            list::ListView,
            pod_length::PodLength,
            primitives::{PodU32, PodU64},
        },
        bytemuck_derive::{Pod as DerivePod, Zeroable},
        core::mem::size_of,
    };

    #[repr(C, align(16))]
    #[derive(DerivePod, Zeroable, Copy, Clone, Debug, PartialEq)]
    struct TestStruct(u128);

    /// Helper to build a byte buffer that conforms to the `ListView` layout.
    fn build_test_buffer<T: Pod, L: PodLength>(
        length: usize,
        capacity: usize,
        items: &[T],
    ) -> Vec<u8> {
        let size = ListView::<T, L>::size_of(capacity).unwrap();
        let mut buffer = vec![0u8; size];

        // Write the length prefix
        let pod_len = L::try_from(length).unwrap();
        let len_bytes = bytemuck::bytes_of(&pod_len);
        buffer[0..size_of::<L>()].copy_from_slice(len_bytes);

        // Write the data items, accounting for padding
        if !items.is_empty() {
            let data_start = ListView::<T, L>::size_of(0).unwrap();
            let items_bytes = bytemuck::cast_slice(items);
            buffer[data_start..data_start.saturating_add(items_bytes.len())]
                .copy_from_slice(items_bytes);
        }

        buffer
    }

    #[test]
    fn test_len_and_capacity() {
        let items = [10u32, 20, 30];
        let buffer = build_test_buffer::<u32, PodU32>(items.len(), 5, &items);
        let view = ListView::<u32>::unpack(&buffer).unwrap();

        assert_eq!(view.len(), 3);
        assert_eq!(view.capacity(), 5);
    }

    #[test]
    fn test_as_slice() {
        let items = [10u32, 20, 30];
        // Buffer has capacity for 5, but we only use 3.
        let buffer = build_test_buffer::<u32, PodU32>(items.len(), 5, &items);
        let view = ListView::<u32, PodU32>::unpack(&buffer).unwrap();

        // `as_slice()` should only return the first `len` items.
        assert_eq!(*view, items[..]);
    }

    #[test]
    fn test_is_empty() {
        // Not empty
        let buffer_full = build_test_buffer::<u32, PodU32>(1, 2, &[10]);
        let view_full = ListView::<u32>::unpack(&buffer_full).unwrap();
        assert!(!view_full.is_empty());

        // Empty
        let buffer_empty = build_test_buffer::<u32, PodU32>(0, 2, &[]);
        let view_empty = ListView::<u32>::unpack(&buffer_empty).unwrap();
        assert!(view_empty.is_empty());
    }

    #[test]
    fn test_iter() {
        let items = [TestStruct(1), TestStruct(2)];
        let buffer = build_test_buffer::<TestStruct, PodU64>(items.len(), 3, &items);
        let view = ListView::<TestStruct, PodU64>::unpack(&buffer).unwrap();

        let mut iter = view.iter();
        assert_eq!(iter.next(), Some(&items[0]));
        assert_eq!(iter.next(), Some(&items[1]));
        assert_eq!(iter.next(), None);
        let collected: Vec<_> = view.iter().collect();
        assert_eq!(collected, vec![&items[0], &items[1]]);
    }

    #[test]
    fn test_iter_on_empty_list() {
        let buffer = build_test_buffer::<u32, PodU32>(0, 5, &[]);
        let view = ListView::<u32, PodU32>::unpack(&buffer).unwrap();

        assert_eq!(view.iter().count(), 0);
        assert_eq!(view.iter().next(), None);
    }

    #[test]
    fn test_zero_capacity() {
        // Buffer is just big enough for the header (len + padding), no data.
        let buffer = build_test_buffer::<TestStruct, PodU32>(0, 0, &[]);
        let view = ListView::<TestStruct, PodU32>::unpack(&buffer).unwrap();

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), 0);
        assert!(view.is_empty());
        assert_eq!(*view, []);
    }

    #[test]
    fn test_with_padding() {
        // Test the effect of padding by checking the total header size.
        // T=AlignedStruct (align 16), L=PodU32 (size 4).
        // The header size should be 16 (4 for len + 12 for padding).
        let header_size = ListView::<TestStruct>::size_of(0).unwrap();
        assert_eq!(header_size, 16);

        let items = [TestStruct(123), TestStruct(456)];
        let buffer = build_test_buffer::<TestStruct, PodU32>(items.len(), 4, &items);
        let view = ListView::<TestStruct>::unpack(&buffer).unwrap();

        // Check if the public API works as expected despite internal padding
        assert_eq!(view.len(), 2);
        assert_eq!(view.capacity(), 4);
        assert_eq!(*view, items[..]);
    }

    #[test]
    fn test_bytes_used_and_allocated() {
        // 3 live elements, capacity 5
        let items = [10u32, 20, 30];
        let capacity = 5;
        let buffer = build_test_buffer::<u32, PodU32>(items.len(), capacity, &items);
        let view = ListView::<u32>::unpack(&buffer).unwrap();

        let expected_used = ListView::<u32>::size_of(view.len()).unwrap();
        let expected_cap = ListView::<u32>::size_of(view.capacity()).unwrap();

        assert_eq!(view.bytes_used().unwrap(), expected_used);
        assert_eq!(view.bytes_allocated().unwrap(), expected_cap);
    }

    #[test]
    fn test_get() {
        let items = [10u32, 20, 30];
        let buffer = build_test_buffer::<u32, PodU32>(items.len(), 5, &items);
        let view = ListView::<u32>::unpack(&buffer).unwrap();

        // Get in-bounds elements
        assert_eq!(view.first(), Some(&10u32));
        assert_eq!(view.get(1), Some(&20u32));
        assert_eq!(view.get(2), Some(&30u32));

        // Get out-of-bounds element (index == len)
        assert_eq!(view.get(3), None);

        // Get way out-of-bounds
        assert_eq!(view.get(100), None);
    }

    #[test]
    fn test_get_on_empty_list() {
        let buffer = build_test_buffer::<u32, PodU32>(0, 5, &[]);
        let view = ListView::<u32, PodU32>::unpack(&buffer).unwrap();
        assert_eq!(view.first(), None);
    }
}
