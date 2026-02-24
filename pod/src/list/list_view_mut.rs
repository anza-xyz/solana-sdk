//! `ListViewMut`, a mutable, compact, zero-copy array wrapper.

use {
    crate::{
        error::PodSliceError, list::list_trait::List, pod_length::PodLength, primitives::PodU32,
    },
    bytemuck::Pod,
    core::ops::{Deref, DerefMut},
    solana_program_error::ProgramError,
};

#[derive(Debug)]
pub struct ListViewMut<'data, T: Pod, L: PodLength = PodU32> {
    pub(crate) length: &'data mut L,
    pub(crate) data: &'data mut [T],
    pub(crate) capacity: usize,
}

impl<T: Pod, L: PodLength> ListViewMut<'_, T, L> {
    /// Add another item to the slice
    pub fn push(&mut self, item: T) -> Result<(), ProgramError> {
        let length = (*self.length).into();
        if length >= self.capacity {
            Err(PodSliceError::BufferTooSmall.into())
        } else {
            self.data[length] = item;
            *self.length = L::try_from(length.saturating_add(1))?;
            Ok(())
        }
    }

    /// Remove and return the element at `index`, shifting all later
    /// elements one position to the left.
    pub fn remove(&mut self, index: usize) -> Result<T, ProgramError> {
        let len = (*self.length).into();
        if index >= len {
            return Err(ProgramError::InvalidArgument);
        }

        let removed_item = self.data[index];

        // Move the tail left by one
        let tail_start = index
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.data.copy_within(tail_start..len, index);

        // Store the new length (len - 1)
        let new_len = len.checked_sub(1).unwrap();
        *self.length = L::try_from(new_len)?;

        Ok(removed_item)
    }
}

impl<T: Pod, L: PodLength> Deref for ListViewMut<'_, T, L> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        let len = (*self.length).into();
        &self.data[..len]
    }
}

impl<T: Pod, L: PodLength> DerefMut for ListViewMut<'_, T, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = (*self.length).into();
        &mut self.data[..len]
    }
}

impl<T: Pod, L: PodLength> List for ListViewMut<'_, T, L> {
    type Item = T;
    type Length = L;

    fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            list::{List, ListView},
            primitives::{PodU16, PodU32, PodU64},
        },
        bytemuck_derive::{Pod, Zeroable},
    };

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Pod, Zeroable)]
    struct TestStruct {
        a: u64,
        b: u32,
        _padding: [u8; 4],
    }

    impl TestStruct {
        fn new(a: u64, b: u32) -> Self {
            Self {
                a,
                b,
                _padding: [0; 4],
            }
        }
    }

    fn init_view_mut<T: Pod, L: PodLength>(
        buffer: &mut Vec<u8>,
        capacity: usize,
    ) -> ListViewMut<T, L> {
        let size = ListView::<T, L>::size_of(capacity).unwrap();
        buffer.resize(size, 0);
        ListView::<T, L>::init(buffer).unwrap()
    }

    #[test]
    fn test_push() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 3);

        assert_eq!(view.len(), 0);
        assert!(view.is_empty());
        assert_eq!(view.capacity(), 3);

        // Push first item
        let item1 = TestStruct::new(1, 10);
        view.push(item1).unwrap();
        assert_eq!(view.len(), 1);
        assert!(!view.is_empty());
        assert_eq!(*view, [item1]);

        // Push second item
        let item2 = TestStruct::new(2, 20);
        view.push(item2).unwrap();
        assert_eq!(view.len(), 2);
        assert_eq!(*view, [item1, item2]);

        // Push third item to fill capacity
        let item3 = TestStruct::new(3, 30);
        view.push(item3).unwrap();
        assert_eq!(view.len(), 3);
        assert_eq!(*view, [item1, item2, item3]);

        // Try to push beyond capacity
        let item4 = TestStruct::new(4, 40);
        let err = view.push(item4).unwrap_err();
        assert_eq!(err, PodSliceError::BufferTooSmall.into());

        // Ensure state is unchanged
        assert_eq!(view.len(), 3);
        assert_eq!(*view, [item1, item2, item3]);
    }

    #[test]
    fn test_remove() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 4);

        let item1 = TestStruct::new(1, 10);
        let item2 = TestStruct::new(2, 20);
        let item3 = TestStruct::new(3, 30);
        let item4 = TestStruct::new(4, 40);
        view.push(item1).unwrap();
        view.push(item2).unwrap();
        view.push(item3).unwrap();
        view.push(item4).unwrap();

        assert_eq!(view.len(), 4);
        assert_eq!(*view, [item1, item2, item3, item4]);

        // Remove from the middle
        let removed = view.remove(1).unwrap();
        assert_eq!(removed, item2);
        assert_eq!(view.len(), 3);
        assert_eq!(*view, [item1, item3, item4]);

        // Remove from the end
        let removed = view.remove(2).unwrap();
        assert_eq!(removed, item4);
        assert_eq!(view.len(), 2);
        assert_eq!(*view, [item1, item3]);

        // Remove from the start
        let removed = view.remove(0).unwrap();
        assert_eq!(removed, item1);
        assert_eq!(view.len(), 1);
        assert_eq!(*view, [item3]);

        // Remove the last element
        let removed = view.remove(0).unwrap();
        assert_eq!(removed, item3);
        assert_eq!(view.len(), 0);
        assert!(view.is_empty());
        assert_eq!(*view, []);
    }

    #[test]
    fn test_remove_out_of_bounds() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 2);

        view.push(TestStruct::new(1, 10)).unwrap();
        view.push(TestStruct::new(2, 20)).unwrap();

        // Try to remove at index == len
        let err = view.remove(2).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
        assert_eq!(view.len(), 2); // Unchanged

        // Try to remove at index > len
        let err = view.remove(100).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
        assert_eq!(view.len(), 2); // Unchanged

        // Empty the view
        view.remove(1).unwrap();
        view.remove(0).unwrap();
        assert!(view.is_empty());

        // Try to remove from empty view
        let err = view.remove(0).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
    }

    #[test]
    fn test_iter_mut() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 4);

        let item1 = TestStruct::new(1, 10);
        let item2 = TestStruct::new(2, 20);
        let item3 = TestStruct::new(3, 30);
        view.push(item1).unwrap();
        view.push(item2).unwrap();
        view.push(item3).unwrap();

        assert_eq!(view.len(), 3);
        assert_eq!(view.capacity(), 4);

        // Modify items using iter_mut
        for item in view.iter_mut() {
            item.a *= 10;
        }

        let expected_item1 = TestStruct::new(10, 10);
        let expected_item2 = TestStruct::new(20, 20);
        let expected_item3 = TestStruct::new(30, 30);

        // Check that the underlying data is modified
        assert_eq!(view.len(), 3);
        assert_eq!(*view, [expected_item1, expected_item2, expected_item3]);

        // Check that iter_mut only iterates over `len` items, not `capacity`
        assert_eq!(view.iter_mut().count(), 3);
    }

    #[test]
    fn test_iter_mut_empty() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU64>(&mut buffer, 5);

        let mut count = 0;
        for _ in view.iter_mut() {
            count += 1;
        }
        assert_eq!(count, 0);
        assert_eq!(view.iter_mut().next(), None);
    }

    #[test]
    fn test_zero_capacity() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 0);

        assert_eq!(view.len(), 0);
        assert_eq!(view.capacity(), 0);
        assert!(view.is_empty());

        let err = view.push(TestStruct::new(1, 1)).unwrap_err();
        assert_eq!(err, PodSliceError::BufferTooSmall.into());

        let err = view.remove(0).unwrap_err();
        assert_eq!(err, ProgramError::InvalidArgument);
    }

    #[test]
    fn test_default_length_type() {
        let capacity = 2;
        let mut buffer = vec![];
        let size = ListView::<TestStruct, PodU64>::size_of(capacity).unwrap();
        buffer.resize(size, 0);

        // Initialize the view *without* specifying L. The compiler uses the default.
        let view = ListView::<TestStruct>::init(&mut buffer).unwrap();

        // Check that the capacity is correct for a PodU64 length.
        assert_eq!(view.capacity(), capacity);
        assert_eq!(view.len(), 0);

        // Verify the size of the length field.
        assert_eq!(size_of_val(view.length), size_of::<PodU32>());
    }

    #[test]
    fn test_bytes_used_and_allocated_mut() {
        // capacity 3, start empty
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU16>(&mut buffer, 3);

        // Empty view
        assert_eq!(
            view.bytes_used().unwrap(),
            ListView::<TestStruct, PodU32>::size_of(0).unwrap()
        );
        assert_eq!(
            view.bytes_allocated().unwrap(),
            ListView::<TestStruct, PodU32>::size_of(view.capacity()).unwrap()
        );

        // After pushing elements
        view.push(TestStruct::new(1, 2)).unwrap();
        view.push(TestStruct::new(3, 4)).unwrap();
        view.push(TestStruct::new(5, 6)).unwrap();
        assert_eq!(
            view.bytes_used().unwrap(),
            ListView::<TestStruct, PodU32>::size_of(3).unwrap()
        );
        assert_eq!(
            view.bytes_allocated().unwrap(),
            ListView::<TestStruct, PodU32>::size_of(view.capacity()).unwrap()
        );
    }
    #[test]
    fn test_get_and_get_mut() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 3);

        let item0 = TestStruct::new(1, 10);
        let item1 = TestStruct::new(2, 20);
        view.push(item0).unwrap();
        view.push(item1).unwrap();

        // Test get()
        assert_eq!(view.first(), Some(&item0));
        assert_eq!(view.get(1), Some(&item1));
        assert_eq!(view.get(2), None); // out of bounds
        assert_eq!(view.get(100), None); // way out of bounds

        // Test get_mut() to modify an item
        let modified_item0 = TestStruct::new(111, 110);
        let item_ref = view.get_mut(0).unwrap();
        *item_ref = modified_item0;

        // Verify the modification
        assert_eq!(view.first(), Some(&modified_item0));
        assert_eq!(*view, [modified_item0, item1]);

        // Test get_mut() out of bounds
        assert_eq!(view.get_mut(2), None);
    }

    #[test]
    fn test_mutable_access_via_indexing() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 3);

        let item0 = TestStruct::new(1, 10);
        let item1 = TestStruct::new(2, 20);
        view.push(item0).unwrap();
        view.push(item1).unwrap();

        assert_eq!(view.len(), 2);

        // Modify via the mutable slice
        view[0].a = 99;

        let expected_item0 = TestStruct::new(99, 10);
        assert_eq!(view.first(), Some(&expected_item0));
        assert_eq!(*view, [expected_item0, item1]);
    }

    #[test]
    fn test_sort_by() {
        let mut buffer = vec![];
        let mut view = init_view_mut::<TestStruct, PodU32>(&mut buffer, 5);

        let item0 = TestStruct::new(5, 1);
        let item1 = TestStruct::new(2, 2);
        let item2 = TestStruct::new(5, 3);
        let item3 = TestStruct::new(1, 4);
        let item4 = TestStruct::new(2, 5);

        view.push(item0).unwrap();
        view.push(item1).unwrap();
        view.push(item2).unwrap();
        view.push(item3).unwrap();
        view.push(item4).unwrap();

        // Sort by `b` field in descending order.
        view.sort_by(|a, b| b.b.cmp(&a.b));
        let expected_order_by_b_desc = [
            item4, // b: 5
            item3, // b: 4
            item2, // b: 3
            item1, // b: 2
            item0, // b: 1
        ];
        assert_eq!(*view, expected_order_by_b_desc);

        // Now, sort by `a` in ascending order. A stable sort preserves the relative
        // order of equal elements from the previous state of the list.
        view.sort_by(|x, y| x.a.cmp(&y.a));

        let expected_order_by_a_stable = [
            item3, // a: 1
            item4, // a: 2 (was before item1 in the previous state)
            item1, // a: 2
            item2, // a: 5 (was before item0 in the previous state)
            item0, // a: 5
        ];
        assert_eq!(*view, expected_order_by_a_stable);
    }
}
