use {
    crate::{list::ListView, pod_length::PodLength},
    bytemuck::Pod,
    solana_program_error::ProgramError,
    std::slice::Iter,
};

/// A trait to abstract the shared, read-only behavior
/// between `ListViewReadOnly` and `ListViewMut`.
pub trait List {
    /// The type of the items stored in the list.
    type Item: Pod;
    /// Length prefix type used (`PodU16`, `PodU32`, …).
    type Length: PodLength;

    /// Returns the number of items in the list.
    fn len(&self) -> usize;

    /// Returns `true` if the list contains no items.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total number of items that can be stored in the list.
    fn capacity(&self) -> usize;

    /// Returns a read-only slice of the items currently in the list.
    fn as_slice(&self) -> &[Self::Item];

    /// Returns a read-only iterator over the list.
    fn iter(&self) -> Iter<'_, Self::Item> {
        self.as_slice().iter()
    }

    /// Returns the number of **bytes currently occupied** by the live elements
    fn bytes_used(&self) -> Result<usize, ProgramError> {
        ListView::<Self::Item, Self::Length>::size_of(self.len())
    }

    /// Returns the number of **bytes reserved** by the entire backing buffer.
    fn bytes_allocated(&self) -> Result<usize, ProgramError> {
        ListView::<Self::Item, Self::Length>::size_of(self.capacity())
    }
}
