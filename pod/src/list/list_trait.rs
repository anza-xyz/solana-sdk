use {
    crate::{error::SplPodError, list::ListView, pod_length::PodLength},
    bytemuck::Pod,
    std::ops::Deref,
};

/// A trait to abstract the shared, read-only behavior
/// between `ListViewReadOnly` and `ListViewMut`.
pub trait List: Deref<Target = [Self::Item]> {
    /// The type of the items stored in the list.
    type Item: Pod;
    /// Length prefix type used (`PodU16`, `PodU32`, …).
    type Length: PodLength;

    /// Returns the total number of items that can be stored in the list.
    fn capacity(&self) -> usize;

    /// Returns the number of **bytes currently occupied** by the live elements
    fn bytes_used(&self) -> Result<usize, SplPodError> {
        ListView::<Self::Item, Self::Length>::size_of(self.len())
    }

    /// Returns the number of **bytes reserved** by the entire backing buffer.
    fn bytes_allocated(&self) -> Result<usize, SplPodError> {
        ListView::<Self::Item, Self::Length>::size_of(self.capacity())
    }
}
