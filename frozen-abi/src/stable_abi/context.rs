use core::ops::{Bound, RangeBounds};

/// Context for `StableAbi<...>` impls on sequence-like collections
/// (`Vec`, `VecDeque`, `HashMap`, `BTreeMap`) that bounds the sampled length
/// to an inclusive range `min..=max`.
///
/// The collection's `random_with_context` draws a length uniformly from
/// `min..=max` and produces that many elements. `min == max` pins the length
/// exactly; `min == 0` means "up to `max` elements" (equivalent to
/// `SequenceLenMax(max)`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SequenceLenRange {
    pub min: usize,
    pub max: usize,
}

impl SequenceLenRange {
    pub fn new(range: impl RangeBounds<usize>) -> Self {
        let min = match range.start_bound() {
            Bound::Included(&min) => min,
            Bound::Excluded(&min) => min.checked_add(1).expect("invalid min in range"),
            Bound::Unbounded => 0,
        };
        let max = match range.end_bound() {
            Bound::Included(&max) => max,
            Bound::Excluded(&max) => max.checked_sub(1).expect("invalid max in range"),
            Bound::Unbounded => usize::MAX,
        };
        assert!(min <= max, "invalid sequence length range");

        Self { min, max }
    }
}

/// Context for `StableAbi<...>` impls on sequence-like collections
/// that caps the sampled length at `0..=N`.
///
/// Equivalent to `SequenceLenRange { min: 0, max: N }`; the per-collection
/// impl delegates to the `SequenceLenRange` impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceLenMax(pub usize);

impl From<SequenceLenMax> for SequenceLenRange {
    fn from(max: SequenceLenMax) -> Self {
        Self::new(0..=max.0)
    }
}

macro_rules! impl_with_context_via {
    (
        impl<$($g:tt),+ $(,)?> StableAbi<$ctx:ty> for $self_ty:ty
        where { $($wc:tt)* },
        |$bind:pat_param| $convert:expr $(,)?
    ) => {
        impl<$($g),+> StableAbi<$ctx> for $self_ty
        where $($wc)*
        {
            fn random_with_context(
                rng: &mut (impl RngCore + ?Sized),
                $bind: $ctx,
            ) -> Self {
                Self::random_with_context(rng, $convert)
            }
        }
    };
}

pub(crate) use impl_with_context_via;
