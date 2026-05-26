use rand::RngCore;

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
    min: usize,
    max: usize,
}

/// Context for `StableAbi<...>` impls on sequence-like collections
/// that caps the sampled length at `0..=N`.
///
/// Equivalent to `SequenceLenRange { min: 0, max: N }`; the per-collection
/// impl delegates to the `SequenceLenRange` impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceLenMax(pub usize);

pub trait StableAbi<Ctx = ()>: Sized {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: Ctx) -> Self;

    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self
    where
        Ctx: Default,
    {
        Self::random_with_context(rng, Ctx::default())
    }
}

mod impls;
