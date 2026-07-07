use {
    crate::stable_abi::{
        context::{SequenceLenMax, SequenceLenRange},
        impls::DEFAULT_COLLECTION_MAX_SAMPLE_LEN,
    },
    rand::{Rng, RngCore},
};

pub mod context;
mod impls;

pub trait StableAbi<Ctx = ()>: Sized {
    fn random_with_context(rng: &mut (impl RngCore + ?Sized), ctx: Ctx) -> Self;

    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self
    where
        Ctx: Default,
    {
        Self::random_with_context(rng, Ctx::default())
    }
}

/// Samples a random collection of `T` items, drawing the element count the same
/// way the built-in sequence containers do (at most
/// `DEFAULT_COLLECTION_MAX_SAMPLE_LEN`).
///
/// Handy for collections that lack a dedicated `StableAbi` impl, via
/// `#[stable_abi_sample(with = "...")]`:
///
/// ```ignore
/// #[stable_abi_sample(with = "sample_collection(rng)")]
/// a: SomeCollection<SomeItem>,
/// ```
///
/// See [`sample_collection_sized`] to control the sampled length.
pub fn sample_collection<C, T>(rng: &mut (impl RngCore + ?Sized)) -> C
where
    T: StableAbi,
    C: FromIterator<T>,
{
    sample_collection_sized(rng, SequenceLenMax(DEFAULT_COLLECTION_MAX_SAMPLE_LEN))
}

/// Like [`sample_collection`], but with an explicit length spec, e.g.
/// `SequenceLenMax(8)` or `SequenceLenRange::new(1..=4)`.
pub fn sample_collection_sized<C, T>(
    rng: &mut (impl RngCore + ?Sized),
    ctx: impl Into<SequenceLenRange>,
) -> C
where
    T: StableAbi,
    C: FromIterator<T>,
{
    let SequenceLenRange { min, max } = ctx.into();
    let len = rng.random_range(min..=max);
    (0..len).map(|_| T::random(rng)).collect()
}
