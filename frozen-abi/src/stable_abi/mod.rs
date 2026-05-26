use rand::RngCore;

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
