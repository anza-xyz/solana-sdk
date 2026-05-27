use rand::RngCore;

mod impls;

pub trait StableAbi: Sized {
    fn random(rng: &mut (impl RngCore + ?Sized)) -> Self;
}
