use rand::{distributions::Standard, Rng, RngCore};

pub trait StableAbi: Sized {
    fn random(rng: &mut impl RngCore) -> Self
    where
        Standard: rand::distributions::Distribution<Self>,
    {
        rng.r#gen::<Self>()
    }
}
