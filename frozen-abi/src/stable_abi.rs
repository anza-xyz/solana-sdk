use rand::{distr::StandardUniform, Rng, RngCore};

pub trait StableAbi: Sized {
    fn random(rng: &mut impl RngCore) -> Self
    where
        StandardUniform: rand::distr::Distribution<Self>,
    {
        rng.random::<Self>()
    }
}
