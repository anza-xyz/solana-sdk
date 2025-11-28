#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use rayon::prelude::*;
#[cfg(not(target_os = "solana"))]
use {
    crate::{error::BlsError, secret_key::SecretKey},
    blstrs::G1Projective,
    group::Group,
};
#[cfg(all(not(target_os = "solana"), feature = "std"))]
use {blstrs::G1Affine, std::sync::LazyLock};

#[cfg(all(not(target_os = "solana"), feature = "std"))]
pub(crate) static NEG_G1_GENERATOR_AFFINE: LazyLock<G1Affine> =
    LazyLock::new(|| (-G1Projective::generator()).into());

/// A trait for types that can be converted into a `PubkeyProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsPubkeyProjective {
    /// Attempt to convert the type into a `PubkeyProjective`.
    fn try_as_projective(&self) -> Result<PubkeyProjective, BlsError>;
}

/// A BLS public key in a projective point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeyProjective(pub(crate) G1Projective);

#[cfg(not(target_os = "solana"))]
impl PubkeyProjective {
    /// Creates the identity element, which is the starting point for aggregation
    ///
    /// The identity element is not a valid public key and it should only be used
    /// for the purpose of aggregation
    pub fn identity() -> Self {
        Self(G1Projective::identity())
    }

    /// Construct a corresponding `BlsPubkey` for a `BlsSecretKey`
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_secret(secret: &SecretKey) -> Self {
        Self(G1Projective::generator() * secret.0)
    }

    /// Aggregate a list of public keys into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, P: AsPubkeyProjective + ?Sized + 'a>(
        &mut self,
        pubkeys: impl Iterator<Item = &'a P>,
    ) -> Result<(), BlsError> {
        for pubkey in pubkeys {
            self.0 += pubkey.try_as_projective()?.0;
        }
        Ok(())
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, P: AsPubkeyProjective + ?Sized + 'a>(
        mut pubkeys: impl Iterator<Item = &'a P>,
    ) -> Result<PubkeyProjective, BlsError> {
        match pubkeys.next() {
            Some(first) => {
                let mut aggregate = first.try_as_projective()?;
                aggregate.aggregate_with(pubkeys)?;
                Ok(aggregate)
            }
            None => Err(BlsError::EmptyAggregation),
        }
    }

    /// Aggregate a list of public keys into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<'a, P: AsPubkeyProjective + Sync + 'a>(
        &mut self,
        pubkeys: impl ParallelIterator<Item = &'a P>,
    ) -> Result<(), BlsError> {
        let aggregate = PubkeyProjective::par_aggregate(pubkeys)?;
        self.0 += &aggregate.0;
        Ok(())
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<'a, P: AsPubkeyProjective + Sync + 'a>(
        pubkeys: impl ParallelIterator<Item = &'a P>,
    ) -> Result<PubkeyProjective, BlsError> {
        pubkeys
            .into_par_iter()
            .map(|key| key.try_as_projective())
            .try_reduce_with(|mut a, b| {
                a.0 += b.0;
                Ok(a)
            })
            .ok_or(BlsError::EmptyAggregation)?
    }
}
