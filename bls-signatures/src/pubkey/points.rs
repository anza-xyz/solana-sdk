#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use rayon::prelude::*;
#[cfg(all(not(target_os = "solana"), feature = "std"))]
use std::sync::LazyLock;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{hash_pop_payload_to_point, hash_signature_message_to_point},
        proof_of_possession::{AsProofOfPossessionAffine, ProofOfPossessionAffine},
        secret_key::SecretKey,
        signature::{AsSignatureAffine, SignatureAffine},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, Gt},
    group::Group,
    pairing::{MillerLoopResult, MultiMillerLoop},
};

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
///
/// This type wraps `G1Projective` and is optimal for aggregation.
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

/// A trait for types that can be converted into a `PubkeyAffine`.
#[cfg(not(target_os = "solana"))]
pub trait AsPubkeyAffine {
    /// Attempt to convert the type into a `PubkeyAffine`.
    fn try_as_affine(&self) -> Result<PubkeyAffine, BlsError>;
}

/// A trait that provides verification methods to any convertible public key type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiablePubkey: AsPubkeyAffine {
    /// Uses this public key to verify any convertible signature type.
    fn verify_signature<S: AsSignatureAffine>(
        &self,
        signature: &S,
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let signature_affine = signature.try_as_affine()?;
        Ok(pubkey_affine._verify_signature(&signature_affine, message))
    }

    /// Uses this public key to verify any convertible proof of possession type.
    fn verify_proof_of_possession<P: AsProofOfPossessionAffine>(
        &self,
        proof: &P,
        payload: Option<&[u8]>,
    ) -> Result<bool, BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let proof_affine = proof.try_as_affine()?;
        Ok(pubkey_affine._verify_proof_of_possession(&proof_affine, payload))
    }
}

/// A BLS public key in an affine point representation.
///
/// This type wraps `G1Affine` and is optimal for verification operations
/// (pairing inputs) as it avoids the cost of converting from projective coordinates.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PubkeyAffine(pub(crate) G1Affine);

#[cfg(not(target_os = "solana"))]
impl PubkeyAffine {
    /// Verify a signature and a message against a public key
    pub(crate) fn _verify_signature(&self, signature: &SignatureAffine, message: &[u8]) -> bool {
        // The verification equation is e(pubkey, H(m)) = e(g1, signature).
        // This can be rewritten as e(pubkey, H(m)) * e(-g1, signature) = 1, which
        // allows for a more efficient verification using a multi-miller loop.
        let hashed_message: G2Affine = hash_signature_message_to_point(message).into();
        let hashed_message_prepared = G2Prepared::from(hashed_message);
        let signature_prepared = G2Prepared::from(signature.0);

        // use the static valud if `std` is available, otherwise compute it
        #[cfg(feature = "std")]
        let neg_g1_generator = &NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&self.0, &hashed_message_prepared),
            (neg_g1_generator, &signature_prepared),
        ]);
        miller_loop_result.final_exponentiation() == Gt::identity()
    }

    /// Verify a proof of possession against a public key
    pub(crate) fn _verify_proof_of_possession(
        &self,
        proof: &ProofOfPossessionAffine,
        payload: Option<&[u8]>,
    ) -> bool {
        // The verification equation is e(pubkey, H(pubkey)) == e(g1, proof).
        // This is rewritten to e(pubkey, H(pubkey)) * e(-g1, proof) = 1 for batching.
        let hashed_pubkey: G2Affine = if let Some(bytes) = payload {
            hash_pop_payload_to_point(bytes).into()
        } else {
            let pubkey_bytes = self.to_bytes_compressed();
            hash_pop_payload_to_point(&pubkey_bytes).into()
        };
        let hashed_pubkey_prepared = G2Prepared::from(hashed_pubkey);
        let proof_prepared = G2Prepared::from(proof.0);

        // Use the static value if std is available, otherwise compute it
        #[cfg(feature = "std")]
        let neg_g1_generator = &NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&self.0, &hashed_pubkey_prepared),
            // Reuse the same pre-computed static value here for efficiency
            (neg_g1_generator, &proof_prepared),
        ]);

        miller_loop_result.final_exponentiation() == Gt::identity()
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsPubkeyAffine> VerifiablePubkey for T {}
