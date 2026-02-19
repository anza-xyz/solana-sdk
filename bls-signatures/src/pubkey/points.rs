#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use rayon::prelude::*;
#[cfg(all(not(target_os = "solana"), feature = "std"))]
use std::sync::LazyLock;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, HashedPoPPayload},
        proof_of_possession::{AsProofOfPossessionAffine, ProofOfPossessionAffine},
        pubkey::bytes::{Pubkey, PubkeyCompressed},
        secret_key::SecretKey,
        signature::{AsSignatureAffine, SignatureAffine},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Prepared, Gt},
    group::{prime::PrimeCurveAffine, Group},
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
    ///
    /// Warning: This function performs mathematical point addition. It does not
    /// perform public key validation (such as identity point checks) or Proof of
    /// Possession (PoP) verification.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, P: AddToPubkeyProjective + ?Sized + 'a>(
        &mut self,
        pubkeys: impl Iterator<Item = &'a P>,
    ) -> Result<(), BlsError> {
        for pubkey in pubkeys {
            pubkey.add_to_accumulator(self)?;
        }
        Ok(())
    }

    /// Aggregate a list of public keys
    ///
    /// Warning: This function performs mathematical point addition. It does not
    /// perform public key validation (such as identity point checks) or Proof of
    /// Possession (PoP) verification.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, P: AddToPubkeyProjective + ?Sized + 'a>(
        pubkeys: impl Iterator<Item = &'a P>,
    ) -> Result<PubkeyProjective, BlsError> {
        let mut aggregate = PubkeyProjective::identity();
        let mut count = 0;
        for pubkey in pubkeys {
            pubkey.add_to_accumulator(&mut aggregate)?;
            count += 1;
        }
        if count == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        Ok(aggregate)
    }

    /// Aggregate a list of public keys into an existing aggregate
    ///
    /// Warning: This function performs mathematical point addition. It does not
    /// perform public key validation (such as identity point checks) or Proof of
    /// Possession (PoP) verification.
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<'a, P: AddToPubkeyProjective + Sync + 'a>(
        &mut self,
        pubkeys: impl ParallelIterator<Item = &'a P>,
    ) -> Result<(), BlsError> {
        let aggregate = PubkeyProjective::par_aggregate(pubkeys)?;
        self.0 += &aggregate.0;
        Ok(())
    }

    /// Aggregate a list of public keys
    ///
    /// Warning: This function performs mathematical point addition. It does not
    /// perform public key validation (such as identity point checks) or Proof of
    /// Possession (PoP) verification.
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<'a, P: AddToPubkeyProjective + Sync + 'a>(
        pubkeys: impl ParallelIterator<Item = &'a P>,
    ) -> Result<PubkeyProjective, BlsError> {
        pubkeys
            .into_par_iter()
            .fold(
                || Ok(PubkeyProjective::identity()),
                |acc, pubkey| {
                    let mut acc = acc?;
                    pubkey.add_to_accumulator(&mut acc)?;
                    Ok(acc)
                },
            )
            .reduce_with(|a, b| {
                let mut a_val = a?;
                let b_val = b?;
                a_val.0 += b_val.0;
                Ok(a_val)
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
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        self.verify_signature_pre_hashed(signature, &hashed_message)
    }

    /// Uses this public key to verify any convertible signature type using a
    /// pre-hashed message.
    fn verify_signature_pre_hashed<S: AsSignatureAffine>(
        &self,
        signature: &S,
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let signature_affine = signature.try_as_affine()?;
        pubkey_affine
            ._verify_signature(&signature_affine, hashed_message)
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }

    /// Uses this public key to verify any convertible proof of possession type.
    fn verify_proof_of_possession<P: AsProofOfPossessionAffine>(
        &self,
        proof: &P,
        payload: Option<&[u8]>,
    ) -> Result<(), BlsError> {
        let hashed_pubkey = if let Some(bytes) = payload {
            HashedPoPPayload::new(bytes)
        } else {
            let pubkey_bytes = self.try_as_affine()?.to_bytes_compressed();
            HashedPoPPayload::new(&pubkey_bytes)
        };
        self.verify_proof_of_possession_pre_hashed(proof, &hashed_pubkey)
    }

    /// Uses this public key to verify any convertible proof of possession type.
    fn verify_proof_of_possession_pre_hashed<P: AsProofOfPossessionAffine>(
        &self,
        proof: &P,
        hashed_payload: &HashedPoPPayload,
    ) -> Result<(), BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let proof_affine = proof.try_as_affine()?;
        pubkey_affine
            ._verify_proof_of_possession(&proof_affine, hashed_payload)
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
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
    pub(crate) fn _verify_signature(
        &self,
        signature: &SignatureAffine,
        hashed_message: &HashedMessage,
    ) -> bool {
        if bool::from(self.0.is_identity()) {
            return false;
        }

        // The verification equation is e(pubkey, H(m)) = e(g1, signature).
        // This can be rewritten as e(pubkey, H(m)) * e(-g1, signature) = 1, which
        // allows for a more efficient verification using a multi-miller loop.
        let hashed_message_prepared = G2Prepared::from(hashed_message.0);
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
        hashed_payload: &HashedPoPPayload,
    ) -> bool {
        if bool::from(self.0.is_identity()) {
            return false;
        }

        // The verification equation is e(pubkey, H(pubkey)) == e(g1, proof).
        // This is rewritten to e(pubkey, H(pubkey)) * e(-g1, proof) = 1 for batching.
        let hashed_pubkey = hashed_payload.0;
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

/// A trait for types that can be efficiently added to a PubkeyProjective accumulator.
#[cfg(not(target_os = "solana"))]
pub trait AddToPubkeyProjective {
    /// Adds itself to the accumulator
    fn add_to_accumulator(&self, acc: &mut PubkeyProjective) -> Result<(), BlsError>;
}

// Fallback for trait objects to support `dyn` types
#[cfg(not(target_os = "solana"))]
impl AddToPubkeyProjective for dyn AsPubkeyProjective {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_accumulator(&self, acc: &mut PubkeyProjective) -> Result<(), BlsError> {
        let proj = self.try_as_projective()?;
        acc.0 += proj.0;
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyAffine,
    affine
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyProjective,
    projective
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(AddToPubkeyProjective, PubkeyProjective, Pubkey, convert);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyCompressed,
    convert
);
