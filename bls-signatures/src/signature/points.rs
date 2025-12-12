#[cfg(all(not(target_os = "solana"), feature = "std"))]
use crate::pubkey::points::NEG_G1_GENERATOR_AFFINE;
#[cfg(not(feature = "std"))]
use blstrs::G1Projective;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::hash_signature_message_to_point,
        pubkey::{AsPubkeyProjective, Pubkey, PubkeyProjective, VerifiablePubkey},
        signature::bytes::Signature,
    },
    blstrs::{Bls12, G1Affine, G2Affine, G2Prepared, G2Projective, Gt},
    group::Group,
    pairing::{MillerLoopResult, MultiMillerLoop},
};
#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use {alloc::vec::Vec, rayon::prelude::*};

/// A trait for types that can be converted into a `SignatureProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureProjective {
    /// Attempt to convert the type into a `SignatureProjective`.
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError>;
}

/// A trait that provides verification methods to any convertible signature type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiableSignature: AsSignatureAffine + Sized {
    /// Verify the signature against any convertible public key type and a message.
    fn verify<P: VerifiablePubkey>(&self, pubkey: &P, message: &[u8]) -> Result<bool, BlsError> {
        pubkey.verify_signature(self, message)
    }
}

/// A BLS signature in a projective point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProjective(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl SignatureProjective {
    /// Creates the identity element, which is the starting point for aggregation
    ///
    /// The identity element is not a valid signature and it should only be used
    /// for the purpose of aggregation
    pub fn identity() -> Self {
        Self(G2Projective::identity())
    }

    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, S: AsSignatureProjective + ?Sized + 'a>(
        &mut self,
        signatures: impl Iterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        for signature in signatures {
            self.0 += signature.try_as_projective()?.0;
        }
        Ok(())
    }

    /// Aggregate a list of signatures
    pub fn aggregate<'a, S: AsSignatureProjective + ?Sized + 'a>(
        mut signatures: impl Iterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        match signatures.next() {
            Some(first) => {
                let mut aggregate = first.try_as_projective()?;
                aggregate.aggregate_with(signatures)?;
                Ok(aggregate)
            }
            None => Err(BlsError::EmptyAggregation),
        }
    }

    /// Verify a list of signatures against a message and a list of public keys
    pub fn verify_aggregate<
        'a,
        P: AsPubkeyProjective + ?Sized + 'a,
        S: AsSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a P>,
        signatures: impl Iterator<Item = &'a S>,
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }

    /// Verifies an aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct<'a>(
        public_keys: impl ExactSizeIterator<Item = &'a Pubkey>,
        signatures: impl ExactSizeIterator<Item = &'a Signature>,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated(public_keys, &aggregate_signature.into(), messages)
    }

    /// Verifies a pre-aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct_aggregated<'a>(
        public_keys: impl ExactSizeIterator<Item = &'a Pubkey>,
        aggregate_signature: &Signature,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }

        // TODO: remove `Vec` allocation if possible for efficiency
        let mut pubkeys_affine = alloc::vec::Vec::with_capacity(public_keys.len());
        let public_keys_len = public_keys.len();
        for pubkey in public_keys {
            let maybe_g1_affine: Option<_> = G1Affine::from_uncompressed(&pubkey.0).into();
            let g1_affine: G1Affine = maybe_g1_affine.ok_or(BlsError::PointConversion)?;
            pubkeys_affine.push(g1_affine);
        }

        let mut prepared_hashes = alloc::vec::Vec::with_capacity(messages.len());
        for message in messages {
            let hashed_message: G2Affine = hash_signature_message_to_point(message).into();
            prepared_hashes.push(G2Prepared::from(hashed_message));
        }

        let maybe_aggregate_signature_affine: Option<G2Affine> =
            G2Affine::from_uncompressed(&aggregate_signature.0).into();
        let aggregate_signature_affine =
            maybe_aggregate_signature_affine.ok_or(BlsError::PointConversion)?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let mut terms = alloc::vec::Vec::with_capacity(public_keys_len.saturating_add(1));
        for i in 0..public_keys_len {
            terms.push((&pubkeys_affine[i], &prepared_hashes[i]));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        Ok(miller_loop_result.final_exponentiation() == Gt::identity())
    }

    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<'a, S: AsSignatureProjective + Sync + 'a>(
        &mut self,
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        let aggregate = SignatureProjective::par_aggregate(signatures)?;
        self.0 += &aggregate.0;
        Ok(())
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<'a, S: AsSignatureProjective + Sync + 'a>(
        signatures: impl ParallelIterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        signatures
            .into_par_iter()
            .map(|sig| sig.try_as_projective())
            .try_reduce_with(|mut a, b| {
                a.0 += b.0;
                Ok(a)
            })
            .ok_or(BlsError::EmptyAggregation)?
    }

    /// Verify a list of signatures against a message and a list of public keys
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate<P: AsPubkeyProjective + Sync, S: AsSignatureProjective + Sync>(
        public_keys: &[P],
        signatures: &[S],
        message: &[u8],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        let (aggregate_pubkey_res, aggregate_signature_res) = rayon::join(
            || PubkeyProjective::par_aggregate(public_keys.into_par_iter()),
            || SignatureProjective::par_aggregate(signatures.into_par_iter()),
        );
        let aggregate_pubkey = aggregate_pubkey_res?;
        let aggregate_signature = aggregate_signature_res?;
        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }

    /// Verifies a set of signatures over a set of distinct messages and
    /// public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct(
        public_keys: &[Pubkey],
        signatures: &[Signature],
        messages: &[&[u8]],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures.into_par_iter())?;
        Self::par_verify_distinct_aggregated(public_keys, &aggregate_signature.into(), messages)
    }

    /// In parallel, verifies a pre-aggregated signature over a set of distinct
    /// messages and public keys.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated(
        public_keys: &[Pubkey],
        aggregate_signature: &Signature,
        messages: &[&[u8]],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }

        // Use `rayon` to perform the three expensive, independent tasks in parallel:
        // 1. Deserialize public keys into curve points.
        // 2. Hash messages into curve points and prepare them for pairing.
        let (pubkeys_affine_res, prepared_hashes_res): (Result<Vec<_>, _>, Result<Vec<_>, _>) =
            rayon::join(
                || {
                    public_keys
                        .par_iter()
                        .map(|pk| {
                            let maybe_pubkey_affine: Option<_> =
                                G1Affine::from_uncompressed(&pk.0).into();
                            maybe_pubkey_affine.ok_or(BlsError::PointConversion)
                        })
                        .collect()
                },
                || {
                    messages
                        .par_iter()
                        .map(|msg| {
                            let hashed_message: G2Affine =
                                hash_signature_message_to_point(msg).into();
                            Ok::<_, BlsError>(G2Prepared::from(hashed_message))
                        })
                        .collect()
                },
            );

        // Check for errors from the parallel operations and unwrap the results.
        let pubkeys_affine = pubkeys_affine_res?;
        let prepared_hashes = prepared_hashes_res?;

        let maybe_aggregate_signature_affine: Option<G2Affine> =
            G2Affine::from_uncompressed(&aggregate_signature.0).into();
        let aggregate_signature_affine =
            maybe_aggregate_signature_affine.ok_or(BlsError::PointConversion)?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let mut terms = alloc::vec::Vec::with_capacity(public_keys.len() + 1);
        for i in 0..public_keys.len() {
            terms.push((&pubkeys_affine[i], &prepared_hashes[i]));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        Ok(miller_loop_result.final_exponentiation() == Gt::identity())
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsSignatureAffine> VerifiableSignature for T {}

/// A trait for types that can be converted into a `SignatureAffine`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureAffine {
    /// Attempt to convert the type into a `SignatureAffine`.
    fn try_as_affine(&self) -> Result<SignatureAffine, BlsError>;
}

/// A BLS signature in an affine point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignatureAffine(pub(crate) G2Affine);
