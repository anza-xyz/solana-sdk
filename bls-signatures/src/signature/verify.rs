use crate::{
    error::BlsError,
    hash::{HashedMessage, PreparedHashedMessage},
    pubkey::{AddToPubkeyProjective, PopVerified, PubkeyProjective, VerifySignature},
    signature::points::{AddToSignatureProjective, AsSignatureAffine, SignatureProjective},
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A trait that provides verification methods to any convertible signature type.
pub trait VerifiableSignature: AsSignatureAffine + Sized {
    /// Verify the signature against any convertible public key type and a message.
    fn verify<P: VerifySignature>(&self, pubkey: &P, message: &[u8]) -> Result<(), BlsError> {
        pubkey.verify_signature(self, message)
    }
}

impl<T: AsSignatureAffine> VerifiableSignature for T {}

impl SignatureProjective {
    /// Verify a list of signatures against a message and a list of PoP-verified public keys
    pub fn verify_aggregate<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a PopVerified<P>>,
        signatures: impl Iterator<Item = &'a S>,
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        Self::verify_aggregate_pre_hashed(public_keys, signatures, &hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed message and a list of
    /// PoP-verified public keys.
    pub fn verify_aggregate_pre_hashed<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a PopVerified<P>>,
        signatures: impl Iterator<Item = &'a S>,
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        Self::verify_aggregate_prepared(public_keys, signatures, &prepared_hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed and prepared message and
    /// a list of PoP-verified public keys.
    pub fn verify_aggregate_prepared<
        'a,
        P: AddToPubkeyProjective + ?Sized + 'a,
        S: AddToSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a PopVerified<P>>,
        signatures: impl Iterator<Item = &'a S>,
        prepared_hashed_message: &PreparedHashedMessage,
    ) -> Result<(), BlsError> {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        // This is safe because AggregatePubkey implements VerifySignature!
        aggregate_pubkey.verify_signature_prepared(&aggregate_signature, prepared_hashed_message)
    }

    /// Verify a list of signatures against a message and a list of PoP-verified public keys
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        Self::par_verify_aggregate_pre_hashed(public_keys, signatures, &hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed message and a list of
    /// PoP-verified public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate_pre_hashed<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        Self::par_verify_aggregate_prepared(public_keys, signatures, &prepared_hashed_message)
    }

    /// Verify a list of signatures against a pre-hashed and prepared message and
    /// a list of PoP-verified public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate_prepared<
        P: AddToPubkeyProjective + Sync,
        S: AddToSignatureProjective + Sync,
    >(
        public_keys: &[PopVerified<P>],
        signatures: &[S],
        prepared_hashed_message: &PreparedHashedMessage,
    ) -> Result<(), BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        let (aggregate_pubkey_res, aggregate_signature_res) = rayon::join(
            || PubkeyProjective::par_aggregate(public_keys.into_par_iter()),
            || SignatureProjective::par_aggregate(signatures.into_par_iter()),
        );

        let aggregate_pubkey = aggregate_pubkey_res?;
        let aggregate_signature = aggregate_signature_res?;
        aggregate_pubkey.verify_signature_prepared(&aggregate_signature, prepared_hashed_message)
    }
}
