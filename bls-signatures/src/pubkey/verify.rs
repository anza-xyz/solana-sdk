#[cfg(feature = "std")]
use std::sync::LazyLock;
use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, HashedPoPPayload, PreparedHashedMessage},
        proof_of_possession::{AsProofOfPossessionAffine, ProofOfPossessionAffine},
        pubkey::points::{AsPubkeyAffine, PopVerified, PubkeyAffine},
        signature::{AsSignatureAffine, SignatureAffine},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Prepared, Gt},
    group::{prime::PrimeCurveAffine, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
};

#[cfg(feature = "std")]
pub(crate) static NEG_G1_GENERATOR_AFFINE: LazyLock<G1Affine> =
    LazyLock::new(|| (-G1Projective::generator()).into());

/// A trait that provides Proof of Possession verification methods to any
/// convertible public key type.
pub trait VerifyPop: AsPubkeyAffine + Sized {
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

    /// Verifies the proof of possession and, upon success, returns a `PopVerified`
    /// wrapper.
    fn verify_and_wrap_pop<P: AsProofOfPossessionAffine>(
        self,
        proof: &P,
        payload: Option<&[u8]>,
    ) -> Result<PopVerified<Self>, BlsError> {
        self.verify_proof_of_possession(proof, payload)?;
        Ok(PopVerified(self))
    }
}

// Blanket implementation so any raw key can attempt to prove itself
impl<T: AsPubkeyAffine> VerifyPop for T {}

/// A trait that provides signature verification methods exclusively to safe public key types.
pub trait VerifySignature: AsPubkeyAffine {
    /// Uses this safe public key to verify any convertible signature type.
    fn verify_signature<S: AsSignatureAffine>(
        &self,
        signature: &S,
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        self.verify_signature_pre_hashed(signature, &hashed_message)
    }

    /// Uses this safe public key to verify any convertible signature type using a pre-hashed message.
    fn verify_signature_pre_hashed<S: AsSignatureAffine>(
        &self,
        signature: &S,
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        self.verify_signature_prepared(signature, &prepared_hashed_message)
    }

    /// Uses this safe public key to verify any convertible signature type using a prepared message.
    fn verify_signature_prepared<S: AsSignatureAffine>(
        &self,
        signature: &S,
        prepared_hashed_message: &PreparedHashedMessage,
    ) -> Result<(), BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let signature_affine = signature.try_as_affine()?;
        pubkey_affine
            ._verify_signature_prepared(&signature_affine, &prepared_hashed_message.prepared)
            .then_some(())
            .ok_or(BlsError::VerificationFailed)
    }
}

impl PubkeyAffine {
    /// Verify a signature and a message against a public key
    pub(crate) fn _verify_signature(
        &self,
        signature: &SignatureAffine,
        hashed_message: &HashedMessage,
    ) -> bool {
        let hashed_message_prepared = G2Prepared::from(hashed_message.0);
        self._verify_signature_prepared(signature, &hashed_message_prepared)
    }

    pub(crate) fn _verify_signature_prepared(
        &self,
        signature: &SignatureAffine,
        hashed_message_prepared: &G2Prepared,
    ) -> bool {
        if bool::from(self.0.is_identity()) {
            return false;
        }

        // The verification equation is e(pubkey, H(m)) = e(g1, signature).
        // This can be rewritten as e(pubkey, H(m)) * e(-g1, signature) = 1, which
        // allows for a more efficient verification using a multi-miller loop.
        let signature_prepared = G2Prepared::from(signature.0);

        // use the static valud if `std` is available, otherwise compute it
        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        #[allow(clippy::arithmetic_side_effects)]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&self.0, hashed_message_prepared),
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
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        #[allow(clippy::arithmetic_side_effects)]
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
