use {
    crate::{
        error::BlsError,
        hash::{HashedMessage, HashedPoPPayload, PreparedHashedMessage},
        prepared_g2::PreparedG2,
        proof_of_possession::{AsProofOfPossessionAffine, ProofOfPossessionAffine},
        pubkey::points::{AsPubkeyAffine, PopVerified, PubkeyAffine},
        signature::{AsSignatureAffine, SignatureAffine},
    },
    blstrs::G1Affine,
    group::prime::PrimeCurveAffine,
};
#[cfg(feature = "std")]
use {blstrs::G1Projective, group::Group, std::sync::LazyLock};

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
        let pubkey_bytes = self.try_as_affine()?.to_bytes_compressed();
        let hashed_pubkey = HashedPoPPayload::new(payload.unwrap_or(&[]), &pubkey_bytes);
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

/// A trait that provides signature verification methods to public-key-like types.
///
/// The crate-provided implementations are intentionally limited to `PopVerified<T>` and
/// aggregate public-key wrappers, so raw public key types from this crate do not gain
/// direct signature-verification methods before PoP verification. This trait remains public
/// as an extension point for downstream key wrappers. Implementing it for an unverified key
/// type opts out of the crate's PoP-verified usage convention and can reintroduce rogue-key
/// risks in aggregation or signer-attribution flows.
pub trait VerifySignature: AsPubkeyAffine {
    /// Uses this public key to verify any convertible signature type.
    fn verify_signature<S: AsSignatureAffine>(
        &self,
        signature: &S,
        message: &[u8],
    ) -> Result<(), BlsError> {
        let hashed_message = HashedMessage::new(message);
        self.verify_signature_pre_hashed(signature, &hashed_message)
    }

    /// Uses this public key to verify any convertible signature type using a pre-hashed message.
    fn verify_signature_pre_hashed<S: AsSignatureAffine>(
        &self,
        signature: &S,
        hashed_message: &HashedMessage,
    ) -> Result<(), BlsError> {
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(hashed_message);
        self.verify_signature_prepared(signature, &prepared_hashed_message)
    }

    /// Uses this public key to verify any convertible signature type using a prepared message.
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
        if bool::from(self.0.is_identity()) {
            return false;
        }

        // Check e(pubkey, H(m)) = e(g1, signature) without preparing
        // either G2 point.
        let generator = G1Affine::generator();
        let message_pairing =
            blst::blst_fp12::miller_loop(hashed_message.0.as_ref(), self.0.as_ref());
        let signature_pairing =
            blst::blst_fp12::miller_loop(signature.0.as_ref(), generator.as_ref());

        // Compare the pairings using one final exponentiation.
        blst::blst_fp12::finalverify(&message_pairing, &signature_pairing)
    }

    pub(crate) fn _verify_signature_prepared(
        &self,
        signature: &SignatureAffine,
        hashed_message_prepared: &PreparedG2,
    ) -> bool {
        if bool::from(self.0.is_identity()) {
            return false;
        }

        // Reuse the message's prepared table.
        let message_pairing = hashed_message_prepared.miller_loop(&self.0);

        // Compute the signature term directly, without a preparation table.
        let generator = G1Affine::generator();
        let signature_pairing =
            blst::blst_fp12::miller_loop(signature.0.as_ref(), generator.as_ref());

        // Check e(pubkey, H(m)) = e(g1, signature) with one final exponentiation.
        blst::blst_fp12::finalverify(&message_pairing, &signature_pairing)
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

        // Check e(pubkey, H(payload || pubkey_bytes)) = e(g1, proof)
        // without preparing either G2 point.
        let generator = G1Affine::generator();
        let payload_pairing =
            blst::blst_fp12::miller_loop(hashed_payload.0.as_ref(), self.0.as_ref());
        let proof_pairing = blst::blst_fp12::miller_loop(proof.0.as_ref(), generator.as_ref());

        // Compare the pairings using one final exponentiation.
        blst::blst_fp12::finalverify(&payload_pairing, &proof_pairing)
    }
}
