#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

pub use crate::pod::{
    ProofOfPossession, ProofOfPossessionCompressed, Pubkey, PubkeyCompressed, Signature,
    SignatureCompressed, BLS_PROOF_OF_POSSESSION_AFFINE_SIZE,
    BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE, BLS_PUBLIC_KEY_AFFINE_SIZE,
    BLS_PUBLIC_KEY_COMPRESSED_SIZE, BLS_SIGNATURE_AFFINE_SIZE, BLS_SIGNATURE_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use crate::{
    error::BlsError,
    keypair::{PubkeyProjective, SecretKey, BLS_SECRET_KEY_SIZE},
    proof_of_possession::ProofOfPossessionProjective,
    signature::SignatureProjective,
};
#[cfg(not(target_os = "solana"))]
use {
    blstrs::{pairing, G1Affine, G2Projective},
    group::prime::PrimeCurveAffine,
};

// TODO: add conversion between compressed and uncompressed representation of
// signatures, pubkeys, and proof of possessions

#[cfg(not(target_os = "solana"))]
pub mod error;
#[cfg(not(target_os = "solana"))]
pub mod keypair;
pub mod pod;
#[cfg(not(target_os = "solana"))]
pub mod proof_of_possession;
#[cfg(not(target_os = "solana"))]
pub mod signature;

/// Domain separation tag used for hashing messages to curve points to prevent
/// potential conflicts between different BLS implementations. This is defined
/// as the ciphersuite ID string as recommended in the standard
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.1.
pub const HASH_TO_POINT_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Domain separation tag used when hashing public keys to G2 in the proof of
/// possession signing and verification functions. See
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.3.
pub const POP_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

#[cfg(not(target_os = "solana"))]
pub struct Bls;
#[cfg(not(target_os = "solana"))]
impl Bls {
    /// Sign a message using the provided secret key
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) fn sign(secret_key: &SecretKey, message: &[u8]) -> SignatureProjective {
        let hashed_message = Bls::hash_message_to_point(message);
        SignatureProjective(hashed_message * secret_key.0)
    }

    /// Verify a signature against a message and a public key
    ///
    /// TODO: Verify by invoking pairing just once
    pub(crate) fn verify(
        public_key: &PubkeyProjective,
        signature: &SignatureProjective,
        message: &[u8],
    ) -> bool {
        let hashed_message = Bls::hash_message_to_point(message);
        pairing(&public_key.0.into(), &hashed_message.into())
            == pairing(&G1Affine::generator(), &signature.0.into())
    }

    /// Generate a proof of possession for the given keypair
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) fn generate_proof_of_possession(
        secret_key: &SecretKey,
        public_key: &PubkeyProjective,
    ) -> ProofOfPossessionProjective {
        let hashed_pubkey_bytes = Self::hash_pubkey_to_g2(public_key);
        ProofOfPossessionProjective(hashed_pubkey_bytes * secret_key.0)
    }

    /// Verify a proof of possession against a public key
    pub(crate) fn verify_proof_of_possession(
        public_key: &PubkeyProjective,
        proof: &ProofOfPossessionProjective,
    ) -> bool {
        let hashed_pubkey_bytes = Self::hash_pubkey_to_g2(public_key);
        pairing(&public_key.0.into(), &hashed_pubkey_bytes.into())
            == pairing(&G1Affine::generator(), &proof.0.into())
    }

    /// Verify a list of signatures against a message and a list of public keys
    pub fn aggregate_verify<'a, I, J>(
        public_keys: I,
        signatures: J,
        message: &[u8],
    ) -> Result<bool, BlsError>
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
        J: IntoIterator<Item = &'a SignatureProjective>,
    {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        Ok(Self::verify(
            &aggregate_pubkey,
            &aggregate_signature,
            message,
        ))
    }

    /// Hash a message to a G2 point
    pub fn hash_message_to_point(message: &[u8]) -> G2Projective {
        G2Projective::hash_to_curve(message, HASH_TO_POINT_DST, &[])
    }

    /// Hash a pubkey to a G2 point
    pub(crate) fn hash_pubkey_to_g2(public_key: &PubkeyProjective) -> G2Projective {
        let pubkey_bytes = public_key.0.to_compressed();
        G2Projective::hash_to_curve(&pubkey_bytes, POP_DST, &[])
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::keypair::Keypair};

    #[test]
    fn test_verify() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature = Bls::sign(&keypair.secret, test_message);
        assert!(Bls::verify(&keypair.public, &signature, test_message));
    }

    #[test]
    fn test_aggregate_verify() {
        let test_message = b"test message";

        let keypair0 = Keypair::new();
        let signature0 = Bls::sign(&keypair0.secret, test_message);
        assert!(Bls::verify(&keypair0.public, &signature0, test_message));

        let keypair1 = Keypair::new();
        let signature1 = Bls::sign(&keypair1.secret, test_message);
        assert!(Bls::verify(&keypair1.public, &signature1, test_message));

        // basic case
        assert!(Bls::aggregate_verify(
            vec![&keypair0.public, &keypair1.public],
            vec![&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // pre-aggregate the signatures
        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1]).unwrap();
        assert!(Bls::aggregate_verify(
            vec![&keypair0.public, &keypair1.public],
            vec![&aggregate_signature],
            test_message,
        )
        .unwrap());

        // pre-aggregate the public keys
        let aggregate_pubkey =
            PubkeyProjective::aggregate([&keypair0.public, &keypair1.public]).unwrap();
        assert!(Bls::aggregate_verify(
            vec![&aggregate_pubkey],
            vec![&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // empty set of public keys or signatures
        let err = Bls::aggregate_verify(vec![], vec![&signature0, &signature1], test_message)
            .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);

        let err = Bls::aggregate_verify(
            vec![&keypair0.public, &keypair1.public],
            vec![],
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
    }

    #[test]
    fn test_proof_of_possession() {
        let keypair = Keypair::new();
        let proof = Bls::generate_proof_of_possession(&keypair.secret, &keypair.public);
        assert!(Bls::verify_proof_of_possession(&keypair.public, &proof));

        let invalid_secret_key = SecretKey::new();
        let invalid_proof = Bls::generate_proof_of_possession(&invalid_secret_key, &keypair.public);
        assert!(!Bls::verify_proof_of_possession(
            &keypair.public,
            &invalid_proof
        ));
    }
}
