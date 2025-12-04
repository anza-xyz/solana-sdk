pub mod bytes;
pub mod conversion;
pub mod points;

pub use bytes::{
    ProofOfPossession, ProofOfPossessionCompressed, BLS_PROOF_OF_POSSESSION_AFFINE_BASE64_SIZE,
    BLS_PROOF_OF_POSSESSION_AFFINE_SIZE, BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE,
    BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use {
    bytes::AsProofOfPossession,
    points::{
        AsProofOfPossessionProjective, ProofOfPossessionProjective, VerifiableProofOfPossession,
    },
};

/// Domain separation tag used when hashing public keys to G2 in the proof of
/// possession signing and verification functions. See the
/// [standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.3).
pub const POP_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            keypair::Keypair,
            pubkey::{Pubkey, PubkeyCompressed, PubkeyProjective, VerifiablePubkey},
        },
        core::str::FromStr,
        std::string::ToString,
    };

    #[test]
    fn test_proof_of_possession() {
        let keypair = Keypair::new();
        let proof_projective = keypair.proof_of_possession(None);

        let pubkey_projective: PubkeyProjective = (&keypair.public).try_into().unwrap();
        let pubkey_affine: Pubkey = keypair.public;
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let proof_affine: ProofOfPossession = proof_projective.into();
        let proof_compressed: ProofOfPossessionCompressed = proof_affine.try_into().unwrap();

        assert!(proof_projective.verify(&pubkey_projective, None).unwrap());
        assert!(proof_affine.verify(&pubkey_projective, None).unwrap());
        assert!(proof_compressed.verify(&pubkey_projective, None).unwrap());

        assert!(proof_projective.verify(&pubkey_affine, None).unwrap());
        assert!(proof_affine.verify(&pubkey_affine, None).unwrap());
        assert!(proof_compressed.verify(&pubkey_affine, None).unwrap());

        assert!(proof_projective.verify(&pubkey_compressed, None).unwrap());
        assert!(proof_affine.verify(&pubkey_compressed, None).unwrap());
        assert!(proof_compressed.verify(&pubkey_compressed, None).unwrap());
    }

    #[test]
    fn proof_of_possession_from_str() {
        let proof_of_possession = ProofOfPossession([1; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE]);
        let proof_of_possession_string = proof_of_possession.to_string();
        let proof_of_possession_from_string =
            ProofOfPossession::from_str(&proof_of_possession_string).unwrap();
        assert_eq!(proof_of_possession, proof_of_possession_from_string);

        let proof_of_possession_compressed =
            ProofOfPossessionCompressed([1; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]);
        let proof_of_possession_compressed_string = proof_of_possession_compressed.to_string();
        let proof_of_possession_compressed_from_string =
            ProofOfPossessionCompressed::from_str(&proof_of_possession_compressed_string).unwrap();
        assert_eq!(
            proof_of_possession_compressed,
            proof_of_possession_compressed_from_string
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_and_deserialize_proof_of_possession() {
        let original = ProofOfPossession::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: ProofOfPossession = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = ProofOfPossession([1; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: ProofOfPossession = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_and_deserialize_proof_of_possession_compressed() {
        let original = ProofOfPossessionCompressed::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: ProofOfPossessionCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = ProofOfPossessionCompressed([1; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: ProofOfPossessionCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_proof_of_possession_with_custom_payload() {
        let keypair = Keypair::new();
        let custom_payload = b"SIMD-0387-context-data";

        let proof_custom = keypair.proof_of_possession(Some(custom_payload));
        assert!(keypair
            .public
            .verify_proof_of_possession(&proof_custom, Some(custom_payload))
            .unwrap());

        assert!(!keypair
            .public
            .verify_proof_of_possession(&proof_custom, None) // try verify with `None`
            .unwrap());

        let wrong_payload = b"wrong-context";
        assert!(!keypair
            .public
            // try verify with wrong payload
            .verify_proof_of_possession(&proof_custom, Some(wrong_payload))
            .unwrap());

        // verify standard PoP behavior
        let proof_standard = keypair.proof_of_possession(None);
        // standard passes with None
        assert!(keypair
            .public
            .verify_proof_of_possession(&proof_standard, None)
            .unwrap());
        // standard fails with custom payload
        assert!(!keypair
            .public
            .verify_proof_of_possession(&proof_standard, Some(custom_payload))
            .unwrap());
    }
}
