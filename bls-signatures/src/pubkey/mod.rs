pub mod bytes;
pub mod conversion;
pub mod points;

pub use bytes::{
    Pubkey, PubkeyCompressed, BLS_PUBLIC_KEY_AFFINE_BASE64_SIZE, BLS_PUBLIC_KEY_AFFINE_SIZE,
    BLS_PUBLIC_KEY_COMPRESSED_BASE64_SIZE, BLS_PUBLIC_KEY_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use {
    bytes::{AsPubkey, VerifiablePubkey},
    points::{AsPubkeyProjective, PubkeyProjective},
};

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            keypair::Keypair,
            proof_of_possession::{ProofOfPossession, ProofOfPossessionCompressed},
            signature::{Signature, SignatureCompressed},
        },
        core::str::FromStr,
        std::string::ToString,
    };
    #[cfg(feature = "parallel")]
    use {crate::error::BlsError, rayon::prelude::*};

    #[test]
    fn test_pubkey_verify_signature() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature_projective = keypair.sign(test_message);

        let pubkey_projective: PubkeyProjective = (&keypair.public).try_into().unwrap();
        let pubkey_affine: Pubkey = keypair.public;
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let signature_affine: Signature = signature_projective.into();
        let signature_compressed: SignatureCompressed = signature_affine.try_into().unwrap();

        assert!(pubkey_projective
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_projective, test_message)
            .unwrap());

        assert!(pubkey_projective
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_affine, test_message)
            .unwrap());

        assert!(pubkey_projective
            .verify_signature(&signature_compressed, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_compressed, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_compressed, test_message)
            .unwrap());
    }

    #[test]
    fn test_pubkey_verify_proof_of_possession() {
        let keypair = Keypair::new();
        let proof_projective = keypair.proof_of_possession(None);

        let pubkey_projective: PubkeyProjective = (&keypair.public).try_into().unwrap();
        let pubkey_affine: Pubkey = pubkey_projective.into();
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let proof_affine: ProofOfPossession = proof_projective.into();
        let proof_compressed: ProofOfPossessionCompressed = proof_affine.try_into().unwrap();

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_projective, None)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_projective, None)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_projective, None)
            .unwrap());

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_affine, None)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_affine, None)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_affine, None)
            .unwrap());

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_compressed, None)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_compressed, None)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_compressed, None)
            .unwrap());
    }

    #[test]
    fn test_pubkey_aggregate_dyn() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();

        let pubkey_projective: PubkeyProjective = (&keypair0.public).try_into().unwrap();
        let pubkey_affine: Pubkey = keypair1.public;
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let dyn_pubkeys: std::vec::Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey_projective, &pubkey_affine, &pubkey_compressed];

        let aggregate_from_dyn = PubkeyProjective::aggregate(dyn_pubkeys.into_iter()).unwrap();
        let pubkeys_for_baseline = [&keypair0.public, &keypair1.public, &keypair1.public];
        let baseline_aggregate =
            PubkeyProjective::aggregate(pubkeys_for_baseline.into_iter()).unwrap();

        assert_eq!(aggregate_from_dyn, baseline_aggregate);
    }

    #[test]
    fn pubkey_from_str() {
        let pubkey_affine = Keypair::new().public;
        let pubkey_affine_string = pubkey_affine.to_string();
        let pubkey_affine_from_string = Pubkey::from_str(&pubkey_affine_string).unwrap();
        assert_eq!(pubkey_affine, pubkey_affine_from_string);

        let pubkey_compressed = PubkeyCompressed([1; BLS_PUBLIC_KEY_COMPRESSED_SIZE]);
        let pubkey_compressed_string = pubkey_compressed.to_string();
        let pubkey_compressed_from_string =
            PubkeyCompressed::from_str(&pubkey_compressed_string).unwrap();
        assert_eq!(pubkey_compressed, pubkey_compressed_from_string);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_and_deserialize_pubkey() {
        let original = Pubkey::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: Pubkey = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = Pubkey([1; BLS_PUBLIC_KEY_AFFINE_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: Pubkey = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_and_deserialize_pubkey_compressed() {
        let original = PubkeyCompressed::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: PubkeyCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = PubkeyCompressed([1; BLS_PUBLIC_KEY_COMPRESSED_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: PubkeyCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_pubkey_aggregation() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let pubkey0 = PubkeyProjective::try_from(&keypair0.public).unwrap();
        let pubkey1 = PubkeyProjective::try_from(&keypair1.public).unwrap();

        // Test `aggregate`
        let sequential_agg = PubkeyProjective::aggregate([pubkey0, pubkey1].iter()).unwrap();
        let parallel_agg = PubkeyProjective::par_aggregate([pubkey0, pubkey1].par_iter()).unwrap();
        assert_eq!(sequential_agg, parallel_agg);

        // Test `aggregate_with`
        let mut parallel_agg_with = pubkey0;
        parallel_agg_with
            .par_aggregate_with([pubkey1].par_iter())
            .unwrap();
        assert_eq!(sequential_agg, parallel_agg_with);

        // Test empty case
        let empty: std::vec::Vec<PubkeyProjective> = std::vec![];
        assert_eq!(
            PubkeyProjective::par_aggregate(empty.par_iter()).unwrap_err(),
            BlsError::EmptyAggregation
        );
    }
}
