pub mod bytes;
pub mod conversion;
pub mod points;

pub use bytes::{
    Signature, SignatureCompressed, BLS_SIGNATURE_AFFINE_BASE64_SIZE, BLS_SIGNATURE_AFFINE_SIZE,
    BLS_SIGNATURE_COMPRESSED_BASE64_SIZE, BLS_SIGNATURE_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use points::{
    AsSignatureAffine, AsSignatureProjective, SignatureAffine, SignatureProjective,
    VerifiableSignature,
};

#[cfg(test)]
mod tests {
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use {
        super::*,
        crate::{
            error::BlsError,
            keypair::Keypair,
            pubkey::{
                AsPubkeyProjective, Pubkey, PubkeyAffine, PubkeyCompressed, PubkeyProjective,
                VerifiablePubkey,
            },
        },
        core::{iter::empty, str::FromStr},
        std::{string::ToString, vec::Vec},
    };
    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::new();
        let test_message = b"test message";

        let signature_projective = keypair.sign(test_message);

        let pubkey_affine: PubkeyAffine = keypair.public;
        let pubkey_projective: PubkeyProjective = pubkey_affine.into();
        let pubkey_uncompressed: Pubkey = pubkey_affine.into(); // [u8; 96]
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.into(); // [u8; 48]

        let signature_affine: SignatureAffine = signature_projective.into();
        let signature_uncompressed: Signature = signature_affine.into(); // [u8; 192]
        let signature_compressed: SignatureCompressed = signature_affine.into(); // [u8; 96]

        // Verify with PubkeyProjective
        assert!(pubkey_projective
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_projective
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_projective
            .verify_signature(&signature_uncompressed, test_message)
            .unwrap());
        assert!(pubkey_projective
            .verify_signature(&signature_compressed, test_message)
            .unwrap());

        // Verify with PubkeyAffine
        assert!(pubkey_affine
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_uncompressed, test_message)
            .unwrap());
        assert!(pubkey_affine
            .verify_signature(&signature_compressed, test_message)
            .unwrap());

        // Verify with Pubkey (Uncompressed Bytes)
        assert!(pubkey_uncompressed
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_uncompressed
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_uncompressed
            .verify_signature(&signature_uncompressed, test_message)
            .unwrap());
        assert!(pubkey_uncompressed
            .verify_signature(&signature_compressed, test_message)
            .unwrap());

        // Verify with PubkeyCompressed (Compressed Bytes)
        assert!(pubkey_compressed
            .verify_signature(&signature_projective, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_affine, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_uncompressed, test_message)
            .unwrap());
        assert!(pubkey_compressed
            .verify_signature(&signature_compressed, test_message)
            .unwrap());
    }

    #[test]
    fn test_signature_aggregate() {
        let test_message = b"test message";
        let keypair0 = Keypair::new();
        let signature0 = keypair0.sign(test_message);

        let test_message = b"test message";
        let keypair1 = Keypair::new();
        let signature1 = keypair1.sign(test_message);
        let signature1_affine: SignatureAffine = signature1.into();

        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1].into_iter()).unwrap();
        let mut aggregate_signature_with = signature0;
        aggregate_signature_with
            .aggregate_with([&signature1_affine].into_iter())
            .unwrap();
        assert_eq!(aggregate_signature, aggregate_signature_with);
    }

    #[test]
    fn test_verify_aggregate() {
        let test_message = b"test message";
        let keypair0 = Keypair::new();
        let signature0 = keypair0.sign(test_message);
        assert!(keypair0
            .public
            .verify_signature(&signature0, test_message)
            .unwrap());
        let keypair1 = Keypair::new();
        let signature1 = keypair1.secret.sign(test_message);
        assert!(keypair1
            .public
            .verify_signature(&signature1, test_message)
            .unwrap());
        // basic case
        assert!(SignatureProjective::verify_aggregate(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&signature0, &signature1].into_iter(),
            test_message,
        )
        .unwrap());
        // verify with affine and compressed types
        let pubkey0_affine: PubkeyAffine = keypair0.public;
        let pubkey1_affine: PubkeyAffine = keypair1.public;
        let signature0_affine: SignatureAffine = signature0.into();
        let signature1_affine: SignatureAffine = signature1.into();
        assert!(SignatureProjective::verify_aggregate(
            [&pubkey0_affine, &pubkey1_affine].into_iter(),
            [&signature0_affine, &signature1_affine].into_iter(),
            test_message,
        )
        .unwrap());
        // pre-aggregate the signatures
        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1].into_iter()).unwrap();
        assert!(SignatureProjective::verify_aggregate(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&aggregate_signature].into_iter(),
            test_message,
        )
        .unwrap());
        // pre-aggregate the public keys
        let aggregate_pubkey =
            PubkeyProjective::aggregate([&keypair0.public, &keypair1.public].into_iter()).unwrap();
        assert!(SignatureProjective::verify_aggregate(
            [&aggregate_pubkey].into_iter(),
            [&signature0, &signature1].into_iter(),
            test_message,
        )
        .unwrap());
        let pubkeys = Vec::new() as Vec<PubkeyProjective>;

        // empty set of public keys or signatures
        let err = SignatureProjective::verify_aggregate(
            pubkeys.iter(),
            [&signature0, &signature1].into_iter(),
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);

        let signatures = Vec::new() as Vec<&SignatureProjective>;
        let err = SignatureProjective::verify_aggregate(
            [&keypair0.public, &keypair1.public].into_iter(),
            signatures.into_iter(),
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
    }

    #[test]
    fn test_verify_distinct() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let message0 = b"message zero";
        let message1 = b"message one";
        let message2 = b"message two";

        let signature0_proj = keypair0.sign(message0);
        let signature1_proj = keypair1.sign(message1);
        let signature2_proj = keypair2.sign(message2);

        let signature0: Signature = signature0_proj.into();
        let signature1: Signature = signature1_proj.into();
        let signature2: Signature = signature2_proj.into();

        // Success cases
        let pubkeys = [
            Pubkey::from(keypair0.public),
            Pubkey::from(keypair1.public),
            Pubkey::from(keypair2.public),
        ];
        let messages: Vec<&[u8]> = std::vec![message0, message1, message2];
        let signatures = std::vec![signature0, signature1, signature2];

        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            messages.iter().cloned()
        )
        .unwrap());

        // Failure cases
        let wrong_order_messages: Vec<&[u8]> = std::vec![message1, message0, message2];
        assert!(!SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            wrong_order_messages.into_iter()
        )
        .unwrap());

        let one_wrong_message_refs: Vec<&[u8]> = std::vec![message0, b"this is wrong", message2];
        assert!(!SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            one_wrong_message_refs.into_iter()
        )
        .unwrap());

        let wrong_keypair = Keypair::new();
        let wrong_pubkeys = [
            Pubkey::from(keypair0.public),
            Pubkey::from(wrong_keypair.public),
            Pubkey::from(keypair2.public),
        ];
        assert!(!SignatureProjective::verify_distinct(
            wrong_pubkeys.iter(),
            signatures.iter(),
            messages.iter().cloned()
        )
        .unwrap());

        let wrong_signature_proj = wrong_keypair.sign(message1);
        let wrong_signature: Signature = wrong_signature_proj.into();
        let wrong_signatures = [signature0, wrong_signature, signature2];
        assert!(!SignatureProjective::verify_distinct(
            pubkeys.iter(),
            wrong_signatures.iter(),
            messages.iter().cloned()
        )
        .unwrap());

        let err = SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            messages[..2].iter().cloned(),
        )
        .unwrap_err();
        assert_eq!(err, BlsError::InputLengthMismatch);

        let err = SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures[..2].iter(),
            messages.into_iter(),
        )
        .unwrap_err();
        assert_eq!(err, BlsError::InputLengthMismatch);

        let err = SignatureProjective::verify_distinct(empty(), empty(), empty()).unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
    }

    #[test]
    fn test_verify_aggregate_dyn() {
        let test_message = b"test message for dyn verify";
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let signature0_projective = keypair0.sign(test_message);
        let signature1_projective = keypair1.sign(test_message);
        let signature2_projective = keypair2.sign(test_message);

        let pubkey0: PubkeyProjective = keypair0.public.into(); // Projective
        let pubkey1_affine: PubkeyAffine = keypair1.public; // Affine
        let pubkey2_compressed: PubkeyCompressed = keypair2.public.into(); // Compressed

        let signature0 = signature0_projective; // Projective
        let signature1_affine: SignatureAffine = signature1_projective.into(); // Affine
        let signature2_compressed: SignatureCompressed = signature2_projective.into(); // Compressed

        let dyn_pubkeys: Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey0, &pubkey1_affine, &pubkey2_compressed];
        let dyn_signatures: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];
        assert!(SignatureProjective::verify_aggregate(
            dyn_pubkeys.into_iter(),
            dyn_signatures.into_iter(),
            test_message
        )
        .unwrap());

        let wrong_message = b"this is not the correct message";
        let dyn_pubkeys_fail: Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey0, &pubkey1_affine, &pubkey2_compressed];
        let dyn_signatures_fail: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];
        assert!(!SignatureProjective::verify_aggregate(
            dyn_pubkeys_fail.into_iter(),
            dyn_signatures_fail.into_iter(),
            wrong_message
        )
        .unwrap());
    }

    #[test]
    fn signature_from_str() {
        let signature_affine_bytes = Signature([1; BLS_SIGNATURE_AFFINE_SIZE]);
        let signature_affine_string = signature_affine_bytes.to_string();
        let signature_affine_from_string = Signature::from_str(&signature_affine_string).unwrap();
        assert_eq!(signature_affine_bytes, signature_affine_from_string);

        let signature_compressed = SignatureCompressed([1; BLS_SIGNATURE_COMPRESSED_SIZE]);
        let signature_compressed_string = signature_compressed.to_string();
        let signature_compressed_from_string =
            SignatureCompressed::from_str(&signature_compressed_string).unwrap();
        assert_eq!(signature_compressed, signature_compressed_from_string);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_signature_aggregation() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let signature0 = keypair0.sign(b"");
        let signature1 = keypair1.sign(b"");

        // Test `aggregate`
        let sequential_agg =
            SignatureProjective::aggregate([signature0, signature1].iter()).unwrap();
        let parallel_agg =
            SignatureProjective::par_aggregate([signature0, signature1].par_iter()).unwrap();
        assert_eq!(sequential_agg, parallel_agg);

        // Test `aggregate_with`
        let mut parallel_agg_with = signature0;
        parallel_agg_with
            .par_aggregate_with([signature1].par_iter())
            .unwrap();
        assert_eq!(sequential_agg, parallel_agg_with);

        // Test empty case
        let empty: std::vec::Vec<SignatureProjective> = Vec::new();
        assert_eq!(
            SignatureProjective::par_aggregate(empty.par_iter()).unwrap_err(),
            BlsError::EmptyAggregation
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_verify_aggregate() {
        let message = b"test message";
        let keypairs: Vec<_> = (0..5).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<_> = keypairs
            .iter()
            .map(|kp| PubkeyProjective::from(&kp.public))
            .collect();
        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();

        // Success case
        assert!(SignatureProjective::par_verify_aggregate(&pubkeys, &signatures, message).unwrap());

        // Failure case (wrong message)
        assert!(!SignatureProjective::par_verify_aggregate(
            &pubkeys,
            &signatures,
            b"wrong message"
        )
        .unwrap());

        // Failure case (bad signature)
        let mut bad_signatures = signatures.clone();
        bad_signatures[0] = keypairs[0].sign(b"a different message");
        assert!(
            !SignatureProjective::par_verify_aggregate(&pubkeys, &bad_signatures, message).unwrap()
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_par_verify_distinct() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let message0 = b"message zero";
        let message1 = b"message one";
        let message2 = b"message two";

        let signature0_proj = keypair0.sign(message0);
        let signature1_proj = keypair1.sign(message1);
        let signature2_proj = keypair2.sign(message2);

        let signature0: Signature = signature0_proj.into();
        let signature1: Signature = signature1_proj.into();
        let signature2: Signature = signature2_proj.into();

        // Use Pubkey (bytes) to match par_verify_distinct signature
        let pubkeys = [
            Pubkey::from(keypair0.public),
            Pubkey::from(keypair1.public),
            Pubkey::from(keypair2.public),
        ];
        let messages_refs: Vec<&[u8]> = std::vec![message0, message1, message2];
        let signatures = [signature0, signature1, signature2];

        assert!(
            SignatureProjective::par_verify_distinct(&pubkeys, &signatures, &messages_refs)
                .unwrap()
        );
    }

    #[test]
    fn test_verify_signature_with_raw_bytes() {
        let keypair = Keypair::new();
        let message = b"byte interop test";
        let signature_projective = keypair.sign(message);

        let pubkey_bytes = keypair.public.to_bytes_compressed();
        let signature_bytes = signature_projective.to_bytes_compressed();

        assert!(pubkey_bytes
            .verify_signature(&signature_bytes, message)
            .unwrap());
        assert!(keypair
            .public
            .verify_signature(&signature_bytes, message)
            .unwrap());
        assert!(pubkey_bytes
            .verify_signature(&signature_bytes, message)
            .unwrap());

        // malleable public key
        let mut bad_pubkey_bytes = pubkey_bytes;
        bad_pubkey_bytes[0] ^= 0xFF;

        let result = bad_pubkey_bytes.verify_signature(&signature_bytes, message);
        assert!(result.is_err());

        // malleable signature
        let mut bad_signature_bytes = signature_bytes;
        bad_signature_bytes[0] ^= 0xFF;

        let result = pubkey_bytes.verify_signature(&bad_signature_bytes, message);
        assert!(result.is_err());
    }
}
