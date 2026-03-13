//! BLS signature types and cryptographic operations.
//!
//! This module provides the representations of BLS signatures on the BLS12-381
//! curve (G2 group), as well as the logic for aggregation and verification.
//!
//! Signatures can be represented as:
//! - **Bytes** (`Signature`, `SignatureCompressed`): For storage and network transmission.
//! - **Points** (`SignatureProjective`, `SignatureAffine`): For cryptographic operations.
//!
//! The module includes highly optimized multi-miller loop logic for verifying
//! aggregated signatures over both shared messages (multisig) and distinct
//! messages (batch verification).
//!
//! # Organization
//! - `bytes`: Raw byte definitions and base64 string conversions.
//! - `points`: Mathematical curve point wrappers and state traits.
//! - `conversion`: Implementations to losslessly convert between bytes, affine, and
//!   projective types.
//! - `aggregate`: Methods for combining multiple signatures into a single aggregate signature.
//! - `verify`: Multisig verification (Verifying multiple public keys against a **single**
//!   shared message).
//! - `verify_distinct`: Batch verification (Verifying multiple public keys against **multiple**
//!   distinct messages).

#[cfg(not(target_os = "solana"))]
pub mod aggregate;
pub mod bytes;
#[cfg(not(target_os = "solana"))]
pub mod conversion;
#[cfg(not(target_os = "solana"))]
pub mod points;
#[cfg(not(target_os = "solana"))]
pub mod verify;
#[cfg(not(target_os = "solana"))]
pub mod verify_distinct;

pub use bytes::{
    Signature, SignatureCompressed, BLS_SIGNATURE_AFFINE_BASE64_SIZE, BLS_SIGNATURE_AFFINE_SIZE,
    BLS_SIGNATURE_COMPRESSED_BASE64_SIZE, BLS_SIGNATURE_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use {
    points::{
        AddToSignatureProjective, AsSignatureAffine, AsSignatureProjective, SignatureAffine,
        SignatureAffineUnchecked, SignatureProjective,
    },
    verify::VerifiableSignature,
};

#[cfg(test)]
mod tests {
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use {
        super::*,
        crate::{
            error::BlsError,
            hash::{HashedMessage, PreparedHashedMessage},
            keypair::Keypair,
            pubkey::{
                AsPubkeyAffine, AsPubkeyProjective, PopVerified, Pubkey, PubkeyAffine,
                PubkeyCompressed, PubkeyProjective, VerifySignature,
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

        let pubkey_affine: PubkeyAffine = *keypair.public;
        let pubkey_projective: PubkeyProjective = pubkey_affine.into();
        let pubkey_uncompressed: Pubkey = pubkey_affine.into(); // [u8; 96]
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.into(); // [u8; 48]

        let verified_projective = unsafe { PopVerified::new_unchecked(pubkey_projective) };
        let verified_affine = unsafe { PopVerified::new_unchecked(pubkey_affine) };
        let verified_uncompressed = unsafe { PopVerified::new_unchecked(pubkey_uncompressed) };
        let verified_compressed = unsafe { PopVerified::new_unchecked(pubkey_compressed) };

        let signature_affine: SignatureAffine = signature_projective.into();
        let signature_uncompressed: Signature = signature_affine.into(); // [u8; 192]
        let signature_compressed: SignatureCompressed = signature_affine.into(); // [u8; 96]

        // Verify with PubkeyProjective
        assert!(verified_projective
            .verify_signature(&signature_projective, test_message)
            .is_ok());
        assert!(verified_projective
            .verify_signature(&signature_affine, test_message)
            .is_ok());
        assert!(verified_projective
            .verify_signature(&signature_uncompressed, test_message)
            .is_ok());
        assert!(verified_projective
            .verify_signature(&signature_compressed, test_message)
            .is_ok());

        // Verify with PubkeyAffine
        assert!(verified_affine
            .verify_signature(&signature_projective, test_message)
            .is_ok());
        assert!(verified_affine
            .verify_signature(&signature_affine, test_message)
            .is_ok());
        assert!(verified_affine
            .verify_signature(&signature_uncompressed, test_message)
            .is_ok());
        assert!(verified_affine
            .verify_signature(&signature_compressed, test_message)
            .is_ok());

        // Verify with Pubkey (Uncompressed Bytes)
        assert!(verified_uncompressed
            .verify_signature(&signature_projective, test_message)
            .is_ok());
        assert!(verified_uncompressed
            .verify_signature(&signature_affine, test_message)
            .is_ok());
        assert!(verified_uncompressed
            .verify_signature(&signature_uncompressed, test_message)
            .is_ok());
        assert!(verified_uncompressed
            .verify_signature(&signature_compressed, test_message)
            .is_ok());

        // Verify with PubkeyCompressed (Compressed Bytes)
        assert!(verified_compressed
            .verify_signature(&signature_projective, test_message)
            .is_ok());
        assert!(verified_compressed
            .verify_signature(&signature_affine, test_message)
            .is_ok());
        assert!(verified_compressed
            .verify_signature(&signature_uncompressed, test_message)
            .is_ok());
        assert!(verified_compressed
            .verify_signature(&signature_compressed, test_message)
            .is_ok());
    }

    #[test]
    fn test_signature_verification_prepared_hashed_message() {
        let keypair = Keypair::new();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = keypair.sign(message);

        let hashed_message = HashedMessage::new(message);
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(&hashed_message);
        let wrong_prepared_hashed_message = PreparedHashedMessage::new(wrong_message);

        assert!(keypair
            .public
            .verify_signature_prepared(&signature, &prepared_hashed_message)
            .is_ok());
        assert!(keypair
            .public
            .verify_signature_prepared(&signature, &wrong_prepared_hashed_message)
            .is_err());
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
            .is_ok());
        let keypair1 = Keypair::new();
        let signature1 = keypair1.secret.sign(test_message);
        assert!(keypair1
            .public
            .verify_signature(&signature1, test_message)
            .is_ok());
        // basic case
        assert!(SignatureProjective::verify_aggregate(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&signature0, &signature1].into_iter(),
            test_message,
        )
        .is_ok());
        let hashed_message = HashedMessage::new(test_message);
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(&hashed_message);
        assert!(SignatureProjective::verify_aggregate_pre_hashed(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&signature0, &signature1].into_iter(),
            &hashed_message,
        )
        .is_ok());
        assert!(SignatureProjective::verify_aggregate_prepared(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&signature0, &signature1].into_iter(),
            &prepared_hashed_message,
        )
        .is_ok());
        // verify with affine and compressed types
        let pubkey0_affine = keypair0.public;
        let pubkey1_affine = keypair1.public;
        let signature0_affine: SignatureAffine = signature0.into();
        let signature1_affine: SignatureAffine = signature1.into();
        assert!(SignatureProjective::verify_aggregate(
            [&pubkey0_affine, &pubkey1_affine].into_iter(),
            [&signature0_affine, &signature1_affine].into_iter(),
            test_message,
        )
        .is_ok());
        // pre-aggregate the signatures
        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1].into_iter()).unwrap();
        assert!(SignatureProjective::verify_aggregate(
            [&keypair0.public, &keypair1.public].into_iter(),
            [&aggregate_signature].into_iter(),
            test_message,
        )
        .is_ok());
        // pre-aggregate the public keys
        let aggregate_pubkey =
            PubkeyProjective::aggregate([&keypair0.public, &keypair1.public].into_iter()).unwrap();
        assert!(aggregate_pubkey
            .verify_signature(&aggregate_signature, test_message,)
            .is_ok());
        let pubkeys = Vec::new() as Vec<PopVerified<PubkeyProjective>>;

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
            Pubkey::from(*keypair0.public),
            Pubkey::from(*keypair1.public),
            Pubkey::from(*keypair2.public),
        ];
        let messages: Vec<&[u8]> = std::vec![message0, message1, message2];
        let signatures = std::vec![signature0, signature1, signature2];

        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            messages.iter().cloned()
        )
        .is_ok());
        let hashed_messages: Vec<_> = messages
            .iter()
            .map(|message| HashedMessage::new(message))
            .collect();
        let prepared_hashed_messages: Vec<_> = hashed_messages
            .iter()
            .map(PreparedHashedMessage::from_hashed_message)
            .collect();
        assert!(SignatureProjective::verify_distinct_pre_hashed(
            pubkeys.iter(),
            signatures.iter(),
            hashed_messages.iter(),
        )
        .is_ok());
        assert!(SignatureProjective::verify_distinct_prepared(
            pubkeys.iter(),
            signatures.iter(),
            prepared_hashed_messages.iter(),
        )
        .is_ok());

        // Failure cases
        let wrong_order_messages: Vec<&[u8]> = std::vec![message1, message0, message2];
        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            wrong_order_messages.into_iter()
        )
        .is_err());

        let one_wrong_message_refs: Vec<&[u8]> = std::vec![message0, b"this is wrong", message2];
        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            one_wrong_message_refs.into_iter()
        )
        .is_err());

        let wrong_keypair = Keypair::new();
        let wrong_pubkeys = [
            Pubkey::from(*keypair0.public),
            Pubkey::from(*wrong_keypair.public),
            Pubkey::from(*keypair2.public),
        ];
        assert!(SignatureProjective::verify_distinct(
            wrong_pubkeys.iter(),
            signatures.iter(),
            messages.iter().cloned()
        )
        .is_err());

        let wrong_signature_proj = wrong_keypair.sign(message1);
        let wrong_signature: Signature = wrong_signature_proj.into();
        let wrong_signatures = [signature0, wrong_signature, signature2];
        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            wrong_signatures.iter(),
            messages.iter().cloned()
        )
        .is_err());

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

        let err = SignatureProjective::verify_distinct(
            empty::<&Pubkey>(),
            empty::<&Signature>(),
            empty(),
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
    }

    #[test]
    fn test_verify_distinct_prepared_identical_messages() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let message = b"same message for all signers";
        let wrong_message = b"different message";

        let signature0: Signature = keypair0.sign(message).into();
        let signature1: Signature = keypair1.sign(message).into();
        let signature2: Signature = keypair2.sign(message).into();

        let pubkeys = [
            Pubkey::from(*keypair0.public),
            Pubkey::from(*keypair1.public),
            Pubkey::from(*keypair2.public),
        ];
        let signatures = [signature0, signature1, signature2];

        // All entries intentionally reuse the same prepared hash input.
        let prepared = PreparedHashedMessage::new(message);
        let prepared_same = [prepared.clone(), prepared.clone(), prepared.clone()];
        assert!(SignatureProjective::verify_distinct_prepared(
            pubkeys.iter(),
            signatures.iter(),
            prepared_same.iter(),
        )
        .is_ok());

        let wrong_prepared = PreparedHashedMessage::new(wrong_message);
        let prepared_wrong = [
            wrong_prepared.clone(),
            wrong_prepared.clone(),
            wrong_prepared.clone(),
        ];
        assert!(SignatureProjective::verify_distinct_prepared(
            pubkeys.iter(),
            signatures.iter(),
            prepared_wrong.iter(),
        )
        .is_err());
    }

    #[test]
    fn test_verify_distinct_subset_identical_messages() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let shared_message = b"shared message";
        let unique_message = b"unique message";

        let signature0: Signature = keypair0.sign(shared_message).into();
        let signature1: Signature = keypair1.sign(shared_message).into();
        let signature2: Signature = keypair2.sign(unique_message).into();

        let pubkeys = [
            Pubkey::from(*keypair0.public),
            Pubkey::from(*keypair1.public),
            Pubkey::from(*keypair2.public),
        ];
        let signatures = [signature0, signature1, signature2];
        let messages: Vec<&[u8]> = std::vec![shared_message, shared_message, unique_message];

        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            messages.iter().cloned(),
        )
        .is_ok());

        let wrong_messages: Vec<&[u8]> = std::vec![shared_message, shared_message, b"wrong"];
        assert!(SignatureProjective::verify_distinct(
            pubkeys.iter(),
            signatures.iter(),
            wrong_messages.iter().cloned(),
        )
        .is_err());
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

        let pubkey0: PubkeyProjective = (*keypair0.public).into(); // Projective
        let pubkey1_affine: PubkeyAffine = *keypair1.public; // Affine
        let pubkey2_compressed: PubkeyCompressed = (*keypair2.public).into(); // Compressed

        let signature0 = signature0_projective; // Projective
        let signature1_affine: SignatureAffine = signature1_projective.into(); // Affine
        let signature2_compressed: SignatureCompressed = signature2_projective.into(); // Compressed

        let p0: &dyn AsPubkeyProjective = &pubkey0;
        let p1: &dyn AsPubkeyProjective = &pubkey1_affine;
        let p2: &dyn AsPubkeyProjective = &pubkey2_compressed;

        let pop0 = unsafe { PopVerified::ref_unchecked(p0) };
        let pop1 = unsafe { PopVerified::ref_unchecked(p1) };
        let pop2 = unsafe { PopVerified::ref_unchecked(p2) };

        let dyn_pubkeys = std::vec![pop0, pop1, pop2];
        let dyn_signatures: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];

        assert!(SignatureProjective::verify_aggregate(
            dyn_pubkeys.into_iter(),
            dyn_signatures.into_iter(),
            test_message
        )
        .is_ok());

        let wrong_message = b"this is not the correct message";

        let p0_fail: &dyn AsPubkeyProjective = &pubkey0;
        let p1_fail: &dyn AsPubkeyProjective = &pubkey1_affine;
        let p2_fail: &dyn AsPubkeyProjective = &pubkey2_compressed;

        let pop0_fail = unsafe { PopVerified::ref_unchecked(p0_fail) };
        let pop1_fail = unsafe { PopVerified::ref_unchecked(p1_fail) };
        let pop2_fail = unsafe { PopVerified::ref_unchecked(p2_fail) };

        let dyn_pubkeys_fail = std::vec![pop0_fail, pop1_fail, pop2_fail];
        let dyn_signatures_fail: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];

        assert!(SignatureProjective::verify_aggregate(
            dyn_pubkeys_fail.into_iter(),
            dyn_signatures_fail.into_iter(),
            wrong_message
        )
        .is_err());
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
        let empty_agg = SignatureProjective::par_aggregate(empty.par_iter()).unwrap();
        assert_eq!(empty_agg, SignatureProjective::identity());
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_verify_aggregate() {
        let message = b"test message";
        let keypairs: Vec<_> = (0..5).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<_> = keypairs
            .iter()
            .map(|kp| unsafe { PopVerified::new_unchecked(PubkeyProjective::from(*kp.public)) })
            .collect();
        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();

        // Success case
        assert!(SignatureProjective::par_verify_aggregate(&pubkeys, &signatures, message).is_ok());
        let hashed_message = HashedMessage::new(message);
        let prepared_hashed_message = PreparedHashedMessage::from_hashed_message(&hashed_message);
        assert!(SignatureProjective::par_verify_aggregate_pre_hashed(
            &pubkeys,
            &signatures,
            &hashed_message
        )
        .is_ok());
        assert!(SignatureProjective::par_verify_aggregate_prepared(
            &pubkeys,
            &signatures,
            &prepared_hashed_message
        )
        .is_ok());

        // Failure case (wrong message)
        assert!(!SignatureProjective::par_verify_aggregate(
            &pubkeys,
            &signatures,
            b"wrong message"
        )
        .is_ok());

        // Failure case (bad signature)
        let mut bad_signatures = signatures.clone();
        bad_signatures[0] = keypairs[0].sign(b"a different message");
        assert!(
            !SignatureProjective::par_verify_aggregate(&pubkeys, &bad_signatures, message).is_ok()
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
            Pubkey::from(*keypair0.public),
            Pubkey::from(*keypair1.public),
            Pubkey::from(*keypair2.public),
        ];
        let messages_refs: Vec<&[u8]> = std::vec![message0, message1, message2];
        let signatures = [signature0, signature1, signature2];

        assert!(
            SignatureProjective::par_verify_distinct(&pubkeys, &signatures, &messages_refs).is_ok()
        );
        let hashed_messages: Vec<_> = messages_refs
            .iter()
            .map(|message| HashedMessage::new(message))
            .collect();
        let prepared_hashed_messages: Vec<_> = hashed_messages
            .iter()
            .map(PreparedHashedMessage::from_hashed_message)
            .collect();
        assert!(SignatureProjective::par_verify_distinct_pre_hashed(
            &pubkeys,
            &signatures,
            &hashed_messages
        )
        .is_ok());
        assert!(SignatureProjective::par_verify_distinct_prepared(
            &pubkeys,
            &signatures,
            &prepared_hashed_messages
        )
        .is_ok());
    }

    #[test]
    fn test_verify_signature_with_raw_bytes() {
        let keypair = Keypair::new();
        let message = b"byte interop test";
        let signature_projective = keypair.sign(message);

        let pubkey_bytes = keypair.public.to_bytes_compressed();
        let signature_bytes = signature_projective.to_bytes_compressed();

        let verified_bytes = unsafe { PopVerified::new_unchecked(pubkey_bytes) };

        assert!(verified_bytes
            .verify_signature(&signature_bytes, message)
            .is_ok());
        assert!(keypair
            .public
            .verify_signature(&signature_bytes, message)
            .is_ok());
        assert!(verified_bytes
            .verify_signature(&signature_bytes, message)
            .is_ok());

        // malleable public key
        let mut bad_pubkey_bytes = pubkey_bytes;
        bad_pubkey_bytes[0] ^= 0xFF;

        let bad_verified_bytes = unsafe { PopVerified::new_unchecked(bad_pubkey_bytes) };
        let result = bad_verified_bytes.verify_signature(&signature_bytes, message);
        assert!(result.is_err());

        // malleable signature
        let mut bad_signature_bytes = signature_bytes;
        bad_signature_bytes[0] ^= 0xFF;

        let result = verified_bytes.verify_signature(&bad_signature_bytes, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_mixed_addition_consistency() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let msg = b"consistency_check";

        let sig1 = keypair1.sign(msg);
        let sig2 = keypair2.sign(msg);

        // Projective + Projective
        let mut expected = sig1;
        expected.0 += sig2.0;

        // Projective + Affine via trait
        let mut optimized = sig1;
        let sig2_affine: SignatureAffine = sig2.into();

        sig2_affine.add_to_accumulator(&mut optimized).unwrap();

        assert_eq!(
            expected, optimized,
            "Mixed addition did not match projective addition for signatures"
        );
    }

    #[test]
    fn test_signature_unchecked_sanity() {
        let keypair = Keypair::new();
        let message = b"unchecked_sanity_test";
        let sig_proj = keypair.sign(message);

        let sig_compressed: SignatureCompressed = sig_proj.into();
        let sig_uncompressed: Signature = sig_proj.into();

        let unchecked_comp = SignatureAffineUnchecked::try_from(&sig_compressed)
            .expect("Should parse valid compressed bytes");

        let checked_comp = unchecked_comp
            .verify_subgroup()
            .expect("Valid signature should pass subgroup check");
        assert_eq!(SignatureAffine::from(sig_proj), checked_comp);

        let unchecked_uncomp = SignatureAffineUnchecked::try_from(&sig_uncompressed)
            .expect("Should parse valid uncompressed bytes");
        let checked_uncomp = unchecked_uncomp
            .verify_subgroup()
            .expect("Valid signature should pass subgroup check");
        assert_eq!(checked_comp, checked_uncomp);

        let mut acc = SignatureProjective::identity();
        unchecked_comp.add_to_accumulator(&mut acc).unwrap();
        assert_eq!(acc, sig_proj);
    }

    #[test]
    fn test_identity_points_behavior() {
        let keypair = Keypair::new();
        let test_message = b"identity test message";

        // Deserializing an identity Signature should succeed
        let id_sig_proj = SignatureProjective::identity();
        let id_sig_compressed: SignatureCompressed = (&id_sig_proj).into();
        let id_sig_recovered: Result<SignatureProjective, _> =
            SignatureProjective::try_from(&id_sig_compressed);
        assert!(
            id_sig_recovered.is_ok(),
            "Identity signatures must be allowed to deserialize"
        );
        assert_eq!(id_sig_proj, id_sig_recovered.unwrap());

        // Verifying with an identity Pubkey must fail
        let id_pubkey_proj = PubkeyProjective::identity();
        let id_pubkey_verified = unsafe { PopVerified::new_unchecked(id_pubkey_proj) };
        let valid_sig = keypair.sign(test_message);

        let verify_result = id_pubkey_verified.verify_signature(&valid_sig, test_message);
        assert!(
            verify_result.is_err(),
            "Verification with identity public key must fail"
        );

        // Aggregate public keys evaluating to identity must fail
        assert!(id_pubkey_verified
            .verify_signature(&id_sig_proj, test_message)
            .is_err());

        // Batch verification with an identity public key must fail
        let pubkey_affine: PubkeyAffine = *keypair.public;
        let id_pubkey_affine: PubkeyAffine = id_pubkey_proj.try_as_affine().unwrap();

        let p0: &dyn AsPubkeyProjective = &pubkey_affine;
        let p1: &dyn AsPubkeyProjective = &id_pubkey_affine;

        let pop0 = unsafe { PopVerified::ref_unchecked(p0) };
        let pop1 = unsafe { PopVerified::ref_unchecked(p1) };

        let dyn_pubkeys = std::vec![pop0, pop1];
        let dyn_signatures: std::vec::Vec<&dyn AsSignatureProjective> =
            std::vec![&valid_sig, &valid_sig];

        assert!(
            SignatureProjective::verify_aggregate(
                dyn_pubkeys.into_iter(),
                dyn_signatures.into_iter(),
                test_message
            )
            .is_err(),
            "Aggregate verification containing an identity public key must fail"
        );

        let pubkeys = [pubkey_affine, id_pubkey_affine];
        let signatures = [Signature::from(&valid_sig), Signature::from(&valid_sig)];
        let messages: std::vec::Vec<&[u8]> = std::vec![b"msg1", b"msg2"];

        assert!(
            SignatureProjective::verify_distinct(
                pubkeys.iter(),
                signatures.iter(),
                messages.into_iter()
            )
            .is_err(),
            "Batch distinct verification containing an identity public key must fail"
        );
    }

    #[test]
    fn test_aggregate_pubkeys_sum_to_identity() {
        let keypair = Keypair::new();
        let message = b"hello";

        // An honest key and its exact opposite (negation)
        let pk1 = PubkeyProjective::from(*keypair.public);
        let mut pk2 = pk1;
        pk2.0 = -pk2.0;

        let pop1 = unsafe { PopVerified::new_unchecked(pk1) };
        let pop2 = unsafe { PopVerified::new_unchecked(pk2) };

        let id_sig = SignatureProjective::identity();

        // Verify aggregate should definitively fail because the aggregated pubkey evaluates to identity
        assert!(SignatureProjective::verify_aggregate(
            [&pop1, &pop2].into_iter(),
            [&id_sig].into_iter(),
            message
        )
        .is_err());
    }
}
