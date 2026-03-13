//! BLS public key types and operations.
//!
//! This module provides the core representations of BLS public keys on the
//! BLS12-381 curve. It includes various forms of public keys to optimize for
//! different operations:
//!
//! - **Bytes** (`Pubkey`, `PubkeyCompressed`): For storage and serialization.
//! - **Points** (`PubkeyProjective`, `PubkeyAffine`): For mathematical operations.
//!   Projective points are faster for aggregation (addition), while affine
//!   points are required for pairing operations (verification).
//!
//! To prevent rogue key attacks during aggregation, this module also introduces
//! the `PopVerified` wrapper, ensuring that a public key has a valid Proof of
//! Possession before it can be used in an aggregated context.
//!
//! # Organization
//! - `bytes`: Raw byte definitions and base64 string conversions.
//! - `points`: Mathematical curve point wrappers and state traits.
//! - `conversion`: Implementations to losslessly convert between bytes, affine,
//!   and projective types.
//! - `aggregate`: Logic for aggregating multiple `PopVerified` public keys.
//! - `verify`: Traits (`VerifyPop`, `VerifySignature`) and multi-miller loop logic
//!   for verification.

#[cfg(not(target_os = "solana"))]
pub mod aggregate;
pub mod bytes;
#[cfg(not(target_os = "solana"))]
pub mod conversion;
#[cfg(not(target_os = "solana"))]
pub mod points;
#[cfg(not(target_os = "solana"))]
pub mod verify;

pub use bytes::{
    Pubkey, PubkeyCompressed, BLS_PUBLIC_KEY_AFFINE_BASE64_SIZE, BLS_PUBLIC_KEY_AFFINE_SIZE,
    BLS_PUBLIC_KEY_COMPRESSED_BASE64_SIZE, BLS_PUBLIC_KEY_COMPRESSED_SIZE,
};
#[cfg(not(target_os = "solana"))]
pub use {
    points::{
        AddToPubkeyProjective, AggregatePubkey, AsPubkeyAffine, AsPubkeyProjective, PopVerified,
        PubkeyAffine, PubkeyAffineUnchecked, PubkeyProjective,
    },
    verify::{VerifyPop, VerifySignature},
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
            proof_of_possession::{
                ProofOfPossession, ProofOfPossessionAffine, ProofOfPossessionCompressed,
            },
            signature::{Signature, SignatureAffine, SignatureCompressed},
        },
        core::str::FromStr,
        std::string::ToString,
    };

    #[test]
    fn test_pubkey_verify_signature() {
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
    fn test_pubkey_verify_proof_of_possession() {
        let keypair = Keypair::new();
        let proof_projective = keypair.proof_of_possession(None);

        let pubkey_affine: PubkeyAffine = *keypair.public;
        let pubkey_projective: PubkeyProjective = pubkey_affine.into();
        let pubkey_uncompressed: Pubkey = pubkey_affine.into();
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.into();

        let proof_affine: ProofOfPossessionAffine = proof_projective.into();
        let proof_uncompressed: ProofOfPossession = proof_affine.into();
        let proof_compressed: ProofOfPossessionCompressed = proof_affine.into();

        // Verify with PubkeyProjective
        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_projective, None)
            .is_ok());
        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_affine, None)
            .is_ok());
        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_uncompressed, None)
            .is_ok());
        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_compressed, None)
            .is_ok());

        // Verify with PubkeyAffine
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_projective, None)
            .is_ok());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_affine, None)
            .is_ok());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_uncompressed, None)
            .is_ok());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_compressed, None)
            .is_ok());

        // Verify with Pubkey (Uncompressed)
        assert!(pubkey_uncompressed
            .verify_proof_of_possession(&proof_projective, None)
            .is_ok());
        assert!(pubkey_uncompressed
            .verify_proof_of_possession(&proof_affine, None)
            .is_ok());
        assert!(pubkey_uncompressed
            .verify_proof_of_possession(&proof_uncompressed, None)
            .is_ok());
        assert!(pubkey_uncompressed
            .verify_proof_of_possession(&proof_compressed, None)
            .is_ok());

        // Verify with PubkeyCompressed
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_projective, None)
            .is_ok());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_affine, None)
            .is_ok());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_uncompressed, None)
            .is_ok());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_compressed, None)
            .is_ok());
    }

    #[test]
    fn test_pubkey_aggregate_dyn() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();

        let pubkey_projective: PubkeyProjective = (*keypair0.public).into();
        let pubkey_affine: PubkeyAffine = *keypair1.public;
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.into();

        let p0: &dyn AsPubkeyProjective = &pubkey_projective;
        let p1: &dyn AsPubkeyProjective = &pubkey_affine;
        let p2: &dyn AsPubkeyProjective = &pubkey_compressed;

        let pop0 = unsafe { PopVerified::ref_unchecked(p0) };
        let pop1 = unsafe { PopVerified::ref_unchecked(p1) };
        let pop2 = unsafe { PopVerified::ref_unchecked(p2) };

        let dyn_pubkeys = std::vec![pop0, pop1, pop2];

        let aggregate_from_dyn = PubkeyProjective::aggregate(dyn_pubkeys.into_iter()).unwrap();

        let pubkey0_proj: PubkeyProjective = (*keypair0.public).into();
        let pubkey1_proj: PubkeyProjective = (*keypair1.public).into();

        let pop0_proj = unsafe { PopVerified::new_unchecked(pubkey0_proj) };
        let pop1_proj = unsafe { PopVerified::new_unchecked(pubkey1_proj) };

        let pubkeys_for_baseline = [&pop0_proj, &pop1_proj, &pop1_proj];
        let baseline_aggregate =
            PubkeyProjective::aggregate(pubkeys_for_baseline.into_iter()).unwrap();

        assert_eq!(aggregate_from_dyn.0, baseline_aggregate.0);
    }

    #[test]
    fn pubkey_from_str() {
        let pubkey_affine_bytes: Pubkey = (*Keypair::new().public).into();
        let pubkey_affine_string = pubkey_affine_bytes.to_string();
        let pubkey_affine_from_string = Pubkey::from_str(&pubkey_affine_string).unwrap();
        assert_eq!(pubkey_affine_bytes, pubkey_affine_from_string);

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

        let pubkey0: PubkeyProjective = (*keypair0.public).into();
        let pubkey1: PubkeyProjective = (*keypair1.public).into();

        let pop0 = unsafe { PopVerified::new_unchecked(pubkey0) };
        let pop1 = unsafe { PopVerified::new_unchecked(pubkey1) };

        // Test `aggregate`
        let sequential_agg = PubkeyProjective::aggregate([pop0, pop1].iter()).unwrap();
        let parallel_agg = PubkeyProjective::par_aggregate([pop0, pop1].par_iter()).unwrap();
        assert_eq!(sequential_agg, parallel_agg);

        // Test `aggregate_with`
        let mut parallel_agg_with = pubkey0;
        parallel_agg_with
            .par_aggregate_with([pop1].par_iter())
            .unwrap();

        assert_eq!(*sequential_agg, parallel_agg_with);

        // Test empty case
        let empty: std::vec::Vec<PopVerified<PubkeyProjective>> = std::vec![];
        let empty_agg = PubkeyProjective::par_aggregate(empty.par_iter()).unwrap();

        // Dereference `empty_agg` to compare against identity
        assert_eq!(*empty_agg, PubkeyProjective::identity());
    }

    #[test]
    fn test_invalid_length_pubkeys() {
        let keypair = Keypair::new();
        let pubkey_bytes = keypair.public.to_bytes_compressed();

        let mut pubkey_long_bytes = alloc::vec::Vec::from(pubkey_bytes);
        pubkey_long_bytes.extend_from_slice(&[0u8; 1]); // Length is now 49

        assert_eq!(
            PubkeyProjective::try_from(pubkey_long_bytes.as_slice()).unwrap_err(),
            BlsError::ParseFromBytes
        );

        let pubkey_short_bytes = &pubkey_bytes[..47];
        assert_eq!(
            PubkeyProjective::try_from(pubkey_short_bytes).unwrap_err(),
            BlsError::ParseFromBytes
        );
    }

    #[test]
    fn test_pubkey_mixed_addition_consistency() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let pk1: PubkeyProjective = (*keypair1.public).into();
        let pk2: PubkeyProjective = (*keypair2.public).into();

        // Projective + Projective
        let mut expected = pk1;
        expected.0 += pk2.0;

        // Projective + Affine via trait
        let mut optimized = pk1;
        let pk2_affine: PubkeyAffine = *keypair2.public; // Already affine

        pk2_affine.add_to_accumulator(&mut optimized).unwrap();

        assert_eq!(
            expected, optimized,
            "Mixed addition did not match projective addition for pubkeys"
        );
    }

    #[test]
    fn test_identity_pubkey_deserialization_fails() {
        let id_pk_proj = PubkeyProjective::identity();

        // Assert compressed byte conversion fails
        let id_pk_compressed: PubkeyCompressed = (&id_pk_proj).into();
        let recovered = PubkeyProjective::try_from(&id_pk_compressed);
        assert_eq!(recovered.unwrap_err(), BlsError::PointConversion);

        // Assert uncompressed byte conversion fails
        let id_pk_uncompressed: Pubkey = (&id_pk_proj).into();
        let recovered_uncompressed = PubkeyProjective::try_from(&id_pk_uncompressed);
        assert_eq!(
            recovered_uncompressed.unwrap_err(),
            BlsError::PointConversion
        );
    }
}
