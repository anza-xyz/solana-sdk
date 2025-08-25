#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use {crate::pubkey::Pubkey, alloc::vec::Vec, core::num::NonZeroUsize, rayon::prelude::*};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        pubkey::{AsPubkeyProjective, PubkeyProjective, VerifiablePubkey},
    },
    blstrs::{G2Affine, G2Projective},
    group::Group,
};
use {
    base64::{prelude::BASE64_STANDARD, Engine},
    core::fmt,
};
#[cfg(feature = "serde")]
use {
    serde::{Deserialize, Serialize},
    serde_with::serde_as,
};

/// Size of a BLS signature in a compressed point representation
pub const BLS_SIGNATURE_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS signature in a compressed point representation in base64
pub const BLS_SIGNATURE_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS signature in an affine point representation
pub const BLS_SIGNATURE_AFFINE_SIZE: usize = 192;

/// Size of a BLS signature in an affine point representation in base64
pub const BLS_SIGNATURE_AFFINE_BASE64_SIZE: usize = 256;

/// Options for configuring advanced verification functions
#[cfg(all(feature = "parallel", not(target_os = "solana")))]
pub struct VerificationOptions {
    /// The number of signatures below which aggregation will be performed sequentially.
    pub aggregation_threshold: NonZeroUsize,
}

#[cfg(all(feature = "parallel", not(target_os = "solana")))]
impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            aggregation_threshold: NonZeroUsize::new(1).unwrap(),
        }
    }
}

/// A trait for types that can be converted into a `SignatureProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureProjective {
    /// Attempt to convert the type into a `SignatureProjective`.
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError>;
}

/// A trait for types that can be converted into a `Signature` (affine).
#[cfg(not(target_os = "solana"))]
pub trait AsSignature {
    /// Attempt to convert the type into a `Signature`.
    fn try_as_affine(&self) -> Result<Signature, BlsError>;
}

/// A trait that provides verification methods to any convertible signature type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiableSignature: AsSignatureProjective {
    /// Verify the signature against any convertible public key type and a message.
    fn verify<P: VerifiablePubkey>(&self, pubkey: &P, message: &[u8]) -> Result<bool, BlsError> {
        // The logic is defined once here.
        let signature_projective = self.try_as_projective()?;
        pubkey.verify_signature(&signature_projective, message)
    }
}

/// A BLS signature in a projective point representation
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
    pub fn aggregate_with<S: AsSignatureProjective + ?Sized>(
        &mut self,
        signatures: &[&S],
    ) -> Result<(), BlsError> {
        for signature in signatures {
            self.0 += signature.try_as_projective()?.0;
        }
        Ok(())
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<S: AsSignatureProjective + ?Sized>(
        signatures: &[&S],
    ) -> Result<SignatureProjective, BlsError> {
        if let Some((first, rest)) = signatures.split_first() {
            let mut aggregate = first.try_as_projective()?;
            aggregate.aggregate_with(rest)?;
            Ok(aggregate)
        } else {
            Err(BlsError::EmptyAggregation)
        }
    }

    /// Verify a list of signatures against a message and a list of public keys
    pub fn aggregate_verify<P: AsPubkeyProjective + ?Sized, S: AsSignatureProjective + ?Sized>(
        public_keys: &[&P],
        signatures: &[&S],
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }

    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_with<S: AsSignatureProjective + Sync>(
        &mut self,
        signatures: &[&S],
    ) -> Result<(), BlsError> {
        let aggregate = SignatureProjective::par_aggregate(signatures)?;
        self.0 += &aggregate.0;
        Ok(())
    }

    /// Aggregate a list of signatures
    #[allow(clippy::arithmetic_side_effects)]
    #[cfg(feature = "parallel")]
    pub fn par_aggregate<S: AsSignatureProjective + Sync>(
        signatures: &[&S],
    ) -> Result<SignatureProjective, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        signatures
            .into_par_iter()
            .map(|sig| (*sig).try_as_projective())
            .reduce(
                || Ok(SignatureProjective::identity()),
                |a, b| {
                    let mut a = a?;
                    let b = b?;
                    a.0 += &b.0;
                    Ok(a)
                },
            )
    }

    /// Verify a list of signatures against a message and a list of public keys
    /// individually in parallel.
    ///
    /// This function first attempts to verify all signatures at once via aggregation.
    /// If the aggregate verification succeeds, it returns a vector of `true`s.
    /// If it fails, it falls back to verifying each signature individually in parallel
    /// to identify the valid and invalid ones.
    #[cfg(feature = "parallel")]
    pub fn par_verify_batch(
        public_keys: &[&Pubkey],
        signatures: &[&Signature],
        message: &[u8],
    ) -> Result<Vec<bool>, BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        if public_keys.is_empty() {
            return Ok(Vec::new());
        }

        // First, try to verify by aggregating all public keys and signatures.
        //
        // Note that `par_aggregate_verify` will not terminate early since all public keys and
        // signatures are already in projective form
        if SignatureProjective::par_aggregate_verify(public_keys, signatures, message)? {
            Ok(alloc::vec![true; public_keys.len()])
        } else {
            // Use Rayon's parallel iterator to verify each signature concurrently.
            Ok(public_keys
                .par_iter()
                .zip(signatures.par_iter())
                .map(|(pubkey, signature)| pubkey._verify_signature(signature, message))
                .collect())
        }
    }

    /// Verify a list of signatures against a message and a list of public keys
    #[cfg(feature = "parallel")]
    pub fn par_aggregate_verify<P: AsPubkeyProjective + Sync, S: AsSignatureProjective + Sync>(
        public_keys: &[&P],
        signatures: &[&S],
        message: &[u8],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        let (aggregate_pubkey_res, aggregate_signature_res) = rayon::join(
            || PubkeyProjective::par_aggregate(public_keys),
            || SignatureProjective::par_aggregate(signatures),
        );
        let aggregate_pubkey = aggregate_pubkey_res?;
        let aggregate_signature = aggregate_signature_res?;
        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }

    /// Verify a list of signatures against a message and a list of public keys,
    /// identifying which signatures are valid.
    ///
    /// This function uses a highly optimized parallel binary search approach (divide and conquer)
    /// to efficiently identify invalid signatures in the batch (O(k log N) pairings).
    #[cfg(feature = "parallel")]
    pub fn par_verify_batch_binary_search(
        public_keys: &[&Pubkey],
        signatures: &[&Signature],
        message: &[u8],
        options: &VerificationOptions,
    ) -> Result<Vec<bool>, BlsError> {
        if public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        // Convert all inputs to the internal projective representation *once*
        // to avoid repeated expensive conversions (e.g., decompression) during recursion.
        let inputs: Result<Vec<(PubkeyProjective, SignatureProjective)>, BlsError> = public_keys
            .par_iter()
            .zip(signatures.par_iter())
            .map(|(pk, sig)| {
                let pk_proj = PubkeyProjective::try_from(*pk)?;
                let sig_proj = SignatureProjective::try_from(*sig)?;
                Ok((pk_proj, sig_proj))
            })
            .collect();

        let inputs = inputs?;
        let n = inputs.len();

        // Initialize results to false (invalid until proven valid).
        let mut results = alloc::vec![false; n];

        // Recursive identification.
        Self::recursive_identify(
            &inputs,
            message,
            &mut results,
            options.aggregation_threshold,
        );

        Ok(results)
    }

    /// Helper function to perform the parallelized binary search on pre-validated inputs.
    #[cfg(feature = "parallel")]
    #[allow(clippy::arithmetic_side_effects)]
    fn recursive_identify(
        inputs: &[(PubkeyProjective, SignatureProjective)],
        message: &[u8],
        results: &mut [bool],
        aggregation_threshold: NonZeroUsize,
    ) {
        if inputs.is_empty() {
            return;
        }

        // Aggregate the current batch.

        // For small subsets, sequential aggregation is often faster due to Rayon overhead.
        let (aggregate_pubkey, aggregate_signature) = if inputs.len() < aggregation_threshold.into()
        {
            // Sequential aggregation
            inputs.iter().fold(
                (
                    PubkeyProjective::identity(),
                    SignatureProjective::identity(),
                ),
                |(mut pk_acc, mut sig_acc), (pk, sig)| {
                    pk_acc.0 += &pk.0;
                    sig_acc.0 += &sig.0;
                    (pk_acc, sig_acc)
                },
            )
        } else {
            // Parallel aggregation
            inputs.par_iter().cloned().reduce(
                || {
                    (
                        PubkeyProjective::identity(),
                        SignatureProjective::identity(),
                    )
                },
                |(mut pk_acc, mut sig_acc), (pk, sig)| {
                    pk_acc.0 += &pk.0;
                    sig_acc.0 += &sig.0;
                    (pk_acc, sig_acc)
                },
            )
        };

        let is_valid = aggregate_pubkey
            .verify_signature(&aggregate_signature, message)
            .unwrap_or(false);

        if is_valid {
            // Success: Mark all in this batch as valid (in parallel).
            results.par_iter_mut().for_each(|r| *r = true);
        } else {
            // Failure: Identify the culprit(s).

            // Base case for recursion: if only one element remains and the aggregate failed,
            // it must be the invalid one (it remains marked false).
            if inputs.len() == 1 {
                return;
            }

            // Binary search: split and recurse in parallel.
            let mid = inputs.len() / 2;

            let (left_inputs, right_inputs) = inputs.split_at(mid);
            // Use split_at_mut to give exclusive mutable access to the corresponding results slice.
            // This guarantees thread safety without locks or atomics.
            let (left_results, right_results) = results.split_at_mut(mid);

            // Use rayon::join to process both halves concurrently.
            rayon::join(
                || {
                    Self::recursive_identify(
                        left_inputs,
                        message,
                        left_results,
                        aggregation_threshold,
                    )
                },
                || {
                    Self::recursive_identify(
                        right_inputs,
                        message,
                        right_results,
                        aggregation_threshold,
                    )
                },
            );
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsSignatureProjective> VerifiableSignature for T {}

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    SignatureProjective,
    Signature,
    SignatureCompressed,
    G2Affine,
    AsSignatureProjective,
    AsSignature
);

/// A serialized BLS signature in a compressed point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SignatureCompressed(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_COMPRESSED_SIZE]"))]
    pub  [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
);

impl Default for SignatureCompressed {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_COMPRESSED_SIZE])
    }
}

impl fmt::Display for SignatureCompressed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = SignatureCompressed,
    BYTES_LEN = BLS_SIGNATURE_COMPRESSED_SIZE,
    BASE64_LEN = BLS_SIGNATURE_COMPRESSED_BASE64_SIZE
);

/// A serialized BLS signature in an affine point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Signature(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_SIGNATURE_AFFINE_SIZE]"))]
    pub  [u8; BLS_SIGNATURE_AFFINE_SIZE],
);

impl Default for Signature {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_AFFINE_SIZE])
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = Signature,
    BYTES_LEN = BLS_SIGNATURE_AFFINE_SIZE,
    BASE64_LEN = BLS_SIGNATURE_AFFINE_BASE64_SIZE
);

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
#[cfg(feature = "bytemuck")]
mod bytemuck_impls {
    use super::*;

    unsafe impl Zeroable for Signature {}
    unsafe impl Pod for Signature {}
    unsafe impl ZeroableInOption for Signature {}
    unsafe impl PodInOption for Signature {}

    unsafe impl Zeroable for SignatureCompressed {}
    unsafe impl Pod for SignatureCompressed {}
    unsafe impl ZeroableInOption for SignatureCompressed {}
    unsafe impl PodInOption for SignatureCompressed {}
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            keypair::Keypair,
            pubkey::{Pubkey, PubkeyCompressed},
        },
        core::str::FromStr,
        std::{string::ToString, vec::Vec},
    };

    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature_projective = keypair.sign(test_message);

        let pubkey_projective: PubkeyProjective = (&keypair.public).try_into().unwrap();
        let pubkey_affine: Pubkey = pubkey_projective.into();
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let signature_affine: Signature = signature_projective.into();
        let signature_compressed: SignatureCompressed = signature_affine.try_into().unwrap();

        assert!(signature_projective
            .verify(&pubkey_projective, test_message)
            .unwrap());
        assert!(signature_affine
            .verify(&pubkey_projective, test_message)
            .unwrap());
        assert!(signature_compressed
            .verify(&pubkey_projective, test_message)
            .unwrap());

        assert!(signature_projective
            .verify(&pubkey_affine, test_message)
            .unwrap());
        assert!(signature_affine
            .verify(&pubkey_affine, test_message)
            .unwrap());
        assert!(signature_compressed
            .verify(&pubkey_affine, test_message)
            .unwrap());

        assert!(signature_projective
            .verify(&pubkey_compressed, test_message)
            .unwrap());
        assert!(signature_affine
            .verify(&pubkey_compressed, test_message)
            .unwrap());
        assert!(signature_compressed
            .verify(&pubkey_compressed, test_message)
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
        let signature1_affine: Signature = signature1.into();

        let aggregate_signature =
            SignatureProjective::aggregate(&[&signature0, &signature1]).unwrap();

        let mut aggregate_signature_with = signature0;
        aggregate_signature_with
            .aggregate_with(&[&signature1_affine])
            .unwrap();

        assert_eq!(aggregate_signature, aggregate_signature_with);
    }

    #[test]
    fn test_aggregate_verify() {
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
        assert!(SignatureProjective::aggregate_verify(
            &[&keypair0.public, &keypair1.public],
            &[&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // verify with affine and compressed types
        let pubkey0_affine: Pubkey = keypair0.public;
        let pubkey1_affine: Pubkey = keypair1.public;
        let signature0_affine: Signature = signature0.into();
        let signature1_affine: Signature = signature1.into();
        assert!(SignatureProjective::aggregate_verify(
            &[&pubkey0_affine, &pubkey1_affine],
            &[&signature0_affine, &signature1_affine],
            test_message,
        )
        .unwrap());

        // pre-aggregate the signatures
        let aggregate_signature =
            SignatureProjective::aggregate(&[&signature0, &signature1]).unwrap();
        assert!(SignatureProjective::aggregate_verify(
            &[&keypair0.public, &keypair1.public],
            &[&aggregate_signature],
            test_message,
        )
        .unwrap());

        // pre-aggregate the public keys
        let aggregate_pubkey =
            PubkeyProjective::aggregate(&[&keypair0.public, &keypair1.public]).unwrap();
        assert!(SignatureProjective::aggregate_verify(
            &[&aggregate_pubkey],
            &[&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // empty set of public keys or signatures
        let err = SignatureProjective::aggregate_verify(
            &[] as &[&PubkeyProjective],
            &[&signature0, &signature1],
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);

        let err = SignatureProjective::aggregate_verify(
            &[&keypair0.public, &keypair1.public],
            &[] as &[&SignatureProjective],
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
    }

    #[test]
    fn test_aggregate_verify_dyn() {
        let test_message = b"test message for dyn verify";

        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let signature0_projective = keypair0.sign(test_message);
        let signature1_projective = keypair1.sign(test_message);
        let signature2_projective = keypair2.sign(test_message);

        let pubkey0 = PubkeyProjective::try_from(keypair0.public).unwrap(); // Projective
        let pubkey1_affine: Pubkey = keypair1.public; // Affine
        let pubkey2_compressed: PubkeyCompressed = keypair2.public.try_into().unwrap(); // Compressed

        let signature0 = signature0_projective; // Projective
        let signature1_affine: Signature = signature1_projective.into(); // Affine
        let signature2_compressed: SignatureCompressed =
            Signature::from(signature2_projective).try_into().unwrap(); // Compressed

        let dyn_pubkeys: Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey0, &pubkey1_affine, &pubkey2_compressed];
        let dyn_signatures: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];

        assert!(
            SignatureProjective::aggregate_verify(&dyn_pubkeys, &dyn_signatures, test_message)
                .unwrap()
        );

        let wrong_message = b"this is not the correct message";
        let dyn_pubkeys_fail: Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey0, &pubkey1_affine, &pubkey2_compressed];
        let dyn_signatures_fail: Vec<&dyn AsSignatureProjective> =
            std::vec![&signature0, &signature1_affine, &signature2_compressed];
        assert!(!SignatureProjective::aggregate_verify(
            &dyn_pubkeys_fail,
            &dyn_signatures_fail,
            wrong_message
        )
        .unwrap());
    }

    #[test]
    fn signature_from_str() {
        let signature_affine = Signature([1; BLS_SIGNATURE_AFFINE_SIZE]);
        let signature_affine_string = signature_affine.to_string();
        let signature_affine_from_string = Signature::from_str(&signature_affine_string).unwrap();
        assert_eq!(signature_affine, signature_affine_from_string);

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
        let sequential_agg = SignatureProjective::aggregate(&[&signature0, &signature1]).unwrap();
        let parallel_agg = SignatureProjective::par_aggregate(&[&signature0, &signature1]).unwrap();
        assert_eq!(sequential_agg, parallel_agg);

        // Test `aggregate_with`
        let mut parallel_agg_with = signature0;
        parallel_agg_with
            .par_aggregate_with(&[&signature1])
            .unwrap();
        assert_eq!(sequential_agg, parallel_agg_with);

        // Test empty case
        let empty_slice: &[&SignatureProjective] = &[];
        assert_eq!(
            SignatureProjective::par_aggregate(empty_slice).unwrap_err(),
            BlsError::EmptyAggregation
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_aggregate_verify() {
        let message = b"test message";
        let keypairs: Vec<_> = (0..5).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<_> = keypairs
            .iter()
            .map(|kp| PubkeyProjective::try_from(&kp.public).unwrap())
            .collect();
        let pubkey_refs: Vec<_> = pubkeys.iter().collect();
        let signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let signature_refs: Vec<_> = signatures.iter().collect();

        // Success case
        assert!(
            SignatureProjective::par_aggregate_verify(&pubkey_refs, &signature_refs, message)
                .unwrap()
        );

        // Failure case (wrong message)
        assert!(!SignatureProjective::par_aggregate_verify(
            &pubkey_refs,
            &signature_refs,
            b"wrong message"
        )
        .unwrap());

        // Failure case (bad signature)
        let mut bad_signatures = signatures.clone();
        bad_signatures[0] = keypairs[0].sign(b"a different message");
        let bad_signature_refs: Vec<_> = bad_signatures.iter().collect();
        assert!(!SignatureProjective::par_aggregate_verify(
            &pubkey_refs,
            &bad_signature_refs,
            message
        )
        .unwrap());
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_par_verify_batch() {
        const NUM_SIGNATURES: usize = 10;
        let message = b"test message for par_verify_batch";

        // Generate keypairs, public keys, and signatures
        let keypairs: Vec<_> = (0..NUM_SIGNATURES).map(|_| Keypair::new()).collect();
        let pubkeys_affine: Vec<_> = keypairs.iter().map(|kp| kp.public).collect();
        let pubkeys: Vec<_> = pubkeys_affine.iter().collect();
        let signatures_proj: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let signatures_affine: Vec<_> = signatures_proj.iter().map(Signature::from).collect();
        let sig_refs: Vec<_> = signatures_affine.iter().collect();

        // All signatures are valid
        let results = SignatureProjective::par_verify_batch(&pubkeys, &sig_refs, message).unwrap();
        assert_eq!(results, std::vec![true; NUM_SIGNATURES]);

        // One signature is invalid (wrong message)
        let mut bad_signatures_proj = signatures_proj.clone();
        let bad_sig = keypairs[3].sign(b"a different message");
        bad_signatures_proj[3] = bad_sig;
        let bad_signatures_affine: Vec<_> =
            bad_signatures_proj.iter().map(Signature::from).collect();
        let bad_sig_refs: Vec<_> = bad_signatures_affine.iter().collect();

        let results =
            SignatureProjective::par_verify_batch(&pubkeys, &bad_sig_refs, message).unwrap();
        let mut expected = std::vec![true; NUM_SIGNATURES];
        expected[3] = false;
        assert_eq!(results, expected);

        // Input length mismatch
        let short_pubkeys = &pubkeys[..NUM_SIGNATURES - 1];
        let err =
            SignatureProjective::par_verify_batch(short_pubkeys, &sig_refs, message).unwrap_err();
        assert_eq!(err, BlsError::InputLengthMismatch);

        // Empty inputs
        let empty_pubkeys: &[&Pubkey] = &[];
        let empty_sigs: &[&Signature] = &[];
        let results =
            SignatureProjective::par_verify_batch(empty_pubkeys, empty_sigs, message).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_par_verify_batch_binary_search() {
        const NUM_SIGNATURES: usize = 50;
        let message = b"test message for binary search";

        // Generate keypairs, public keys, and valid signatures
        let keypairs: Vec<_> = (0..NUM_SIGNATURES).map(|_| Keypair::new()).collect();
        let pubkeys_affine: Vec<_> = keypairs.iter().map(|kp| kp.public).collect();
        let pubkeys: Vec<_> = pubkeys_affine.iter().collect();
        let signatures_proj: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let signatures_affine: Vec<_> = signatures_proj.iter().map(Signature::from).collect();
        let sig_refs: Vec<_> = signatures_affine.iter().collect();

        // Create some invalid signatures for testing
        let invalid_sig_wrong_msg = keypairs[0].sign(b"wrong message");
        let invalid_sig_wrong_key = Keypair::new().sign(message);

        let options_small_thresh = VerificationOptions {
            aggregation_threshold: std::num::NonZero::new(4).unwrap(), // Force parallel recursion
        };
        let options_large_thresh = VerificationOptions {
            aggregation_threshold: std::num::NonZero::new(100).unwrap(), // Force sequential aggregation
        };

        // All signatures are valid
        for options in [&options_small_thresh, &options_large_thresh] {
            let results = SignatureProjective::par_verify_batch_binary_search(
                &pubkeys, &sig_refs, message, options,
            )
            .unwrap();
            assert_eq!(results, std::vec![true; NUM_SIGNATURES]);
        }

        // One signature is invalid
        for options in [&options_small_thresh, &options_large_thresh] {
            let mut bad_signatures_proj = signatures_proj.clone();
            bad_signatures_proj[25] = invalid_sig_wrong_msg;
            let bad_signatures_affine: Vec<_> =
                bad_signatures_proj.iter().map(Signature::from).collect();
            let bad_sig_refs: Vec<_> = bad_signatures_affine.iter().collect();

            let results = SignatureProjective::par_verify_batch_binary_search(
                &pubkeys,
                &bad_sig_refs,
                message,
                options,
            )
            .unwrap();
            let mut expected = std::vec![true; NUM_SIGNATURES];
            expected[25] = false;
            assert_eq!(results, expected);
        }

        // Multiple signatures are invalid
        for options in [&options_small_thresh, &options_large_thresh] {
            let mut bad_signatures_proj = signatures_proj.clone();
            bad_signatures_proj[5] = invalid_sig_wrong_key;
            bad_signatures_proj[15] = invalid_sig_wrong_msg;
            bad_signatures_proj[45] = invalid_sig_wrong_key;
            let bad_signatures_affine: Vec<_> =
                bad_signatures_proj.iter().map(Signature::from).collect();
            let bad_sig_refs: Vec<_> = bad_signatures_affine.iter().collect();

            let results = SignatureProjective::par_verify_batch_binary_search(
                &pubkeys,
                &bad_sig_refs,
                message,
                options,
            )
            .unwrap();
            let mut expected = std::vec![true; NUM_SIGNATURES];
            expected[5] = false;
            expected[15] = false;
            expected[45] = false;
            assert_eq!(results, expected);
        }

        // All signatures are invalid
        for options in [&options_small_thresh, &options_large_thresh] {
            let bad_signatures_proj: Vec<_> =
                (0..NUM_SIGNATURES).map(|_| invalid_sig_wrong_msg).collect();
            let bad_signatures_affine: Vec<_> =
                bad_signatures_proj.iter().map(Signature::from).collect();
            let bad_sig_refs: Vec<_> = bad_signatures_affine.iter().collect();

            let results = SignatureProjective::par_verify_batch_binary_search(
                &pubkeys,
                &bad_sig_refs,
                message,
                options,
            )
            .unwrap();
            assert_eq!(results, std::vec![false; NUM_SIGNATURES]);
        }

        // Input length mismatch
        let short_pubkeys = &pubkeys[..NUM_SIGNATURES - 1];
        let err = SignatureProjective::par_verify_batch_binary_search(
            short_pubkeys,
            &sig_refs,
            message,
            &options_small_thresh,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::InputLengthMismatch);

        // Empty inputs
        let empty_pubkeys: &[&Pubkey] = &[];
        let empty_sigs: &[&Signature] = &[];
        let results = SignatureProjective::par_verify_batch_binary_search(
            empty_pubkeys,
            empty_sigs,
            message,
            &options_small_thresh,
        )
        .unwrap();
        assert!(results.is_empty());
    }
}
