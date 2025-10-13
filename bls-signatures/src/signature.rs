#[cfg(all(not(target_os = "solana"), feature = "std"))]
use crate::pubkey::NEG_G1_GENERATOR_AFFINE;
#[cfg(not(feature = "std"))]
use blstrs::G1Projective;
#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::hash_message_to_point,
        pubkey::{AsPubkeyProjective, Pubkey, PubkeyProjective, VerifiablePubkey},
    },
    blstrs::{Bls12, G1Affine, G2Affine, G2Prepared, G2Projective, Gt},
    group::Group,
    pairing::{MillerLoopResult, MultiMillerLoop},
};
#[cfg(all(feature = "parallel", not(target_os = "solana")))]
use {alloc::vec::Vec, rayon::prelude::*};
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
    pub fn aggregate_with<'a, S: AsSignatureProjective + ?Sized + 'a>(
        &mut self,
        signatures: impl Iterator<Item = &'a S>,
    ) -> Result<(), BlsError> {
        for signature in signatures {
            self.0 += signature.try_as_projective()?.0;
        }
        Ok(())
    }

    /// Aggregate a list of signatures
    pub fn aggregate<'a, S: AsSignatureProjective + ?Sized + 'a>(
        mut signatures: impl Iterator<Item = &'a S>,
    ) -> Result<SignatureProjective, BlsError> {
        match signatures.next() {
            Some(first) => {
                let mut aggregate = first.try_as_projective()?;
                aggregate.aggregate_with(signatures)?;
                Ok(aggregate)
            }
            None => Err(BlsError::EmptyAggregation),
        }
    }

    /// Verify a list of signatures against a message and a list of public keys
    pub fn verify_aggregate<
        'a,
        P: AsPubkeyProjective + ?Sized + 'a,
        S: AsSignatureProjective + ?Sized + 'a,
    >(
        public_keys: impl Iterator<Item = &'a P>,
        signatures: impl Iterator<Item = &'a S>,
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }

    /// Verifies an aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct<'a>(
        public_keys: impl ExactSizeIterator<Item = &'a Pubkey>,
        signatures: impl ExactSizeIterator<Item = &'a Signature>,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;
        Self::verify_distinct_aggregated(public_keys, &aggregate_signature.into(), messages)
    }

    /// Verifies a pre-aggregated signature over a set of distinct messages and
    /// public keys.
    pub fn verify_distinct_aggregated<'a>(
        public_keys: impl ExactSizeIterator<Item = &'a Pubkey>,
        aggregate_signature: &Signature,
        messages: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }

        // TODO: remove `Vec` allocation if possible for efficiency
        let mut pubkeys_affine = alloc::vec::Vec::with_capacity(public_keys.len());
        let public_keys_len = public_keys.len();
        for pubkey in public_keys {
            let maybe_g1_affine: Option<_> = G1Affine::from_uncompressed(&pubkey.0).into();
            let g1_affine: G1Affine = maybe_g1_affine.ok_or(BlsError::PointConversion)?;
            pubkeys_affine.push(g1_affine);
        }

        let mut prepared_hashes = alloc::vec::Vec::with_capacity(messages.len());
        for message in messages {
            let hashed_message: G2Affine = hash_message_to_point(message).into();
            prepared_hashes.push(G2Prepared::from(hashed_message));
        }

        let maybe_aggregate_signature_affine: Option<G2Affine> =
            G2Affine::from_uncompressed(&aggregate_signature.0).into();
        let aggregate_signature_affine =
            maybe_aggregate_signature_affine.ok_or(BlsError::PointConversion)?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let mut terms = alloc::vec::Vec::with_capacity(public_keys_len.saturating_add(1));
        for i in 0..public_keys_len {
            terms.push((&pubkeys_affine[i], &prepared_hashes[i]));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        Ok(miller_loop_result.final_exponentiation() == Gt::identity())
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
    #[cfg(feature = "parallel")]
    pub fn par_verify_aggregate<P: AsPubkeyProjective + Sync, S: AsSignatureProjective + Sync>(
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

    /// Verifies a set of signatures over a set of distinct messages and
    /// public keys in parallel.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct(
        public_keys: &[&Pubkey],
        signatures: &[&Signature],
        messages: &[&[u8]],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }
        let aggregate_signature = SignatureProjective::par_aggregate(signatures)?;
        Self::par_verify_distinct_aggregated(public_keys, &aggregate_signature.into(), messages)
    }

    /// In parallel, verifies a pre-aggregated signature over a set of distinct
    /// messages and public keys.
    #[cfg(feature = "parallel")]
    pub fn par_verify_distinct_aggregated(
        public_keys: &[&Pubkey],
        aggregate_signature: &Signature,
        messages: &[&[u8]],
    ) -> Result<bool, BlsError> {
        if public_keys.len() != messages.len() {
            return Err(BlsError::InputLengthMismatch);
        }
        if public_keys.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }

        // Use `rayon` to perform the three expensive, independent tasks in parallel:
        // 1. Deserialize public keys into curve points.
        // 2. Hash messages into curve points and prepare them for pairing.
        let (pubkeys_affine_res, prepared_hashes_res): (Result<Vec<_>, _>, Result<Vec<_>, _>) =
            rayon::join(
                || {
                    public_keys
                        .par_iter()
                        .map(|pk| {
                            let maybe_pubkey_affine: Option<_> =
                                G1Affine::from_uncompressed(&pk.0).into();
                            maybe_pubkey_affine.ok_or(BlsError::PointConversion)
                        })
                        .collect()
                },
                || {
                    messages
                        .par_iter()
                        .map(|msg| {
                            let hashed_message: G2Affine = hash_message_to_point(msg).into();
                            Ok::<_, BlsError>(G2Prepared::from(hashed_message))
                        })
                        .collect()
                },
            );

        // Check for errors from the parallel operations and unwrap the results.
        let pubkeys_affine = pubkeys_affine_res?;
        let prepared_hashes = prepared_hashes_res?;

        let maybe_aggregate_signature_affine: Option<G2Affine> =
            G2Affine::from_uncompressed(&aggregate_signature.0).into();
        let aggregate_signature_affine =
            maybe_aggregate_signature_affine.ok_or(BlsError::PointConversion)?;
        let signature_prepared = G2Prepared::from(aggregate_signature_affine);

        #[cfg(feature = "std")]
        let neg_g1_generator = &*NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let mut terms = alloc::vec::Vec::with_capacity(public_keys.len() + 1);
        for i in 0..public_keys.len() {
            terms.push((&pubkeys_affine[i], &prepared_hashes[i]));
        }
        terms.push((neg_g1_generator, &signature_prepared));

        let miller_loop_result = Bls12::multi_miller_loop(&terms);
        Ok(miller_loop_result.final_exponentiation() == Gt::identity())
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
        core::{iter::empty, str::FromStr},
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
        let pubkey0_affine: Pubkey = keypair0.public;
        let pubkey1_affine: Pubkey = keypair1.public;
        let signature0_affine: Signature = signature0.into();
        let signature1_affine: Signature = signature1.into();
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
        let pubkeys = [keypair0.public, keypair1.public, keypair2.public];
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
        let wrong_pubkeys = [keypair0.public, wrong_keypair.public, keypair2.public];
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
        let sequential_agg =
            SignatureProjective::aggregate([signature0, signature1].iter()).unwrap();
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
    fn test_parallel_verify_aggregate() {
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
            SignatureProjective::par_verify_aggregate(&pubkey_refs, &signature_refs, message)
                .unwrap()
        );

        // Failure case (wrong message)
        assert!(!SignatureProjective::par_verify_aggregate(
            &pubkey_refs,
            &signature_refs,
            b"wrong message"
        )
        .unwrap());

        // Failure case (bad signature)
        let mut bad_signatures = signatures.clone();
        bad_signatures[0] = keypairs[0].sign(b"a different message");
        let bad_signature_refs: Vec<_> = bad_signatures.iter().collect();
        assert!(!SignatureProjective::par_verify_aggregate(
            &pubkey_refs,
            &bad_signature_refs,
            message
        )
        .unwrap());
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

        let pubkeys = [&keypair0.public, &keypair1.public, &keypair2.public];
        let messages_refs: Vec<&[u8]> = std::vec![message0, message1, message2];
        let signatures = [&signature0, &signature1, &signature2];

        assert!(
            SignatureProjective::par_verify_distinct(&pubkeys, &signatures, &messages_refs,)
                .unwrap()
        );
    }
}
