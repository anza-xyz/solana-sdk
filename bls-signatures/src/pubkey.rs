#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{hash_message_to_point, hash_pubkey_to_g2},
        proof_of_possession::{AsProofOfPossessionProjective, ProofOfPossessionProjective},
        secret_key::SecretKey,
        signature::{AsSignatureProjective, SignatureProjective},
    },
    blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, Gt},
    group::Group,
    once_cell::sync::Lazy,
    pairing::{MillerLoopResult, MultiMillerLoop},
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

/// Size of a BLS public key in a compressed point representation
pub const BLS_PUBLIC_KEY_COMPRESSED_SIZE: usize = 48;

/// Size of a BLS public key in a compressed point representation in base64
pub const BLS_PUBLIC_KEY_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS public key in an affine point representation
pub const BLS_PUBLIC_KEY_AFFINE_SIZE: usize = 96;

/// Size of a BLS public key in an affine point representation in base64
pub const BLS_PUBLIC_KEY_AFFINE_BASE64_SIZE: usize = 256;

#[cfg(not(target_os = "solana"))]
static NEG_G1_GENERATOR_AFFINE: Lazy<G1Affine> = Lazy::new(|| (-G1Projective::generator()).into());

/// A trait for types that can be converted into a `PubkeyProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsPubkeyProjective {
    /// Attempt to convert the type into a `PubkeyProjective`.
    fn try_as_projective(&self) -> Result<PubkeyProjective, BlsError>;
}

/// A trait that provides verification methods to any convertible public key type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiablePubkey: AsPubkeyProjective {
    /// Uses this public key to verify any convertible signature type.
    fn verify_signature<S: AsSignatureProjective>(
        &self,
        signature: &S,
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let pubkey_projective = self.try_as_projective()?;
        let signature_projective = signature.try_as_projective()?;
        Ok(pubkey_projective._verify_signature(&signature_projective, message))
    }

    /// Uses this public key to verify any convertible proof of possession type.
    fn verify_proof_of_possession<P: AsProofOfPossessionProjective>(
        &self,
        proof: &P,
    ) -> Result<bool, BlsError> {
        let pubkey_projective = self.try_as_projective()?;
        let proof_projective = proof.try_as_projective()?;
        Ok(pubkey_projective._verify_proof_of_possession(&proof_projective))
    }
}

/// A BLS public key in a projective point representation
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeyProjective(pub(crate) G1Projective);

#[cfg(not(target_os = "solana"))]
impl PubkeyProjective {
    /// Creates the identity element, which is the starting point for aggregation
    ///
    /// The identity element is not a valid public key and it should only be used
    /// for the purpose of aggregation
    pub fn identity() -> Self {
        Self(G1Projective::identity())
    }

    /// Verify a signature and a message against a public key
    pub(crate) fn _verify_signature(
        &self,
        signature: &SignatureProjective,
        message: &[u8],
    ) -> bool {
        // The verification equation is e(pubkey, H(m)) = e(g1, signature).
        // This can be rewritten as e(pubkey, H(m)) * e(-g1, signature) = 1, which
        // allows for a more efficient verification using a multi-miller loop.
        let hashed_message: G2Affine = hash_message_to_point(message).into();
        let pubkey_affine: G1Affine = self.0.into();
        let signature_affine: G2Affine = signature.0.into();

        let hashed_message_prepared = G2Prepared::from(hashed_message);
        let signature_prepared = G2Prepared::from(signature_affine);

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&pubkey_affine, &hashed_message_prepared),
            (&NEG_G1_GENERATOR_AFFINE, &signature_prepared),
        ]);
        miller_loop_result.final_exponentiation() == Gt::identity()
    }

    /// Verify a proof of possession against a public key
    pub(crate) fn _verify_proof_of_possession(&self, proof: &ProofOfPossessionProjective) -> bool {
        // The verification equation is e(pubkey, H(pubkey)) == e(g1, proof).
        // This is rewritten to e(pubkey, H(pubkey)) * e(-g1, proof) = 1 for batching.
        let hashed_pubkey_affine: G2Affine = hash_pubkey_to_g2(self).into();
        let proof_affine: G2Affine = proof.0.into();

        let pubkey_affine: G1Affine = self.0.into();
        let hashed_pubkey_prepared = G2Prepared::from(hashed_pubkey_affine);
        let proof_prepared = G2Prepared::from(proof_affine);

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&pubkey_affine, &hashed_pubkey_prepared),
            // Reuse the same pre-computed static value here for efficiency
            (&NEG_G1_GENERATOR_AFFINE, &proof_prepared),
        ]);

        miller_loop_result.final_exponentiation() == Gt::identity()
    }

    /// Construct a corresponding `BlsPubkey` for a `BlsSecretKey`
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_secret(secret: &SecretKey) -> Self {
        Self(G1Projective::generator() * secret.0)
    }

    /// Aggregate a list of public keys into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, P: 'a + AsPubkeyProjective + ?Sized, I>(
        &mut self,
        pubkeys: I,
    ) -> Result<(), BlsError>
    where
        I: IntoIterator<Item = &'a P>,
    {
        for pubkey in pubkeys {
            self.0 += &pubkey.try_as_projective()?.0;
        }
        Ok(())
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, P: 'a + AsPubkeyProjective + ?Sized, I>(
        pubkeys: I,
    ) -> Result<PubkeyProjective, BlsError>
    where
        I: IntoIterator<Item = &'a P>,
    {
        let mut iter = pubkeys.into_iter();
        if let Some(first) = iter.next() {
            let mut aggregate = first.try_as_projective()?;
            aggregate.aggregate_with(iter)?;
            Ok(aggregate)
        } else {
            Err(BlsError::EmptyAggregation)
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsPubkeyProjective> VerifiablePubkey for T {}

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    PubkeyProjective,
    Pubkey,
    PubkeyCompressed,
    G1Affine,
    AsPubkeyProjective
);

#[cfg(not(target_os = "solana"))]
impl TryFrom<&[u8]> for PubkeyProjective {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != BLS_PUBLIC_KEY_AFFINE_SIZE {
            return Err(BlsError::ParseFromBytes);
        }
        // unwrap safe due to the length check above
        let public_affine = Pubkey(bytes.try_into().unwrap());

        public_affine.try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&PubkeyProjective> for [u8; BLS_PUBLIC_KEY_AFFINE_SIZE] {
    fn from(pubkey: &PubkeyProjective) -> Self {
        let pubkey_affine: Pubkey = (*pubkey).into();
        pubkey_affine.0
    }
}

/// A serialized BLS public key in a compressed point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PubkeyCompressed(
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")
    )]
    pub [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
);

impl Default for PubkeyCompressed {
    fn default() -> Self {
        Self([0; BLS_PUBLIC_KEY_COMPRESSED_SIZE])
    }
}

impl fmt::Display for PubkeyCompressed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PubkeyCompressed,
    BYTES_LEN = BLS_PUBLIC_KEY_COMPRESSED_SIZE,
    BASE64_LEN = BLS_PUBLIC_KEY_COMPRESSED_BASE64_SIZE
);

/// A serialized BLS public key in an affine point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Pubkey(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_PUBLIC_KEY_AFFINE_SIZE]"))]
    pub  [u8; BLS_PUBLIC_KEY_AFFINE_SIZE],
);

impl Default for Pubkey {
    fn default() -> Self {
        Self([0; BLS_PUBLIC_KEY_AFFINE_SIZE])
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = Pubkey,
    BYTES_LEN = BLS_PUBLIC_KEY_AFFINE_SIZE,
    BASE64_LEN = BLS_PUBLIC_KEY_AFFINE_BASE64_SIZE
);

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
#[cfg(feature = "bytemuck")]
mod bytemuck_impls {
    use super::*;
    unsafe impl Zeroable for PubkeyCompressed {}
    unsafe impl Pod for PubkeyCompressed {}
    unsafe impl ZeroableInOption for PubkeyCompressed {}
    unsafe impl PodInOption for PubkeyCompressed {}

    unsafe impl Zeroable for Pubkey {}
    unsafe impl Pod for Pubkey {}
    unsafe impl ZeroableInOption for Pubkey {}
    unsafe impl PodInOption for Pubkey {}
}

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
        std::{string::ToString, vec::Vec},
    };

    #[test]
    fn test_pubkey_verify_signature() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature_projective = keypair.sign(test_message);

        let pubkey_projective = keypair.public;
        let pubkey_affine: Pubkey = pubkey_projective.into();
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
        let proof_projective = keypair.proof_of_possession();

        let pubkey_projective = keypair.public;
        let pubkey_affine: Pubkey = pubkey_projective.into();
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let proof_affine: ProofOfPossession = proof_projective.into();
        let proof_compressed: ProofOfPossessionCompressed = proof_affine.try_into().unwrap();

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_projective)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_projective)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_projective)
            .unwrap());

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_affine)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_affine)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_affine)
            .unwrap());

        assert!(pubkey_projective
            .verify_proof_of_possession(&proof_compressed)
            .unwrap());
        assert!(pubkey_affine
            .verify_proof_of_possession(&proof_compressed)
            .unwrap());
        assert!(pubkey_compressed
            .verify_proof_of_possession(&proof_compressed)
            .unwrap());
    }

    #[test]
    fn test_pubkey_aggregate_dyn() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();

        let pubkey_projective = keypair0.public;
        let pubkey_affine: Pubkey = keypair1.public.into();
        let pubkey_compressed: PubkeyCompressed = Pubkey::from(keypair1.public).try_into().unwrap();

        let dyn_pubkeys: Vec<&dyn AsPubkeyProjective> =
            std::vec![&pubkey_projective, &pubkey_affine, &pubkey_compressed];

        let aggregate_from_dyn = PubkeyProjective::aggregate(dyn_pubkeys).unwrap();
        let pubkeys_for_baseline = [keypair0.public, keypair1.public, keypair1.public];
        let baseline_aggregate = PubkeyProjective::aggregate(&pubkeys_for_baseline).unwrap();

        assert_eq!(aggregate_from_dyn, baseline_aggregate);
    }

    #[test]
    fn pubkey_from_str() {
        let pubkey = Keypair::new().public;
        let pubkey_affine: Pubkey = pubkey.into();
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
}
