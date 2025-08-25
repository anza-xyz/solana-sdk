#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{error::BlsError, pubkey::VerifiablePubkey},
    blstrs::{G2Affine, G2Projective},
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

/// Domain separation tag used when hashing public keys to G2 in the proof of
/// possession signing and verification functions. See the
/// [standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.3).
pub const POP_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Size of a BLS proof of possession in a compressed point representation
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS proof of possession in a compressed point representation in base64
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS proof of possession in an affine point representation
pub const BLS_PROOF_OF_POSSESSION_AFFINE_SIZE: usize = 192;

/// Size of a BLS proof of possession in an affine point representation in base64
pub const BLS_PROOF_OF_POSSESSION_AFFINE_BASE64_SIZE: usize = 256;

/// A trait for types that can be converted into a `ProofOfPossessionProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsProofOfPossessionProjective {
    /// Attempt to convert the type into a `ProofOfPossessionProjective`.
    fn try_as_projective(&self) -> Result<ProofOfPossessionProjective, BlsError>;
}

/// A trait for types that can be converted into a `ProofOfPossession` (affine).
#[cfg(not(target_os = "solana"))]
pub trait AsProofOfPossession {
    /// Attempt to convert the type into a `ProofOfPossession`.
    fn try_as_affine(&self) -> Result<ProofOfPossession, BlsError>;
}

/// A trait that provides verification methods to any convertible proof of possession type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiableProofOfPossession: AsProofOfPossessionProjective {
    /// Verifies the proof of possession against any convertible public key type.
    fn verify<P: VerifiablePubkey>(&self, pubkey: &P) -> Result<bool, BlsError> {
        let proof_projective = self.try_as_projective()?;
        pubkey.verify_proof_of_possession(&proof_projective)
    }
}

/// A BLS proof of possession in a projective point representation
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofOfPossessionProjective(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl<T: AsProofOfPossessionProjective> VerifiableProofOfPossession for T {}

#[cfg(not(target_os = "solana"))]
impl_bls_conversions!(
    ProofOfPossessionProjective,
    ProofOfPossession,
    ProofOfPossessionCompressed,
    G2Affine,
    AsProofOfPossessionProjective,
    AsProofOfPossession
);

/// A serialized BLS signature in a compressed point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ProofOfPossessionCompressed(
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]")
    )]
    pub [u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
);

impl Default for ProofOfPossessionCompressed {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE])
    }
}

impl fmt::Display for ProofOfPossessionCompressed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = ProofOfPossessionCompressed,
    BYTES_LEN = BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
    BASE64_LEN = BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE
);

/// A serialized BLS signature in an affine point representation
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ProofOfPossession(
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE]")
    )]
    pub [u8; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE],
);

impl Default for ProofOfPossession {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE])
    }
}

impl fmt::Display for ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = ProofOfPossession,
    BYTES_LEN = BLS_PROOF_OF_POSSESSION_AFFINE_SIZE,
    BASE64_LEN = BLS_PROOF_OF_POSSESSION_AFFINE_BASE64_SIZE
);

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
#[cfg(feature = "bytemuck")]
mod bytemuck_impls {
    use super::*;

    unsafe impl Zeroable for ProofOfPossessionCompressed {}
    unsafe impl Pod for ProofOfPossessionCompressed {}
    unsafe impl ZeroableInOption for ProofOfPossessionCompressed {}
    unsafe impl PodInOption for ProofOfPossessionCompressed {}

    unsafe impl Zeroable for ProofOfPossession {}
    unsafe impl Pod for ProofOfPossession {}
    unsafe impl ZeroableInOption for ProofOfPossession {}
    unsafe impl PodInOption for ProofOfPossession {}
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            keypair::Keypair,
            pubkey::{Pubkey, PubkeyCompressed, PubkeyProjective},
        },
        core::str::FromStr,
        std::string::ToString,
    };

    #[test]
    fn test_proof_of_possession() {
        let keypair = Keypair::new();
        let proof_projective = keypair.proof_of_possession();

        let pubkey_projective: PubkeyProjective = (&keypair.public).try_into().unwrap();
        let pubkey_affine: Pubkey = keypair.public;
        let pubkey_compressed: PubkeyCompressed = pubkey_affine.try_into().unwrap();

        let proof_affine: ProofOfPossession = proof_projective.into();
        let proof_compressed: ProofOfPossessionCompressed = proof_affine.try_into().unwrap();

        assert!(proof_projective.verify(&pubkey_projective).unwrap());
        assert!(proof_affine.verify(&pubkey_projective).unwrap());
        assert!(proof_compressed.verify(&pubkey_projective).unwrap());

        assert!(proof_projective.verify(&pubkey_affine).unwrap());
        assert!(proof_affine.verify(&pubkey_affine).unwrap());
        assert!(proof_compressed.verify(&pubkey_affine).unwrap());

        assert!(proof_projective.verify(&pubkey_compressed).unwrap());
        assert!(proof_affine.verify(&pubkey_compressed).unwrap());
        assert!(proof_compressed.verify(&pubkey_compressed).unwrap());
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
}
