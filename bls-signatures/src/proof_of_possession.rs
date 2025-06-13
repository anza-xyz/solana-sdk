#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{error::BlsError, pubkey::PubkeyProjective},
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
/// possession signing and verification functions. See
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.3.
pub const POP_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Size of a BLS proof of possession in a compressed point representation
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS proof of possession in a compressed point representation in base64
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_BASE64_SIZE: usize = 128;

/// Size of a BLS proof of possession in an affine point representation
pub const BLS_PROOF_OF_POSSESSION_AFFINE_SIZE: usize = 192;

/// Size of a BLS proof of possession in an affine point representation in base64
pub const BLS_PROOF_OF_POSSESSKON_AFFINE_BASE64_SIZE: usize = 256;

/// A BLS proof of possession in a projective point representation
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOfPossessionProjective(pub(crate) G2Projective);
#[cfg(not(target_os = "solana"))]
impl ProofOfPossessionProjective {
    /// Verify a proof of possession against a public key
    pub fn verify(&self, public_key: &PubkeyProjective) -> bool {
        public_key.verify_proof_of_possession(self)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<ProofOfPossessionProjective> for ProofOfPossession {
    fn from(proof: ProofOfPossessionProjective) -> Self {
        (&proof).into()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&ProofOfPossessionProjective> for ProofOfPossession {
    fn from(proof: &ProofOfPossessionProjective) -> Self {
        Self(proof.0.to_uncompressed())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<ProofOfPossession> for ProofOfPossessionProjective {
    type Error = BlsError;

    fn try_from(proof: ProofOfPossession) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&ProofOfPossession> for ProofOfPossessionProjective {
    type Error = BlsError;

    fn try_from(proof: &ProofOfPossession) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&proof.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}

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
    BASE64_LEN = BLS_PROOF_OF_POSSESSKON_AFFINE_BASE64_SIZE
);

#[cfg(not(target_os = "solana"))]
impl TryFrom<ProofOfPossession> for ProofOfPossessionCompressed {
    type Error = BlsError;

    fn try_from(proof: ProofOfPossession) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&ProofOfPossession> for ProofOfPossessionCompressed {
    type Error = BlsError;

    fn try_from(proof: &ProofOfPossession) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&proof.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.to_compressed()))
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<ProofOfPossessionCompressed> for ProofOfPossession {
    type Error = BlsError;

    fn try_from(proof: ProofOfPossessionCompressed) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&ProofOfPossessionCompressed> for ProofOfPossession {
    type Error = BlsError;

    fn try_from(proof: &ProofOfPossessionCompressed) -> Result<Self, Self::Error> {
        let maybe_compressed: Option<G2Affine> = G2Affine::from_compressed(&proof.0).into();
        let compressed = maybe_compressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(compressed.to_uncompressed()))
    }
}

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
    use {super::*, crate::keypair::Keypair, core::str::FromStr, std::string::ToString};

    #[test]
    fn test_proof_of_possession() {
        let keypair = Keypair::new();
        let proof = keypair.proof_of_possession();
        assert!(keypair.public.verify_proof_of_possession(&proof));
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
