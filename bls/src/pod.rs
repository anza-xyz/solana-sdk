use {
    bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption},
    serde::{Deserialize, Serialize},
    serde_with::serde_as,
};

/// Size of a BLS signature in a compressed point representation
pub const BLS_SIGNATURE_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS signature in an affine point representation
pub const BLS_SIGNATURE_AFFINE_SIZE: usize = 192;

/// A serialized BLS signature in a compressed point representation
#[serde_with::serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SignatureCompressed(
    #[serde_as(as = "[_; BLS_SIGNATURE_COMPRESSED_SIZE]")] pub [u8; BLS_SIGNATURE_COMPRESSED_SIZE],
);

impl Default for SignatureCompressed {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_COMPRESSED_SIZE])
    }
}

/// A serialized BLS signature in an affine point representation
#[serde_with::serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Signature(
    #[serde_as(as = "[_; BLS_SIGNATURE_AFFINE_SIZE]")] pub [u8; BLS_SIGNATURE_AFFINE_SIZE],
);

impl Default for Signature {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_AFFINE_SIZE])
    }
}

/// Size of a BLS proof of possession in a compressed point representation
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE: usize = 96;

/// Size of a BLS proof of possession in an affine point representation
pub const BLS_PROOF_OF_POSSESSION_AFFINE_SIZE: usize = 192;

/// A serialized BLS signature in a compressed point representation
#[serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ProofOfPossessionCompressed(
    #[serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]")]
    pub  [u8; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
);

impl Default for ProofOfPossessionCompressed {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE])
    }
}

/// A serialized BLS signature in an affine point representation
#[serde_as]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ProofOfPossession(
    #[serde_as(as = "[_; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE]")]
    pub  [u8; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE],
);

impl Default for ProofOfPossession {
    fn default() -> Self {
        Self([0; BLS_PROOF_OF_POSSESSION_AFFINE_SIZE])
    }
}

/// Size of a BLS public key in a compressed point representation
pub const BLS_PUBLIC_KEY_COMPRESSED_SIZE: usize = 48;

/// Size of a BLS public key in an affine point representation
pub const BLS_PUBLIC_KEY_AFFINE_SIZE: usize = 96;

/// A serialized BLS public key in a compressed point representation
#[serde_as]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct PubkeyCompressed(
    #[serde_as(as = "[_; BLS_PUBLIC_KEY_COMPRESSED_SIZE]")] pub [u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
);

impl Default for PubkeyCompressed {
    fn default() -> Self {
        Self([0; BLS_PUBLIC_KEY_COMPRESSED_SIZE])
    }
}

/// A serialized BLS public key in an affine point representation
#[serde_as]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Pubkey(
    #[serde_as(as = "[_; BLS_PUBLIC_KEY_AFFINE_SIZE]")] pub [u8; BLS_PUBLIC_KEY_AFFINE_SIZE],
);

impl Default for Pubkey {
    fn default() -> Self {
        Self([0; BLS_PUBLIC_KEY_AFFINE_SIZE])
    }
}

// Byte arrays are both `Pod` and `Zeraoble`, but the traits `bytemuck::Pod` and
// `bytemuck::Zeroable` can only be derived for power-of-two length byte arrays.
// Directly implement these traits for types that are simple wrappers around
// byte arrays.
unsafe impl Zeroable for PubkeyCompressed {}
unsafe impl Pod for PubkeyCompressed {}
unsafe impl ZeroableInOption for PubkeyCompressed {}
unsafe impl PodInOption for PubkeyCompressed {}

unsafe impl Zeroable for Pubkey {}
unsafe impl Pod for Pubkey {}
unsafe impl ZeroableInOption for Pubkey {}
unsafe impl PodInOption for Pubkey {}

unsafe impl Zeroable for Signature {}
unsafe impl Pod for Signature {}
unsafe impl ZeroableInOption for Signature {}
unsafe impl PodInOption for Signature {}

unsafe impl Zeroable for SignatureCompressed {}
unsafe impl Pod for SignatureCompressed {}
unsafe impl ZeroableInOption for SignatureCompressed {}
unsafe impl PodInOption for SignatureCompressed {}

unsafe impl Zeroable for ProofOfPossessionCompressed {}
unsafe impl Pod for ProofOfPossessionCompressed {}
unsafe impl ZeroableInOption for ProofOfPossessionCompressed {}
unsafe impl PodInOption for ProofOfPossessionCompressed {}

unsafe impl Zeroable for ProofOfPossession {}
unsafe impl Pod for ProofOfPossession {}
unsafe impl ZeroableInOption for ProofOfPossession {}
unsafe impl PodInOption for ProofOfPossession {}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn serialize_and_deserialize_signature() {
        let original = Signature::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: Signature = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = Signature([1; BLS_SIGNATURE_AFFINE_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: Signature = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serialize_and_deserialize_signature_compressed() {
        let original = SignatureCompressed::default();
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: SignatureCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);

        let original = SignatureCompressed([1; BLS_SIGNATURE_COMPRESSED_SIZE]);
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: SignatureCompressed = bincode::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

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
