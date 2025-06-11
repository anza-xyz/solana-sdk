#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{hash_message_to_point, hash_pubkey_to_g2},
        proof_of_possession::ProofOfPossessionProjective,
        secret_key::SecretKey,
        signature::SignatureProjective,
    },
    blstrs::{pairing, G1Affine, G1Projective},
    group::{prime::PrimeCurveAffine, Group},
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

/// A BLS public key in a projective point representation
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeyProjective(pub(crate) G1Projective);

#[cfg(not(target_os = "solana"))]
impl Default for PubkeyProjective {
    fn default() -> Self {
        Self(G1Projective::identity())
    }
}

#[cfg(not(target_os = "solana"))]
impl PubkeyProjective {
    /// Construct a corresponding `BlsPubkey` for a `BlsSecretKey`
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_secret(secret: &SecretKey) -> Self {
        Self(G1Projective::generator() * secret.0)
    }

    /// Verify a signature against a message and a public key
    ///
    /// TODO: Verify by invoking pairing just once
    pub fn verify(&self, signature: &SignatureProjective, message: &[u8]) -> bool {
        let hashed_message = hash_message_to_point(message);
        pairing(&self.0.into(), &hashed_message.into())
            == pairing(&G1Affine::generator(), &signature.0.into())
    }

    /// Verify a proof of possession against a public key
    pub fn verify_proof_of_possession(&self, proof: &ProofOfPossessionProjective) -> bool {
        let hashed_pubkey_bytes = hash_pubkey_to_g2(self);
        pairing(&self.0.into(), &hashed_pubkey_bytes.into())
            == pairing(&G1Affine::generator(), &proof.0.into())
    }

    /// Aggregate a list of public keys into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, I>(&mut self, pubkeys: I)
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
    {
        self.0 = pubkeys.into_iter().fold(self.0, |mut acc, pubkey| {
            acc += &pubkey.0;
            acc
        });
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, I>(pubkeys: I) -> Result<PubkeyProjective, BlsError>
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
    {
        let mut iter = pubkeys.into_iter();
        if let Some(acc) = iter.next() {
            let aggregate_point = iter.fold(acc.0, |mut acc, pubkey| {
                acc += &pubkey.0;
                acc
            });
            Ok(Self(aggregate_point))
        } else {
            Err(BlsError::EmptyAggregation)
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl From<PubkeyProjective> for Pubkey {
    fn from(proof: PubkeyProjective) -> Self {
        Self(proof.0.to_uncompressed())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<Pubkey> for PubkeyProjective {
    type Error = BlsError;

    fn try_from(proof: Pubkey) -> Result<Self, Self::Error> {
        (&proof).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&Pubkey> for PubkeyProjective {
    type Error = BlsError;

    fn try_from(proof: &Pubkey) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G1Affine> = G1Affine::from_uncompressed(&proof.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}

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
    use {super::*, crate::keypair::Keypair, core::str::FromStr, std::string::ToString};

    #[test]
    fn test_verify() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature = keypair.sign(test_message);
        assert!(keypair.public.verify(&signature, test_message));
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
