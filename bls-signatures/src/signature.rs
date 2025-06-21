#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
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

/// A BLS signature in a projective point representation
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProjective(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl Default for SignatureProjective {
    fn default() -> Self {
        Self(G2Projective::identity())
    }
}

#[cfg(not(target_os = "solana"))]
impl SignatureProjective {
    /// Aggregate a list of signatures into an existing aggregate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, I>(&mut self, signatures: I)
    where
        I: IntoIterator<Item = &'a SignatureProjective>,
    {
        self.0 = signatures.into_iter().fold(self.0, |mut acc, signature| {
            acc += &signature.0;
            acc
        });
    }

    /// Aggregate a list of public keys
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, I>(signatures: I) -> Result<SignatureProjective, BlsError>
    where
        I: IntoIterator<Item = &'a SignatureProjective>,
    {
        let mut iter = signatures.into_iter();
        if let Some(acc) = iter.next() {
            let aggregate_point = iter.fold(acc.0, |mut acc, signature| {
                acc += &signature.0;
                acc
            });
            Ok(Self(aggregate_point))
        } else {
            Err(BlsError::EmptyAggregation)
        }
    }

    /// Verify a list of signatures against a message and a list of public keys
    pub fn aggregate_verify<'a, I, J>(
        public_keys: I,
        signatures: J,
        message: &[u8],
    ) -> Result<bool, BlsError>
    where
        I: IntoIterator<Item = &'a PubkeyProjective>,
        J: IntoIterator<Item = &'a SignatureProjective>,
    {
        let aggregate_pubkey = PubkeyProjective::aggregate(public_keys)?;
        let aggregate_signature = SignatureProjective::aggregate(signatures)?;

        aggregate_pubkey.verify_signature(&aggregate_signature, message)
    }
}

#[cfg(not(target_os = "solana"))]
pub trait VerifiableSignature: AsSignatureProjective {
    /// Verify the signature against any convertible public key type and a message
    fn verify<P: AsPubkeyProjective>(&self, pubkey: &P, message: &[u8]) -> Result<bool, BlsError> {
        let signature_projective = self.try_as_projective()?;
        let pubkey_projective = pubkey.try_as_projective()?;
        pubkey_projective.verify_signature(&signature_projective, message)
    }
}

#[cfg(not(target_os = "solana"))]
impl<T: AsSignatureProjective> VerifiableSignature for T {}

/// A trait for types that can be converted into a `SignatureProjective` for verification
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureProjective {
    /// Attempt to convert the type into a `SignatureProjective`
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError>;
}

#[cfg(not(target_os = "solana"))]
impl AsSignatureProjective for SignatureProjective {
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError> {
        Ok(*self)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<SignatureProjective> for Signature {
    fn from(signature: SignatureProjective) -> Self {
        (&signature).into()
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&SignatureProjective> for Signature {
    fn from(signature: &SignatureProjective) -> Self {
        Self(signature.0.to_uncompressed())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<Signature> for SignatureProjective {
    type Error = BlsError;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&signature.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&Signature> for SignatureProjective {
    type Error = BlsError;

    fn try_from(signature: &Signature) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&signature.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.into()))
    }
}

#[cfg(not(target_os = "solana"))]
impl AsSignatureProjective for Signature {
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError> {
        SignatureProjective::try_from(self)
    }
}

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

#[cfg(not(target_os = "solana"))]
impl TryFrom<Signature> for SignatureCompressed {
    type Error = BlsError;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        (&signature).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&Signature> for SignatureCompressed {
    type Error = BlsError;

    fn try_from(signature: &Signature) -> Result<Self, Self::Error> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_uncompressed(&signature.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(uncompressed.to_compressed()))
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<SignatureCompressed> for Signature {
    type Error = BlsError;

    fn try_from(signature: SignatureCompressed) -> Result<Self, Self::Error> {
        (&signature).try_into()
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<&SignatureCompressed> for Signature {
    type Error = BlsError;

    fn try_from(signature: &SignatureCompressed) -> Result<Self, Self::Error> {
        let maybe_compressed: Option<G2Affine> = G2Affine::from_compressed(&signature.0).into();
        let compressed = maybe_compressed.ok_or(BlsError::PointConversion)?;
        Ok(Self(compressed.to_uncompressed()))
    }
}

#[cfg(not(target_os = "solana"))]
impl AsSignatureProjective for SignatureCompressed {
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError> {
        let maybe_uncompressed: Option<G2Affine> = G2Affine::from_compressed(&self.0).into();
        let uncompressed = maybe_uncompressed.ok_or(BlsError::PointConversion)?;
        Ok(SignatureProjective(uncompressed.into()))
    }
}

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
        std::{string::ToString, vec},
    };

    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::new();
        let test_message = b"test message";
        let signature_projective = keypair.sign(test_message);

        let pubkey_projective = keypair.public;
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

        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1]).unwrap();

        let mut aggregate_signature_with = signature0;
        aggregate_signature_with.aggregate_with([&signature1]);

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
            vec![&keypair0.public, &keypair1.public],
            vec![&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // pre-aggregate the signatures
        let aggregate_signature =
            SignatureProjective::aggregate([&signature0, &signature1]).unwrap();
        assert!(SignatureProjective::aggregate_verify(
            vec![&keypair0.public, &keypair1.public],
            vec![&aggregate_signature],
            test_message,
        )
        .unwrap());

        // pre-aggregate the public keys
        let aggregate_pubkey =
            PubkeyProjective::aggregate([&keypair0.public, &keypair1.public]).unwrap();
        assert!(SignatureProjective::aggregate_verify(
            vec![&aggregate_pubkey],
            vec![&signature0, &signature1],
            test_message,
        )
        .unwrap());

        // empty set of public keys or signatures
        let err = SignatureProjective::aggregate_verify(
            vec![],
            vec![&signature0, &signature1],
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);

        let err = SignatureProjective::aggregate_verify(
            vec![&keypair0.public, &keypair1.public],
            vec![],
            test_message,
        )
        .unwrap_err();
        assert_eq!(err, BlsError::EmptyAggregation);
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
}
