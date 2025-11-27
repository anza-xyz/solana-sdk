#[cfg(all(not(target_os = "solana"), feature = "std"))]
use crate::pubkey::points::NEG_G1_GENERATOR_AFFINE;
#[cfg(not(feature = "std"))]
use blstrs::G1Projective;
#[cfg(feature = "bytemuck")]
use bytemuck::{Pod, PodInOption, Zeroable, ZeroableInOption};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        hash::{hash_message_to_point, hash_pubkey_to_g2},
        proof_of_possession::{AsProofOfPossession, ProofOfPossession},
        pubkey::points::PubkeyProjective,
        signature::{AsSignature, Signature},
    },
    blstrs::{Bls12, G1Affine, G2Affine, G2Prepared, Gt},
    group::Group,
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

/// A trait for types that can be converted into a `Pubkey` (affine/uncompressed bytes).
#[cfg(not(target_os = "solana"))]
pub trait AsPubkey {
    /// Attempt to convert the type into a `Pubkey`.
    fn try_as_affine(&self) -> Result<Pubkey, BlsError>;
}

/// A trait that provides verification methods to any convertible public key type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiablePubkey: AsPubkey {
    /// Uses this public key to verify any convertible signature type.
    fn verify_signature<S: AsSignature>(
        &self,
        signature: &S,
        message: &[u8],
    ) -> Result<bool, BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let signature_affine = signature.try_as_affine()?;
        Ok(pubkey_affine._verify_signature(&signature_affine, message))
    }

    /// Uses this public key to verify any convertible proof of possession type.
    fn verify_proof_of_possession<P: AsProofOfPossession>(
        &self,
        proof: &P,
        payload: Option<&[u8]>,
    ) -> Result<bool, BlsError> {
        let pubkey_affine = self.try_as_affine()?;
        let proof_affine = proof.try_as_affine()?;
        Ok(pubkey_affine._verify_proof_of_possession(&proof_affine, payload))
    }
}

/// A serialized BLS public key in a compressed point representation.
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

/// A serialized BLS public key in an affine point representation.
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Pubkey(
    #[cfg_attr(feature = "serde", serde_as(as = "[_; BLS_PUBLIC_KEY_AFFINE_SIZE]"))]
    pub  [u8; BLS_PUBLIC_KEY_AFFINE_SIZE],
);

#[cfg(not(target_os = "solana"))]
impl Pubkey {
    /// Verify a signature and a message against a public key
    pub(crate) fn _verify_signature(&self, signature: &Signature, message: &[u8]) -> bool {
        let Some(pubkey_affine): Option<G1Affine> = G1Affine::from_uncompressed(&self.0).into()
        else {
            return false;
        };
        let Some(signature_affine): Option<G2Affine> =
            G2Affine::from_uncompressed(&signature.0).into()
        else {
            return false;
        };

        // The verification equation is e(pubkey, H(m)) = e(g1, signature).
        // This can be rewritten as e(pubkey, H(m)) * e(-g1, signature) = 1, which
        // allows for a more efficient verification using a multi-miller loop.
        let hashed_message: G2Affine = hash_message_to_point(message).into();
        let hashed_message_prepared = G2Prepared::from(hashed_message);
        let signature_prepared = G2Prepared::from(signature_affine);

        // use the static valud if `std` is available, otherwise compute it
        #[cfg(feature = "std")]
        let neg_g1_generator = &NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&pubkey_affine, &hashed_message_prepared),
            (neg_g1_generator, &signature_prepared),
        ]);
        miller_loop_result.final_exponentiation() == Gt::identity()
    }

    /// Verify a proof of possession against a public key
    pub(crate) fn _verify_proof_of_possession(
        &self,
        proof: &ProofOfPossession,
        payload: Option<&[u8]>,
    ) -> bool {
        let Some(pubkey_affine): Option<G1Affine> = G1Affine::from_uncompressed(&self.0).into()
        else {
            return false;
        };
        let Some(proof_affine): Option<G2Affine> = G2Affine::from_uncompressed(&proof.0).into()
        else {
            return false;
        };
        // Dependency on conversion: PubkeyProjective::try_from(self)
        // Since we are in the same crate, this circular logic works via the trait system,
        // but explicit usage requires the trait or impl to be visible.
        let Ok(pubkey_projective) = PubkeyProjective::try_from(self) else {
            return false;
        };

        // The verification equation is e(pubkey, H(pubkey)) == e(g1, proof).
        // This is rewritten to e(pubkey, H(pubkey)) * e(-g1, proof) = 1 for batching.
        let hashed_pubkey_affine: G2Affine = hash_pubkey_to_g2(&pubkey_projective, payload).into();
        let hashed_pubkey_prepared = G2Prepared::from(hashed_pubkey_affine);
        let proof_prepared = G2Prepared::from(proof_affine);

        // Use the static value if std is available, otherwise compute it
        #[cfg(feature = "std")]
        let neg_g1_generator = &NEG_G1_GENERATOR_AFFINE;
        #[cfg(not(feature = "std"))]
        let neg_g1_generator_val: G1Affine = (-G1Projective::generator()).into();
        #[cfg(not(feature = "std"))]
        let neg_g1_generator = &neg_g1_generator_val;

        let miller_loop_result = Bls12::multi_miller_loop(&[
            (&pubkey_affine, &hashed_pubkey_prepared),
            // Reuse the same pre-computed static value here for efficiency
            (neg_g1_generator, &proof_prepared),
        ]);

        miller_loop_result.final_exponentiation() == Gt::identity()
    }
}

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

#[cfg(not(target_os = "solana"))]
impl<T: AsPubkey> VerifiablePubkey for T {}
