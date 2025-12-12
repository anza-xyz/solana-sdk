#[cfg(not(target_os = "solana"))]
use {
    crate::{error::BlsError, pubkey::VerifiablePubkey},
    blstrs::{G2Affine, G2Projective},
};

/// A trait for types that can be converted into a `ProofOfPossessionProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsProofOfPossessionProjective {
    /// Attempt to convert the type into a `ProofOfPossessionProjective`.
    fn try_as_projective(&self) -> Result<ProofOfPossessionProjective, BlsError>;
}

/// A trait that provides verification methods to any convertible proof of possession type.
#[cfg(not(target_os = "solana"))]
pub trait VerifiableProofOfPossession: AsProofOfPossessionAffine + Sized {
    /// Verifies the proof of possession against any convertible public key type.
    fn verify<P: VerifiablePubkey>(
        &self,
        pubkey: &P,
        payload: Option<&[u8]>,
    ) -> Result<bool, BlsError> {
        pubkey.verify_proof_of_possession(self, payload)
    }
}

/// A BLS proof of possession in a projective point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofOfPossessionProjective(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl<T: AsProofOfPossessionAffine> VerifiableProofOfPossession for T {}

/// A trait for types that can be converted into a `ProofOfPossessionAffine`.
#[cfg(not(target_os = "solana"))]
pub trait AsProofOfPossessionAffine {
    /// Attempt to convert the type into a `ProofOfPossessionAffine`.
    fn try_as_affine(&self) -> Result<ProofOfPossessionAffine, BlsError>;
}

/// A BLS proof of possession in an affine point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProofOfPossessionAffine(pub(crate) G2Affine);
