use {
    crate::{
        error::BlsError,
        pubkey::{
            bytes::{Pubkey, PubkeyCompressed},
            verify::VerifySignature,
        },
        secret_key::SecretKey,
    },
    blstrs::{G1Affine, G1Projective},
    core::ops::Deref,
    group::Group,
};

/// A trait for types that can be converted into a `PubkeyProjective`.
pub trait AsPubkeyProjective {
    /// Attempt to convert the type into a `PubkeyProjective`.
    fn try_as_projective(&self) -> Result<PubkeyProjective, BlsError>;
}

/// A BLS public key in a projective point representation.
///
/// This type wraps `G1Projective` and is optimal for aggregation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeyProjective(pub(crate) G1Projective);

impl PubkeyProjective {
    /// Creates the identity element, which is the starting point for aggregation
    ///
    /// The identity element is not a valid public key and it should only be used
    /// for the purpose of aggregation
    pub fn identity() -> Self {
        Self(G1Projective::identity())
    }

    /// Construct a corresponding `BlsPubkey` for a `BlsSecretKey`
    #[allow(clippy::arithmetic_side_effects)]
    pub fn from_secret(secret: &SecretKey) -> Self {
        Self(G1Projective::generator() * secret.0)
    }
}

/// A trait for types that can be converted into a `PubkeyAffine`.
pub trait AsPubkeyAffine {
    /// Attempt to convert the type into a `PubkeyAffine`.
    fn try_as_affine(&self) -> Result<PubkeyAffine, BlsError>;
}

/// A BLS public key in an affine point representation.
///
/// This type wraps `G1Affine` and is optimal for verification operations
/// (pairing inputs) as it avoids the cost of converting from projective coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PubkeyAffine(pub(crate) G1Affine);

/// A trait for types that can be efficiently added to a PubkeyProjective accumulator.
pub trait AddToPubkeyProjective {
    /// Adds itself to the accumulator
    fn add_to_accumulator(&self, acc: &mut PubkeyProjective) -> Result<(), BlsError>;
}

// Fallback for trait objects to support `dyn` types
impl AddToPubkeyProjective for dyn AsPubkeyProjective {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_accumulator(&self, acc: &mut PubkeyProjective) -> Result<(), BlsError> {
        let proj = self.try_as_projective()?;
        acc.0 += proj.0;
        Ok(())
    }
}

impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyAffine,
    affine
);
impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyProjective,
    projective
);
impl_add_to_accumulator!(AddToPubkeyProjective, PubkeyProjective, Pubkey, convert);
impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyCompressed,
    convert
);

/// A BLS public key in an affine point representation that is guaranteed to
/// be a point on the curve, but it is *not* guaranteed to be in the prime-order
/// subgroup G1.
///
/// This type allows for efficient "unchecked" deserialization. It is designed
/// to be used with aggregation functions where the expensive subgroup check
/// can be performed on the aggregate instead of each individual public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PubkeyAffineUnchecked(pub(crate) G1Affine);

impl PubkeyAffineUnchecked {
    /// Performs the subgroup check (coset check) on this point.
    ///
    /// This verifies that the point is on the curve and in the correct q-order
    /// subgroup G1. Returns a validated `PubkeyAffine` on success.
    pub fn verify_subgroup(&self) -> Result<PubkeyAffine, BlsError> {
        if bool::from(self.0.is_torsion_free()) {
            Ok(PubkeyAffine(self.0))
        } else {
            Err(BlsError::VerificationFailed)
        }
    }
}

impl_unchecked_conversions!(
    PubkeyAffineUnchecked,
    PubkeyAffine,
    PubkeyProjective,
    PubkeyCompressed,
    Pubkey,
    G1Affine
);

impl_add_to_accumulator!(
    AddToPubkeyProjective,
    PubkeyProjective,
    PubkeyAffineUnchecked,
    affine
);

/// A wrapper indicating that the inner public key type has been Proof-of-Possession (PoP) verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct PopVerified<T: ?Sized>(pub(crate) T);

impl<T: ?Sized> PopVerified<T> {
    /// Bypasses the cryptographic PoP check.
    ///
    /// # Safety
    /// Only use this if the public key was loaded from a trusted source
    /// where its Proof of Possession was previously verified (e.g., a local validator ledger).
    pub unsafe fn new_unchecked(inner: T) -> Self
    where
        T: Sized,
    {
        Self(inner)
    }

    /// Bypasses the cryptographic PoP check, yielding a reference to the verified type.
    ///
    /// # Safety
    /// Only use this if the public key was loaded from a trusted source.
    pub unsafe fn ref_unchecked(inner: &T) -> &Self {
        // Safety: PopVerified is #[repr(transparent)], so they have identical memory layouts.
        &*(inner as *const T as *const Self)
    }

    /// Consumes the wrapper, returning the inner type.
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.0
    }
}

impl<T: ?Sized> Deref for PopVerified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A wrapper indicating that this is an aggregate of exclusively PoP-verified public keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AggregatePubkey<T: ?Sized>(pub(crate) T);

impl<T: ?Sized> Deref for AggregatePubkey<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl_pubkey_wrapper_delegations!(PopVerified);
impl_pubkey_wrapper_delegations!(AggregatePubkey);
