#[cfg(not(target_os = "solana"))]
use {
    crate::{
        error::BlsError,
        signature::bytes::{Signature, SignatureCompressed},
    },
    blstrs::{G2Affine, G2Projective},
    group::Group, // Needed for identity()
};

/// A trait for types that can be converted into a `SignatureProjective`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureProjective {
    /// Attempt to convert the type into a `SignatureProjective`.
    fn try_as_projective(&self) -> Result<SignatureProjective, BlsError>;
}

/// A BLS signature in a projective point representation.
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
}

/// A trait for types that can be converted into a `SignatureAffine`.
#[cfg(not(target_os = "solana"))]
pub trait AsSignatureAffine {
    /// Attempt to convert the type into a `SignatureAffine`.
    fn try_as_affine(&self) -> Result<SignatureAffine, BlsError>;
}

/// A BLS signature in an affine point representation.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignatureAffine(pub(crate) G2Affine);

/// A trait for types that can be efficiently added to a `SignatureProjective` accumulator.
/// This enables Mixed Addition (Projective += Affine) optimization.
#[cfg(not(target_os = "solana"))]
pub trait AddToSignatureProjective {
    /// Adds itself to the accumulator
    fn add_to_accumulator(&self, acc: &mut SignatureProjective) -> Result<(), BlsError>;
}

// Fallback for trait objects to support `dyn` types
#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjective for dyn AsSignatureProjective {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_accumulator(&self, acc: &mut SignatureProjective) -> Result<(), BlsError> {
        let proj = self.try_as_projective()?;
        acc.0 += proj.0;
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureAffine,
    affine
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureProjective,
    projective
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    Signature,
    convert
);
#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureCompressed,
    convert
);

/// A BLS signature in an affine point representation that is guaranteed to
/// be a point on the curve, but it is *not* guaranteed to be in the prime-order
/// subgroup G2.
///
/// This type allows for efficient "unchecked" deserialization. It is designed
/// to be used with aggregation functions where the expensive subgroup check
/// can be performed on the aggregate instead of each individual signature.
///
/// Aggregate it with [`SignatureProjectiveUnchecked`], which performs that
/// check on the sum. Adding it to a `SignatureProjective` through
/// `AddToSignatureProjective` performs no subgroup check at all.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SignatureAffineUnchecked(pub(crate) G2Affine);

#[cfg(not(target_os = "solana"))]
impl SignatureAffineUnchecked {
    /// Performs the subgroup check (coset check) on this point.
    ///
    /// This verifies that the point is on the curve and in the correct q-order subgroup G2.
    /// Returns a validated `SignatureAffine` on success.
    pub fn verify_subgroup(&self) -> Result<SignatureAffine, BlsError> {
        if bool::from(self.0.is_torsion_free()) {
            Ok(SignatureAffine(self.0))
        } else {
            Err(BlsError::VerificationFailed)
        }
    }
}

impl_unchecked_conversions!(
    SignatureAffineUnchecked,
    SignatureAffine,
    SignatureProjective,
    SignatureCompressed,
    Signature,
    G2Affine,
    false
);

#[cfg(not(target_os = "solana"))]
impl_add_to_accumulator!(
    AddToSignatureProjective,
    SignatureProjective,
    SignatureAffineUnchecked,
    affine
);

/// A sum of BLS signatures in a projective point representation that is
/// guaranteed to be a point on the curve, but it is *not* guaranteed to be in
/// the prime-order subgroup G2.
///
/// This is the accumulator for signatures that were deserialized with only the
/// on-curve check. The subgroup check runs once, on the sum, in
/// [`Self::verify_subgroup`], which is the only way to turn the sum into a
/// `SignatureProjective`.
///
/// A sum that passes the check says nothing about its inputs: signatures
/// outside of G2 are accepted when their components outside of G2 cancel. Use
/// this only when the aggregate is the only signature that gets verified and
/// used afterwards, and never treat the inputs, or the sum of a subset of
/// them, as valid.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProjectiveUnchecked(pub(crate) G2Projective);

#[cfg(not(target_os = "solana"))]
impl SignatureProjectiveUnchecked {
    /// Creates the identity element, which is the starting point for aggregation
    pub fn identity() -> Self {
        Self(G2Projective::identity())
    }

    /// Performs the subgroup check (coset check) on the sum.
    ///
    /// Returns a validated `SignatureProjective` on success.
    pub fn verify_subgroup(&self) -> Result<SignatureProjective, BlsError> {
        // SAFETY: The point is a valid, initialized `blst_p2` that outlives
        // the call, and blst only reads it.
        if unsafe { blst::blst_p2_in_g2(self.0.as_ref()) } {
            Ok(SignatureProjective(self.0))
        } else {
            Err(BlsError::VerificationFailed)
        }
    }
}

/// A trait for types that can be added to a `SignatureProjectiveUnchecked`
/// accumulator without a subgroup check.
#[cfg(not(target_os = "solana"))]
pub trait AddToSignatureProjectiveUnchecked {
    /// Adds itself to the accumulator, checking only that it is a point on the curve
    fn add_to_unchecked_accumulator(
        &self,
        acc: &mut SignatureProjectiveUnchecked,
    ) -> Result<(), BlsError>;
}

#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjectiveUnchecked for SignatureAffineUnchecked {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_unchecked_accumulator(
        &self,
        acc: &mut SignatureProjectiveUnchecked,
    ) -> Result<(), BlsError> {
        // Efficient mixed addition (Projective += Affine)
        acc.0 += self.0;
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjectiveUnchecked for SignatureProjectiveUnchecked {
    #[allow(clippy::arithmetic_side_effects)]
    fn add_to_unchecked_accumulator(
        &self,
        acc: &mut SignatureProjectiveUnchecked,
    ) -> Result<(), BlsError> {
        // Projective += Projective
        acc.0 += self.0;
        Ok(())
    }
}

#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjectiveUnchecked for Signature {
    fn add_to_unchecked_accumulator(
        &self,
        acc: &mut SignatureProjectiveUnchecked,
    ) -> Result<(), BlsError> {
        SignatureAffineUnchecked::try_from(self)?.add_to_unchecked_accumulator(acc)
    }
}

#[cfg(not(target_os = "solana"))]
impl AddToSignatureProjectiveUnchecked for SignatureCompressed {
    fn add_to_unchecked_accumulator(
        &self,
        acc: &mut SignatureProjectiveUnchecked,
    ) -> Result<(), BlsError> {
        SignatureAffineUnchecked::try_from(self)?.add_to_unchecked_accumulator(acc)
    }
}
