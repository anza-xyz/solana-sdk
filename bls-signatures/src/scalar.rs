//! Scalar weights for linear combinations of public keys and signatures.

use {blstrs::Scalar as BlstrsScalar, ff::Field, rand::rngs::OsRng};

/// A scalar weight used to form linear combinations of public keys or
/// signatures, as in [`PubkeyProjective::aggregate_with_scalars`] and
/// [`SignatureProjective::aggregate_with_scalars`].
///
/// This wraps the underlying BLS12-381 scalar field element so that callers do
/// not need a direct `blstrs` dependency (nor the `ff` and `rand` versions it
/// happens to be pinned to) in order to build one.
///
/// [`PubkeyProjective::aggregate_with_scalars`]: crate::pubkey::PubkeyProjective::aggregate_with_scalars
/// [`SignatureProjective::aggregate_with_scalars`]: crate::signature::SignatureProjective::aggregate_with_scalars
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scalar(pub(crate) BlstrsScalar);

impl Scalar {
    /// The additive identity.
    pub const ZERO: Self = Self(BlstrsScalar::ZERO);

    /// The multiplicative identity, i.e. an unweighted term.
    pub const ONE: Self = Self(BlstrsScalar::ONE);

    /// Constructs a uniformly random scalar using `OsRng`.
    pub fn random() -> Self {
        let mut rng = OsRng;
        Self(BlstrsScalar::random(&mut rng))
    }

    /// Parses a canonical little-endian scalar.
    ///
    /// Returns `None` if `bytes` is not a canonical encoding, i.e. if it is not
    /// less than the field modulus.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Self> {
        Option::<BlstrsScalar>::from(BlstrsScalar::from_bytes_le(bytes)).map(Self)
    }

    /// Returns the canonical little-endian encoding of this scalar.
    pub fn to_bytes_le(&self) -> [u8; 32] {
        self.0.to_bytes_le()
    }
}

/// The additive identity, matching [`Scalar::ZERO`].
impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self(BlstrsScalar::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_roundtrip() {
        let scalar = Scalar::random();
        let bytes = scalar.to_bytes_le();
        assert_eq!(Scalar::from_bytes_le(&bytes), Some(scalar));
    }

    #[test]
    fn test_from_bytes_le_rejects_non_canonical() {
        // The BLS12-381 scalar field modulus, little-endian; the smallest
        // non-canonical encoding.
        // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        let modulus = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4,
            0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29,
            0x53, 0xa7, 0xed, 0x73,
        ];
        assert_eq!(Scalar::from_bytes_le(&modulus), None);
        // One less than the modulus is canonical.
        let mut max = modulus;
        max[0] = 0x00;
        assert!(Scalar::from_bytes_le(&max).is_some());
    }

    #[test]
    fn test_constants_and_from_u64() {
        assert_eq!(Scalar::from(0u64), Scalar::ZERO);
        assert_eq!(Scalar::from(1u64), Scalar::ONE);
        assert_ne!(Scalar::from(7u64), Scalar::ONE);
    }

    #[test]
    fn test_default_is_zero() {
        assert_eq!(Scalar::default(), Scalar::ZERO);
    }

    #[test]
    fn test_random_is_random() {
        assert_ne!(Scalar::random(), Scalar::random());
    }
}
