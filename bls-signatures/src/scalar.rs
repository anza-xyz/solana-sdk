//! Scalar weights for linear combinations of public keys and signatures.

// Field arithmetic is modular: it neither overflows nor panics, so the usual
// concerns behind this lint do not apply to the operator impls below.
#![allow(clippy::arithmetic_side_effects)]

use {
    blstrs::Scalar as BlstrsScalar,
    core::{
        iter::{Product, Sum},
        ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
    ff::Field,
    rand::rngs::OsRng,
};

/// A scalar weight used to form linear combinations of public keys or
/// signatures, as in [`PubkeyProjective::aggregate_with_weights`] and
/// [`SignatureProjective::aggregate_with_weights`].
///
/// This wraps the underlying BLS12-381 scalar field element so that callers do
/// not need a direct `blstrs` dependency (nor the `ff` and `rand` versions it
/// happens to be pinned to) in order to build one. The full set of field
/// operations is available through the standard [`Add`], [`Sub`], [`Mul`] and
/// [`Neg`] traits (plus their assigning and by-reference forms), so weights can
/// be derived arithmetically without reaching for `blstrs` either.
///
/// [`PubkeyProjective::aggregate_with_weights`]: crate::pubkey::PubkeyProjective::aggregate_with_weights
/// [`SignatureProjective::aggregate_with_weights`]: crate::signature::SignatureProjective::aggregate_with_weights
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

    /// Returns `self + self`.
    pub fn double(&self) -> Self {
        Self(self.0.double())
    }

    /// Returns `self * self`.
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Returns the multiplicative inverse of this scalar, or `None` if it is
    /// [`Scalar::ZERO`].
    pub fn invert(&self) -> Option<Self> {
        Option::<BlstrsScalar>::from(self.0.invert()).map(Self)
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

/// Forwards a binary operator and its assigning form to the wrapped field
/// element, covering every owned/borrowed combination of operands.
macro_rules! impl_binop {
    ($op_trait:ident, $op:ident, $assign_trait:ident, $assign:ident) => {
        impl $op_trait<Scalar> for Scalar {
            type Output = Scalar;

            fn $op(self, rhs: Scalar) -> Scalar {
                Scalar(self.0.$op(rhs.0))
            }
        }

        impl $op_trait<&Scalar> for Scalar {
            type Output = Scalar;

            fn $op(self, rhs: &Scalar) -> Scalar {
                Scalar(self.0.$op(rhs.0))
            }
        }

        impl $op_trait<Scalar> for &Scalar {
            type Output = Scalar;

            fn $op(self, rhs: Scalar) -> Scalar {
                Scalar(self.0.$op(rhs.0))
            }
        }

        impl $op_trait<&Scalar> for &Scalar {
            type Output = Scalar;

            fn $op(self, rhs: &Scalar) -> Scalar {
                Scalar(self.0.$op(rhs.0))
            }
        }

        impl $assign_trait<Scalar> for Scalar {
            fn $assign(&mut self, rhs: Scalar) {
                self.0.$assign(rhs.0);
            }
        }

        impl $assign_trait<&Scalar> for Scalar {
            fn $assign(&mut self, rhs: &Scalar) {
                self.0.$assign(rhs.0);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign);
impl_binop!(Sub, sub, SubAssign, sub_assign);
impl_binop!(Mul, mul, MulAssign, mul_assign);

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar(self.0.neg())
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar(self.0.neg())
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Scalar>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
    }
}

impl<'a> Product<&'a Scalar> for Scalar {
    fn product<I: Iterator<Item = &'a Scalar>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
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

    #[test]
    fn test_arithmetic() {
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);

        assert_eq!(two + three, Scalar::from(5u64));
        assert_eq!(three - two, Scalar::ONE);
        assert_eq!(two * three, Scalar::from(6u64));
        assert_eq!(two + (-two), Scalar::ZERO);
        assert_eq!(two.double(), Scalar::from(4u64));
        assert_eq!(three.square(), Scalar::from(9u64));
        assert_eq!(two * two.invert().unwrap(), Scalar::ONE);
        assert_eq!(Scalar::ZERO.invert(), None);
    }

    #[test]
    // The point of this test is to exercise the by-reference operator impls.
    #[allow(clippy::op_ref)]
    fn test_arithmetic_by_reference() {
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let five = Scalar::from(5u64);

        // Every owned/borrowed combination agrees.
        assert_eq!(&two + &three, five);
        assert_eq!(&two + three, five);
        assert_eq!(two + &three, five);
        assert_eq!(-&two, -two);

        let mut accumulator = two;
        accumulator += &three;
        accumulator -= two;
        accumulator *= &two;
        assert_eq!(accumulator, Scalar::from(6u64));
    }

    #[test]
    fn test_sum_and_product() {
        let scalars = [Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];

        assert_eq!(
            scalars.iter().sum::<Scalar>(),
            Scalar::from(9u64) // 2 + 3 + 4
        );
        assert_eq!(
            scalars.into_iter().product::<Scalar>(),
            Scalar::from(24u64) // 2 * 3 * 4
        );
        assert_eq!(core::iter::empty::<Scalar>().sum::<Scalar>(), Scalar::ZERO);
        assert_eq!(
            core::iter::empty::<Scalar>().product::<Scalar>(),
            Scalar::ONE
        );
    }
}
