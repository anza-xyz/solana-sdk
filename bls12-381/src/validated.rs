//! Points and immutable views with a subgroup-validity guarantee bound to their byte order.
//!
//! Infinity is valid. Protocols requiring nonidentity points must check that
//! separately. These types have private fields, no mutable raw access, and no
//! `Pod`/`Zeroable` implementation. Extracting a raw point discards the guarantee.

use {
    crate::{Endianness, G1Compressed, G1Point, G2Compressed, G2Point, Scalar},
    core::{marker::PhantomData, mem::MaybeUninit},
};

mod sealed {
    pub trait Sealed {}
}

/// A supported, compile-time byte order. Sealed to the two marker types.
pub trait Encoding: sealed::Sealed + Copy {
    /// The byte order used by this encoding.
    const ENDIANNESS: Endianness;
}
/// Little-endian field and scalar encodings.
#[derive(Clone, Copy, Debug)]
pub struct LittleEndian;
/// Big-endian field and scalar encodings.
#[derive(Clone, Copy, Debug)]
pub struct BigEndian;
impl sealed::Sealed for LittleEndian {}
impl sealed::Sealed for BigEndian {}
impl Encoding for LittleEndian {
    const ENDIANNESS: Endianness = Endianness::Little;
}
impl Encoding for BigEndian {
    const ENDIANNESS: Endianness = Endianness::Big;
}

macro_rules! validated_group {
    ($owned:ident, $view:ident, $slice:ident, $raw:ty, $compressed:ty) => {
        /// An owned subgroup-valid point; infinity is permitted.
        #[derive(Clone, Copy, Debug)]
        pub struct $owned<E: Encoding> {
            point: $raw,
            marker: PhantomData<E>,
        }

        /// An immutable subgroup-valid view, bound to its byte order.
        #[derive(Clone, Copy, Debug)]
        pub struct $view<'a, E: Encoding> {
            point: &'a $raw,
            marker: PhantomData<E>,
        }

        /// An immutable slice whose every point has been individually validated.
        #[derive(Clone, Copy, Debug)]
        pub struct $slice<'a, E: Encoding> {
            points: &'a [$raw],
            marker: PhantomData<E>,
        }

        impl<E: Encoding> $owned<E> {
            fn from_valid(point: $raw) -> Self {
                Self {
                    point,
                    marker: PhantomData,
                }
            }

            /// Validates an owned raw point, including subgroup membership.
            #[inline]
            pub fn validate(point: $raw) -> Option<Self> {
                point
                    .validate(E::ENDIANNESS)
                    .then_some(Self::from_valid(point))
            }

            /// Returns the point at infinity.
            #[inline]
            pub fn infinity() -> Self {
                Self::from_valid(<$raw>::infinity(E::ENDIANNESS))
            }

            /// Returns the standard subgroup generator.
            #[inline]
            pub fn generator() -> Self {
                Self::from_valid(<$raw>::generator(E::ENDIANNESS))
            }

            /// Decompresses a point, checking its encoding and subgroup membership.
            #[inline]
            pub fn decompress(point: &$compressed) -> Option<Self> {
                point.decompress(E::ENDIANNESS).map(Self::from_valid)
            }

            /// Multiplies a raw point by a scalar, validating both inputs.
            /// Both inputs must use the byte order of `E`.
            #[inline]
            pub fn from_mul(point: &$raw, scalar: &Scalar) -> Option<Self> {
                point.mul(scalar, E::ENDIANNESS).map(Self::from_valid)
            }

            /// Borrows an immutable validated view of the point.
            #[inline]
            pub fn as_ref(&self) -> $view<'_, E> {
                $view {
                    point: &self.point,
                    marker: PhantomData,
                }
            }

            /// Borrows the raw point.
            #[inline]
            pub fn as_point(&self) -> &$raw {
                &self.point
            }

            /// Extracts the raw point, discarding the type's validity guarantee.
            #[inline]
            pub fn into_point(self) -> $raw {
                self.point
            }

            /// Sums validated points without repeating subgroup checks.
            /// Returns infinity for empty input.
            #[inline]
            pub fn sum_validated<'a>(points: impl IntoIterator<Item = $view<'a, E>>) -> Option<Self>
            where
                E: 'a,
            {
                let mut points = points.into_iter();
                let Some(first) = points.next() else {
                    return Some(Self::infinity());
                };
                let mut a = MaybeUninit::<$raw>::uninit();
                let mut b = MaybeUninit::<$raw>::uninit();
                // Borrow the first point to avoid copying it into an initial
                // accumulator, then alternate the output buffers.
                let mut acc = first.as_point();
                loop {
                    let Some(p) = points.next() else {
                        return Some(Self::from_valid(*acc));
                    };
                    if !acc.add_assign_unchecked(p.as_point(), &mut a, E::ENDIANNESS) {
                        return None;
                    }
                    let Some(q) = points.next() else {
                        // SAFETY: `add_assign_unchecked` returned `true`, so
                        // `a` is fully initialized.
                        return Some(Self::from_valid(unsafe { a.assume_init() }));
                    };
                    // SAFETY: `add_assign_unchecked` returned `true`, so
                    // `a` is fully initialized.
                    if !unsafe { a.assume_init_ref() }.add_assign_unchecked(
                        q.as_point(),
                        &mut b,
                        E::ENDIANNESS,
                    ) {
                        return None;
                    }
                    // SAFETY: `add_assign_unchecked` returned `true`, so
                    // `b` is fully initialized.
                    acc = unsafe { b.assume_init_ref() };
                }
            }
        }

        // Match the fallible named operations of the raw SDK API. Their
        // Option return type intentionally differs from arithmetic operators.
        #[allow(clippy::should_implement_trait)]
        impl<'a, E: Encoding> $view<'a, E> {
            /// Validates a raw point and borrows it as an immutable view.
            #[inline]
            pub fn validate(point: &'a $raw) -> Option<Self> {
                point.validate(E::ENDIANNESS).then_some(Self {
                    point,
                    marker: PhantomData,
                })
            }

            /// Borrows the raw point in the byte order `E::ENDIANNESS`.
            #[inline]
            pub fn as_point(self) -> &'a $raw {
                self.point
            }

            /// Returns whether the point is infinity.
            #[inline]
            pub fn is_infinity(self) -> bool {
                self.point.is_infinity(E::ENDIANNESS)
            }

            /// Copies the point into an owned validated point.
            #[inline]
            pub fn into_owned(self) -> $owned<E> {
                $owned::from_valid(*self.point)
            }

            /// Adds two points without repeating subgroup checks.
            #[doc = concat!("For accumulation, use [`", stringify!($owned), "::sum_validated`] to avoid returning an owned point after each addition.")]
            #[inline]
            pub fn add(self, other: Self) -> Option<$owned<E>> {
                self.point
                    .add_unchecked(other.point, E::ENDIANNESS)
                    .map($owned::from_valid)
            }

            /// Subtracts another point without repeating subgroup checks.
            #[inline]
            pub fn sub(self, other: Self) -> Option<$owned<E>> {
                self.point
                    .sub_unchecked(other.point, E::ENDIANNESS)
                    .map($owned::from_valid)
            }

            /// Negates the point without repeating subgroup checks.
            #[inline]
            pub fn neg(self) -> Option<$owned<E>> {
                self.point
                    .neg_unchecked(E::ENDIANNESS)
                    .map($owned::from_valid)
            }

            /// Multiplies the point by a scalar using the native multiplication syscall.
            /// The scalar must use the byte order of `E`.
            #[inline]
            pub fn mul(self, scalar: &Scalar) -> Option<$owned<E>> {
                $owned::from_mul(self.point, scalar)
            }
        }

        impl<'a, E: Encoding> $slice<'a, E> {
            /// Validates every point in the slice, including subgroup membership.
            #[inline]
            pub fn validate(points: &'a [$raw]) -> Option<Self> {
                for point in points {
                    if !point.validate(E::ENDIANNESS) {
                        return None;
                    }
                }
                Some(Self {
                    points,
                    marker: PhantomData,
                })
            }

            /// Iterates through immutable validated views of the points.
            #[inline]
            pub fn iter(self) -> impl Iterator<Item = $view<'a, E>> {
                self.points.iter().map(|point| $view {
                    point,
                    marker: PhantomData,
                })
            }

            /// Sums the points, returning infinity for an empty slice.
            #[inline]
            pub fn sum(self) -> Option<$owned<E>> {
                $owned::sum_validated(self.iter())
            }
        }
    };
}

validated_group!(ValidG1, ValidG1Ref, ValidG1Slice, G1Point, G1Compressed);
validated_group!(ValidG2, ValidG2Ref, ValidG2Slice, G2Point, G2Compressed);

/// Encodings cannot be mixed:
/// ```compile_fail,E0308
/// use solana_bls12_381::validated::{BigEndian, LittleEndian, ValidG1};
/// let p = ValidG1::<BigEndian>::generator();
/// let q = ValidG1::<LittleEndian>::generator();
/// p.as_ref().add(q.as_ref());
/// ```
/// Raw deserialization cannot establish validity:
/// ```compile_fail,E0277
/// use solana_bls12_381::validated::{LittleEndian, ValidG1};
/// fn require_pod<T: bytemuck::Pod>() {}
/// require_pod::<ValidG1<LittleEndian>>();
/// ```
/// ```compile_fail,E0277
/// use solana_bls12_381::validated::{LittleEndian, ValidG2};
/// fn require_zeroable<T: bytemuck::Zeroable>() {}
/// require_zeroable::<ValidG2<LittleEndian>>();
/// ```
#[cfg(doctest)]
struct ValidityGuarantees;
