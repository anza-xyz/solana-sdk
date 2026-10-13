use crate::Endianness;
#[cfg(any(
    feature = "bytemuck",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use bytemuck_derive::{Pod, Zeroable};

/// Size of a BLS12-381 scalar field element in bytes.
pub const SCALAR_SIZE: usize = 32;

/// A scalar field element: a 256-bit integer, used for scalar multiplication.
///
/// # Canonicity
///
/// Scalars must be canonical — strictly below the scalar field order `r`.
/// A value at or above `r` is rejected rather than reduced mod `r`, so
/// [`G1Point::mul`] and [`G2Point::mul`] return `None`, the same result they
/// give for an invalid point.
///
/// Scalars that do not arrive already reduced — a hash output, or bytes taken
/// directly from instruction data — must be reduced by the caller, on-chain or
/// off.
///
/// # Endianness
///
/// A scalar's byte order must match the [`Endianness`] of the operation
/// consuming it.
///
/// [`G1Point::mul`]: crate::g1::G1Point::mul
/// [`G2Point::mul`]: crate::g2::G2Point::mul
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct Scalar(
    /// The raw encoding, in whichever [`Endianness`] the consuming operation
    /// uses. Canonicity unchecked.
    pub [u8; SCALAR_SIZE],
);

impl Scalar {
    /// Zero. Canonical in both encodings; takes any point to infinity.
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; SCALAR_SIZE])
    }

    /// One, in the given encoding. Leaves any point unchanged.
    #[inline]
    pub const fn one(endianness: Endianness) -> Self {
        Self::from_u64(1, endianness)
    }

    /// Widens a `u64` into a scalar. Always canonical, since `r` is far larger
    /// than `u64::MAX`.
    #[inline]
    pub const fn from_u64(value: u64, endianness: Endianness) -> Self {
        // Index of the first limb byte in the big-endian layout.
        const BE_LIMB_OFFSET: usize = SCALAR_SIZE - 8;

        let mut bytes = [0u8; SCALAR_SIZE];
        let mut i = 0;
        match endianness {
            Endianness::Little => {
                let limb = value.to_le_bytes();
                while i < 8 {
                    bytes[i] = limb[i];
                    i = i.wrapping_add(1);
                }
            }
            Endianness::Big => {
                let limb = value.to_be_bytes();
                while i < 8 {
                    // `i < 8` and `BE_LIMB_OFFSET + 8 == SCALAR_SIZE`, so the
                    // sum is in bounds and never wraps.
                    bytes[BE_LIMB_OFFSET.wrapping_add(i)] = limb[i];
                    i = i.wrapping_add(1);
                }
            }
        }
        Self(bytes)
    }

    /// Copies a byte array into a scalar. Canonicity is not checked; see the
    /// type documentation.
    #[inline]
    pub const fn from_bytes(bytes: [u8; SCALAR_SIZE]) -> Self {
        Self(bytes)
    }

    /// Reinterprets a byte array as a scalar, without copying.
    ///
    /// Available under `default-features = false`.
    #[inline]
    pub const fn from_bytes_ref(bytes: &[u8; SCALAR_SIZE]) -> &Self {
        // SAFETY: `Scalar` is `#[repr(transparent)]` over
        // `[u8; SCALAR_SIZE]`, so the two have identical layout and a
        // reference to one may be reinterpreted as a reference to the other.
        unsafe { &*(bytes as *const [u8; SCALAR_SIZE] as *const Self) }
    }

    /// Copies out the raw encoding.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0
    }

    /// Borrows the raw encoding.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.0
    }

    /// Whether this scalar is zero.
    ///
    /// Not `const fn`: array equality is not const-callable. The byte loop it
    /// replaces was const, but cost ~72 CU against ~13 CU here.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; SCALAR_SIZE]
    }
}
