#[cfg(any(
    feature = "bytemuck",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use bytemuck_derive::{Pod, Zeroable};
use {
    crate::{scalar::Scalar, Endianness},
    core::mem::MaybeUninit,
};

/// Size of a compressed BLS12-381 G2 point in bytes.
pub const G2_COMPRESSED_POINT_SIZE: usize = 96;

/// Size of an uncompressed BLS12-381 G2 affine point in bytes.
pub const G2_UNCOMPRESSED_POINT_SIZE: usize = 192;

/// An uncompressed G2 affine point: `x` and `y` in the extension field,
/// 192 bytes.
///
/// The all-zero encoding is not the identity; use [`Self::infinity`]. See the
/// crate documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct G2Point(
    /// The raw affine encoding, in whichever [`Endianness`] each operation is
    /// given. No validity invariant: these bytes may not be a curve point.
    pub [u8; G2_UNCOMPRESSED_POINT_SIZE],
);

/// A compressed G2 point: `x` with control flags in the top byte, 96 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct G2Compressed(
    /// The raw compressed encoding, in whichever [`Endianness`] each operation
    /// is given. No validity invariant.
    pub [u8; G2_COMPRESSED_POINT_SIZE],
);

/// G2 base point, big-endian.
const G2_GENERATOR_BE: [u8; G2_UNCOMPRESSED_POINT_SIZE] = [
    0x13, 0xE0, 0x2B, 0x60, 0x52, 0x71, 0x9F, 0x60, 0x7D, 0xAC, 0xD3, 0xA0, 0x88, 0x27, 0x4F, 0x65,
    0x59, 0x6B, 0xD0, 0xD0, 0x99, 0x20, 0xB6, 0x1A, 0xB5, 0xDA, 0x61, 0xBB, 0xDC, 0x7F, 0x50, 0x49,
    0x33, 0x4C, 0xF1, 0x12, 0x13, 0x94, 0x5D, 0x57, 0xE5, 0xAC, 0x7D, 0x05, 0x5D, 0x04, 0x2B, 0x7E,
    0x02, 0x4A, 0xA2, 0xB2, 0xF0, 0x8F, 0x0A, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2D, 0xC5, 0x10, 0x51,
    0xC6, 0xE4, 0x7A, 0xD4, 0xFA, 0x40, 0x3B, 0x02, 0xB4, 0x51, 0x0B, 0x64, 0x7A, 0xE3, 0xD1, 0x77,
    0x0B, 0xAC, 0x03, 0x26, 0xA8, 0x05, 0xBB, 0xEF, 0xD4, 0x80, 0x56, 0xC8, 0xC1, 0x21, 0xBD, 0xB8,
    0x06, 0x06, 0xC4, 0xA0, 0x2E, 0xA7, 0x34, 0xCC, 0x32, 0xAC, 0xD2, 0xB0, 0x2B, 0xC2, 0x8B, 0x99,
    0xCB, 0x3E, 0x28, 0x7E, 0x85, 0xA7, 0x63, 0xAF, 0x26, 0x74, 0x92, 0xAB, 0x57, 0x2E, 0x99, 0xAB,
    0x3F, 0x37, 0x0D, 0x27, 0x5C, 0xEC, 0x1D, 0xA1, 0xAA, 0xA9, 0x07, 0x5F, 0xF0, 0x5F, 0x79, 0xBE,
    0x0C, 0xE5, 0xD5, 0x27, 0x72, 0x7D, 0x6E, 0x11, 0x8C, 0xC9, 0xCD, 0xC6, 0xDA, 0x2E, 0x35, 0x1A,
    0xAD, 0xFD, 0x9B, 0xAA, 0x8C, 0xBD, 0xD3, 0xA7, 0x6D, 0x42, 0x9A, 0x69, 0x51, 0x60, 0xD1, 0x2C,
    0x92, 0x3A, 0xC9, 0xCC, 0x3B, 0xAC, 0xA2, 0x89, 0xE1, 0x93, 0x54, 0x86, 0x08, 0xB8, 0x28, 0x01,
];

/// G2 base point, little-endian.
const G2_GENERATOR_LE: [u8; G2_UNCOMPRESSED_POINT_SIZE] = [
    0xB8, 0xBD, 0x21, 0xC1, 0xC8, 0x56, 0x80, 0xD4, 0xEF, 0xBB, 0x05, 0xA8, 0x26, 0x03, 0xAC, 0x0B,
    0x77, 0xD1, 0xE3, 0x7A, 0x64, 0x0B, 0x51, 0xB4, 0x02, 0x3B, 0x40, 0xFA, 0xD4, 0x7A, 0xE4, 0xC6,
    0x51, 0x10, 0xC5, 0x2D, 0x27, 0x05, 0x08, 0x26, 0x91, 0x0A, 0x8F, 0xF0, 0xB2, 0xA2, 0x4A, 0x02,
    0x7E, 0x2B, 0x04, 0x5D, 0x05, 0x7D, 0xAC, 0xE5, 0x57, 0x5D, 0x94, 0x13, 0x12, 0xF1, 0x4C, 0x33,
    0x49, 0x50, 0x7F, 0xDC, 0xBB, 0x61, 0xDA, 0xB5, 0x1A, 0xB6, 0x20, 0x99, 0xD0, 0xD0, 0x6B, 0x59,
    0x65, 0x4F, 0x27, 0x88, 0xA0, 0xD3, 0xAC, 0x7D, 0x60, 0x9F, 0x71, 0x52, 0x60, 0x2B, 0xE0, 0x13,
    0x01, 0x28, 0xB8, 0x08, 0x86, 0x54, 0x93, 0xE1, 0x89, 0xA2, 0xAC, 0x3B, 0xCC, 0xC9, 0x3A, 0x92,
    0x2C, 0xD1, 0x60, 0x51, 0x69, 0x9A, 0x42, 0x6D, 0xA7, 0xD3, 0xBD, 0x8C, 0xAA, 0x9B, 0xFD, 0xAD,
    0x1A, 0x35, 0x2E, 0xDA, 0xC6, 0xCD, 0xC9, 0x8C, 0x11, 0x6E, 0x7D, 0x72, 0x27, 0xD5, 0xE5, 0x0C,
    0xBE, 0x79, 0x5F, 0xF0, 0x5F, 0x07, 0xA9, 0xAA, 0xA1, 0x1D, 0xEC, 0x5C, 0x27, 0x0D, 0x37, 0x3F,
    0xAB, 0x99, 0x2E, 0x57, 0xAB, 0x92, 0x74, 0x26, 0xAF, 0x63, 0xA7, 0x85, 0x7E, 0x28, 0x3E, 0xCB,
    0x99, 0x8B, 0xC2, 0x2B, 0xB0, 0xD2, 0xAC, 0x32, 0xCC, 0x34, 0xA7, 0x2E, 0xA0, 0xC4, 0x06, 0x06,
];

/// Canonical infinity encodings, compared against by [`G2Point::is_infinity`]
/// and used as the left operand of a negation.
///
/// Hoisting these out of the predicates turns a 192-byte loop into a single
/// array comparison: measured at ~1,380 CU and ~20 CU respectively.
const G2_INFINITY_BE: G2Point = G2Point::infinity(Endianness::Big);
const G2_INFINITY_LE: G2Point = G2Point::infinity(Endianness::Little);

/// Compressed counterparts of [`G2_INFINITY_BE`] and [`G2_INFINITY_LE`].
const G2_COMPRESSED_INFINITY_BE: G2Compressed = G2Compressed::infinity(Endianness::Big);
const G2_COMPRESSED_INFINITY_LE: G2Compressed = G2Compressed::infinity(Endianness::Little);

/// Borrows the infinity constant for the given encoding.
///
/// Negation subtracts from infinity, and building that operand with
/// [`G2Point::infinity`] zeroes 192 bytes of stack on every call. Borrowing a
/// promoted constant reads it from `.rodata` instead.
#[inline]
const fn infinity_ref(endianness: Endianness) -> &'static G2Point {
    match endianness {
        Endianness::Big => &G2_INFINITY_BE,
        Endianness::Little => &G2_INFINITY_LE,
    }
}

impl G2Point {
    /// Returns the identity (infinity) element in the given encoding.
    #[inline]
    pub const fn infinity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; G2_UNCOMPRESSED_POINT_SIZE];
        match endianness {
            // Zcash standard sets the infinity flag on the highest byte.
            Endianness::Big => bytes[0] = 0x40,
            Endianness::Little => bytes[95] = 0x40,
        }
        Self(bytes)
    }

    /// The standard G2 base point from the Zcash/IETF specification.
    #[inline]
    pub const fn generator(endianness: Endianness) -> Self {
        match endianness {
            Endianness::Big => Self(G2_GENERATOR_BE),
            Endianness::Little => Self(G2_GENERATOR_LE),
        }
    }

    /// Whether this is the canonical infinity encoding: infinity flag set,
    /// every other bit clear.
    ///
    /// Evaluated locally, without a syscall. A point that fails this check is
    /// not thereby invalid — that question belongs to [`Self::validate`].
    ///
    /// Not `const fn`: array equality is not const-callable. The byte loop it
    /// replaces was const, but cost ~7 CU per byte — the per-byte flag-index
    /// test tripled what the comparison itself costs — against ~20 CU total
    /// for the whole array here.
    #[inline]
    pub fn is_infinity(&self, endianness: Endianness) -> bool {
        match endianness {
            Endianness::Big => self.0 == G2_INFINITY_BE.0,
            Endianness::Little => self.0 == G2_INFINITY_LE.0,
        }
    }

    /// Copies a byte array into a point.
    ///
    /// For instruction data, [`Self::from_bytes_ref`] or `bytemuck::cast_ref`
    /// avoid the copy.
    #[inline]
    pub const fn from_bytes(bytes: [u8; G2_UNCOMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Copies out the raw 192-byte encoding. [`Self::as_bytes`] borrows
    /// instead.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; G2_UNCOMPRESSED_POINT_SIZE] {
        self.0
    }

    /// Borrows the raw encoding.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; G2_UNCOMPRESSED_POINT_SIZE] {
        &self.0
    }

    /// Reinterprets a byte array as a point, without copying.
    ///
    /// Available under `default-features = false`, unlike `bytemuck::cast_ref`.
    /// Performs no validation.
    #[inline]
    pub const fn from_bytes_ref(bytes: &[u8; G2_UNCOMPRESSED_POINT_SIZE]) -> &Self {
        // SAFETY: `G2Point` is `#[repr(transparent)]` over
        // `[u8; G2_UNCOMPRESSED_POINT_SIZE]`, so the two have identical
        // layout and a reference to one may be reinterpreted as a reference to
        // the other.
        unsafe { &*(bytes as *const [u8; G2_UNCOMPRESSED_POINT_SIZE] as *const Self) }
    }

    /// Negates in place, skipping the subgroup check on `self`.
    ///
    /// An off-subgroup input yields an off-subgroup result rather than an error.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn neg_assign_unchecked(
        &self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        infinity_ref(endianness).sub_assign_unchecked(self, out, endianness)
    }

    /// Allocating form of [`Self::neg_assign_unchecked`].
    #[inline]
    pub fn neg_unchecked(&self, endianness: Endianness) -> Option<Self> {
        infinity_ref(endianness).sub_unchecked(self, endianness)
    }

    /// Negates in place, validating `self` first.
    ///
    /// Issues two syscalls: validation, then subtraction from infinity.
    /// Infinity needs no validation of its own, and the subtraction syscall
    /// repeats the field and on-curve checks internally, so one validation
    /// covers the pair.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn neg_assign(&self, out: &mut MaybeUninit<Self>, endianness: Endianness) -> bool {
        if !self.validate(endianness) {
            return false;
        }
        self.neg_assign_unchecked(out, endianness)
    }

    /// Allocating form of [`Self::neg_assign`].
    #[inline]
    pub fn neg(&self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.neg_assign(&mut out, endianness) {
            // SAFETY: `neg_assign` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Adds in place, skipping the subgroup check on both operands.
    ///
    /// The principal compute-unit optimization. The subgroup is closed under
    /// addition, so an accumulator built from validated points remains valid
    /// and re-validating it each iteration buys nothing: validate at the trust
    /// boundary and accumulate with this method. See the README for the loop.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn add_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G2_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G2_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
            // syscall wrote all of it — see "Output buffer contract" in lib.rs
            // for why that holds even though SIMD-0388 never says so.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_ADD,
                    self.0.as_ptr(),
                    other.0.as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                )
            };
            status == 0
        }

        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let left_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&self.0);
            let right_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&other.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_addition_unchecked(
                solana_bls12_381_syscall::Version::V0,
                left_pod,
                right_pod,
                end,
            ) {
                out.write(Self(res.0));
                true
            } else {
                false
            }
        }
    }

    /// Allocating form of [`Self::add_assign_unchecked`].
    #[inline]
    pub fn add_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.add_assign_unchecked(other, &mut out, endianness) {
            // SAFETY: `add_assign_unchecked` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Adds in place, validating both operands first.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn add_assign(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        if !self.validate(endianness) || !other.validate(endianness) {
            return false;
        }
        self.add_assign_unchecked(other, out, endianness)
    }

    /// Allocating form of [`Self::add_assign`].
    #[inline]
    pub fn add(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.add_assign(other, &mut out, endianness) {
            // SAFETY: `add_assign` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Subtracts in place, skipping the subgroup check on both operands.
    ///
    /// Carries the same caveat as [`Self::add_assign_unchecked`].
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn sub_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G2_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G2_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
            // syscall wrote all of it — see "Output buffer contract" in lib.rs
            // for why that holds even though SIMD-0388 never says so.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_SUB,
                    self.0.as_ptr(),
                    other.0.as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                )
            };
            status == 0
        }

        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let left_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&self.0);
            let right_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&other.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_subtraction_unchecked(
                solana_bls12_381_syscall::Version::V0,
                left_pod,
                right_pod,
                end,
            ) {
                out.write(Self(res.0));
                true
            } else {
                false
            }
        }
    }

    /// Allocating form of [`Self::sub_assign_unchecked`].
    #[inline]
    pub fn sub_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.sub_assign_unchecked(other, &mut out, endianness) {
            // SAFETY: `sub_assign_unchecked` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Subtracts in place, validating both operands first.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn sub_assign(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        if !self.validate(endianness) || !other.validate(endianness) {
            return false;
        }
        self.sub_assign_unchecked(other, out, endianness)
    }

    /// Allocating form of [`Self::sub_assign`].
    #[inline]
    pub fn sub(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.sub_assign(other, &mut out, endianness) {
            // SAFETY: `sub_assign` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Multiplies by a scalar in place.
    ///
    /// The syscall validates the point itself, so there is no `_unchecked`
    /// variant and calling [`Self::validate`] beforehand pays for the check
    /// twice. The scalar must be canonical; see [`Scalar`].
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn mul_assign(
        &self,
        scalar: &Scalar,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G2_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G2_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
            // syscall wrote all of it — see "Output buffer contract" in lib.rs
            // for why that holds even though SIMD-0388 never says so.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_MUL,
                    scalar.0.as_ptr(),
                    self.0.as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                )
            };
            status == 0
        }

        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let point_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&self.0);
            let scalar_pod: &solana_bls12_381_syscall::PodScalar = bytemuck::cast_ref(&scalar.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_multiplication(
                solana_bls12_381_syscall::Version::V0,
                point_pod,
                scalar_pod,
                end,
            ) {
                out.write(Self(res.0));
                true
            } else {
                false
            }
        }
    }

    /// Allocating form of [`Self::mul_assign`].
    #[inline]
    pub fn mul(&self, scalar: &Scalar, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.mul_assign(scalar, &mut out, endianness) {
            // SAFETY: `mul_assign` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Checks that the coordinates are field elements, that the point is on
    /// the curve, and that it lies in the prime-order subgroup.
    ///
    /// The subgroup check dominates the cost. See the README for when to hoist
    /// this out of a loop.
    #[inline]
    pub fn validate(&self, endianness: Endianness) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G2_BE,
            };
            // For BLS12-381 curve IDs the runtime ignores the result pointer
            // and answers through the return value. The one-byte buffer is
            // just there to keep the call well-formed.
            let mut dummy = [0u8; 1];
            // SAFETY: `self.0` is valid for reads of `G2_UNCOMPRESSED_POINT_SIZE`
            // bytes, `dummy` for writes of 1.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_validate_point(
                    curve_id,
                    self.0.as_ptr(),
                    dummy.as_mut_ptr(),
                )
            };
            status == 0
        }

        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let point_pod: &solana_bls12_381_syscall::PodG2Point = bytemuck::cast_ref(&self.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            solana_bls12_381_syscall::bls12_381_g2_point_validation(
                solana_bls12_381_syscall::Version::V0,
                point_pod,
                end,
            )
        }
    }
}

impl G2Compressed {
    /// Compressed infinity: compression and infinity flags set, the rest
    /// clear.
    #[inline]
    pub const fn infinity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; G2_COMPRESSED_POINT_SIZE];
        match endianness {
            Endianness::Big => bytes[0] = 0xC0,
            Endianness::Little => bytes[G2_COMPRESSED_POINT_SIZE - 1] = 0xC0,
        }
        Self(bytes)
    }

    /// Whether this is the canonical compressed infinity encoding. Evaluated
    /// locally, without a syscall.
    ///
    /// Not `const fn`; see [`G2Point::is_infinity`].
    #[inline]
    pub fn is_infinity(&self, endianness: Endianness) -> bool {
        match endianness {
            Endianness::Big => self.0 == G2_COMPRESSED_INFINITY_BE.0,
            Endianness::Little => self.0 == G2_COMPRESSED_INFINITY_LE.0,
        }
    }

    /// Copies a byte array into a compressed point.
    #[inline]
    pub const fn from_bytes(bytes: [u8; G2_COMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Reinterprets a byte array as a compressed point, without copying.
    ///
    /// Available under `default-features = false`. Performs no validation.
    #[inline]
    pub const fn from_bytes_ref(bytes: &[u8; G2_COMPRESSED_POINT_SIZE]) -> &Self {
        // SAFETY: `G2Compressed` is `#[repr(transparent)]` over
        // `[u8; G2_COMPRESSED_POINT_SIZE]`, so the two have identical layout
        // and a reference to one may be reinterpreted as a reference to the
        // other.
        unsafe { &*(bytes as *const [u8; G2_COMPRESSED_POINT_SIZE] as *const Self) }
    }

    /// Copies out the raw compressed encoding.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; G2_COMPRESSED_POINT_SIZE] {
        self.0
    }

    /// Borrows the raw compressed encoding.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; G2_COMPRESSED_POINT_SIZE] {
        &self.0
    }

    /// Checks the control bits, the `x` coordinate, the curve equation, and
    /// subgroup membership.
    ///
    /// There is no validate-compressed syscall, so this decompresses and
    /// discards the result, costing exactly what [`Self::decompress`] costs.
    /// Callers that intend to decompress should do so and match on `None`
    /// rather than pay for both.
    #[inline]
    pub fn validate(&self, endianness: Endianness) -> bool {
        let mut out = MaybeUninit::uninit();
        self.decompress_assign(&mut out, endianness)
    }

    /// Decompresses into an affine point, checking format, field, curve
    /// equation, and subgroup membership.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    #[inline]
    pub fn decompress_assign(
        &self,
        out: &mut MaybeUninit<G2Point>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G2_BE,
            };
            // SAFETY: `self.0` is valid for reads of its size, `out` for
            // writes of `G2_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
            // syscall wrote all of it — see "Output buffer contract" in lib.rs.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_decompress(
                    curve_id,
                    self.0.as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                )
            };
            status == 0
        }

        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let pod: &solana_bls12_381_syscall::PodG2Compressed = bytemuck::cast_ref(&self.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_decompress(
                solana_bls12_381_syscall::Version::V0,
                pod,
                end,
            ) {
                out.write(G2Point(res.0));
                true
            } else {
                false
            }
        }
    }

    /// Allocating form of [`Self::decompress_assign`].
    #[inline]
    pub fn decompress(&self, endianness: Endianness) -> Option<G2Point> {
        let mut out = MaybeUninit::uninit();
        if self.decompress_assign(&mut out, endianness) {
            // SAFETY: `decompress_assign` returned `true`, so `out` is fully
            // initialized.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }
}
