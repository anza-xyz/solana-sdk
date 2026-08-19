#[cfg(any(
    feature = "bytemuck",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use bytemuck_derive::{Pod, Zeroable};
use {
    crate::{scalar::Scalar, Endianness},
    core::mem::MaybeUninit,
};

/// Size of a compressed BLS12-381 G1 point in bytes.
pub const G1_COMPRESSED_POINT_SIZE: usize = 48;

/// Size of an uncompressed BLS12-381 G1 affine point in bytes.
pub const G1_UNCOMPRESSED_POINT_SIZE: usize = 96;

/// An uncompressed G1 affine point: `x` and `y`, 96 bytes.
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
pub struct G1Point(
    /// The raw affine encoding, in whichever [`Endianness`] each operation is
    /// given. No validity invariant: these bytes may not be a curve point.
    pub [u8; G1_UNCOMPRESSED_POINT_SIZE],
);

/// A compressed G1 point: `x` with control flags in the top byte, 48 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "bytemuck",
        not(any(target_os = "solana", target_arch = "bpf"))
    ),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct G1Compressed(
    /// The raw compressed encoding, in whichever [`Endianness`] each operation
    /// is given. No validity invariant.
    pub [u8; G1_COMPRESSED_POINT_SIZE],
);

/// G1 base point, big-endian.
const G1_GENERATOR_BE: [u8; G1_UNCOMPRESSED_POINT_SIZE] = [
    0x17, 0xF1, 0xD3, 0xA7, 0x31, 0x97, 0xD7, 0x94, 0x26, 0x95, 0x63, 0x8C, 0x4F, 0xA9, 0xAC, 0x0F,
    0xC3, 0x68, 0x8C, 0x4F, 0x97, 0x74, 0xB9, 0x05, 0xA1, 0x4E, 0x3A, 0x3F, 0x17, 0x1B, 0xAC, 0x58,
    0x6C, 0x55, 0xE8, 0x3F, 0xF9, 0x7A, 0x1A, 0xEF, 0xFB, 0x3A, 0xF0, 0x0A, 0xDB, 0x22, 0xC6, 0xBB,
    0x08, 0xB3, 0xF4, 0x81, 0xE3, 0xAA, 0xA0, 0xF1, 0xA0, 0x9E, 0x30, 0xED, 0x74, 0x1D, 0x8A, 0xE4,
    0xFC, 0xF5, 0xE0, 0x95, 0xD5, 0xD0, 0x0A, 0xF6, 0x00, 0xDB, 0x18, 0xCB, 0x2C, 0x04, 0xB3, 0xED,
    0xD0, 0x3C, 0xC7, 0x44, 0xA2, 0x88, 0x8A, 0xE4, 0x0C, 0xAA, 0x23, 0x29, 0x46, 0xC5, 0xE7, 0xE1,
];

/// G1 base point, little-endian.
const G1_GENERATOR_LE: [u8; G1_UNCOMPRESSED_POINT_SIZE] = [
    0xBB, 0xC6, 0x22, 0xDB, 0x0A, 0xF0, 0x3A, 0xFB, 0xEF, 0x1A, 0x7A, 0xF9, 0x3F, 0xE8, 0x55, 0x6C,
    0x58, 0xAC, 0x1B, 0x17, 0x3F, 0x3A, 0x4E, 0xA1, 0x05, 0xB9, 0x74, 0x97, 0x4F, 0x8C, 0x68, 0xC3,
    0x0F, 0xAC, 0xA9, 0x4F, 0x8C, 0x63, 0x95, 0x26, 0x94, 0xD7, 0x97, 0x31, 0xA7, 0xD3, 0xF1, 0x17,
    0xE1, 0xE7, 0xC5, 0x46, 0x29, 0x23, 0xAA, 0x0C, 0xE4, 0x8A, 0x88, 0xA2, 0x44, 0xC7, 0x3C, 0xD0,
    0xED, 0xB3, 0x04, 0x2C, 0xCB, 0x18, 0xDB, 0x00, 0xF6, 0x0A, 0xD0, 0xD5, 0x95, 0xE0, 0xF5, 0xFC,
    0xE4, 0x8A, 0x1D, 0x74, 0xED, 0x30, 0x9E, 0xA0, 0xF1, 0xA0, 0xAA, 0xE3, 0x81, 0xF4, 0xB3, 0x08,
];

impl G1Point {
    /// Returns the identity (infinity) element in the given encoding.
    pub const fn infinity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; G1_UNCOMPRESSED_POINT_SIZE];
        match endianness {
            // Zcash standard sets the infinity flag on the highest byte.
            Endianness::Big => bytes[0] = 0x40,
            Endianness::Little => bytes[47] = 0x40,
        }
        Self(bytes)
    }

    /// The standard G1 base point from the Zcash/IETF specification.
    pub const fn generator(endianness: Endianness) -> Self {
        match endianness {
            Endianness::Big => Self(G1_GENERATOR_BE),
            Endianness::Little => Self(G1_GENERATOR_LE),
        }
    }

    /// Whether this is the canonical infinity encoding: infinity flag set,
    /// every other bit clear.
    ///
    /// Evaluated locally, without a syscall. A point that fails this check is
    /// not thereby invalid — that question belongs to [`Self::validate`].
    pub const fn is_infinity(&self, endianness: Endianness) -> bool {
        let flag_index = match endianness {
            Endianness::Big => 0,
            Endianness::Little => 47,
        };
        if self.0[flag_index] != 0x40 {
            return false;
        }
        let mut i = 0;
        while i < G1_UNCOMPRESSED_POINT_SIZE {
            if i != flag_index && self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Copies a byte array into a point.
    ///
    /// For instruction data, [`Self::from_bytes_ref`] or `bytemuck::cast_ref`
    /// avoid the copy.
    pub const fn from_bytes(bytes: [u8; G1_UNCOMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Copies out the raw 96-byte encoding. [`Self::as_bytes`] borrows
    /// instead.
    pub const fn to_bytes(&self) -> [u8; G1_UNCOMPRESSED_POINT_SIZE] {
        self.0
    }

    /// Borrows the raw encoding.
    pub const fn as_bytes(&self) -> &[u8; G1_UNCOMPRESSED_POINT_SIZE] {
        &self.0
    }

    /// Reinterprets a byte array as a point, without copying.
    ///
    /// Available under `default-features = false`, unlike `bytemuck::cast_ref`.
    /// Performs no validation.
    pub const fn from_bytes_ref(bytes: &[u8; G1_UNCOMPRESSED_POINT_SIZE]) -> &Self {
        // SAFETY: `G1Point` is `#[repr(transparent)]` over
        // `[u8; G1_UNCOMPRESSED_POINT_SIZE]`, so the two have identical
        // layout and a reference to one may be reinterpreted as a reference to
        // the other.
        unsafe { &*(bytes as *const [u8; G1_UNCOMPRESSED_POINT_SIZE] as *const Self) }
    }

    /// Negates in place, skipping the subgroup check on `self`.
    ///
    /// An off-subgroup input yields an off-subgroup result rather than an error.
    ///
    /// On `true`, `out` is initialized and may be `assume_init`ed; on `false`
    /// it is poisoned. See
    /// [Output buffer contract](crate#output-buffer-contract).
    pub fn neg_assign_unchecked(
        &self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        Self::infinity(endianness).sub_assign_unchecked(self, out, endianness)
    }

    /// Allocating form of [`Self::neg_assign_unchecked`].
    pub fn neg_unchecked(&self, endianness: Endianness) -> Option<Self> {
        Self::infinity(endianness).sub_unchecked(self, endianness)
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
    pub fn neg_assign(&self, out: &mut MaybeUninit<Self>, endianness: Endianness) -> bool {
        if !self.validate(endianness) {
            return false;
        }
        self.neg_assign_unchecked(out, endianness)
    }

    /// Allocating form of [`Self::neg_assign`].
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
    pub fn add_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G1_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
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
            let left_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&self.0);
            let right_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&other.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_addition_unchecked(
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
    pub fn sub_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G1_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
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
            let left_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&self.0);
            let right_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&other.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_subtraction_unchecked(
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
    pub fn mul_assign(
        &self,
        scalar: &Scalar,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: inputs are valid for reads of their sizes, `out` for
            // writes of `G1_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
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
            let point_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&self.0);
            let scalar_pod: &solana_bls12_381_syscall::PodScalar = bytemuck::cast_ref(&scalar.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_multiplication(
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
    pub fn validate(&self, endianness: Endianness) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // For BLS12-381 curve IDs the runtime ignores the result pointer
            // and answers through the return value. The one-byte buffer is
            // just there to keep the call well-formed.
            let mut dummy = [0u8; 1];
            // SAFETY: `self.0` is valid for reads of `G1_UNCOMPRESSED_POINT_SIZE`
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
            let point_pod: &solana_bls12_381_syscall::PodG1Point = bytemuck::cast_ref(&self.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            solana_bls12_381_syscall::bls12_381_g1_point_validation(
                solana_bls12_381_syscall::Version::V0,
                point_pod,
                end,
            )
        }
    }
}

impl G1Compressed {
    /// Compressed infinity: compression and infinity flags set, the rest
    /// clear.
    pub const fn infinity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; G1_COMPRESSED_POINT_SIZE];
        match endianness {
            Endianness::Big => bytes[0] = 0xC0,
            Endianness::Little => bytes[G1_COMPRESSED_POINT_SIZE - 1] = 0xC0,
        }
        Self(bytes)
    }

    /// Whether this is the canonical compressed infinity encoding. Evaluated
    /// locally, without a syscall.
    pub const fn is_infinity(&self, endianness: Endianness) -> bool {
        let flag_index = match endianness {
            Endianness::Big => 0,
            Endianness::Little => G1_COMPRESSED_POINT_SIZE - 1,
        };
        if self.0[flag_index] != 0xC0 {
            return false;
        }
        let mut i = 0;
        while i < G1_COMPRESSED_POINT_SIZE {
            if i != flag_index && self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Copies a byte array into a compressed point.
    pub const fn from_bytes(bytes: [u8; G1_COMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Reinterprets a byte array as a compressed point, without copying.
    ///
    /// Available under `default-features = false`. Performs no validation.
    pub const fn from_bytes_ref(bytes: &[u8; G1_COMPRESSED_POINT_SIZE]) -> &Self {
        // SAFETY: `G1Compressed` is `#[repr(transparent)]` over
        // `[u8; G1_COMPRESSED_POINT_SIZE]`, so the two have identical layout
        // and a reference to one may be reinterpreted as a reference to the
        // other.
        unsafe { &*(bytes as *const [u8; G1_COMPRESSED_POINT_SIZE] as *const Self) }
    }

    /// Copies out the raw compressed encoding.
    pub const fn to_bytes(&self) -> [u8; G1_COMPRESSED_POINT_SIZE] {
        self.0
    }

    /// Borrows the raw compressed encoding.
    pub const fn as_bytes(&self) -> &[u8; G1_COMPRESSED_POINT_SIZE] {
        &self.0
    }

    /// Checks the control bits, the `x` coordinate, the curve equation, and
    /// subgroup membership.
    ///
    /// There is no validate-compressed syscall, so this decompresses and
    /// discards the result, costing exactly what [`Self::decompress`] costs.
    /// Callers that intend to decompress should do so and match on `None`
    /// rather than pay for both.
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
    pub fn decompress_assign(
        &self,
        out: &mut MaybeUninit<G1Point>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: `self.0` is valid for reads of its size, `out` for
            // writes of `G1_UNCOMPRESSED_POINT_SIZE`. A 0 return means the
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
            let pod: &solana_bls12_381_syscall::PodG1Compressed = bytemuck::cast_ref(&self.0);

            let end = match endianness {
                Endianness::Little => solana_bls12_381_syscall::Endianness::LE,
                Endianness::Big => solana_bls12_381_syscall::Endianness::BE,
            };

            if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_decompress(
                solana_bls12_381_syscall::Version::V0,
                pod,
                end,
            ) {
                out.write(G1Point(res.0));
                true
            } else {
                false
            }
        }
    }

    /// Allocating form of [`Self::decompress_assign`].
    pub fn decompress(&self, endianness: Endianness) -> Option<G1Point> {
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
