#[cfg(any(feature = "bytemuck", not(target_os = "solana")))]
use bytemuck_derive::{Pod, Zeroable};
use {
    crate::{scalar::Scalar, Endianness},
    core::mem::MaybeUninit,
};

/// Size of a compressed BLS12-381 G1 point in bytes.
pub const G1_COMPRESSED_POINT_SIZE: usize = 48;

/// Size of an uncompressed BLS12-381 G1 affine point in bytes.
pub const G1_UNCOMPRESSED_POINT_SIZE: usize = 96;

/// Uncompressed BLS12-381 G1 affine point.
/// Represents the `x` and `y` coordinates (96 bytes total).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "bytemuck", not(target_os = "solana")),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct G1Point(pub [u8; G1_UNCOMPRESSED_POINT_SIZE]);

/// Compressed BLS12-381 G1 point.
/// Represents the `x` coordinate with control flags in the MSB (48 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "bytemuck", not(target_os = "solana")),
    derive(Pod, Zeroable)
)]
#[repr(transparent)]
pub struct G1Compressed(pub [u8; G1_COMPRESSED_POINT_SIZE]);

impl G1Point {
    /// Returns the identity (infinity) element for the given endianness.
    pub const fn infinity(endianness: Endianness) -> Self {
        let mut bytes = [0u8; G1_UNCOMPRESSED_POINT_SIZE];
        match endianness {
            // Zcash standard sets the infinity flag on the highest byte.
            Endianness::Big => bytes[0] = 0x40,
            Endianness::Little => bytes[47] = 0x40,
        }
        Self(bytes)
    }

    /// Constructs a point from a byte array via a memory copy.
    ///
    /// Note: For zero-copy deserialization from instruction data, use
    /// `bytemuck::cast_ref` directly on the byte slice.
    pub const fn from_bytes(bytes: [u8; G1_UNCOMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying byte array via a memory copy.
    pub const fn to_bytes(&self) -> [u8; G1_UNCOMPRESSED_POINT_SIZE] {
        self.0
    }

    /// Safely negates the point by subtracting it from infinity.
    pub fn neg(&self, endianness: Endianness) -> Option<Self> {
        Self::infinity(endianness).sub(self, endianness)
    }

    /// In-place point addition.
    ///
    /// WARNING: This operation skips the prime-order subgroup check
    /// for performance. Only use this if inputs are known to be valid.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
    pub fn add_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: the input pointers are valid for reads of their
            // respective sizes and `out` is valid for writes of
            // `G1_UNCOMPRESSED_POINT_SIZE` bytes. Per SIMD-0388 the syscall writes
            // the full output buffer whenever it returns 0.
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

        #[cfg(not(target_os = "solana"))]
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

    /// Point addition returning a new allocated point.
    /// Skips subgroup checks.
    pub fn add_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.add_assign_unchecked(other, &mut out, endianness) {
            // SAFETY: `add_assign_unchecked` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Safe in-place point addition.
    /// Validates both operands (field, curve, subgroup) prior to addition.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
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

    /// Safe point addition returning a new allocated point.
    pub fn add(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.add_assign(other, &mut out, endianness) {
            // SAFETY: `add_assign` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// In-place point subtraction.
    ///
    /// WARNING: This operation skips the prime-order subgroup check
    /// for performance. Only use this if inputs are known to be valid.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
    pub fn sub_assign_unchecked(
        &self,
        other: &Self,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: the input pointers are valid for reads of their
            // respective sizes and `out` is valid for writes of
            // `G1_UNCOMPRESSED_POINT_SIZE` bytes. Per SIMD-0388 the syscall writes
            // the full output buffer whenever it returns 0.
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

        #[cfg(not(target_os = "solana"))]
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

    /// Point subtraction returning a new allocated point.
    /// Skips subgroup checks.
    pub fn sub_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.sub_assign_unchecked(other, &mut out, endianness) {
            // SAFETY: `sub_assign_unchecked` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Safe in-place point subtraction.
    /// Validates both operands prior to subtraction.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
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

    /// Safe point subtraction returning a new allocated point.
    pub fn sub(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.sub_assign(other, &mut out, endianness) {
            // SAFETY: `sub_assign` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// In-place scalar multiplication.
    ///
    /// Note: The underlying syscall inherently performs full validation
    /// (field, curve, and subgroup checks) on the input point.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
    pub fn mul_assign(
        &self,
        scalar: &Scalar,
        out: &mut MaybeUninit<Self>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: the input pointers are valid for reads of their
            // respective sizes and `out` is valid for writes of
            // `G1_UNCOMPRESSED_POINT_SIZE` bytes. Per SIMD-0388 the syscall writes
            // the full output buffer whenever it returns 0.
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

        #[cfg(not(target_os = "solana"))]
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

    /// Scalar multiplication returning a new allocated point.
    pub fn mul(&self, scalar: &Scalar, endianness: Endianness) -> Option<Self> {
        let mut out = MaybeUninit::uninit();
        if self.mul_assign(scalar, &mut out, endianness) {
            // SAFETY: `mul_assign` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }

    /// Full point validation.
    /// Checks that coordinates represent a valid field element, satisfy the
    /// curve equation, and exist within the prime-order subgroup.
    pub fn validate(&self, endianness: Endianness) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            let mut dummy = [0u8; 1];
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_validate_point(
                    curve_id,
                    self.0.as_ptr(),
                    dummy.as_mut_ptr(),
                )
            };
            status == 0
        }

        #[cfg(not(target_os = "solana"))]
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
    /// Constructs a compressed point from a byte array via a memory copy.
    pub const fn from_bytes(bytes: [u8; G1_COMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying compressed byte array via a memory copy.
    pub const fn to_bytes(&self) -> [u8; G1_COMPRESSED_POINT_SIZE] {
        self.0
    }

    /// In-place decompression into an uncompressed affine point.
    /// Inherently performs format, field, curve, and subgroup validation.
    ///
    /// Returns `true` if and only if every byte of `out` was written, in
    /// which case the caller may `assume_init` it. On `false`, `out` is
    /// left untouched and must not be assumed initialized.
    pub fn decompress_assign(
        &self,
        out: &mut MaybeUninit<G1Point>,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            // SAFETY: `self.0` is valid for reads of its size and `out`
            // is valid for writes of `G1_UNCOMPRESSED_POINT_SIZE` bytes. Per
            // SIMD-0388 the syscall writes the full output buffer
            // whenever it returns 0.
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_decompress(
                    curve_id,
                    self.0.as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                )
            };
            status == 0
        }

        #[cfg(not(target_os = "solana"))]
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

    /// Decompresses into a new allocated affine point.
    pub fn decompress(&self, endianness: Endianness) -> Option<G1Point> {
        let mut out = MaybeUninit::uninit();
        if self.decompress_assign(&mut out, endianness) {
            // SAFETY: `decompress_assign` returned `true`, so every byte of
            // `out` has been written.
            Some(unsafe { out.assume_init() })
        } else {
            None
        }
    }
}
