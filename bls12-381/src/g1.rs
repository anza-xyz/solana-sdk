use {
    crate::{scalar::Scalar, Endianness},
    bytemuck::{Pod, Zeroable},
    core::mem::MaybeUninit,
};

pub const G1_COMPRESSED_POINT_SIZE: usize = 48;
pub const G1_UNCOMPRESSED_POINT_SIZE: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct G1Point(pub [u8; G1_UNCOMPRESSED_POINT_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct G1Compressed(pub [u8; G1_COMPRESSED_POINT_SIZE]);

impl G1Point {
    pub fn add_unchecked_assign(
        &self,
        other: &Self,
        out: &mut Self,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_ADD,
                    self.0.as_ptr(),
                    other.0.as_ptr(),
                    out.0.as_mut_ptr(),
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
                out.0.copy_from_slice(&res.0);
                true
            } else {
                false
            }
        }
    }

    pub fn add_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut result = MaybeUninit::<Self>::uninit();
        let success =
            self.add_unchecked_assign(other, unsafe { result.assume_init_mut() }, endianness);

        if success {
            Some(unsafe { result.assume_init() })
        } else {
            None
        }
    }

    pub fn sub_unchecked_assign(
        &self,
        other: &Self,
        out: &mut Self,
        endianness: Endianness,
    ) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_SUB,
                    self.0.as_ptr(),
                    other.0.as_ptr(),
                    out.0.as_mut_ptr(),
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
                out.0.copy_from_slice(&res.0);
                true
            } else {
                false
            }
        }
    }

    pub fn sub_unchecked(&self, other: &Self, endianness: Endianness) -> Option<Self> {
        let mut result = MaybeUninit::<Self>::uninit();
        let success =
            self.sub_unchecked_assign(other, unsafe { result.assume_init_mut() }, endianness);

        if success {
            Some(unsafe { result.assume_init() })
        } else {
            None
        }
    }

    pub fn mul_assign(&self, scalar: &Scalar, out: &mut Self, endianness: Endianness) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_group_op(
                    curve_id,
                    solana_define_syscall::curve_constants::GROUP_OP_MUL,
                    scalar.0.as_ptr(),
                    self.0.as_ptr(),
                    out.0.as_mut_ptr(),
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
                out.0.copy_from_slice(&res.0);
                true
            } else {
                false
            }
        }
    }

    pub fn mul(&self, scalar: &Scalar, endianness: Endianness) -> Option<Self> {
        let mut result = MaybeUninit::<Self>::uninit();
        let success = self.mul_assign(scalar, unsafe { result.assume_init_mut() }, endianness);

        if success {
            Some(unsafe { result.assume_init() })
        } else {
            None
        }
    }

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
    pub fn decompress_assign(&self, out: &mut G1Point, endianness: Endianness) -> bool {
        #[cfg(target_os = "solana")]
        {
            let curve_id = match endianness {
                Endianness::Little => solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                Endianness::Big => solana_define_syscall::curve_constants::BLS12_381_G1_BE,
            };
            let status = unsafe {
                solana_define_syscall::definitions::sol_curve_decompress(
                    curve_id,
                    self.0.as_ptr(),
                    out.0.as_mut_ptr(),
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
                out.0.copy_from_slice(&res.0);
                true
            } else {
                false
            }
        }
    }

    pub fn decompress(&self, endianness: Endianness) -> Option<G1Point> {
        let mut result = MaybeUninit::<G1Point>::uninit();
        let success = self.decompress_assign(unsafe { result.assume_init_mut() }, endianness);

        if success {
            Some(unsafe { result.assume_init() })
        } else {
            None
        }
    }
}
