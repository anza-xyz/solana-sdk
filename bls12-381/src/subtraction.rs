pub const G1_POINT_SIZE: usize = 96;
pub const G2_POINT_SIZE: usize = 192;

use crate::error::Bls12381Error;

/// Subtracts the right BLS12-381 G1 point from the left BLS12-381 G1 point, encoded in little-endian format.
pub fn g1_sub_le(
    left: &[u8; G1_POINT_SIZE],
    right: &[u8; G1_POINT_SIZE],
) -> Result<[u8; G1_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                solana_define_syscall::curve_constants::GROUP_OP_SUB,
                left.as_ptr(),
                right.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let left_pod = solana_bls12_381_syscall::PodG1Point(*left);
        let right_pod = solana_bls12_381_syscall::PodG1Point(*right);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_subtraction_unchecked(
            solana_bls12_381_syscall::Version::V0,
            &left_pod,
            &right_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Subtracts the right BLS12-381 G1 point from the left BLS12-381 G1 point, encoded in big-endian format.
pub fn g1_sub_be(
    left: &[u8; G1_POINT_SIZE],
    right: &[u8; G1_POINT_SIZE],
) -> Result<[u8; G1_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G1_BE,
                solana_define_syscall::curve_constants::GROUP_OP_SUB,
                left.as_ptr(),
                right.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let left_pod = solana_bls12_381_syscall::PodG1Point(*left);
        let right_pod = solana_bls12_381_syscall::PodG1Point(*right);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_subtraction_unchecked(
            solana_bls12_381_syscall::Version::V0,
            &left_pod,
            &right_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Subtracts the right BLS12-381 G2 point from the left BLS12-381 G2 point, encoded in little-endian format.
pub fn g2_sub_le(
    left: &[u8; G2_POINT_SIZE],
    right: &[u8; G2_POINT_SIZE],
) -> Result<[u8; G2_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                solana_define_syscall::curve_constants::GROUP_OP_SUB,
                left.as_ptr(),
                right.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let left_pod = solana_bls12_381_syscall::PodG2Point(*left);
        let right_pod = solana_bls12_381_syscall::PodG2Point(*right);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_subtraction_unchecked(
            solana_bls12_381_syscall::Version::V0,
            &left_pod,
            &right_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Subtracts the right BLS12-381 G2 point from the left BLS12-381 G2 point, encoded in big-endian format.
pub fn g2_sub_be(
    left: &[u8; G2_POINT_SIZE],
    right: &[u8; G2_POINT_SIZE],
) -> Result<[u8; G2_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G2_BE,
                solana_define_syscall::curve_constants::GROUP_OP_SUB,
                left.as_ptr(),
                right.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let left_pod = solana_bls12_381_syscall::PodG2Point(*left);
        let right_pod = solana_bls12_381_syscall::PodG2Point(*right);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_subtraction_unchecked(
            solana_bls12_381_syscall::Version::V0,
            &left_pod,
            &right_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}
