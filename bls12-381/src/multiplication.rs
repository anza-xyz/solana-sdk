pub const G1_POINT_SIZE: usize = 96;
pub const G2_POINT_SIZE: usize = 192;
pub const SCALAR_SIZE: usize = 32;

use crate::error::Bls12381Error;

/// Multiplies a BLS12-381 G1 point by a scalar, both encoded in little-endian format.
pub fn g1_mul_le(
    scalar: &[u8; SCALAR_SIZE],
    point: &[u8; G1_POINT_SIZE],
) -> Result<[u8; G1_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                solana_define_syscall::curve_constants::GROUP_OP_MUL,
                scalar.as_ptr(),
                point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG1Point(*point);
        let scalar_pod = solana_bls12_381_syscall::PodScalar(*scalar);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_multiplication(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            &scalar_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Multiplies a BLS12-381 G1 point by a scalar, both encoded in big-endian format.
pub fn g1_mul_be(
    scalar: &[u8; SCALAR_SIZE],
    point: &[u8; G1_POINT_SIZE],
) -> Result<[u8; G1_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G1_BE,
                solana_define_syscall::curve_constants::GROUP_OP_MUL,
                scalar.as_ptr(),
                point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG1Point(*point);
        let scalar_pod = solana_bls12_381_syscall::PodScalar(*scalar);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_multiplication(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            &scalar_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Multiplies a BLS12-381 G2 point by a scalar, both encoded in little-endian format.
pub fn g2_mul_le(
    scalar: &[u8; SCALAR_SIZE],
    point: &[u8; G2_POINT_SIZE],
) -> Result<[u8; G2_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                solana_define_syscall::curve_constants::GROUP_OP_MUL,
                scalar.as_ptr(),
                point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG2Point(*point);
        let scalar_pod = solana_bls12_381_syscall::PodScalar(*scalar);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_multiplication(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            &scalar_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Multiplies a BLS12-381 G2 point by a scalar, both encoded in big-endian format.
pub fn g2_mul_be(
    scalar: &[u8; SCALAR_SIZE],
    point: &[u8; G2_POINT_SIZE],
) -> Result<[u8; G2_POINT_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_group_op(
                solana_define_syscall::curve_constants::BLS12_381_G2_BE,
                solana_define_syscall::curve_constants::GROUP_OP_MUL,
                scalar.as_ptr(),
                point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG2Point(*point);
        let scalar_pod = solana_bls12_381_syscall::PodScalar(*scalar);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_multiplication(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            &scalar_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}
