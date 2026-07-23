pub const G1_POINT_SIZE: usize = 96;
pub const G2_POINT_SIZE: usize = 192;

use crate::error::Bls12381Error;

/// Validates that a BLS12-381 G1 point encoded in little-endian format is on the curve and in the correct subgroup.
pub fn g1_validate_le(point: &[u8; G1_POINT_SIZE]) -> Result<(), Bls12381Error> {
    #[cfg(target_os = "solana")]
    {
        let mut dummy = [0u8; 1];
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_validate_point(
                solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                point.as_ptr(),
                dummy.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG1Point(*point);

        if !solana_bls12_381_syscall::bls12_381_g1_point_validation(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(())
}

/// Validates that a BLS12-381 G1 point encoded in big-endian format is on the curve and in the correct subgroup.
pub fn g1_validate_be(point: &[u8; G1_POINT_SIZE]) -> Result<(), Bls12381Error> {
    #[cfg(target_os = "solana")]
    {
        let mut dummy = [0u8; 1];
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_validate_point(
                solana_define_syscall::curve_constants::BLS12_381_G1_BE,
                point.as_ptr(),
                dummy.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG1Point(*point);

        if !solana_bls12_381_syscall::bls12_381_g1_point_validation(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(())
}

/// Validates that a BLS12-381 G2 point encoded in little-endian format is on the curve and in the correct subgroup.
pub fn g2_validate_le(point: &[u8; G2_POINT_SIZE]) -> Result<(), Bls12381Error> {
    #[cfg(target_os = "solana")]
    {
        let mut dummy = [0u8; 1];
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_validate_point(
                solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                point.as_ptr(),
                dummy.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG2Point(*point);

        if !solana_bls12_381_syscall::bls12_381_g2_point_validation(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(())
}

/// Validates that a BLS12-381 G2 point encoded in big-endian format is on the curve and in the correct subgroup.
pub fn g2_validate_be(point: &[u8; G2_POINT_SIZE]) -> Result<(), Bls12381Error> {
    #[cfg(target_os = "solana")]
    {
        let mut dummy = [0u8; 1];
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_validate_point(
                solana_define_syscall::curve_constants::BLS12_381_G2_BE,
                point.as_ptr(),
                dummy.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let point_pod = solana_bls12_381_syscall::PodG2Point(*point);

        if !solana_bls12_381_syscall::bls12_381_g2_point_validation(
            solana_bls12_381_syscall::Version::V0,
            &point_pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(())
}
