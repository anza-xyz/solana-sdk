pub const G1_COMPRESSED_SIZE: usize = 48;
pub const G1_UNCOMPRESSED_SIZE: usize = 96;

pub const G2_COMPRESSED_SIZE: usize = 96;
pub const G2_UNCOMPRESSED_SIZE: usize = 192;

use crate::error::Bls12381Error;

/// Decompresses a BLS12-381 G1 point encoded in little-endian format.
pub fn g1_decompress_le(
    compressed_point: &[u8; G1_COMPRESSED_SIZE],
) -> Result<[u8; G1_UNCOMPRESSED_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_UNCOMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_decompress(
                solana_define_syscall::curve_constants::BLS12_381_G1_LE,
                compressed_point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let pod = solana_bls12_381_syscall::PodG1Compressed(*compressed_point);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_decompress(
            solana_bls12_381_syscall::Version::V0,
            &pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Decompresses a BLS12-381 G1 point encoded in big-endian format.
pub fn g1_decompress_be(
    compressed_point: &[u8; G1_COMPRESSED_SIZE],
) -> Result<[u8; G1_UNCOMPRESSED_SIZE], Bls12381Error> {
    let mut result = [0u8; G1_UNCOMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_decompress(
                solana_define_syscall::curve_constants::BLS12_381_G1_BE,
                compressed_point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let pod = solana_bls12_381_syscall::PodG1Compressed(*compressed_point);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g1_decompress(
            solana_bls12_381_syscall::Version::V0,
            &pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Decompresses a BLS12-381 G2 point encoded in little-endian format.
pub fn g2_decompress_le(
    compressed_point: &[u8; G2_COMPRESSED_SIZE],
) -> Result<[u8; G2_UNCOMPRESSED_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_UNCOMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_decompress(
                solana_define_syscall::curve_constants::BLS12_381_G2_LE,
                compressed_point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let pod = solana_bls12_381_syscall::PodG2Compressed(*compressed_point);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_decompress(
            solana_bls12_381_syscall::Version::V0,
            &pod,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Decompresses a BLS12-381 G2 point encoded in big-endian format.
pub fn g2_decompress_be(
    compressed_point: &[u8; G2_COMPRESSED_SIZE],
) -> Result<[u8; G2_UNCOMPRESSED_SIZE], Bls12381Error> {
    let mut result = [0u8; G2_UNCOMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_decompress(
                solana_define_syscall::curve_constants::BLS12_381_G2_BE,
                compressed_point.as_ptr(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let pod = solana_bls12_381_syscall::PodG2Compressed(*compressed_point);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_g2_decompress(
            solana_bls12_381_syscall::Version::V0,
            &pod,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}
