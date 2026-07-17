#[cfg(target_os = "solana")]
use solana_define_syscall::definitions as syscalls;

#[cfg(not(target_os = "solana"))]
use agave_bls12_381::{
    bls12_381_g1_addition, bls12_381_g2_addition, Endianness, PodG1Point, PodG2Point, Version,
};

use crate::{
    Bls12381Error, ADD, BLS12_381_G1_BE, BLS12_381_G1_LE, BLS12_381_G2_BE, BLS12_381_G2_LE,
};

pub const BLS12_381_G1_POINT_SIZE: usize = 96;
pub const BLS12_381_G2_POINT_SIZE: usize = 192;

/// Performs BLS12-381 G1 point addition (Big-Endian).
#[inline(always)]
pub fn bls12_381_g1_addition_be(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Bls12381Error> {
    if left.len() != BLS12_381_G1_POINT_SIZE || right.len() != BLS12_381_G1_POINT_SIZE {
        return Err(Bls12381Error::InvalidInputData);
    }

    #[cfg(not(target_os = "solana"))]
    {
        let p1 = PodG1Point(left.try_into().unwrap());
        let p2 = PodG1Point(right.try_into().unwrap());
        if let Some(result) = bls12_381_g1_addition_unchecked(Version::V0, &p1, &p2, Endianness::BE)
        {
            Ok(result.0.to_vec())
        } else {
            Err(Bls12381Error::InvalidInputData)
        }
    }

    #[cfg(target_os = "solana")]
    {
        let mut result_buffer = vec![0u8; BLS12_381_G1_POINT_SIZE];
        let result = unsafe {
            syscalls::sol_curve_group_op(
                BLS12_381_G1_BE,
                ADD,
                left.as_ptr() as *const u8,
                right.as_ptr() as *const u8,
                result_buffer.as_mut_ptr(),
            )
        };
        if result == 0 {
            Ok(result_buffer)
        } else {
            Err(Bls12381Error::UnexpectedError)
        }
    }
}

/// Performs BLS12-381 G1 point addition (Little-Endian).
#[inline(always)]
pub fn bls12_381_g1_addition_le(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Bls12381Error> {
    if left.len() != BLS12_381_G1_POINT_SIZE || right.len() != BLS12_381_G1_POINT_SIZE {
        return Err(Bls12381Error::InvalidInputData);
    }

    #[cfg(not(target_os = "solana"))]
    {
        let p1 = PodG1Point(left.try_into().unwrap());
        let p2 = PodG1Point(right.try_into().unwrap());
        if let Some(result) = bls12_381_g1_addition_unchecked(Version::V0, &p1, &p2, Endianness::LE)
        {
            Ok(result.0.to_vec())
        } else {
            Err(Bls12381Error::InvalidInputData)
        }
    }

    #[cfg(target_os = "solana")]
    {
        let mut result_buffer = vec![0u8; BLS12_381_G1_POINT_SIZE];
        let result = unsafe {
            syscalls::sol_curve_group_op(
                BLS12_381_G1_LE,
                ADD,
                left.as_ptr() as *const u8,
                right.as_ptr() as *const u8,
                result_buffer.as_mut_ptr(),
            )
        };
        if result == 0 {
            Ok(result_buffer)
        } else {
            Err(Bls12381Error::UnexpectedError)
        }
    }
}

/// Performs BLS12-381 G2 point addition (Big-Endian).
#[inline(always)]
pub fn bls12_381_g2_addition_be(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Bls12381Error> {
    if left.len() != BLS12_381_G2_POINT_SIZE || right.len() != BLS12_381_G2_POINT_SIZE {
        return Err(Bls12381Error::InvalidInputData);
    }

    #[cfg(not(target_os = "solana"))]
    {
        let p1 = PodG2Point(left.try_into().unwrap());
        let p2 = PodG2Point(right.try_into().unwrap());
        if let Some(result) = bls12_381_g2_addition_unchecked(Version::V0, &p1, &p2, Endianness::BE)
        {
            Ok(result.0.to_vec())
        } else {
            Err(Bls12381Error::InvalidInputData)
        }
    }

    #[cfg(target_os = "solana")]
    {
        let mut result_buffer = vec![0u8; BLS12_381_G2_POINT_SIZE];
        let result = unsafe {
            syscalls::sol_curve_group_op(
                BLS12_381_G2_BE,
                ADD,
                left.as_ptr() as *const u8,
                right.as_ptr() as *const u8,
                result_buffer.as_mut_ptr(),
            )
        };
        if result == 0 {
            Ok(result_buffer)
        } else {
            Err(Bls12381Error::UnexpectedError)
        }
    }
}

/// Performs BLS12-381 G2 point addition (Little-Endian).
#[inline(always)]
pub fn bls12_381_g2_addition_le(left: &[u8], right: &[u8]) -> Result<Vec<u8>, Bls12381Error> {
    if left.len() != BLS12_381_G2_POINT_SIZE || right.len() != BLS12_381_G2_POINT_SIZE {
        return Err(Bls12381Error::InvalidInputData);
    }

    #[cfg(not(target_os = "solana"))]
    {
        let p1 = PodG2Point(left.try_into().unwrap());
        let p2 = PodG2Point(right.try_into().unwrap());
        if let Some(result) = bls12_381_g2_addition_unchecked(Version::V0, &p1, &p2, Endianness::LE)
        {
            Ok(result.0.to_vec())
        } else {
            Err(Bls12381Error::InvalidInputData)
        }
    }

    #[cfg(target_os = "solana")]
    {
        let mut result_buffer = vec![0u8; BLS12_381_G2_POINT_SIZE];
        let result = unsafe {
            syscalls::sol_curve_group_op(
                BLS12_381_G2_LE,
                ADD,
                left.as_ptr() as *const u8,
                right.as_ptr() as *const u8,
                result_buffer.as_mut_ptr(),
            )
        };
        if result == 0 {
            Ok(result_buffer)
        } else {
            Err(Bls12381Error::UnexpectedError)
        }
    }
}
