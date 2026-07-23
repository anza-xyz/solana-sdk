pub const G1_POINT_SIZE: usize = 96;
pub const G2_POINT_SIZE: usize = 192;
pub const GT_ELEMENT_SIZE: usize = 576;

/// Maximum number of pairs allowed by the syscall for a single pairing operation.
pub const MAX_PAIRING_LENGTH: usize = 8;

use crate::error::Bls12381Error;

/// Computes the pairing map for a batch of BLS12-381 G1 and G2 points encoded in little-endian format.
///
/// Computes: `e(P_1, Q_1) * e(P_2, Q_2) * ... * e(P_n, Q_n)`
/// Returns the target group (Gt) element as a 576-byte array.
pub fn pairing_map_le(
    g1_points: &[[u8; G1_POINT_SIZE]],
    g2_points: &[[u8; G2_POINT_SIZE]],
) -> Result<[u8; GT_ELEMENT_SIZE], Bls12381Error> {
    if g1_points.len() != g2_points.len() || g1_points.len() > MAX_PAIRING_LENGTH {
        return Err(Bls12381Error::InvalidInputData);
    }

    let mut result = [0u8; GT_ELEMENT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_pairing_map(
                solana_define_syscall::curve_constants::BLS12_381_LE,
                g1_points.len() as u64,
                g1_points.as_ptr() as *const u8,
                g2_points.as_ptr() as *const u8,
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let g1_pods: &[solana_bls12_381_syscall::PodG1Point] = bytemuck::cast_slice(g1_points);
        let g2_pods: &[solana_bls12_381_syscall::PodG2Point] = bytemuck::cast_slice(g2_points);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_pairing_map(
            solana_bls12_381_syscall::Version::V0,
            g1_pods,
            g2_pods,
            solana_bls12_381_syscall::Endianness::LE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}

/// Computes the pairing map for a batch of BLS12-381 G1 and G2 points encoded in big-endian format.
///
/// Computes: `e(P_1, Q_1) * e(P_2, Q_2) * ... * e(P_n, Q_n)`
/// Returns the target group (Gt) element as a 576-byte array.
pub fn pairing_map_be(
    g1_points: &[[u8; G1_POINT_SIZE]],
    g2_points: &[[u8; G2_POINT_SIZE]],
) -> Result<[u8; GT_ELEMENT_SIZE], Bls12381Error> {
    if g1_points.len() != g2_points.len() || g1_points.len() > MAX_PAIRING_LENGTH {
        return Err(Bls12381Error::InvalidInputData);
    }

    let mut result = [0u8; GT_ELEMENT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let status = unsafe {
            solana_define_syscall::definitions::sol_curve_pairing_map(
                solana_define_syscall::curve_constants::BLS12_381_BE,
                g1_points.len() as u64,
                g1_points.as_ptr() as *const u8,
                g2_points.as_ptr() as *const u8,
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let g1_pods: &[solana_bls12_381_syscall::PodG1Point] = bytemuck::cast_slice(g1_points);
        let g2_pods: &[solana_bls12_381_syscall::PodG2Point] = bytemuck::cast_slice(g2_points);

        if let Some(res) = solana_bls12_381_syscall::bls12_381_pairing_map(
            solana_bls12_381_syscall::Version::V0,
            g1_pods,
            g2_pods,
            solana_bls12_381_syscall::Endianness::BE,
        ) {
            result.copy_from_slice(&res.0);
        } else {
            return Err(Bls12381Error::InvalidInputData);
        }
    }

    Ok(result)
}
