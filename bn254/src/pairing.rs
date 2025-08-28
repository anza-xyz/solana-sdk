use crate::{AltBn128Error, LE_FLAG};
#[cfg(target_os = "solana")]
use solana_define_syscall::definitions as syscalls;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        consts::ALT_BN128_POINT_SIZE as G1_POINT_SIZE,
        target_arch::{Endianness, G1, G2},
        PodG1, PodG2,
    },
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
};

/// Pair element length.
pub const ALT_BN128_PAIRING_ELEMENT_LEN: usize = 192;
/// Output length for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_LEN: usize = 32;

pub const ALT_BN128_PAIRING: u64 = 3;
pub const ALT_BN128_PAIRING_LE: u64 = ALT_BN128_PAIRING | LE_FLAG;

/// The version enum used to version changes to the `alt_bn128_pairing` syscall.
#[cfg(not(target_os = "solana"))]
pub enum VersionedPairing {
    V0,
}

/// The syscall implementation for the `alt_bn128_pairing` syscall.
///
/// This function is intended to be used by the Agave validator client and exists primarily
/// for validator code. Solana programs or other downstream projects should use
/// `alt_bn128_pairing` or `alt_bn128_pairing_le` instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a breaking change
/// can result in a fork in the Solana cluster. Any such change requires an
/// approved Solana SIMD. Subsequently, a new `VersionedPairing` variant must be added,
/// and the new logic must be scoped to that variant.
#[cfg(not(target_os = "solana"))]
pub fn versioned_pairing(
    _version: VersionedPairing,
    input: &[u8],
    endianness: Endianness,
) -> Result<Vec<u8>, AltBn128Error> {
    if input
        .len()
        .checked_rem(ALT_BN128_PAIRING_ELEMENT_LEN)
        .is_none()
    {
        return Err(AltBn128Error::InvalidInputData);
    }

    let ele_len = input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_LEN);

    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(ele_len);
    for chunk in input.chunks(ALT_BN128_PAIRING_ELEMENT_LEN).take(ele_len) {
        let (p_bytes, q_bytes) = chunk.split_at(G1_POINT_SIZE);

        let g1 = match endianness {
            Endianness::BE => PodG1::from_be_bytes(p_bytes)?.try_into()?,
            Endianness::LE => PodG1::from_le_bytes(p_bytes)?.try_into()?,
        };
        let g2 = match endianness {
            Endianness::BE => PodG2::from_be_bytes(q_bytes)?.try_into()?,
            Endianness::LE => PodG2::from_le_bytes(q_bytes)?.try_into()?,
        };

        vec_pairs.push((g1, g2));
    }

    let mut result = BigInteger256::from(0u64);
    let res = <Bn<Config> as Pairing>::multi_pairing(
        vec_pairs.iter().map(|pair| pair.0),
        vec_pairs.iter().map(|pair| pair.1),
    );

    if res.0 == ark_bn254::Fq12::one() {
        result = BigInteger256::from(1u64);
    }

    let output = match endianness {
        Endianness::BE => result.to_bytes_be(),
        Endianness::LE => result.to_bytes_le(),
    };
    Ok(output)
}

#[inline(always)]
pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        versioned_pairing(VersionedPairing::V0, input, Endianness::BE)
    }
    #[cfg(target_os = "solana")]
    {
        if input
            .len()
            .checked_rem(ALT_BN128_PAIRING_ELEMENT_LEN)
            .is_none()
        {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; 32];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer.to_vec()),
            _ => Err(AltBn128Error::UnexpectedError),
        }
    }
}

#[inline(always)]
pub fn alt_bn128_pairing_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        versioned_pairing(VersionedPairing::V0, input, Endianness::LE)
    }
    #[cfg(target_os = "solana")]
    {
        if input
            .len()
            .checked_rem(ALT_BN128_PAIRING_ELEMENT_LEN)
            .is_none()
        {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; 32];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING_LE,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer.to_vec()),
            _ => Err(AltBn128Error::UnexpectedError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_bn128_pairing_invalid_length() {
        use ark_ff::{BigInteger, BigInteger256};

        let input = [0; 193];
        let result = alt_bn128_pairing(&input);
        assert!(result.is_ok());
        let expected = BigInteger256::from(1u64).to_bytes_be();
        assert_eq!(result.unwrap(), expected);
    }
}
