use crate::{
    consts::{ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE},
    AltBn128Error, LE_FLAG,
};
#[cfg(target_os = "solana")]
use solana_define_syscall::definitions as syscalls;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        consts::ALT_BN128_G1_POINT_SIZE as G1_POINT_SIZE,
        target_arch::{reject_flag_bits, Endianness, G1, G2},
        PodG1, PodG2,
    },
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
};

/// Pair element size.
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE; // 192
/// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

#[deprecated(
    since = "3.1.0",
    note = "Please use `ALT_BN128_PAIRING_ELEMENT_SIZE` instead"
)]
pub const ALT_BN128_PAIRING_ELEMENT_LEN: usize = ALT_BN128_PAIRING_ELEMENT_SIZE;
#[deprecated(
    since = "3.1.0",
    note = "Please use `ALT_BN128_PAIRING_OUTPUT_SIZE` instead"
)]
pub const ALT_BN128_PAIRING_OUTPUT_LEN: usize = ALT_BN128_PAIRING_OUTPUT_SIZE;

pub const ALT_BN128_PAIRING_BE: u64 = 3;
#[deprecated(since = "3.1.0", note = "Please use `ALT_BN128_PAIRING_BE` instead")]
pub const ALT_BN128_PAIRING: u64 = ALT_BN128_PAIRING_BE;
pub const ALT_BN128_PAIRING_LE: u64 = ALT_BN128_PAIRING_BE | LE_FLAG;

/// The version enum used to version changes to the `alt_bn128_pairing` syscall.
#[cfg(not(target_os = "solana"))]
pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
    /// Reject field elements with either of the two most significant bits
    /// set, as EIP-197 does (<https://github.com/anza-xyz/agave/issues/3379>).
    V2,
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
pub fn alt_bn128_versioned_pairing(
    version: VersionedPairing,
    input: &[u8],
    endianness: Endianness,
) -> Result<Vec<u8>, AltBn128Error> {
    match version {
        VersionedPairing::V0 => {
            if input
                .len()
                .checked_rem(ALT_BN128_PAIRING_ELEMENT_SIZE)
                .is_none()
            {
                return Err(AltBn128Error::InvalidInputData);
            }
        }
        VersionedPairing::V1 | VersionedPairing::V2 => {
            #[allow(clippy::manual_is_multiple_of)]
            if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
                return Err(AltBn128Error::InvalidInputData);
            }
        }
    }

    let ele_len = input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_SIZE);

    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(ele_len);
    for chunk in input.chunks(ALT_BN128_PAIRING_ELEMENT_SIZE).take(ele_len) {
        let (p_bytes, q_bytes) = chunk.split_at(G1_POINT_SIZE);

        let (g1_pod, g2_pod) = match endianness {
            Endianness::BE => (
                PodG1::from_be_bytes(p_bytes)?,
                PodG2::from_be_bytes(q_bytes)?,
            ),
            Endianness::LE => (
                PodG1::from_le_bytes(p_bytes)?,
                PodG2::from_le_bytes(q_bytes)?,
            ),
        };

        if matches!(version, VersionedPairing::V2) {
            reject_flag_bits(&g1_pod.0)?;
            reject_flag_bits(&g2_pod.0)?;
        }

        let g1: G1 = g1_pod.try_into()?;
        let g2: G2 = g2_pod.try_into()?;

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
pub fn alt_bn128_pairing_be(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        alt_bn128_versioned_pairing(VersionedPairing::V2, input, Endianness::BE)
    }
    #[cfg(target_os = "solana")]
    {
        if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
            return Err(AltBn128Error::InvalidInputData);
        }
        // SAFETY: This is sound as sol_alt_bn128_group_op pairing always fills all 32 bytes of our buffer
        let mut result_buffer = Vec::with_capacity(ALT_BN128_PAIRING_OUTPUT_SIZE);
        unsafe {
            let result = syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING_BE,
                input as *const _ as *const u8,
                input.len() as u64,
                result_buffer.as_mut_ptr(),
            );
            match result {
                0 => {
                    result_buffer.set_len(ALT_BN128_PAIRING_OUTPUT_SIZE);
                    Ok(result_buffer)
                }
                _ => Err(AltBn128Error::UnexpectedError),
            }
        }
    }
}

#[deprecated(since = "3.1.0", note = "Please use `alt_bn128_pairing_be` instead")]
#[allow(deprecated)]
#[inline(always)]
pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        alt_bn128_versioned_pairing(VersionedPairing::V0, input, Endianness::BE)
    }
    #[cfg(target_os = "solana")]
    {
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
        alt_bn128_versioned_pairing(VersionedPairing::V2, input, Endianness::LE)
    }
    #[cfg(target_os = "solana")]
    {
        if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
            return Err(AltBn128Error::InvalidInputData);
        }
        // SAFETY: This is sound as sol_alt_bn128_group_op pairing always fills all 32 bytes of our buffer
        let mut result_buffer = Vec::with_capacity(ALT_BN128_PAIRING_OUTPUT_SIZE);
        unsafe {
            let result = syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING_LE,
                input as *const _ as *const u8,
                input.len() as u64,
                result_buffer.as_mut_ptr(),
            );
            match result {
                0 => {
                    result_buffer.set_len(ALT_BN128_PAIRING_OUTPUT_SIZE);
                    Ok(result_buffer)
                }
                _ => Err(AltBn128Error::UnexpectedError),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_ec::AffineRepr,
        ark_serialize::{CanonicalSerialize, Compress},
    };

    #[test]
    fn alt_bn128_pairing_invalid_length() {
        let input = [0; 193];
        let result = alt_bn128_pairing_be(&input);
        assert!(result.is_err());
    }

    /// `(G1 generator, G2 generator)`, little-endian (the `ark-serialize`
    /// layout).
    fn generator_pair_le() -> [u8; ALT_BN128_PAIRING_ELEMENT_SIZE] {
        let mut input = [0u8; ALT_BN128_PAIRING_ELEMENT_SIZE];
        input[0] = 1;
        input[32] = 2;
        let g2 = G2::generator();
        g2.x.serialize_with_mode(&mut input[64..128], Compress::No)
            .unwrap();
        g2.y.serialize_with_mode(&mut input[128..], Compress::No)
            .unwrap();
        input
    }

    #[test]
    fn pairing_v2_rejects_flag_bits() {
        let clean_le = generator_pair_le();
        let expected =
            alt_bn128_versioned_pairing(VersionedPairing::V1, &clean_le, Endianness::LE).unwrap();
        assert_eq!(
            alt_bn128_versioned_pairing(VersionedPairing::V2, &clean_le, Endianness::LE),
            Ok(expected)
        );

        // Index 63 is the most significant byte of the G1 `y`, index 191 that
        // of the G2 `y_c1`: the bytes `ark-serialize` reads flags from.
        for (index, bit) in [(63, 0x80u8), (63, 0x40), (191, 0x80), (191, 0x40)] {
            let mut flagged_le = clean_le;
            flagged_le[index] |= bit;
            assert!(
                alt_bn128_versioned_pairing(VersionedPairing::V1, &flagged_le, Endianness::LE)
                    .is_ok()
            );
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V2, &flagged_le, Endianness::LE),
                Err(AltBn128Error::InvalidInputData)
            );
        }
    }
}
