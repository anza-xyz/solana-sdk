use crate::{
    consts::{ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, ALT_BN128_GT_ELEMENT_SIZE},
    AltBn128Error, LE_FLAG,
};
#[cfg(target_os = "solana")]
use solana_define_syscall::definitions as syscalls;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        consts::ALT_BN128_G1_POINT_SIZE as G1_POINT_SIZE,
        target_arch::{Endianness, G1, G2},
        PodG1, PodG2,
    },
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
    ark_serialize::CanonicalSerialize,
};

/// Pair element size.
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE; // 192
/// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

/// Pair element size for the pairing map operation. This is the same as
/// `ALT_BN128_PAIRING_ELEMENT_SIZE`.
pub const ALT_BN128_PAIRING_MAP_ELEMENT_SIZE: usize = ALT_BN128_PAIRING_ELEMENT_SIZE; // 192
/// Output size for the pairing map operation.
pub const ALT_BN128_PAIRING_MAP_OUTPUT_SIZE: usize = ALT_BN128_GT_ELEMENT_SIZE; // 384

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

/// SIMD-0650: pairing with target group (Gt) output.
pub const ALT_BN128_PAIRING_MAP_BE: u64 = 7;
pub const ALT_BN128_PAIRING_MAP_LE: u64 = ALT_BN128_PAIRING_MAP_BE | LE_FLAG;

/// The version enum used to version changes to the `alt_bn128_pairing` syscall.
#[cfg(not(target_os = "solana"))]
pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
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
        VersionedPairing::V1 =>
        {
            #[allow(clippy::manual_is_multiple_of)]
            if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
                return Err(AltBn128Error::InvalidInputData);
            }
        }
    }

    let res = multi_pairing(input, &endianness)?;
    let mut result = BigInteger256::from(0u64);

    if res == ark_bn254::Fq12::one() {
        result = BigInteger256::from(1u64);
    }

    let output = match endianness {
        Endianness::BE => result.to_bytes_be(),
        Endianness::LE => result.to_bytes_le(),
    };
    Ok(output)
}

/// Decodes and validates a sequence of `(G1, G2)` pairs and computes the
/// product of their pairings.
#[cfg(not(target_os = "solana"))]
fn multi_pairing(input: &[u8], endianness: &Endianness) -> Result<ark_bn254::Fq12, AltBn128Error> {
    let ele_len = input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_SIZE);

    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(ele_len);
    for chunk in input.chunks(ALT_BN128_PAIRING_ELEMENT_SIZE).take(ele_len) {
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

    let res = <Bn<Config> as Pairing>::multi_pairing(
        vec_pairs.iter().map(|pair| pair.0),
        vec_pairs.iter().map(|pair| pair.1),
    );

    Ok(res.0)
}

/// The version enum used to version changes to the `alt_bn128_pairing_map` syscall.
#[cfg(not(target_os = "solana"))]
pub enum VersionedPairingMap {
    /// SIMD-0650 - BN254 Pairing with Target Group Output
    V0,
}

/// The syscall implementation for the `alt_bn128_pairing_map` syscall.
///
/// The input layout and validation are identical to those of
/// `alt_bn128_versioned_pairing` (`VersionedPairing::V1`). Instead of a 32-byte
/// identity flag, the output is the 384-byte target group (Gt) element
/// `e(P1, Q1) * ... * e(Pn, Qn)` after the final exponentiation. An empty input
/// yields the multiplicative identity of the target group.
///
/// The Gt element is an element of `Fq12`, flattened into twelve `Fq`
/// coefficients `c0, ..., c11` in canonical tower order (`Fq12.c_a.c_b.c_c` is
/// `c_(6a + 2b + c)`):
///
/// - `Endianness::LE`: `c0, c1, ..., c11`, each coefficient in little-endian.
/// - `Endianness::BE`: `c11, c10, ..., c0`, each coefficient in big-endian.
///   This is exactly the byte-reversal of the little-endian encoding.
///
/// This function is intended to be used by the Agave validator client and exists primarily
/// for validator code. Solana programs or other downstream projects should use
/// `alt_bn128_pairing_map_be` or `alt_bn128_pairing_map_le` instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a breaking change
/// can result in a fork in the Solana cluster. Any such change requires an
/// approved Solana SIMD. Subsequently, a new `VersionedPairingMap` variant must be added,
/// and the new logic must be scoped to that variant.
#[cfg(not(target_os = "solana"))]
pub fn alt_bn128_versioned_pairing_map(
    version: VersionedPairingMap,
    input: &[u8],
    endianness: Endianness,
) -> Result<Vec<u8>, AltBn128Error> {
    match version {
        VersionedPairingMap::V0 =>
        {
            #[allow(clippy::manual_is_multiple_of)]
            if input.len() % ALT_BN128_PAIRING_MAP_ELEMENT_SIZE != 0 {
                return Err(AltBn128Error::InvalidInputData);
            }
        }
    }

    let res = multi_pairing(input, &endianness)?;

    // `ark-serialize` writes the canonical (non-Montgomery) little-endian
    // encoding of the coefficients in tower order `c0, ..., c11`.
    let mut output = Vec::with_capacity(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
    res.serialize_uncompressed(&mut output)
        .map_err(|_| AltBn128Error::UnexpectedError)?;
    if output.len() != ALT_BN128_PAIRING_MAP_OUTPUT_SIZE {
        return Err(AltBn128Error::UnexpectedError);
    }

    if matches!(endianness, Endianness::BE) {
        output.reverse();
    }

    Ok(output)
}

#[inline(always)]
pub fn alt_bn128_pairing_be(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        alt_bn128_versioned_pairing(VersionedPairing::V1, input, Endianness::BE)
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
        alt_bn128_versioned_pairing(VersionedPairing::V1, input, Endianness::LE)
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

/// Computes the product of pairings `e(P1, Q1) * ... * e(Pn, Qn)` and returns
/// the resulting 384-byte target group (Gt) element (SIMD-0650).
///
/// The input is a sequence of 192-byte `(G1, G2)` pairs, encoded exactly as
/// for `alt_bn128_pairing_be`. The output consists of the twelve `Fq`
/// coefficients `c11, ..., c0` of the `Fq12` element, each in big-endian.
#[inline(always)]
pub fn alt_bn128_pairing_map_be(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        alt_bn128_versioned_pairing_map(VersionedPairingMap::V0, input, Endianness::BE)
    }
    #[cfg(target_os = "solana")]
    {
        if input.len() % ALT_BN128_PAIRING_MAP_ELEMENT_SIZE != 0 {
            return Err(AltBn128Error::InvalidInputData);
        }
        // SAFETY: This is sound as sol_alt_bn128_group_op pairing map always fills all 384 bytes of our buffer
        let mut result_buffer = Vec::with_capacity(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
        unsafe {
            let result = syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING_MAP_BE,
                input as *const _ as *const u8,
                input.len() as u64,
                result_buffer.as_mut_ptr(),
            );
            match result {
                0 => {
                    result_buffer.set_len(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
                    Ok(result_buffer)
                }
                _ => Err(AltBn128Error::UnexpectedError),
            }
        }
    }
}

/// Computes the product of pairings `e(P1, Q1) * ... * e(Pn, Qn)` and returns
/// the resulting 384-byte target group (Gt) element (SIMD-0650).
///
/// The input is a sequence of 192-byte `(G1, G2)` pairs, encoded exactly as
/// for `alt_bn128_pairing_le`. The output consists of the twelve `Fq`
/// coefficients `c0, ..., c11` of the `Fq12` element, each in little-endian.
#[inline(always)]
pub fn alt_bn128_pairing_map_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    #[cfg(not(target_os = "solana"))]
    {
        alt_bn128_versioned_pairing_map(VersionedPairingMap::V0, input, Endianness::LE)
    }
    #[cfg(target_os = "solana")]
    {
        if input.len() % ALT_BN128_PAIRING_MAP_ELEMENT_SIZE != 0 {
            return Err(AltBn128Error::InvalidInputData);
        }
        // SAFETY: This is sound as sol_alt_bn128_group_op pairing map always fills all 384 bytes of our buffer
        let mut result_buffer = Vec::with_capacity(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
        unsafe {
            let result = syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING_MAP_LE,
                input as *const _ as *const u8,
                input.len() as u64,
                result_buffer.as_mut_ptr(),
            );
            match result {
                0 => {
                    result_buffer.set_len(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
                    Ok(result_buffer)
                }
                _ => Err(AltBn128Error::UnexpectedError),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_bn128_pairing_invalid_length() {
        let input = [0; 193];
        let result = alt_bn128_pairing_be(&input);
        assert!(result.is_err());
    }

    #[test]
    fn alt_bn128_pairing_map_invalid_length() {
        let input = [0; 193];
        assert!(alt_bn128_pairing_map_be(&input).is_err());
        assert!(alt_bn128_pairing_map_le(&input).is_err());
    }

    #[test]
    fn alt_bn128_pairing_map_empty_input() {
        let mut identity = [0u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE];
        identity[0] = 1;
        assert_eq!(alt_bn128_pairing_map_le(&[]).unwrap(), identity);
        identity.reverse();
        assert_eq!(alt_bn128_pairing_map_be(&[]).unwrap(), identity);
    }
}
