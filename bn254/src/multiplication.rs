use crate::PodG1;
pub use target_arch::*;

pub(crate) mod consts {
    /// Input length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_INPUT_LEN: usize = 96;
    /// Output length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_OUTPUT_LEN: usize = 64;

    const LE_FLAG: u64 = 0x80;

    pub const ALT_BN128_MUL: u64 = 2;
    pub const ALT_BN128_MUL_LE: u64 = ALT_BN128_MUL | LE_FLAG;
}

#[cfg(not(target_os = "solana"))]
pub(crate) mod target_arch {
    use {
        super::{consts::*, PodG1},
        crate::{
            target_arch::{convert_endianness_64, reverse_copy, Endianness, G1},
            AltBn128Error,
        },
        ark_ec::{self, AffineRepr},
        ark_ff::BigInteger256,
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress},
    };

    #[inline(always)]
    pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_multiplication(input, Endianness::BE, ALT_BN128_MULTIPLICATION_INPUT_LEN)
    }

    #[inline(always)]
    pub fn alt_bn128_multiplication_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_multiplication(input, Endianness::LE, ALT_BN128_MULTIPLICATION_INPUT_LEN)
    }

    #[inline(always)]
    pub fn alt_bn128_multiplication_128(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_multiplication(input, Endianness::BE, 128) // hard-code length; we will remove this function in the future
    }

    fn alt_bn128_apply_multiplication(
        input: &[u8],
        endianness: Endianness,
        expected_length: usize,
    ) -> Result<Vec<u8>, AltBn128Error> {
        match endianness {
            Endianness::BE => {
                if input.len() > expected_length {
                    return Err(AltBn128Error::InvalidInputData);
                }
            }
            Endianness::LE => {
                if input.len() != expected_length {
                    return Err(AltBn128Error::InvalidInputData);
                }
            }
        }

        let mut input = input.to_vec();
        match endianness {
            Endianness::BE => input.resize(expected_length, 0),
            Endianness::LE => (),
        }

        let p: G1 = match endianness {
            Endianness::BE => PodG1::from_be_bytes(&input[..64])?.try_into()?,
            Endianness::LE => PodG1::from_le_bytes(&input[..64])?.try_into()?,
        };
        let mut fr_bytes = [0u8; 32];
        match endianness {
            Endianness::BE => {
                reverse_copy(&input[64..96], &mut fr_bytes)?;
            }
            Endianness::LE => {
                fr_bytes.copy_from_slice(&input[64..96]);
            }
        }
        let fr = BigInteger256::deserialize_uncompressed_unchecked(fr_bytes.as_slice())
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        let result_point: G1 = p.mul_bigint(fr).into();

        let mut result_point_data = [0u8; ALT_BN128_MULTIPLICATION_OUTPUT_LEN];

        result_point
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point
            .y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        match endianness {
            Endianness::BE => Ok(convert_endianness_64(&result_point_data[..])),
            Endianness::LE => Ok(result_point_data.to_vec()),
        }
    }
}

#[cfg(target_os = "solana")]
pub(crate) mod target_arch {
    use {super::consts, crate::AltBn128Error, solana_define_syscall::definitions as syscalls};

    pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > consts::ALT_BN128_MULTIPLICATION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; consts::ALT_BN128_MULTIPLICATION_OUTPUT_LEN];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                consts::ALT_BN128_MUL,
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

    pub fn alt_bn128_multiplication_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() != consts::ALT_BN128_MULTIPLICATION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; consts::ALT_BN128_MULTIPLICATION_OUTPUT_LEN];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                consts::ALT_BN128_MUL_LE,
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
