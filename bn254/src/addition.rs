use crate::PodG1;
pub use target_arch::*;

pub(crate) mod consts {
    /// Input length for the add operation.
    pub const ALT_BN128_ADDITION_INPUT_LEN: usize = 128;
    /// Output length for the add operation.
    pub const ALT_BN128_ADDITION_OUTPUT_LEN: usize = 64;

    const LE_FLAG: u64 = 0x80;

    pub const ALT_BN128_ADD: u64 = 0;
    pub const ALT_BN128_SUB: u64 = 1;
    pub const ALT_BN128_ADD_LE: u64 = ALT_BN128_ADD | LE_FLAG;
    pub const ALT_BN128_SUB_LE: u64 = ALT_BN128_SUB | LE_FLAG;
}

#[cfg(not(target_os = "solana"))]
pub(crate) mod target_arch {
    use {
        super::{consts::*, PodG1},
        crate::{
            target_arch::{convert_endianness_64, Endianness, G1},
            AltBn128Error,
        },
        ark_serialize::{CanonicalSerialize, Compress},
    };

    #[inline(always)]
    pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_addition(input, Endianness::BE)
    }

    #[inline(always)]
    pub fn alt_bn128_addition_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        alt_bn128_apply_addition(input, Endianness::LE)
    }

    fn alt_bn128_apply_addition(
        input: &[u8],
        endianness: Endianness,
    ) -> Result<Vec<u8>, AltBn128Error> {
        match endianness {
            Endianness::BE => {
                if input.len() > ALT_BN128_ADDITION_INPUT_LEN {
                    return Err(AltBn128Error::InvalidInputData);
                }
            }
            Endianness::LE => {
                if input.len() != ALT_BN128_ADDITION_INPUT_LEN {
                    return Err(AltBn128Error::InvalidInputData);
                }
            }
        }

        let mut input = input.to_vec();
        match endianness {
            Endianness::BE => input.resize(ALT_BN128_ADDITION_INPUT_LEN, 0),
            Endianness::LE => (),
        }

        let p: G1 = match endianness {
            Endianness::BE => PodG1::from_be_bytes(&input[..64])?.try_into()?,
            Endianness::LE => PodG1::from_le_bytes(&input[..64])?.try_into()?,
        };

        let q: G1 = match endianness {
            Endianness::BE => PodG1::from_be_bytes(&input[64..])?.try_into()?,
            Endianness::LE => PodG1::from_le_bytes(&input[64..])?.try_into()?,
        };

        #[allow(clippy::arithmetic_side_effects)]
        let result_point = p + q;

        let mut result_point_data = [0u8; ALT_BN128_ADDITION_OUTPUT_LEN];
        let result_point_affine: G1 = result_point.into();
        result_point_affine
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point_affine
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

    pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > consts::ALT_BN128_ADDITION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0; consts::ALT_BN128_ADDITION_OUTPUT_LEN];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                consts::ALT_BN128_ADD,
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

    pub fn alt_bn128_addition_le(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() != consts::ALT_BN128_ADDITION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0; consts::ALT_BN128_ADDITION_OUTPUT_LEN];
        let result = unsafe {
            syscalls::sol_alt_bn128_group_op(
                consts::ALT_BN128_ADD_LE,
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
