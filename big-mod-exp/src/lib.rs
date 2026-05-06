#![cfg_attr(docsrs, feature(doc_cfg))]

pub const BIGINT_ENDIANNESS_BE: u64 = 0;
pub const BIGINT_ENDIANNESS_LE: u64 = 1;
pub const BIGINT_MODEXP_MAX_BYTES: u64 = 512;

/// Endianness of bigint inputs and result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Endianness {
    BigEndian = BIGINT_ENDIANNESS_BE,
    LittleEndian = BIGINT_ENDIANNESS_LE,
}

impl From<Endianness> for u64 {
    fn from(endianness: Endianness) -> Self {
        match endianness {
            Endianness::BigEndian => BIGINT_ENDIANNESS_BE,
            Endianness::LittleEndian => BIGINT_ENDIANNESS_LE,
        }
    }
}

#[repr(C)]
pub struct BigModExpParams {
    pub base: *const u8,
    pub base_len: u64,
    pub exponent: *const u8,
    pub exponent_len: u64,
    pub modulus: *const u8,
    pub modulus_len: u64,
}

#[repr(C)]
pub struct BigIntModExpParams {
    pub base_addr: u64,
    pub base_len: u64,
    pub exponent_addr: u64,
    pub exponent_len: u64,
    pub modulus_addr: u64,
    pub modulus_len: u64,
    pub result_addr: u64,
    pub result_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BigIntModExpError {
    InvalidLength,
}

/// Big integer modular exponentiation.
///
/// Inputs and output are encoded using `endianness`. The returned value is
/// padded to exactly `modulus.len()` bytes.
pub fn bigint_modexp(
    base: &[u8],
    exponent: &[u8],
    modulus: &[u8],
    endianness: Endianness,
) -> Vec<u8> {
    #[cfg(not(target_os = "solana"))]
    {
        use {
            num_bigint::BigUint,
            num_traits::{One, Zero},
        };

        let modulus_len = modulus.len();
        let (base, exponent, modulus) = match endianness {
            Endianness::BigEndian => (
                BigUint::from_bytes_be(base),
                BigUint::from_bytes_be(exponent),
                BigUint::from_bytes_be(modulus),
            ),
            Endianness::LittleEndian => (
                BigUint::from_bytes_le(base),
                BigUint::from_bytes_le(exponent),
                BigUint::from_bytes_le(modulus),
            ),
        };

        if modulus.is_zero() || modulus.is_one() {
            return vec![0_u8; modulus_len];
        }

        let ret_int = base.modpow(&exponent, &modulus);
        match endianness {
            Endianness::BigEndian => {
                let ret_int = ret_int.to_bytes_be();
                let mut return_value = vec![0_u8; modulus_len.saturating_sub(ret_int.len())];
                return_value.extend(ret_int);
                return_value
            }
            Endianness::LittleEndian => {
                let mut return_value = ret_int.to_bytes_le();
                return_value.resize(modulus_len, 0);
                return_value
            }
        }
    }

    #[cfg(target_os = "solana")]
    {
        let mut return_value = vec![0_u8; modulus.len()];

        let param = BigIntModExpParams {
            base_addr: base.as_ptr() as u64,
            base_len: base.len() as u64,
            exponent_addr: exponent.as_ptr() as u64,
            exponent_len: exponent.len() as u64,
            modulus_addr: modulus.as_ptr() as u64,
            modulus_len: modulus.len() as u64,
            result_addr: return_value.as_mut_ptr() as u64,
            result_len: return_value.len() as u64,
        };

        let result = unsafe {
            solana_define_syscall::definitions::sol_bigint_modexp(
                endianness.into(),
                &param as *const _ as *const u8,
            )
        };
        assert_eq!(result, 0, "sol_bigint_modexp failed");

        return_value
    }
}

/// Big-endian big integer modular exponentiation.
///
/// This is the compatibility wrapper for the original `solana-big-mod-exp`
/// API. Prefer [`bigint_modexp`] when little-endian support is needed.
pub fn big_mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    bigint_modexp(base, exponent, modulus, Endianness::BigEndian)
}

fn eip_198_length(input: &[u8], offset: usize) -> Result<u64, BigIntModExpError> {
    let mut word = [0u8; 32];
    if let Some(bytes) = input.get(offset..) {
        let copy_len = bytes.len().min(word.len());
        word[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(BigIntModExpError::InvalidLength);
    }

    let mut length_bytes = [0u8; 8];
    length_bytes.copy_from_slice(&word[24..]);
    let length = u64::from_be_bytes(length_bytes);
    if length > BIGINT_MODEXP_MAX_BYTES {
        return Err(BigIntModExpError::InvalidLength);
    }

    Ok(length)
}

fn eip_198_bytes(input: &[u8], offset: usize, len: u64) -> Vec<u8> {
    let len = len as usize;
    let mut bytes = vec![0u8; len];
    if let Some(input) = input.get(offset..) {
        let copy_len = input.len().min(len);
        bytes[..copy_len].copy_from_slice(&input[..copy_len]);
    }
    bytes
}

/// Ethereum EIP-198-compatible big-endian modular exponentiation.
///
/// This helper parses the packed EIP-198 input format and evaluates it through
/// the native Solana ModExp helper. Missing input bytes are right-padded with
/// zeroes, and bytes after the declared operands are ignored.
pub fn eip_198_modexp(input: &[u8]) -> Result<Vec<u8>, BigIntModExpError> {
    let base_len = eip_198_length(input, 0)?;
    let exponent_len = eip_198_length(input, 32)?;
    let modulus_len = eip_198_length(input, 64)?;

    let base_offset = 96;
    let exponent_offset = base_offset + base_len as usize;
    let modulus_offset = exponent_offset + exponent_len as usize;

    let base = eip_198_bytes(input, base_offset, base_len);
    let exponent = eip_198_bytes(input, exponent_offset, exponent_len);
    let modulus = eip_198_bytes(input, modulus_offset, modulus_len);

    Ok(bigint_modexp(
        &base,
        &exponent,
        &modulus,
        Endianness::BigEndian,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_mod_exp_test() {
        #[derive(serde_derive::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct TestCase {
            base: String,
            exponent: String,
            modulus: String,
            expected: String,
        }

        let test_data = include_str!("../tests/data/big_mod_exp_cases.json");

        let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();
        test_cases.iter().for_each(|test| {
            let base = array_bytes::hex2bytes_unchecked(&test.base);
            let exponent = array_bytes::hex2bytes_unchecked(&test.exponent);
            let modulus = array_bytes::hex2bytes_unchecked(&test.modulus);
            let expected = array_bytes::hex2bytes_unchecked(&test.expected);
            let result = big_mod_exp(base.as_slice(), exponent.as_slice(), modulus.as_slice());
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn bigint_modexp_eip_198_test() {
        let base = [0x03];
        let exponent = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        );
        let modulus = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        );

        let result = bigint_modexp(&base, &exponent, &modulus, Endianness::BigEndian);
        let mut expected = vec![0; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn bigint_modexp_empty_inputs_test() {
        assert_eq!(
            bigint_modexp(&[], &[], &[0x02], Endianness::BigEndian),
            vec![0x01]
        );
        assert_eq!(
            bigint_modexp(&[], &[], &[0x00], Endianness::BigEndian),
            vec![0x00]
        );
        assert_eq!(
            bigint_modexp(&[], &[], &[], Endianness::BigEndian),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn bigint_modexp_little_endian_test() {
        let base_be = [0x01, 0x02];
        let exponent_be = [0x03];
        let modulus_be = [0x10, 0x01];

        let mut base_le = base_be;
        let mut exponent_le = exponent_be;
        let mut modulus_le = modulus_be;
        base_le.reverse();
        exponent_le.reverse();
        modulus_le.reverse();

        let result_be = bigint_modexp(&base_be, &exponent_be, &modulus_be, Endianness::BigEndian);
        let mut result_le = bigint_modexp(
            &base_le,
            &exponent_le,
            &modulus_le,
            Endianness::LittleEndian,
        );
        result_le.reverse();

        assert_eq!(result_be, result_le);
    }

    #[test]
    fn eip_198_modexp_test() {
        let base = [0x03];
        let exponent = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        );
        let modulus = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        );

        let mut input = vec![0u8; 96];
        input[31] = base.len() as u8;
        input[63] = exponent.len() as u8;
        input[95] = modulus.len() as u8;
        input.extend(base);
        input.extend(exponent);
        input.extend(modulus);
        input.extend([0xff; 8]);

        let result = eip_198_modexp(&input).unwrap();
        let mut expected = vec![0; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn eip_198_modexp_right_padding_test() {
        let mut input = vec![0u8; 96];
        input[31] = 1;
        input[63] = 1;
        input[95] = 1;
        input.push(5);

        assert_eq!(eip_198_modexp(&input).unwrap(), vec![0]);
    }

    #[test]
    fn eip_198_modexp_rejects_lengths_over_syscall_limit_test() {
        let mut input = vec![0u8; 96];
        input[30] = 2;
        input[31] = 1;

        assert_eq!(
            eip_198_modexp(&input),
            Err(BigIntModExpError::InvalidLength)
        );
    }
}
