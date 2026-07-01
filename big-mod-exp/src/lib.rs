#![cfg_attr(docsrs, feature(doc_cfg))]

/// Parameters for the `sol_big_mod_exp` syscall.
///
/// The pointed-to input slices are encoded as little-endian unsigned integers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BigModExpParams {
    /// VM pointer to the base bytes.
    pub base: u64,
    /// Length of the base bytes.
    pub base_len: u64,
    /// VM pointer to the exponent bytes.
    pub exponent: u64,
    /// Length of the exponent bytes.
    pub exponent_len: u64,
    /// VM pointer to the modulus bytes.
    pub modulus: u64,
    /// Length of the modulus bytes and writable result buffer.
    pub modulus_len: u64,
}

pub const BIG_MOD_EXP_MAX_BYTES: u64 = 512;
pub const BIG_MOD_EXP_BASE_CU: u64 = 422;
pub const BIG_MOD_EXP_CU_DIVISOR: u64 = 189;
pub const BIG_MOD_EXP_MIN_EXPONENT_LENGTH: u64 = 75;
pub const BIG_MOD_EXP_MOD_REDUCTION_COMPLEXITY_FACTOR: u64 = 15;

/// Big integer modular exponentiation.
///
/// Inputs and output are little-endian unsigned integers. The returned value,
/// if any, is padded to exactly `modulus.len()` bytes with trailing zeroes.
///
/// # Returns
///
/// Returns `None` if any operand is longer than [`BIG_MOD_EXP_MAX_BYTES`] or if
/// `modulus` is empty, zero, one, or even.
pub fn big_mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Option<Vec<u8>> {
    if !validate_inputs(base, exponent, modulus) {
        return None;
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        use num_bigint::BigUint;

        let modulus_len = modulus.len();

        if is_zero_le(exponent) {
            return Some(padded_one(modulus_len));
        }

        let modulus = BigUint::from_bytes_le(modulus);
        let mut base = BigUint::from_bytes_le(base);

        if base >= modulus {
            base = core::ops::Rem::rem(base, &modulus);
        }

        if base == BigUint::ZERO {
            return Some(vec![0; modulus_len]);
        }

        if base.bits() == 1 || is_one_le(exponent) {
            return Some(padded_to_modulus_len(base.to_bytes_le(), modulus_len));
        }

        let exponent = BigUint::from_bytes_le(exponent);
        let ret_int = base.modpow(&exponent, &modulus);
        Some(padded_to_modulus_len(ret_int.to_bytes_le(), modulus_len))
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut return_value = vec![0_u8; modulus.len()];
        let params = BigModExpParams {
            base: base.as_ptr() as u64,
            base_len: base.len() as u64,
            exponent: exponent.as_ptr() as u64,
            exponent_len: exponent.len() as u64,
            modulus: modulus.as_ptr() as u64,
            modulus_len: modulus.len() as u64,
        };
        // SAFETY: `validate_inputs` bounds the slice lengths and rejects
        // invalid moduli. The syscall reads the params and input slices before
        // writing exactly `modulus.len()` bytes to `return_value`.
        unsafe {
            solana_define_syscall::definitions::sol_big_mod_exp(
                &params as *const _ as *const u8,
                return_value.as_mut_ptr(),
            );
        };
        Some(return_value)
    }
}

fn validate_inputs(base: &[u8], exponent: &[u8], modulus: &[u8]) -> bool {
    let max_len = BIG_MOD_EXP_MAX_BYTES as usize;

    base.len() <= max_len
        && exponent.len() <= max_len
        && modulus.len() <= max_len
        && validate_modulus(modulus)
}

fn validate_modulus(modulus: &[u8]) -> bool {
    let Some((&least_significant_byte, more_significant_bytes)) = modulus.split_first() else {
        return false;
    };

    if least_significant_byte & 1 == 0 {
        return false;
    }

    least_significant_byte > 1 || more_significant_bytes.iter().any(|byte| *byte != 0)
}

#[cfg(any(test, not(any(target_os = "solana", target_arch = "bpf"))))]
fn is_zero_le(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(any(test, not(any(target_os = "solana", target_arch = "bpf"))))]
fn is_one_le(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(1)) && bytes[1..].iter().all(|byte| *byte == 0)
}

#[cfg(any(test, not(any(target_os = "solana", target_arch = "bpf"))))]
fn padded_one(modulus_len: usize) -> Vec<u8> {
    let mut return_value = vec![0; modulus_len];
    return_value[0] = 1;
    return_value
}

#[cfg(any(test, not(any(target_os = "solana", target_arch = "bpf"))))]
fn padded_to_modulus_len(mut return_value: Vec<u8>, modulus_len: usize) -> Vec<u8> {
    return_value.resize(modulus_len, 0);
    return_value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde_derive::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        base: String,
        exponent: String,
        modulus: String,
        expected: String,
    }

    fn be_hex_to_le_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = array_bytes::hex2bytes_unchecked(hex);
        bytes.reverse();
        bytes
    }

    fn is_supported_modulus(modulus: &[u8]) -> bool {
        validate_modulus(modulus)
    }

    #[test]
    fn big_mod_exp_params_abi_layout_test() {
        assert_eq!(core::mem::size_of::<BigModExpParams>(), 48);
        assert_eq!(core::mem::align_of::<BigModExpParams>(), 8);
        assert_eq!(core::mem::offset_of!(BigModExpParams, base), 0);
        assert_eq!(core::mem::offset_of!(BigModExpParams, base_len), 8);
        assert_eq!(core::mem::offset_of!(BigModExpParams, exponent), 16);
        assert_eq!(core::mem::offset_of!(BigModExpParams, exponent_len), 24);
        assert_eq!(core::mem::offset_of!(BigModExpParams, modulus), 32);
        assert_eq!(core::mem::offset_of!(BigModExpParams, modulus_len), 40);
    }

    #[test]
    fn big_mod_exp_json_test_vectors() {
        let test_data = include_str!("../tests/data/big_mod_exp_cases.json");
        let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

        for (index, test) in test_cases.iter().enumerate() {
            // The test vectors are encoded in big-endian hex, so convert to little-endian bytes.
            let base = be_hex_to_le_bytes(&test.base);
            let exponent = be_hex_to_le_bytes(&test.exponent);
            let modulus = be_hex_to_le_bytes(&test.modulus);
            let expected = be_hex_to_le_bytes(&test.expected);

            if is_supported_modulus(&modulus) {
                let result = big_mod_exp(&base, &exponent, &modulus);
                assert_eq!(result, Some(expected), "JSON test vector {index}");
            } else {
                assert_eq!(
                    big_mod_exp(&base, &exponent, &modulus),
                    None,
                    "JSON test vector {index}"
                );
            }
        }
    }

    #[test]
    fn big_mod_exp_basic_test() {
        let result = big_mod_exp(&[0x05], &[0x02], &[0x07]);
        assert_eq!(result, Some(vec![0x04]));
    }

    #[test]
    fn big_mod_exp_large_exponent_test() {
        let base = [0x03];
        let exponent = array_bytes::hex2bytes_unchecked(
            "2efcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let modulus = array_bytes::hex2bytes_unchecked(
            "2ffcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        let result = big_mod_exp(&base, &exponent, &modulus);
        let mut expected = vec![0; 32];
        expected[0] = 1;
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn big_mod_exp_eip_198_little_endian_test() {
        let base = array_bytes::hex2bytes_unchecked(
            "0300000000000000000000000000000000000000000000000000000000000000",
        );
        let exponent = array_bytes::hex2bytes_unchecked(
            "2efcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let modulus = array_bytes::hex2bytes_unchecked(
            "2ffcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let result = big_mod_exp(&base, &exponent, &modulus);
        let mut expected = vec![0; 32];
        expected[0] = 1;
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn big_mod_exp_empty_exponent_test() {
        assert_eq!(big_mod_exp(&[], &[], &[0x03]), Some(vec![0x01]));
    }

    #[test]
    fn big_mod_exp_zero_exponent_test() {
        assert_eq!(
            big_mod_exp(&[0x00], &[0x00, 0x00], &[0x03, 0x00]),
            Some(vec![0x01, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_zero_base_test() {
        assert_eq!(
            big_mod_exp(&[0x00, 0x00], &[0x02], &[0x03, 0x00]),
            Some(vec![0x00, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_one_exponent_equal_length_reduction_test() {
        assert_eq!(
            big_mod_exp(&[0x0a, 0x01], &[0x01, 0x00], &[0x07, 0x01]),
            Some(vec![0x03, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_output_padding_test() {
        assert_eq!(
            big_mod_exp(&[0x02], &[0x02], &[0x07, 0x00]),
            Some(vec![0x04, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_base_padding_test() {
        assert_eq!(
            big_mod_exp(&[0x02], &[0x03], &[0x07, 0x00]),
            big_mod_exp(&[0x02, 0x00], &[0x03], &[0x07, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_reduction_test() {
        assert_eq!(
            big_mod_exp(&[0x00, 0xe1, 0xf5, 0x05], &[0x01], &[0xb3, 0x15]),
            Some(vec![0x5d, 0x11])
        );
    }

    #[test]
    fn big_mod_exp_base_equal_modulus_test() {
        assert_eq!(big_mod_exp(&[0x07], &[0x02], &[0x07]), Some(vec![0x00]));
    }

    #[test]
    fn big_mod_exp_max_length_inputs_test() {
        let max_len = BIG_MOD_EXP_MAX_BYTES as usize;
        let base = vec![0xff; max_len];
        let exponent = vec![0; max_len];
        let modulus = vec![0xff; max_len];

        let mut expected = vec![0; max_len];
        expected[0] = 1;
        assert_eq!(big_mod_exp(&base, &exponent, &modulus), Some(expected));
    }

    #[test]
    fn big_mod_exp_empty_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[], &[], &[]), None);
    }

    #[test]
    fn big_mod_exp_zero_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x00]), None);
    }

    #[test]
    fn big_mod_exp_one_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x01]), None);
    }

    #[test]
    fn big_mod_exp_even_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x02]), None);
    }

    #[test]
    fn big_mod_exp_base_too_long_returns_none() {
        let base = vec![0; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        let modulus = vec![0xff; BIG_MOD_EXP_MAX_BYTES as usize];
        assert_eq!(big_mod_exp(&base, &[], &modulus), None);
    }

    #[test]
    fn big_mod_exp_exponent_too_long_returns_none() {
        let exponent = vec![0; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        assert_eq!(big_mod_exp(&[], &exponent, &[0x03]), None);
    }

    #[test]
    fn big_mod_exp_modulus_too_long_returns_none() {
        let mut modulus = vec![0xff; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        modulus[0] |= 1;
        assert_eq!(big_mod_exp(&[], &[], &modulus), None);
    }

    #[test]
    fn big_mod_exp_multi_byte_one_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x01, 0x00]), None);
    }

    #[test]
    fn big_mod_exp_multi_byte_zero_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x00, 0x00]), None);
    }

    #[test]
    fn big_mod_exp_explicit_zero_base_empty_exponent_test() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x03]), Some(vec![0x01]));
    }

    #[test]
    fn big_mod_exp_multi_byte_even_modulus_returns_none() {
        assert_eq!(big_mod_exp(&[0x00], &[], &[0x02, 0x01, 0x00]), None);
    }

    #[test]
    fn big_mod_exp_base_equal_modulus_reduction_test() {
        assert_eq!(
            big_mod_exp(&[0x07, 0x00], &[0x01], &[0x07, 0x00]),
            Some(vec![0x00, 0x00])
        );
    }

    #[test]
    fn big_mod_exp_highly_padded_modulus_test() {
        // Modulus is 3, padded to 4 bytes. Output padded to 4 bytes.
        assert_eq!(
            big_mod_exp(&[0x02], &[0x02], &[0x03, 0x00, 0x00, 0x00]),
            Some(vec![0x01, 0x00, 0x00, 0x00])
        );
    }
}
