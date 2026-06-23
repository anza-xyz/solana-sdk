#![cfg_attr(docsrs, feature(doc_cfg))]

/// Parameters for the `sol_big_mod_exp` syscall.
///
/// The pointed-to input slices are encoded as little-endian unsigned integers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BigModExpParams {
    /// VM pointer to the base bytes.
    pub base: *const u8,
    /// Length of the base bytes.
    pub base_len: u64,
    /// VM pointer to the exponent bytes.
    pub exponent: *const u8,
    /// Length of the exponent bytes.
    pub exponent_len: u64,
    /// VM pointer to the modulus bytes.
    pub modulus: *const u8,
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
/// Inputs and output are little-endian unsigned integers. The returned value is
/// padded to exactly `modulus.len()` bytes with trailing zeroes.
///
/// # Panics
///
/// Panics if any operand is longer than [`BIG_MOD_EXP_MAX_BYTES`] or if
/// `modulus` is empty, zero, one, or even.
pub fn big_mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    validate_inputs(base, exponent, modulus);

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        use num_bigint::BigUint;

        let modulus_len = modulus.len();

        if is_zero_le(exponent) {
            return padded_one(modulus_len);
        }
        if is_zero_le(base) {
            return vec![0; modulus_len];
        }

        let should_reduce_base = base_needs_reduction(base, modulus);
        let modulus = BigUint::from_bytes_le(modulus);
        let mut base = BigUint::from_bytes_le(base);

        if should_reduce_base {
            base %= &modulus;
        }

        if is_one_le(exponent) {
            return padded_to_modulus_len(base.to_bytes_le(), modulus_len);
        }

        let exponent = BigUint::from_bytes_le(exponent);
        let ret_int = base.modpow(&exponent, &modulus);
        padded_to_modulus_len(ret_int.to_bytes_le(), modulus_len)
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut return_value = vec![0_u8; modulus.len()];
        let params = BigModExpParams {
            base: base.as_ptr(),
            base_len: base.len() as u64,
            exponent: exponent.as_ptr(),
            exponent_len: exponent.len() as u64,
            modulus: modulus.as_ptr(),
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
        return_value
    }
}

fn validate_inputs(base: &[u8], exponent: &[u8], modulus: &[u8]) {
    let max_len = BIG_MOD_EXP_MAX_BYTES as usize;

    assert!(
        base.len() <= max_len,
        "base length exceeds BIG_MOD_EXP_MAX_BYTES"
    );
    assert!(
        exponent.len() <= max_len,
        "exponent length exceeds BIG_MOD_EXP_MAX_BYTES"
    );
    assert!(
        modulus.len() <= max_len,
        "modulus length exceeds BIG_MOD_EXP_MAX_BYTES"
    );

    validate_modulus(modulus);
}

fn validate_modulus(modulus: &[u8]) {
    let Some((&least_significant_byte, more_significant_bytes)) = modulus.split_first() else {
        panic!("modulus length must be nonzero");
    };

    let has_nonzero_more_significant_byte = more_significant_bytes.iter().any(|byte| *byte != 0);

    if least_significant_byte == 0 && !has_nonzero_more_significant_byte {
        panic!("modulus must be greater than one");
    }
    assert!(least_significant_byte & 1 == 1, "modulus must be odd");

    if least_significant_byte == 1 && !has_nonzero_more_significant_byte {
        panic!("modulus must be greater than one");
    }
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
fn significant_len_le(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1)
}

#[cfg(any(test, not(any(target_os = "solana", target_arch = "bpf"))))]
fn base_needs_reduction(base: &[u8], modulus: &[u8]) -> bool {
    let base_len = significant_len_le(base);
    let modulus_len = significant_len_le(modulus);

    match base_len.cmp(&modulus_len) {
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Equal => {
            base[..base_len]
                .iter()
                .rev()
                .cmp(modulus[..modulus_len].iter().rev())
                != core::cmp::Ordering::Less
        }
    }
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
        let Some((&least_significant_byte, more_significant_bytes)) = modulus.split_first() else {
            return false;
        };

        let has_nonzero_more_significant_byte =
            more_significant_bytes.iter().any(|byte| *byte != 0);

        (least_significant_byte > 1 || has_nonzero_more_significant_byte)
            && least_significant_byte & 1 == 1
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
                assert_eq!(result, expected, "JSON test vector {index}");
            } else {
                let result = std::panic::catch_unwind(|| big_mod_exp(&base, &exponent, &modulus));
                assert!(result.is_err(), "JSON test vector {index}");
            }
        }
    }

    #[test]
    fn big_mod_exp_basic_test() {
        let result = big_mod_exp(&[0x05], &[0x02], &[0x07]);
        assert_eq!(result, vec![0x04]);
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
        assert_eq!(result, expected);
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
        assert_eq!(result, expected);
    }

    #[test]
    fn big_mod_exp_empty_exponent_test() {
        assert_eq!(big_mod_exp(&[], &[], &[0x03]), vec![0x01]);
    }

    #[test]
    fn big_mod_exp_zero_exponent_test() {
        assert_eq!(
            big_mod_exp(&[0x00], &[0x00, 0x00], &[0x03, 0x00]),
            vec![0x01, 0x00]
        );
    }

    #[test]
    fn big_mod_exp_zero_base_test() {
        assert_eq!(
            big_mod_exp(&[0x00, 0x00], &[0x02], &[0x03, 0x00]),
            vec![0x00, 0x00]
        );
    }

    #[test]
    fn big_mod_exp_one_exponent_equal_length_reduction_test() {
        assert_eq!(
            big_mod_exp(&[0x0a, 0x01], &[0x01, 0x00], &[0x07, 0x01]),
            vec![0x03, 0x00]
        );
    }

    #[test]
    fn big_mod_exp_output_padding_test() {
        assert_eq!(
            big_mod_exp(&[0x02], &[0x02], &[0x07, 0x00]),
            vec![0x04, 0x00]
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
            vec![0x5d, 0x11]
        );
    }

    #[test]
    fn base_needs_reduction_test() {
        assert!(base_needs_reduction(&[0x0a, 0x01], &[0x07, 0x01]));
        assert!(base_needs_reduction(&[0x07, 0x01], &[0x07, 0x01]));
        assert!(!base_needs_reduction(&[0x06, 0x01], &[0x07, 0x01]));
        assert!(!base_needs_reduction(&[0x02, 0x00], &[0x03]));
    }

    #[test]
    fn big_mod_exp_max_length_inputs_test() {
        let max_len = BIG_MOD_EXP_MAX_BYTES as usize;
        let base = vec![0xff; max_len];
        let exponent = vec![0; max_len];
        let modulus = vec![0xff; max_len];

        let mut expected = vec![0; max_len];
        expected[0] = 1;
        assert_eq!(big_mod_exp(&base, &exponent, &modulus), expected);
    }

    #[test]
    #[should_panic(expected = "modulus length must be nonzero")]
    fn big_mod_exp_empty_modulus_panics() {
        big_mod_exp(&[], &[], &[]);
    }

    #[test]
    #[should_panic(expected = "modulus must be greater than one")]
    fn big_mod_exp_zero_modulus_panics() {
        big_mod_exp(&[0x00], &[], &[0x00]);
    }

    #[test]
    #[should_panic(expected = "modulus must be greater than one")]
    fn big_mod_exp_one_modulus_panics() {
        big_mod_exp(&[0x00], &[], &[0x01]);
    }

    #[test]
    #[should_panic(expected = "modulus must be odd")]
    fn big_mod_exp_even_modulus_panics() {
        big_mod_exp(&[0x00], &[], &[0x02]);
    }

    #[test]
    #[should_panic(expected = "base length exceeds BIG_MOD_EXP_MAX_BYTES")]
    fn big_mod_exp_base_too_long_panics() {
        let base = vec![0; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        let modulus = vec![0xff; BIG_MOD_EXP_MAX_BYTES as usize];
        big_mod_exp(&base, &[], &modulus);
    }

    #[test]
    #[should_panic(expected = "exponent length exceeds BIG_MOD_EXP_MAX_BYTES")]
    fn big_mod_exp_exponent_too_long_panics() {
        let exponent = vec![0; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        big_mod_exp(&[], &exponent, &[0x03]);
    }

    #[test]
    #[should_panic(expected = "modulus length exceeds BIG_MOD_EXP_MAX_BYTES")]
    fn big_mod_exp_modulus_too_long_panics() {
        let mut modulus = vec![0xff; BIG_MOD_EXP_MAX_BYTES as usize + 1];
        modulus[0] |= 1;
        big_mod_exp(&[], &[], &modulus);
    }

    #[test]
    #[should_panic(expected = "modulus must be greater than one")]
    fn big_mod_exp_multi_byte_one_modulus_panics() {
        big_mod_exp(&[0x00], &[], &[0x01, 0x00]);
    }

    #[test]
    #[should_panic(expected = "modulus must be greater than one")]
    fn big_mod_exp_multi_byte_zero_modulus_panics() {
        big_mod_exp(&[0x00], &[], &[0x00, 0x00]);
    }
}
