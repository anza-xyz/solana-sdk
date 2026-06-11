#![cfg_attr(docsrs, feature(doc_cfg))]

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
    let padded_base =
        (base.len() < modulus.len()).then(|| pad_base_to_modulus_len(base, modulus.len()));
    let base = padded_base.as_deref().unwrap_or(base);

    #[cfg(not(target_os = "solana"))]
    {
        use num_bigint::BigUint;

        let modulus_len = modulus.len();
        let base = BigUint::from_bytes_le(base);
        let exponent = BigUint::from_bytes_le(exponent);
        let modulus = BigUint::from_bytes_le(modulus);

        let ret_int = base.modpow(&exponent, &modulus);
        let mut return_value = ret_int.to_bytes_le();
        return_value.resize(modulus_len, 0);
        return_value
    }

    #[cfg(target_os = "solana")]
    {
        let mut return_value = vec![0_u8; modulus.len()];
        unsafe {
            solana_define_syscall::definitions::sol_big_mod_exp(
                base.as_ptr(),
                base.len() as u64,
                exponent.as_ptr(),
                exponent.len() as u64,
                modulus.as_ptr(),
                modulus.len() as u64,
                return_value.as_mut_ptr(),
            )
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
    assert!(!modulus.is_empty(), "modulus length must be nonzero");
    assert!(!is_zero_or_one(modulus), "modulus must be greater than one");
    assert!(is_odd(modulus), "modulus must be odd");
}

fn pad_base_to_modulus_len(base: &[u8], modulus_len: usize) -> Vec<u8> {
    let mut padded_base = vec![0; modulus_len];
    padded_base[..base.len()].copy_from_slice(base);
    padded_base
}

fn is_zero_or_one(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0) || is_one(input)
}

fn is_one(input: &[u8]) -> bool {
    input.iter().enumerate().all(|(index, byte)| {
        let is_least_significant_byte = index == 0;
        matches!((is_least_significant_byte, *byte), (true, 1) | (false, 0))
    })
}

fn is_odd(input: &[u8]) -> bool {
    input[0] & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
