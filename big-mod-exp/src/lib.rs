#![cfg_attr(docsrs, feature(doc_cfg))]

pub const BIG_MOD_EXP_ENDIANNESS_BE: u64 = 0;
pub const BIG_MOD_EXP_ENDIANNESS_LE: u64 = 1;
pub const BIG_MOD_EXP_MAX_BYTES: u64 = 512;

/// Endianness of big integer inputs and result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Endianness {
    BigEndian = BIG_MOD_EXP_ENDIANNESS_BE,
    LittleEndian = BIG_MOD_EXP_ENDIANNESS_LE,
}

impl From<Endianness> for u64 {
    fn from(endianness: Endianness) -> Self {
        endianness as u64
    }
}

#[repr(C)]
pub struct BigModExpParams {
    pub base_addr: u64,
    pub base_len: u64,
    pub exponent_addr: u64,
    pub exponent_len: u64,
    pub modulus_addr: u64,
    pub modulus_len: u64,
    pub result_addr: u64,
    pub result_len: u64,
}

/// Big integer modular exponentiation.
///
/// Inputs and output are encoded using `endianness`. The returned value is
/// padded to exactly `modulus.len()` bytes.
pub fn big_mod_exp_with_endianness(
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

        let param = BigModExpParams {
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
            solana_define_syscall::definitions::sol_big_mod_exp(
                endianness.into(),
                &param as *const _ as *const u8,
            )
        };
        assert_eq!(result, 0, "sol_big_mod_exp failed");

        return_value
    }
}

/// Big-endian big integer modular exponentiation.
///
/// This is the compatibility wrapper for the original `solana-big-mod-exp`
/// API. Prefer [`big_mod_exp_with_endianness`] when little-endian support is
/// needed.
pub fn big_mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    big_mod_exp_with_endianness(base, exponent, modulus, Endianness::BigEndian)
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
    fn big_mod_exp_large_exponent_test() {
        let base = [0x03];
        let exponent = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        );
        let modulus = array_bytes::hex2bytes_unchecked(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        );

        let result = big_mod_exp_with_endianness(&base, &exponent, &modulus, Endianness::BigEndian);
        let mut expected = vec![0; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn big_mod_exp_empty_inputs_test() {
        assert_eq!(
            big_mod_exp_with_endianness(&[], &[], &[0x02], Endianness::BigEndian),
            vec![0x01]
        );
        assert_eq!(
            big_mod_exp_with_endianness(&[], &[], &[0x00], Endianness::BigEndian),
            vec![0x00]
        );
        assert_eq!(
            big_mod_exp_with_endianness(&[], &[], &[], Endianness::BigEndian),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn big_mod_exp_little_endian_test() {
        let base_be = [0x01, 0x02];
        let exponent_be = [0x03];
        let modulus_be = [0x10, 0x01];

        let mut base_le = base_be;
        let mut exponent_le = exponent_be;
        let mut modulus_le = modulus_be;
        base_le.reverse();
        exponent_le.reverse();
        modulus_le.reverse();

        let result_be =
            big_mod_exp_with_endianness(&base_be, &exponent_be, &modulus_be, Endianness::BigEndian);
        let mut result_le = big_mod_exp_with_endianness(
            &base_le,
            &exponent_le,
            &modulus_le,
            Endianness::LittleEndian,
        );
        result_le.reverse();

        assert_eq!(result_be, result_le);
    }
}
