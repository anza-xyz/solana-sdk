//! Regression tests for <https://github.com/anza-xyz/agave/issues/3379>.
//!
//! EIP-196/197 require every base field element to be strictly below the
//! 254-bit modulus, so an element with bit 254 or 255 set is out of range and
//! the whole input is rejected. The `ark-serialize` decoder behind the
//! syscalls instead reads those bits of the last coordinate as point flags
//! and strips them, so the original syscall versions accept such inputs, and
//! a set `PointAtInfinity` flag even turns a valid point into infinity. The
//! current versions reject the input up front.
//!
//! The vectors take valid inputs from the go-ethereum suite and set one flag
//! bit on one coordinate at a time. go-ethereum v1.17.5 and `revm-precompile`
//! 43.0.2 reject every one of them as an invalid field element.

mod common;

use {
    common::*,
    serde_derive::Deserialize,
    solana_bn254::{prelude::*, versioned::*},
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FlagBitCase {
    name: String,
    input: String,
}

fn load(json: &str) -> Vec<FlagBitCase> {
    let cases: Vec<FlagBitCase> = serde_json::from_str(json).unwrap();
    assert!(!cases.is_empty());
    cases
}

#[test]
fn g1_addition_rejects_flag_bits() {
    let cases = load(include_str!("data/flag_bit_addition_cases.json"));
    for case in &cases {
        check_g1_addition_fails(&case.name, &hex2bytes(&case.input));
    }

    // The original syscall version lets flag bits on the last coordinate
    // through. Pinning that here keeps the new version load-bearing.
    let accepted_by_v0 = cases
        .iter()
        .filter(|case| {
            alt_bn128_versioned_g1_addition(
                VersionedG1Addition::V0,
                &hex2bytes(&case.input),
                Endianness::BE,
            )
            .is_ok()
        })
        .count();
    assert!(accepted_by_v0 > 0);
}

#[test]
fn g1_multiplication_rejects_flag_bits() {
    let cases = load(include_str!("data/flag_bit_multiplication_cases.json"));
    for case in &cases {
        let input = hex2bytes(&case.input);
        assert!(
            alt_bn128_g1_multiplication_be(&input).is_err(),
            "{}: big-endian input must be rejected",
            case.name
        );
        let input_le = g1_multiplication_input_be_to_le(&input.try_into().unwrap());
        assert!(
            alt_bn128_g1_multiplication_le(&input_le).is_err(),
            "{}: little-endian input must be rejected",
            case.name
        );
    }

    let accepted_by_v1 = cases
        .iter()
        .filter(|case| {
            alt_bn128_versioned_g1_multiplication(
                VersionedG1Multiplication::V1,
                &hex2bytes(&case.input),
                Endianness::BE,
            )
            .is_ok()
        })
        .count();
    assert!(accepted_by_v1 > 0);
}

#[test]
fn pairing_rejects_flag_bits() {
    let cases = load(include_str!("data/flag_bit_pairing_cases.json"));
    for case in &cases {
        check_pairing_fails(&case.name, &hex2bytes(&case.input));
    }

    let accepted_by_v1 = cases
        .iter()
        .filter(|case| {
            alt_bn128_versioned_pairing(
                VersionedPairing::V1,
                &hex2bytes(&case.input),
                Endianness::BE,
            )
            .is_ok()
        })
        .count();
    assert!(accepted_by_v1 > 0);
}
