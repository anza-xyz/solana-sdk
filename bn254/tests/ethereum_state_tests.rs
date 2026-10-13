//! Consistency checks against the BN254 (alt_bn128) precompile vectors of the
//! Ethereum state test suite (`GeneralStateTests/stZeroKnowledge*`, now
//! maintained in `ethereum/execution-spec-tests`).
//!
//! Unlike the go-ethereum vectors exercised in `curve_operations.rs`, these
//! cover the *negative* side of the specification as well: points that are
//! not on the curve, coordinates that are not reduced modulo the field prime,
//! G2 points outside the prime-order subgroup and malformed input lengths.
//! Every input that Ethereum rejects must be rejected by Solana, and every
//! input that Ethereum accepts must produce the same output.
//!
//! See `tests/data/README.md` for how the vectors were derived.

mod common;

use {common::*, serde_derive::Deserialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StateTestCase {
    name: String,
    input: String,
    /// Hex-encoded precompile output, or `None` when the Ethereum precompile
    /// fails on this input.
    expected: Option<String>,
}

fn load(json: &str) -> Vec<StateTestCase> {
    let cases: Vec<StateTestCase> = serde_json::from_str(json).unwrap();
    assert!(!cases.is_empty());
    // Guard against a corrupted data file silently turning the suite into a
    // positive-only one.
    assert!(cases.iter().any(|case| case.expected.is_none()));
    assert!(cases.iter().any(|case| case.expected.is_some()));
    cases
}

#[test]
fn ethereum_state_tests_ecadd() {
    for case in load(include_str!("data/eth_state_addition_cases.json")) {
        let input = hex2bytes(&case.input);
        match &case.expected {
            Some(expected) => check_g1_addition(&case.name, &input, &hex2bytes(expected)),
            None => check_g1_addition_fails(&case.name, &input),
        }
    }
}

#[test]
fn ethereum_state_tests_ecmul() {
    for case in load(include_str!("data/eth_state_multiplication_cases.json")) {
        let input = hex2bytes(&case.input);
        match &case.expected {
            Some(expected) => check_g1_multiplication(&case.name, &input, &hex2bytes(expected)),
            None => check_g1_multiplication_fails(&case.name, &input),
        }
    }
}

#[test]
fn ethereum_state_tests_ecpairing() {
    for case in load(include_str!("data/eth_state_pairing_cases.json")) {
        let input = hex2bytes(&case.input);
        match &case.expected {
            Some(expected) => check_pairing(&case.name, &input, &hex2bytes(expected)),
            None => check_pairing_fails(&case.name, &input),
        }
    }
}
