mod common;

use {
    common::*,
    serde_derive::Deserialize,
    solana_bn254::{compression::prelude::*, prelude::*},
};

/// A known-answer test in the format of go-ethereum's
/// `core/vm/testdata/precompiles/*.json` files.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GethTestCase {
    input: String,
    expected: String,
    name: String,
}

fn load_geth_vectors(json: &str) -> Vec<GethTestCase> {
    let cases: Vec<GethTestCase> = serde_json::from_str(json).unwrap();
    assert!(!cases.is_empty());
    cases
}

#[test]
fn alt_bn128_g1_addition_test() {
    for test in load_geth_vectors(include_str!("data/addition_cases.json")) {
        check_g1_addition(
            &test.name,
            &hex2bytes(&test.input),
            &hex2bytes(&test.expected),
        );
    }
}

#[test]
fn alt_bn128_g2_addition_test() {
    let test_data = include_str!("data/addition_g2_cases.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
        expected: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input)
            .try_into()
            .unwrap();
        let result = alt_bn128_g2_addition_be(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);

        // le test
        let input_le = convert_endianness::<64, ALT_BN128_G2_ADDITION_INPUT_SIZE>(&input);
        let result = alt_bn128_g2_addition_le(&input_le);
        assert!(result.is_ok());
        let expected_le = convert_endianness::<64, 128>(&expected.try_into().unwrap());
        assert_eq!(result.unwrap(), expected_le);
    });
}

#[test]
fn alt_bn128_g1_multiplication_test() {
    for test in load_geth_vectors(include_str!("data/multiplication_cases.json")) {
        check_g1_multiplication(
            &test.name,
            &hex2bytes(&test.input),
            &hex2bytes(&test.expected),
        );
    }
}

#[test]
fn alt_bn128_g2_multiplication_test() {
    let test_data = include_str!("data/multiplication_g2_cases.json");
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
        expected: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input)
            .try_into()
            .unwrap();
        let result = alt_bn128_g2_multiplication_be(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);

        // le test
        let p_le = convert_endianness::<64, ALT_BN128_G2_POINT_SIZE>(
            &input[..ALT_BN128_G2_POINT_SIZE].try_into().unwrap(),
        );
        let scalar_le = convert_endianness::<32, ALT_BN128_FIELD_SIZE>(
            &input[ALT_BN128_G2_POINT_SIZE..].try_into().unwrap(),
        );
        let input_le = [&p_le[..], &scalar_le[..]].concat().try_into().unwrap();
        let result = alt_bn128_g2_multiplication_le(&input_le);
        assert!(result.is_ok());
        let expected_le = convert_endianness::<64, 128>(&expected.try_into().unwrap());
        assert_eq!(result.unwrap(), expected_le);
    });
}

#[test]
fn alt_bn128_pairing_test() {
    for test in load_geth_vectors(include_str!("data/pairing_cases.json")) {
        check_pairing(
            &test.name,
            &hex2bytes(&test.input),
            &hex2bytes(&test.expected),
        );
    }
}

// This test validates the compression and decompression roundtrip logic.
#[test]
fn alt_bn128_compression_pairing_test_input() {
    let test_data = include_str!("data/pairing_cases.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input);

        // This test reuses data from the pairing test suite, which can include
        // inputs too short for this test's logic (e.g. the "empty" test case).
        // We skip those cases to prevent a panic when slicing the input bytes
        // for the G1 and G2 points.
        if input.len() < 192 {
            return;
        }
        let g1 = input[0..64].to_vec();
        let g1_compressed = alt_bn128_g1_compress_be(&g1).unwrap();
        assert_eq!(g1, alt_bn128_g1_decompress_be(&g1_compressed).unwrap());
        let g2 = input[64..192].to_vec();
        let g2_compressed = alt_bn128_g2_compress_be(&g2).unwrap();
        assert_eq!(g2, alt_bn128_g2_decompress_be(&g2_compressed).unwrap());

        // test le
        let g1_le = convert_endianness::<32, 64>(&g1.try_into().unwrap());
        let g1_compressed_le = alt_bn128_g1_compress_le(&g1_le).unwrap();
        assert_eq!(
            g1_le,
            alt_bn128_g1_decompress_le(&g1_compressed_le).unwrap()
        );
        let g2_le = convert_endianness::<64, 128>(&g2.try_into().unwrap());
        let g2_compressed_le = alt_bn128_g2_compress_le(&g2_le).unwrap();
        assert_eq!(
            g2_le,
            alt_bn128_g2_decompress_le(&g2_compressed_le).unwrap()
        );
    });
}
