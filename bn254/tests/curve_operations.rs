use {
    serde_derive::Deserialize,
    solana_bn254::{compression::prelude::*, prelude::*},
};

#[test]
fn alt_bn128_addition_test() {
    let test_data = include_str!("data/addition_cases.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
        expected: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input);
        let result = alt_bn128_addition(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);
    });
}

#[test]
fn alt_bn128_multiplication_test() {
    let test_data = include_str!("data/multiplication_cases.json");
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
        expected: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input);
        let result = alt_bn128_multiplication(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);
    });
}

#[test]
fn alt_bn128_pairing_test() {
    let test_data = include_str!("data/pairing_cases.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCase {
        input: String,
        expected: String,
    }

    let test_cases: Vec<TestCase> = serde_json::from_str(test_data).unwrap();

    test_cases.iter().for_each(|test| {
        let input = array_bytes::hex2bytes_unchecked(&test.input);
        let result = alt_bn128_pairing(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);
    });
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
        if input.len() < 192 {
            return;
        }
        let g1 = input[0..64].to_vec();
        let g1_compressed = alt_bn128_g1_compress(&g1).unwrap();
        assert_eq!(g1, alt_bn128_g1_decompress(&g1_compressed).unwrap());
        let g2 = input[64..192].to_vec();
        let g2_compressed = alt_bn128_g2_compress(&g2).unwrap();
        assert_eq!(g2, alt_bn128_g2_decompress(&g2_compressed).unwrap());
    });
}
