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
        let mut input = array_bytes::hex2bytes_unchecked(&test.input);
        let result = alt_bn128_g1_addition_be(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);

        // le test
        input.resize(ALT_BN128_G1_ADDITION_INPUT_SIZE, 0);
        let input_le =
            convert_endianness::<32, ALT_BN128_G1_ADDITION_INPUT_SIZE>(&input.try_into().unwrap());
        let result = alt_bn128_g1_addition_le(&input_le);
        assert!(result.is_ok());
        let expected_le = convert_endianness::<32, 64>(&expected.try_into().unwrap());
        assert_eq!(result.unwrap(), expected_le);
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
        let mut input = array_bytes::hex2bytes_unchecked(&test.input);
        let result = alt_bn128_g1_multiplication_be(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);

        // le test
        input.resize(ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE, 0);
        let input_le = convert_endianness::<32, ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE>(
            &input.try_into().unwrap(),
        );
        let result = alt_bn128_g1_multiplication_le(&input_le);
        assert!(result.is_ok());
        let expected_le = convert_endianness::<32, 64>(&expected.try_into().unwrap());
        assert_eq!(result.unwrap(), expected_le);
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
        let result = alt_bn128_pairing_be(&input);
        assert!(result.is_ok());
        let expected = array_bytes::hex2bytes_unchecked(&test.expected);
        assert_eq!(result.unwrap(), expected);

        // le test
        let input_le: Vec<u8> = (0..input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_SIZE))
            .flat_map(|i| {
                let g1_start = i * ALT_BN128_PAIRING_ELEMENT_SIZE;
                let g1_end = g1_start + ALT_BN128_G1_POINT_SIZE;
                let g2_end = g1_start + ALT_BN128_PAIRING_ELEMENT_SIZE;

                let g1 = convert_endianness::<32, 64>(&input[g1_start..g1_end].try_into().unwrap());
                let g2 = convert_endianness::<64, 128>(&input[g1_end..g2_end].try_into().unwrap());

                g1.into_iter().chain(g2)
            })
            .collect();

        let result = alt_bn128_pairing_le(&input_le);
        assert!(result.is_ok());
        let expected_le = convert_endianness::<32, 32>(&expected.try_into().unwrap());
        assert_eq!(result.unwrap(), expected_le);
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
