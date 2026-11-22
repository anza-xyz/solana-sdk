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

// SIMD-0650: checks the pairing map output against an independent `ark-bn254`
// computation and encoding of the target group element.
#[test]
fn alt_bn128_pairing_map_test() {
    use {
        ark_bn254::{Bn254, Fr, G1Affine, G2Affine},
        ark_ec::{pairing::Pairing, AffineRepr, CurveGroup},
        ark_ff::{BigInteger, Field, PrimeField},
        ark_serialize::CanonicalSerialize,
        std::ops::Mul,
    };

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let pairs = [
        (
            g1.mul(Fr::from(3u64)).into_affine(),
            g2.mul(Fr::from(5u64)).into_affine(),
        ),
        (
            g1.mul(Fr::from(7u64)).into_affine(),
            g2.mul(Fr::from(11u64)).into_affine(),
        ),
        (G1Affine::zero(), g2),
    ];

    let encode_le = |pairs: &[(G1Affine, G2Affine)]| {
        let mut input = Vec::new();
        for (p, q) in pairs {
            let mut pair = [0u8; ALT_BN128_PAIRING_MAP_ELEMENT_SIZE];
            if !p.is_zero() {
                p.x.serialize_uncompressed(&mut pair[..32]).unwrap();
                p.y.serialize_uncompressed(&mut pair[32..64]).unwrap();
            }
            if !q.is_zero() {
                q.x.serialize_uncompressed(&mut pair[64..128]).unwrap();
                q.y.serialize_uncompressed(&mut pair[128..]).unwrap();
            }
            input.extend_from_slice(&pair);
        }
        input
    };

    for n in 0..=pairs.len() {
        let pairs = &pairs[..n];
        let gt = Bn254::multi_pairing(pairs.iter().map(|p| p.0), pairs.iter().map(|p| p.1)).0;

        // c0, ..., c11 in tower order, each in little-endian
        let expected_le: Vec<u8> = gt
            .to_base_prime_field_elements()
            .flat_map(|c| c.into_bigint().to_bytes_le())
            .collect();
        assert_eq!(expected_le.len(), ALT_BN128_PAIRING_MAP_OUTPUT_SIZE);
        // c11, ..., c0, each in big-endian
        let expected_be: Vec<u8> = expected_le.iter().rev().copied().collect();

        let input_le = encode_le(pairs);
        let input_be: Vec<u8> = input_le
            .chunks_exact(ALT_BN128_PAIRING_MAP_ELEMENT_SIZE)
            .flat_map(|pair| {
                let g1 = convert_endianness::<32, 64>(pair[..64].try_into().unwrap());
                let g2 = convert_endianness::<64, 128>(pair[64..].try_into().unwrap());
                g1.into_iter().chain(g2)
            })
            .collect();

        assert_eq!(alt_bn128_pairing_map_le(&input_le).unwrap(), expected_le);
        assert_eq!(alt_bn128_pairing_map_be(&input_be).unwrap(), expected_be);
    }

    // e(3 G1, 5 G2) * e(7 G1, 11 G2) = e(92 G1, G2)
    let combined = encode_le(&[(g1.mul(Fr::from(92u64)).into_affine(), g2)]);
    assert_eq!(
        alt_bn128_pairing_map_le(&encode_le(&pairs[..2])).unwrap(),
        alt_bn128_pairing_map_le(&combined).unwrap(),
    );

    // a G2 point outside the prime-order subgroup is rejected
    let off_subgroup = (1u64..)
        .find_map(|x| {
            let q = G2Affine::get_point_from_x_unchecked(ark_bn254::Fq2::from(x), false)?;
            (!q.is_in_correct_subgroup_assuming_on_curve()).then_some(q)
        })
        .unwrap();
    assert!(alt_bn128_pairing_map_le(&encode_le(&[(g1, off_subgroup)])).is_err());
}
