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

// SIMD-0650: fixed vector shared with `solana-bn254-syscall`, so that the two
// implementations of the pairing map are pinned to the same encoding.
#[test]
fn alt_bn128_pairing_map_generator_matches_fixed_vector() {
    use {
        ark_bn254::{G1Affine, G2Affine},
        ark_ec::AffineRepr,
        ark_serialize::CanonicalSerialize,
    };

    assert_eq!(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE, 384);

    // Snapshot of Bn254::pairing(G1Affine::generator(), G2Affine::generator())
    // from ark-bn254 0.5.0, with each base field coefficient encoded in LE.
    // Keep these bytes fixed to detect changes to the pairing normalization
    // or encoding when dependencies change.
    let expected_le: [u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE] = [
        0x95, 0x0e, 0x87, 0x9d, 0x73, 0x63, 0x1f, 0x5e, 0xb5, 0x78, 0x85, 0x89, 0xeb, 0x5f, 0x7e,
        0xf8, 0xd6, 0x3e, 0x0a, 0x28, 0xde, 0x1b, 0xa0, 0x0d, 0xfe, 0x4c, 0xa9, 0xed, 0x3f, 0x25,
        0x2b, 0x26, 0x4a, 0x8a, 0xfb, 0x8e, 0xb4, 0x34, 0x9d, 0xb4, 0x66, 0xed, 0x18, 0x09, 0xea,
        0x4d, 0x7c, 0x39, 0xbd, 0xab, 0x79, 0x38, 0x82, 0x1f, 0x1b, 0x0a, 0x00, 0xa2, 0x95, 0xc7,
        0x2c, 0x2d, 0xe0, 0x02, 0xe0, 0x1d, 0xbd, 0xfd, 0x02, 0x54, 0x13, 0x4e, 0xfc, 0xb1, 0xec,
        0x87, 0x73, 0x95, 0xd2, 0x5f, 0x93, 0x77, 0x19, 0xb3, 0x44, 0xad, 0xb1, 0xa5, 0x8d, 0x12,
        0x9b, 0xe2, 0xd6, 0xf2, 0xa9, 0x13, 0x2b, 0x16, 0xa1, 0x6e, 0x8a, 0xb0, 0x30, 0xb1, 0x30,
        0xe6, 0x9c, 0x69, 0xbd, 0x20, 0xb4, 0xc4, 0x59, 0x86, 0xe6, 0x74, 0x4a, 0x98, 0x31, 0x4b,
        0x5c, 0x1a, 0x0f, 0x50, 0xfa, 0xa9, 0x0b, 0x04, 0xdb, 0xaf, 0x9e, 0xf8, 0xae, 0xee, 0xe3,
        0xf5, 0x0b, 0xe3, 0x1c, 0x21, 0x0b, 0x59, 0x8f, 0x47, 0x52, 0xf0, 0x73, 0x98, 0x7f, 0x9d,
        0x35, 0xbe, 0x8f, 0x67, 0x70, 0xd8, 0x3f, 0x2f, 0xfc, 0x0a, 0xf0, 0xd1, 0x8d, 0xd9, 0xd2,
        0xdb, 0xcd, 0xf9, 0x43, 0x82, 0x5a, 0xcc, 0x12, 0xa7, 0xa9, 0xdd, 0xca, 0x45, 0xe6, 0x29,
        0xd9, 0x62, 0xc6, 0xbd, 0x64, 0x90, 0x8c, 0x39, 0x30, 0xa5, 0x54, 0x1c, 0xfe, 0x29, 0x24,
        0xdc, 0xc5, 0x58, 0x0d, 0x5c, 0xef, 0x7a, 0x4b, 0xfd, 0xec, 0x90, 0xa9, 0x1b, 0x59, 0x92,
        0x6f, 0x85, 0x0d, 0x4a, 0x79, 0x23, 0xc0, 0x1a, 0x5a, 0x5d, 0xbf, 0x0f, 0x5c, 0x09, 0x4a,
        0x2b, 0x9f, 0xb9, 0xd4, 0x15, 0x82, 0x0f, 0xa6, 0xb4, 0x0c, 0x59, 0xbb, 0x9e, 0xad, 0xe9,
        0xc9, 0x53, 0x40, 0x7b, 0x0f, 0xc1, 0x1d, 0xa3, 0x50, 0xa9, 0xd8, 0x72, 0xca, 0xd6, 0xd3,
        0x14, 0x29, 0x74, 0xca, 0x38, 0x58, 0x54, 0xaf, 0xdf, 0x5f, 0x58, 0x3c, 0x04, 0x23, 0x1a,
        0xdc, 0x59, 0x57, 0xc8, 0x91, 0x4b, 0x6b, 0x20, 0xdc, 0x89, 0x66, 0x0e, 0xd7, 0xc3, 0xbb,
        0xe7, 0xc0, 0x1d, 0x97, 0x2b, 0xe2, 0xd5, 0x3e, 0xcd, 0xb2, 0x7a, 0x1b, 0xcc, 0x16, 0xac,
        0x61, 0x0d, 0xb9, 0x5a, 0xa7, 0xd2, 0x37, 0xc8, 0xff, 0x55, 0xa8, 0x98, 0xcb, 0x88, 0x64,
        0x5a, 0x0e, 0x32, 0x53, 0x0b, 0x23, 0xd7, 0xeb, 0xf5, 0xda, 0xfd, 0xd7, 0x9b, 0x0f, 0x9c,
        0x2a, 0xc4, 0xba, 0x07, 0xce, 0x18, 0xd3, 0xd1, 0x6c, 0xf3, 0x6e, 0x47, 0x91, 0x6c, 0x4c,
        0xae, 0x5d, 0x08, 0xd3, 0xaf, 0xa8, 0x13, 0x97, 0x2c, 0x76, 0x9e, 0x85, 0x14, 0x53, 0x3e,
        0x38, 0x0c, 0x94, 0x43, 0xb3, 0xe1, 0xee, 0x5c, 0x96, 0xfa, 0x3a, 0x0a, 0x73, 0xf3, 0x01,
        0xb6, 0x26, 0x45, 0x47, 0x21, 0x52, 0x7b, 0xf9, 0x00,
    ];
    let mut expected_be = expected_le;
    expected_be.reverse();

    let (g1, g2) = (G1Affine::generator(), G2Affine::generator());
    let mut input_le = [0u8; ALT_BN128_PAIRING_MAP_ELEMENT_SIZE];
    g1.x.serialize_uncompressed(&mut input_le[..32]).unwrap();
    g1.y.serialize_uncompressed(&mut input_le[32..64]).unwrap();
    g2.x.serialize_uncompressed(&mut input_le[64..128]).unwrap();
    g2.y.serialize_uncompressed(&mut input_le[128..]).unwrap();
    let mut input_be = [0u8; ALT_BN128_PAIRING_MAP_ELEMENT_SIZE];
    input_be[..64].copy_from_slice(&convert_endianness::<32, 64>(
        input_le[..64].try_into().unwrap(),
    ));
    input_be[64..].copy_from_slice(&convert_endianness::<64, 128>(
        input_le[64..].try_into().unwrap(),
    ));

    assert_eq!(alt_bn128_pairing_map_le(&input_le).unwrap(), expected_le);
    assert_eq!(alt_bn128_pairing_map_be(&input_be).unwrap(), expected_be);
}
