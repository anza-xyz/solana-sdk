//! Helpers shared by the tests that check `solana-bn254` against Ethereum's
//! EIP-196 / EIP-197 known-answer test vectors.
//!
//! The Ethereum precompiles and the Solana syscalls agree on the arithmetic
//! and on the point validation rules, but they differ in how they treat the
//! *length* of the input:
//!
//! - Both zero-pad inputs that are shorter than the nominal size (G1 addition:
//!   128 bytes, G1 multiplication: 96 bytes).
//! - Ethereum silently ignores any bytes beyond the nominal size. Solana
//!   rejects such inputs with `AltBn128Error::InvalidInputData` (for the G1
//!   multiplication syscall this is the SIMD-0222 behaviour; the deprecated
//!   `alt_bn128_multiplication_128` entry point still accepts up to 128 bytes).
//!
//! The helpers below encode these rules once so that every vector, whichever
//! Ethereum source it comes from, is checked against both the big-endian and
//! the little-endian Solana entry points.

#![allow(dead_code)]

use solana_bn254::{compression::prelude::convert_endianness, prelude::*};

pub fn hex2bytes(hex: &str) -> Vec<u8> {
    array_bytes::hex2bytes_unchecked(hex)
}

/// Zero-pads `input` on the right to `len` bytes, as EIP-196 prescribes for
/// short inputs.
fn zero_pad(input: &[u8], len: usize) -> Vec<u8> {
    let mut padded = input.to_vec();
    padded.resize(len, 0);
    padded
}

fn g1_addition_input_be_to_le(
    input_be: &[u8; ALT_BN128_G1_ADDITION_INPUT_SIZE],
) -> [u8; ALT_BN128_G1_ADDITION_INPUT_SIZE] {
    convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_ADDITION_INPUT_SIZE>(input_be)
}

fn g1_multiplication_input_be_to_le(
    input_be: &[u8; ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE],
) -> [u8; ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE] {
    let (point, scalar) = input_be.split_at(ALT_BN128_G1_POINT_SIZE);
    let point_le = convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(
        point.try_into().unwrap(),
    );
    let scalar_le = convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_FIELD_SIZE>(
        scalar.try_into().unwrap(),
    );
    let mut input_le = [0u8; ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE];
    input_le[..ALT_BN128_G1_POINT_SIZE].copy_from_slice(&point_le);
    input_le[ALT_BN128_G1_POINT_SIZE..].copy_from_slice(&scalar_le);
    input_le
}

/// Converts a whole EIP-197 pairing input (a sequence of `(G1, G2)` pairs) to
/// the little-endian encoding expected by `alt_bn128_pairing_le`. The input
/// length must be a multiple of the pair size.
pub fn pairing_input_be_to_le(input_be: &[u8]) -> Vec<u8> {
    assert!(input_be
        .len()
        .is_multiple_of(ALT_BN128_PAIRING_ELEMENT_SIZE));
    input_be
        .chunks_exact(ALT_BN128_PAIRING_ELEMENT_SIZE)
        .flat_map(|pair| {
            let (g1, g2) = pair.split_at(ALT_BN128_G1_POINT_SIZE);
            let g1_le = convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(
                g1.try_into().unwrap(),
            );
            let g2_le = convert_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(
                g2.try_into().unwrap(),
            );
            g1_le.into_iter().chain(g2_le)
        })
        .collect()
}

fn g1_output_be_to_le(output_be: &[u8]) -> [u8; ALT_BN128_G1_POINT_SIZE] {
    convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(
        output_be.try_into().unwrap(),
    )
}

/// Checks a successful Ethereum G1 addition vector (`ecadd`, precompile 0x06)
/// against the Solana G1 addition syscall.
pub fn check_g1_addition(name: &str, mut input: &[u8], expected: &[u8]) {
    if input.len() > ALT_BN128_G1_ADDITION_INPUT_SIZE {
        // Ethereum ignores the trailing bytes; Solana rejects the input.
        assert_eq!(
            alt_bn128_g1_addition_be(input),
            Err(AltBn128Error::InvalidInputData),
            "{name}: over-long input must be rejected"
        );
        // Once the ignored bytes are dropped, the results must agree.
        input = &input[..ALT_BN128_G1_ADDITION_INPUT_SIZE];
    }

    assert_eq!(
        alt_bn128_g1_addition_be(input).as_deref(),
        Ok(expected),
        "{name}: big-endian result"
    );

    let padded = zero_pad(input, ALT_BN128_G1_ADDITION_INPUT_SIZE);
    let input_le = g1_addition_input_be_to_le(&padded.try_into().unwrap());
    assert_eq!(
        alt_bn128_g1_addition_le(&input_le).as_deref(),
        Ok(&g1_output_be_to_le(expected)[..]),
        "{name}: little-endian result"
    );
}

/// Checks an Ethereum G1 addition vector that the precompile rejects. Solana
/// must reject it as well, for the raw input and for the zero-padded
/// little-endian encoding.
pub fn check_g1_addition_fails(name: &str, input: &[u8]) {
    assert!(
        alt_bn128_g1_addition_be(input).is_err(),
        "{name}: big-endian input must be rejected"
    );

    // Ethereum's rejection is caused by the first 128 bytes, so the truncated
    // and padded encodings must be rejected too.
    let truncated = &input[..input.len().min(ALT_BN128_G1_ADDITION_INPUT_SIZE)];
    assert!(
        alt_bn128_g1_addition_be(truncated).is_err(),
        "{name}: truncated big-endian input must be rejected"
    );
    let padded = zero_pad(truncated, ALT_BN128_G1_ADDITION_INPUT_SIZE);
    let input_le = g1_addition_input_be_to_le(&padded.try_into().unwrap());
    assert!(
        alt_bn128_g1_addition_le(&input_le).is_err(),
        "{name}: little-endian input must be rejected"
    );
}

/// Checks a successful Ethereum G1 multiplication vector (`ecmul`, precompile
/// 0x07) against the Solana G1 multiplication syscall.
pub fn check_g1_multiplication(name: &str, mut input: &[u8], expected: &[u8]) {
    if input.len() > ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE {
        // Ethereum ignores the trailing bytes; the SIMD-0222 syscall rejects
        // the input.
        assert_eq!(
            alt_bn128_g1_multiplication_be(input),
            Err(AltBn128Error::InvalidInputData),
            "{name}: over-long input must be rejected"
        );
        // The pre-SIMD-0222 entry point accepted (and ignored) up to 32 extra
        // bytes, exactly like Ethereum.
        #[allow(deprecated)]
        let legacy = alt_bn128_multiplication_128(input);
        if input.len() <= 128 {
            assert_eq!(
                legacy.as_deref(),
                Ok(expected),
                "{name}: legacy 128-byte entry point result"
            );
        } else {
            assert!(
                legacy.is_err(),
                "{name}: legacy 128-byte entry point must reject the input"
            );
        }
        input = &input[..ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE];
    }

    assert_eq!(
        alt_bn128_g1_multiplication_be(input).as_deref(),
        Ok(expected),
        "{name}: big-endian result"
    );

    let padded = zero_pad(input, ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE);
    let input_le = g1_multiplication_input_be_to_le(&padded.try_into().unwrap());
    assert_eq!(
        alt_bn128_g1_multiplication_le(&input_le).as_deref(),
        Ok(&g1_output_be_to_le(expected)[..]),
        "{name}: little-endian result"
    );
}

/// Checks an Ethereum G1 multiplication vector that the precompile rejects.
pub fn check_g1_multiplication_fails(name: &str, input: &[u8]) {
    assert!(
        alt_bn128_g1_multiplication_be(input).is_err(),
        "{name}: big-endian input must be rejected"
    );
    #[allow(deprecated)]
    let legacy = alt_bn128_multiplication_128(input);
    assert!(
        legacy.is_err(),
        "{name}: legacy 128-byte entry point must reject the input"
    );

    let truncated = &input[..input.len().min(ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE)];
    assert!(
        alt_bn128_g1_multiplication_be(truncated).is_err(),
        "{name}: truncated big-endian input must be rejected"
    );
    let padded = zero_pad(truncated, ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE);
    let input_le = g1_multiplication_input_be_to_le(&padded.try_into().unwrap());
    assert!(
        alt_bn128_g1_multiplication_le(&input_le).is_err(),
        "{name}: little-endian input must be rejected"
    );
}

/// Checks a successful Ethereum pairing vector (`ecpairing`, precompile 0x08)
/// against the Solana pairing syscall. Both sides require the input length to
/// be a multiple of the pair size, so no length adjustment is needed.
pub fn check_pairing(name: &str, input: &[u8], expected: &[u8]) {
    assert_eq!(
        alt_bn128_pairing_be(input).as_deref(),
        Ok(expected),
        "{name}: big-endian result"
    );

    let input_le = pairing_input_be_to_le(input);
    let expected_le = convert_endianness::<
        ALT_BN128_PAIRING_OUTPUT_SIZE,
        ALT_BN128_PAIRING_OUTPUT_SIZE,
    >(expected.try_into().unwrap());
    assert_eq!(
        alt_bn128_pairing_le(&input_le).as_deref(),
        Ok(&expected_le[..]),
        "{name}: little-endian result"
    );
}

/// Checks an Ethereum pairing vector that the precompile rejects.
pub fn check_pairing_fails(name: &str, input: &[u8]) {
    assert!(
        alt_bn128_pairing_be(input).is_err(),
        "{name}: big-endian input must be rejected"
    );
    if input.len().is_multiple_of(ALT_BN128_PAIRING_ELEMENT_SIZE) {
        let input_le = pairing_input_be_to_le(input);
        assert!(
            alt_bn128_pairing_le(&input_le).is_err(),
            "{name}: little-endian input must be rejected"
        );
    } else {
        // A malformed length is rejected before any point is decoded.
        assert!(
            alt_bn128_pairing_le(input).is_err(),
            "{name}: little-endian input with a bad length must be rejected"
        );
    }
}
