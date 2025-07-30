//! Provides a space-efficient encoding scheme for two boolean vectors.
//!
//! This module implements a compression algorithm to encode two boolean vectors
//! of the same length into a single byte vector (`Vec<u8>`). It achieves
//! this by mapping each pair of corresponding bits from the input vectors into a
//! single ternary (base-3) digit.
//!
//! # Principle
//!
//! The core idea is to treat pairs of booleans as a single unit with three
//! valid states, which can be represented by the digits 0, 1, and 2.
//!
//! - `(false, false)` -> `0`
//! - `(true, false)`  -> `1`
//! - `(false, true)`  -> `2`
//!
//! The combination `(true, true)` is considered invalid and will result in an error
//! during encoding.
//!
//! These ternary digits are then packed into 8-bit integers (`u8`) for compact
//! storage. Since `3^5 < 2^8`, each `u8` can hold 5 ternary digits.
//!
//! # Encoded Format
//!
//! The resulting `Vec<u8>` has a simple structure:
//! 1.  **Length Prefix (2 bytes)**: A `u16` in little-endian format storing the
//!     original number of bits (i.e., the length of the input vectors).
//! 2.  **Data Payload (N * 1 byte)**: A sequence of single bytes, where each
//!     byte is a `u8` value containing 5 encoded ternary digits.

/// An error that can occur during the encoding process.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The provided bit-vectors have unmatching lengths.
    MismatchedLengths,
    /// The combination `(true, true)` was found, which is not allowed.
    InvalidBitCombination,
    /// The length of the input vectors exceeds `u16::MAX` (65,535).
    LengthExceedsLimit,
    /// Arithmetic overflow.
    ArithmeticOverflow,
}

// Each u8 chunk can hold 5 base-3 symbols (3^5 = 243 <= 255).
const BASE3_SYMBOL_PER_CHUNK: usize = 5;
const ENCODED_BYTES_PER_CHUNK: usize = 1; // std::mem::size_of::<u8>()

/// Encodes two boolean vectors, provided as byte slices, into a single `Vec<u8>`.
///
/// # Parameters
/// - `base_bytes`: The byte slice for the base boolean vector.
/// - `fallback_bytes`: The byte slice for the fallback boolean vector.
/// - `num_bits`: The exact number of bits from the start of the slices to encode.
pub fn encode_from_bytes(
    base_bytes: &[u8],
    fallback_bytes: &[u8],
    num_bits: usize,
) -> Result<Vec<u8>, EncodeError> {
    if num_bits > u16::MAX as usize {
        return Err(EncodeError::LengthExceedsLimit);
    }
    let required_bytes = num_bits
        .checked_add(7)
        .ok_or(EncodeError::ArithmeticOverflow)?
        .checked_div(8)
        .ok_or(EncodeError::ArithmeticOverflow)?;

    // If `base_bytes.len()` or `fallback_bytes.len()` is greater than `required_bytes`,
    // the extra bytes will simply be ignored.
    if base_bytes.len() < required_bytes || fallback_bytes.len() < required_bytes {
        return Err(EncodeError::MismatchedLengths);
    }

    let total_u8_length = num_bits
        .checked_add(BASE3_SYMBOL_PER_CHUNK - 1)
        .ok_or(EncodeError::ArithmeticOverflow)?
        .checked_div(BASE3_SYMBOL_PER_CHUNK)
        .ok_or(EncodeError::ArithmeticOverflow)?;

    let total_byte_length = total_u8_length
        .checked_mul(ENCODED_BYTES_PER_CHUNK)
        .ok_or(EncodeError::ArithmeticOverflow)?;

    let capacity = total_byte_length
        .checked_add(2) // we use 2 bytes to hold the bit lengths
        .ok_or(EncodeError::ArithmeticOverflow)?;
    let mut result = Vec::with_capacity(capacity);

    result.extend_from_slice(&(num_bits as u16).to_le_bytes());

    for chunk_index in 0..total_u8_length {
        let mut block_num: u8 = 0;
        let start_bit = chunk_index
            .checked_mul(BASE3_SYMBOL_PER_CHUNK)
            .ok_or(EncodeError::ArithmeticOverflow)?;
        let end_bit = start_bit
            .checked_add(BASE3_SYMBOL_PER_CHUNK)
            .ok_or(EncodeError::ArithmeticOverflow)?
            .min(num_bits);

        for i in (start_bit..end_bit).rev() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            let base_bit = (base_bytes[byte_idx] >> bit_idx) & 1 == 1;
            let fallback_bit = (fallback_bytes[byte_idx] >> bit_idx) & 1 == 1;

            let chunk_num = match (base_bit, fallback_bit) {
                (false, false) => 0u8,
                (true, false) => 1u8,
                (false, true) => 2u8,
                (true, true) => return Err(EncodeError::InvalidBitCombination),
            };
            block_num = block_num
                .checked_mul(3)
                .ok_or(EncodeError::ArithmeticOverflow)?
                .checked_add(chunk_num)
                .ok_or(EncodeError::ArithmeticOverflow)?;
        }
        result.push(block_num);
    }

    Ok(result)
}

/// An error that can occur during the decoding process.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The byte slice is too short to contain a valid 2-byte length prefix.
    InvalidLengthPrefix,
    /// The data payload does not have the expected length.
    CorruptDataPayload,
    /// Arithmetic overflow.
    ArithmeticOverflow,
}

/// Decodes an encoded byte slice back into two byte vectors.
///
/// This function returns a tuple containing the base byte vector, the fallback
/// byte vector, and the exact number of valid bits in those vectors.
pub fn decode_to_bytes(
    bytes: &[u8],
    max_len: usize,
) -> Result<(Vec<u8>, Vec<u8>, usize), DecodeError> {
    if bytes.len() < 2 {
        return Err(DecodeError::InvalidLengthPrefix);
    }
    let mut len_arr = [0u8; 2];
    len_arr.copy_from_slice(&bytes[..2]);
    let total_bits = u16::from_le_bytes(len_arr) as usize;

    if total_bits > max_len {
        return Err(DecodeError::CorruptDataPayload);
    }

    let data_bytes = &bytes[2..];

    let expected_num_chunks = total_bits
        .checked_add(BASE3_SYMBOL_PER_CHUNK - 1)
        .and_then(|n| n.checked_div(BASE3_SYMBOL_PER_CHUNK))
        .ok_or(DecodeError::CorruptDataPayload)?;

    let expected_payload_len = expected_num_chunks
        .checked_mul(ENCODED_BYTES_PER_CHUNK)
        .ok_or(DecodeError::CorruptDataPayload)?;

    if data_bytes.len() != expected_payload_len {
        return Err(DecodeError::CorruptDataPayload);
    }

    let decoded_byte_len = total_bits
        .checked_add(7)
        .ok_or(DecodeError::ArithmeticOverflow)?
        .checked_div(8)
        .ok_or(DecodeError::ArithmeticOverflow)?;
    let mut base_bytes = vec![0u8; decoded_byte_len];
    let mut fallback_bytes = vec![0u8; decoded_byte_len];

    let mut bits_remaining = total_bits;
    for (i, block_byte) in data_bytes.iter().enumerate() {
        let mut block_num = *block_byte;
        let bits_in_this_chunk = bits_remaining.min(BASE3_SYMBOL_PER_CHUNK);

        for j in 0..bits_in_this_chunk {
            let remainder = block_num % 3;
            block_num /= 3;

            let bit_index = i
                .checked_mul(BASE3_SYMBOL_PER_CHUNK)
                .ok_or(DecodeError::ArithmeticOverflow)?
                .checked_add(j)
                .ok_or(DecodeError::ArithmeticOverflow)?;
            let byte_idx = bit_index / 8;
            let bit_idx = bit_index % 8;

            let (base_bit, fallback_bit) = match remainder {
                0 => (false, false),
                1 => (true, false),
                2 => (false, true),
                _ => unreachable!(),
            };

            if base_bit {
                base_bytes[byte_idx] |= 1 << bit_idx;
            }
            if fallback_bit {
                fallback_bytes[byte_idx] |= 1 << bit_idx;
            }
        }
        bits_remaining = bits_remaining
            .checked_sub(bits_in_this_chunk)
            .ok_or(DecodeError::ArithmeticOverflow)?;
    }

    Ok((base_bytes, fallback_bytes, total_bits))
}

#[cfg(feature = "bitvec")]
pub use bitvec_support::*;

#[cfg(feature = "bitvec")]
mod bitvec_support {
    use {super::*, bitvec::prelude::*};

    /// A wrapper to encode two `BitVec`s into a single `Vec<u8>`.
    pub fn encode(
        bit_vec_base: &BitVec<u8, Lsb0>,
        bit_vec_fallback: &BitVec<u8, Lsb0>,
    ) -> Result<Vec<u8>, EncodeError> {
        if bit_vec_base.len() != bit_vec_fallback.len() {
            return Err(EncodeError::MismatchedLengths);
        }
        encode_from_bytes(
            bit_vec_base.as_raw_slice(),
            bit_vec_fallback.as_raw_slice(),
            bit_vec_base.len(),
        )
    }

    /// A wrapper to decode a byte vector back into two `BitVec`s.
    #[allow(clippy::type_complexity)]
    pub fn decode(
        bytes: &[u8],
        max_len: usize,
    ) -> Result<(BitVec<u8, Lsb0>, BitVec<u8, Lsb0>), DecodeError> {
        let (base_bytes, fallback_bytes, total_bits) = decode_to_bytes(bytes, max_len)?;

        let mut base_vec = BitVec::from_vec(base_bytes);
        base_vec.truncate(total_bits);

        let mut fallback_vec = BitVec::from_vec(fallback_bytes);
        fallback_vec.truncate(total_bits);

        Ok((base_vec, fallback_vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_round_trip_small() {
        let num_bits = 10;
        let base_bytes = vec![0b0100_1001, 0b0000_0001];
        let fallback_bytes = vec![0b1010_0110, 0b0000_0000];

        let encoded = encode_from_bytes(&base_bytes, &fallback_bytes, num_bits).unwrap();
        let (decoded_base, decoded_fallback, decoded_bits) =
            decode_to_bytes(&encoded, num_bits).unwrap();

        assert_eq!(decoded_bits, num_bits);
        assert_eq!(base_bytes, decoded_base);
        assert_eq!(fallback_bytes, decoded_fallback);
    }

    #[cfg(feature = "bitvec")]
    mod bitvec_tests {
        use {
            super::{super::bitvec_support::*, *},
            bitvec::prelude::*,
        };

        fn create_test_data(len: usize) -> (BitVec<u8, Lsb0>, BitVec<u8, Lsb0>) {
            let mut base = BitVec::with_capacity(len);
            let mut fallback = BitVec::with_capacity(len);
            for i in 0..len {
                match i % 3 {
                    0 => {
                        base.push(false);
                        fallback.push(false);
                    }
                    1 => {
                        base.push(true);
                        fallback.push(false);
                    }
                    _ => {
                        base.push(false);
                        fallback.push(true);
                    }
                }
            }
            (base, fallback)
        }

        #[test]
        fn test_bitvec_round_trip_empty() {
            let (base, fallback) = create_test_data(0);
            let encoded = encode(&base, &fallback).unwrap();
            assert_eq!(encoded, vec![0, 0]);
            let (decoded_base, decoded_fallback) = decode(&encoded, 0).unwrap();
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        }

        #[test]
        fn test_bitvec_round_trip_small() {
            let (base, fallback) = create_test_data(10);
            let encoded = encode(&base, &fallback).unwrap();
            let (decoded_base, decoded_fallback) = decode(&encoded, 10).unwrap();
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        }

        #[test]
        fn test_bitvec_round_trip_exact_chunk() {
            let len = BASE3_SYMBOL_PER_CHUNK;
            let (base, fallback) = create_test_data(len); // 5
            let encoded = encode(&base, &fallback).unwrap();
            let (decoded_base, decoded_fallback) = decode(&encoded, len).unwrap();
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        }

        #[test]
        fn test_bitvec_round_trip_multi_chunk_partial() {
            let len = 7; // 1 full chunk, 1 partial
            let (base, fallback) = create_test_data(len);
            let encoded = encode(&base, &fallback).unwrap();
            let (decoded_base, decoded_fallback) = decode(&encoded, len).unwrap();
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        }

        #[test]
        fn test_bitvec_round_trip_multi_chunk_exact() {
            let len = 10; // 2 full chunks
            let (base, fallback) = create_test_data(len);
            let encoded = encode(&base, &fallback).unwrap();
            let (decoded_base, decoded_fallback) = decode(&encoded, len).unwrap();
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        }

        #[test]
        fn test_bitvec_encode_error_mismatched_lengths() {
            let (base, _) = create_test_data(10);
            let (_, fallback) = create_test_data(11);
            let result = encode(&base, &fallback);
            assert_eq!(result, Err(EncodeError::MismatchedLengths));
        }

        #[test]
        fn test_bitvec_encode_error_invalid_combination() {
            let mut base = BitVec::<u8, Lsb0>::new();
            base.push(false);
            base.push(true);

            let mut fallback = BitVec::<u8, Lsb0>::new();
            fallback.push(false);
            fallback.push(true);

            let result = encode(&base, &fallback);
            assert_eq!(result, Err(EncodeError::InvalidBitCombination));
        }

        #[test]
        fn test_bitvec_decode_error_invalid_length_prefix() {
            let bytes = vec![1];
            let result = decode(&bytes, 0);
            assert_eq!(result, Err(DecodeError::InvalidLengthPrefix));
        }

        #[test]
        fn test_bitvec_decode_error_corrupt_payload() {
            let len = 10;
            let (base, fallback) = create_test_data(len);
            let mut encoded = encode(&base, &fallback).unwrap();
            encoded.pop(); // Make the payload an invalid length
            let result = decode(&encoded, len);
            assert_eq!(result, Err(DecodeError::CorruptDataPayload));
        }

        #[test]
        fn test_bitvec_decode_error_length_exceeds_max() {
            let len = 10;
            let (base, fallback) = create_test_data(len);
            let encoded = encode(&base, &fallback).unwrap();
            let result = decode(&encoded, len - 1);
            assert_eq!(result, Err(DecodeError::CorruptDataPayload));
        }
    }
}
