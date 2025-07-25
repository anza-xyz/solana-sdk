//! Provides a space-efficient encoding scheme for one or two boolean vectors.
//!
//! This module implements compression algorithms to encode boolean vectors
//! into a single byte vector (`Vec<u8>`). It supports two distinct schemes
//! based on the number of input vectors.
//!
//! # Encoding Schemes
//!
//! ## Base2 Encoding (Single Vector)
//! When a single boolean vector is provided, it is encoded directly.
//! The format is:
//! 1.  **Version Byte (1 byte)**: `Version::Base2` as a `u8`.
//! 2.  **Length Prefix (2 bytes)**: A `u16` in little-endian format storing the
//!     number of bits in the vector.
//! 3.  **Data Payload**: The raw byte data of the boolean vector.
//!
//! ## Base3 Encoding (Two Vectors)
//! When two boolean vectors of the same length are provided, they are compressed
//! together. This scheme assumes that for any given index, the bits in both
//! vectors will not both be `1`.
//!
//! The pairs of booleans are mapped to a single ternary (base-3) digit:
//! - `(false, false)` -> `0`
//! - `(true, false)`  -> `1`
//! - `(false, true)`  -> `2`
//!
//! The combination `(true, true)` is considered invalid. These ternary digits are
//! packed five at a time into a single `u8`, since `3^5 < 2^8`.
//!
//! The format is:
//! 1.  **Version Byte (1 byte)**: `Version::Base3` as a `u8`.
//! 2.  **Length Prefix (2 bytes)**: A `u16` in little-endian format storing the
//!     original number of bits (i.e., the length of the input vectors).
//! 3.  **Data Payload**: A sequence of bytes containing the packed base-3 digits.

use {
    bitvec::prelude::*,
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::FromPrimitive,
};

/// Represents the encoding version, used as the first byte in the output.
#[derive(Debug, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Version {
    Base2 = 0,
    Base3 = 1,
}

/// An error that can occur during the encoding process.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// In Base3 encoding, the provided bit-vectors have unmatching lengths.
    MismatchedLengths,
    /// In Base3 encoding, the invalid combination `(true, true)` was found.
    InvalidBitCombination,
    /// The length of the input vectors exceeds `u16::MAX` (65,535).
    LengthExceedsLimit,
    /// An arithmetic operation resulted in an overflow.
    ArithmeticOverflow,
}

// Each u8 can hold 5 base-3 symbols (3^5 = 243).
const BASE3_SYMBOLS_PER_BYTE: usize = 5;

/// Encodes a single boolean vector using Base2 encoding.
///
/// The output `Vec<u8>` is prefixed with the `Version::Base2` byte.
pub fn encode_base2(bit_vec: &BitVec<u8, Lsb0>) -> Result<Vec<u8>, EncodeError> {
    let num_bits = bit_vec.len();
    if num_bits > u16::MAX as usize {
        return Err(EncodeError::LengthExceedsLimit);
    }

    let raw_slice = bit_vec.as_raw_slice();
    let capacity = 3usize
        .checked_add(raw_slice.len())
        .ok_or(EncodeError::ArithmeticOverflow)?;
    let mut result = Vec::with_capacity(capacity);
    result.push(Version::Base2 as u8);
    result.extend_from_slice(&(num_bits as u16).to_le_bytes());
    result.extend_from_slice(raw_slice);

    Ok(result)
}

/// Encodes two boolean vectors using Base3 encoding.
///
/// This function assumes that for any given index, `bit_vec_base` and
/// `bit_vec_fallback` will not both have a bit set to `1`.
/// The output `Vec<u8>` is prefixed with the `Version::Base3` byte.
pub fn encode_base3(
    bit_vec_base: &BitVec<u8, Lsb0>,
    bit_vec_fallback: &BitVec<u8, Lsb0>,
) -> Result<Vec<u8>, EncodeError> {
    if bit_vec_base.len() != bit_vec_fallback.len() {
        return Err(EncodeError::MismatchedLengths);
    }
    let num_bits = bit_vec_base.len();
    if num_bits > u16::MAX as usize {
        return Err(EncodeError::LengthExceedsLimit);
    }

    let base_bytes = bit_vec_base.as_raw_slice();
    let fallback_bytes = bit_vec_fallback.as_raw_slice();

    let num_chunks = num_bits.div_ceil(BASE3_SYMBOLS_PER_BYTE);
    let capacity = 3usize
        .checked_add(num_chunks)
        .ok_or(EncodeError::ArithmeticOverflow)?;
    let mut result = Vec::with_capacity(capacity);

    result.push(Version::Base3 as u8);
    result.extend_from_slice(&(num_bits as u16).to_le_bytes());

    for chunk_index in 0..num_chunks {
        let mut block_num: u8 = 0;
        let start_bit = chunk_index
            .checked_mul(BASE3_SYMBOLS_PER_BYTE)
            .ok_or(EncodeError::ArithmeticOverflow)?;
        let end_bit = start_bit
            .checked_add(BASE3_SYMBOLS_PER_BYTE)
            .ok_or(EncodeError::ArithmeticOverflow)?
            .min(num_bits);

        // Process bits in reverse order to simplify packing
        for i in (start_bit..end_bit).rev() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            let base_bit = (base_bytes.get(byte_idx).unwrap_or(&0) >> bit_idx) & 1 == 1;
            let fallback_bit = (fallback_bytes.get(byte_idx).unwrap_or(&0) >> bit_idx) & 1 == 1;

            let chunk_num = match (base_bit, fallback_bit) {
                (false, false) => 0u8,
                (true, false) => 1u8,
                (false, true) => 2u8,
                (true, true) => return Err(EncodeError::InvalidBitCombination),
            };

            block_num = block_num
                .checked_mul(3)
                .and_then(|n| n.checked_add(chunk_num))
                .ok_or(EncodeError::ArithmeticOverflow)?;
        }
        result.push(block_num);
    }
    Ok(result)
}

/// Represents the result of a decoding operation.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// A single vector from Base2 decoding.
    Base2(BitVec<u8, Lsb0>),
    /// Two vectors from Base3 decoding.
    Base3(BitVec<u8, Lsb0>, BitVec<u8, Lsb0>),
}

/// An error that can occur during the decoding process.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input slice is too short to be valid.
    InputTooShort,
    /// The encoding version byte is unsupported.
    UnsupportedEncoding,
    /// The data payload is not of the expected length.
    CorruptDataPayload,
    /// An arithmetic operation resulted in an overflow.
    ArithmeticOverflow,
}

/// Decodes an encoded byte slice into one or two boolean vectors.
///
/// It reads the first byte to determine the encoding scheme and then decodes
/// the rest of the data accordingly.
pub fn decode(bytes: &[u8], max_len: usize) -> Result<Decoded, DecodeError> {
    if bytes.len() < 3 {
        // Must have at least version (1) + length (2)
        return Err(DecodeError::InputTooShort);
    }

    let version_byte = bytes[0];
    let version = Version::from_u8(version_byte).ok_or(DecodeError::UnsupportedEncoding)?;

    let mut len_arr = [0u8; 2];
    len_arr.copy_from_slice(&bytes[1..3]);
    let total_bits = u16::from_le_bytes(len_arr) as usize;

    if total_bits > max_len {
        return Err(DecodeError::CorruptDataPayload);
    }

    let data_bytes = &bytes[3..];

    match version {
        Version::Base2 => decode_impl_base2(data_bytes, total_bits),
        Version::Base3 => decode_impl_base3(data_bytes, total_bits),
    }
}

// Internal function to handle Base2 decoding logic
fn decode_impl_base2(data_bytes: &[u8], total_bits: usize) -> Result<Decoded, DecodeError> {
    let expected_byte_len = total_bits.div_ceil(8);
    if data_bytes.len() != expected_byte_len {
        return Err(DecodeError::CorruptDataPayload);
    }

    let mut bit_vec = BitVec::from_slice(data_bytes);
    bit_vec.truncate(total_bits);

    Ok(Decoded::Base2(bit_vec))
}

// Internal function to handle Base3 decoding logic
fn decode_impl_base3(data_bytes: &[u8], total_bits: usize) -> Result<Decoded, DecodeError> {
    let expected_num_chunks = total_bits.div_ceil(BASE3_SYMBOLS_PER_BYTE);

    if data_bytes.len() != expected_num_chunks {
        return Err(DecodeError::CorruptDataPayload);
    }

    let decoded_byte_len = total_bits.div_ceil(8);
    let mut base_bytes = vec![0u8; decoded_byte_len];
    let mut fallback_bytes = vec![0u8; decoded_byte_len];

    for (chunk_index, &block_byte) in data_bytes.iter().enumerate() {
        let mut block_num = block_byte;
        let start_bit = chunk_index
            .checked_mul(BASE3_SYMBOLS_PER_BYTE)
            .ok_or(DecodeError::ArithmeticOverflow)?;
        let end_bit = start_bit
            .checked_add(BASE3_SYMBOLS_PER_BYTE)
            .ok_or(DecodeError::ArithmeticOverflow)?
            .min(total_bits);

        for bit_index in start_bit..end_bit {
            let remainder = block_num % 3;
            block_num /= 3;

            let byte_idx = bit_index / 8;
            let bit_idx = bit_index % 8;

            let (base_bit, fallback_bit) = match remainder {
                0 => (false, false),
                1 => (true, false),
                2 => (false, true),
                _ => unreachable!(), // Modulo 3 can't be > 2
            };

            if base_bit {
                base_bytes[byte_idx] |= 1 << bit_idx;
            }
            if fallback_bit {
                fallback_bytes[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    let mut base_vec = BitVec::from_vec(base_bytes);
    base_vec.truncate(total_bits);
    let mut fallback_vec = BitVec::from_vec(fallback_bytes);
    fallback_vec.truncate(total_bits);

    Ok(Decoded::Base3(base_vec, fallback_vec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_base3_test_data(len: usize) -> (BitVec<u8, Lsb0>, BitVec<u8, Lsb0>) {
        let mut base = BitVec::with_capacity(len);
        let mut fallback = BitVec::with_capacity(len);
        for i in 0..len {
            match i % 3 {
                0 => {
                    // (false, false) -> 0
                    base.push(false);
                    fallback.push(false);
                }
                1 => {
                    // (true, false) -> 1
                    base.push(true);
                    fallback.push(false);
                }
                _ => {
                    // (false, true) -> 2
                    base.push(false);
                    fallback.push(true);
                }
            }
        }
        (base, fallback)
    }

    #[test]
    fn test_base2_round_trip() {
        let original = bitvec![u8, Lsb0; 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1];
        let original_len = original.len();
        let encoded = encode_base2(&original).unwrap();

        // Check header
        assert_eq!(encoded[0], Version::Base2 as u8); // Version byte
        assert_eq!(
            u16::from_le_bytes(encoded[1..3].try_into().unwrap()),
            original_len as u16
        );

        let decoded = decode(&encoded, original_len).unwrap();
        if let Decoded::Base2(decoded_vec) = decoded {
            assert_eq!(original, decoded_vec);
        } else {
            panic!("Decoded into the wrong type");
        }
    }

    #[test]
    fn test_base2_empty() {
        let original = BitVec::<u8, Lsb0>::new();
        let encoded = encode_base2(&original).unwrap();
        assert_eq!(encoded, vec![Version::Base2 as u8, 0, 0]);
        let decoded = decode(&encoded, 0).unwrap();
        assert_eq!(decoded, Decoded::Base2(original));
    }

    #[test]
    fn test_base3_round_trip() {
        let (base, fallback) = create_base3_test_data(23); // Not a multiple of 5
        let original_len = base.len();
        let encoded = encode_base3(&base, &fallback).unwrap();

        // Check header
        assert_eq!(encoded[0], Version::Base3 as u8); // Version byte
        assert_eq!(
            u16::from_le_bytes(encoded[1..3].try_into().unwrap()),
            original_len as u16
        );

        let decoded = decode(&encoded, original_len).unwrap();
        if let Decoded::Base3(decoded_base, decoded_fallback) = decoded {
            assert_eq!(base, decoded_base);
            assert_eq!(fallback, decoded_fallback);
        } else {
            panic!("Decoded into the wrong type");
        }
    }

    #[test]
    fn test_base3_exact_bytes() {
        let (base, fallback) = create_base3_test_data(10); // 2 full bytes
        let encoded = encode_base3(&base, &fallback).unwrap();
        let decoded = decode(&encoded, 10).unwrap();
        assert_eq!(decoded, Decoded::Base3(base, fallback));
    }

    #[test]
    fn test_base3_empty() {
        let (base, fallback) = create_base3_test_data(0);
        let encoded = encode_base3(&base, &fallback).unwrap();
        assert_eq!(encoded, vec![Version::Base3 as u8, 0, 0]);
        let decoded = decode(&encoded, 0).unwrap();
        assert_eq!(decoded, Decoded::Base3(base, fallback));
    }

    #[test]
    fn test_encode_base3_invalid_combination() {
        let base = bitvec![u8, Lsb0; 0, 1];
        let fallback = bitvec![u8, Lsb0; 0, 1];
        let result = encode_base3(&base, &fallback);
        assert_eq!(result, Err(EncodeError::InvalidBitCombination));
    }

    #[test]
    fn test_encode_length_limit() {
        let long_vec = BitVec::repeat(false, (u16::MAX as usize) + 1);
        let result = encode_base2(&long_vec);
        assert_eq!(result, Err(EncodeError::LengthExceedsLimit));
    }

    #[test]
    fn test_decode_unsupported_encoding() {
        let bytes = vec![2, 0, 0, 1, 2, 3]; // Invalid version byte '2'
        let result = decode(&bytes, 10);
        assert_eq!(result, Err(DecodeError::UnsupportedEncoding));
    }

    #[test]
    fn test_decode_input_too_short() {
        let bytes = vec![1, 0]; // Only 2 bytes, needs at least 3
        let result = decode(&bytes, 10);
        assert_eq!(result, Err(DecodeError::InputTooShort));
    }

    #[test]
    fn test_decode_max_len_exceeded() {
        let (base, fallback) = create_base3_test_data(20);
        let encoded = encode_base3(&base, &fallback).unwrap();
        // Try to decode with a max_len that is too small
        let result = decode(&encoded, 19);
        assert_eq!(result, Err(DecodeError::CorruptDataPayload));
    }

    #[test]
    fn test_decode_corrupt_payload() {
        let (base, fallback) = create_base3_test_data(10);
        let mut encoded = encode_base3(&base, &fallback).unwrap();
        encoded.pop(); // Corrupt the payload by removing a byte
        let result = decode(&encoded, 10);
        assert_eq!(result, Err(DecodeError::CorruptDataPayload));
    }
}
