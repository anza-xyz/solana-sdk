use {
    crate::{reverse_48_byte_chunks, swap_g2_c0_c1, Endianness, Version},
    blstrs::{G1Affine, G2Affine, Scalar},
    std::convert::TryInto,
};

pub fn bls12_381_g1_multiplication(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 128 {
        return None;
    }

    let p1 = match endianness {
        Endianness::BE => {
            // make zero-copy when possible
            let bytes: &[u8; 96] = input[0..96].try_into().ok()?;
            G1Affine::from_uncompressed(bytes).into_option()?
        }
        Endianness::LE => {
            // to reverse the bytes, we need an owned copy
            let mut bytes: [u8; 96] = input[0..96].try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            G1Affine::from_uncompressed(&bytes).into_option()?
        }
    };

    // blstrs provides specific BE/LE parsers, so we don't need manual reversal.
    let scalar_bytes: &[u8; 32] = input[96..128].try_into().ok()?;
    let scalar = match endianness {
        Endianness::BE => Scalar::from_bytes_be(scalar_bytes).into_option()?,
        Endianness::LE => Scalar::from_bytes_le(scalar_bytes).into_option()?,
    };

    let result_proj = p1 * scalar;
    let mut result_affine = result_proj.to_uncompressed();

    if matches!(endianness, Endianness::LE) {
        reverse_48_byte_chunks(&mut result_affine);
    }
    Some(result_affine.to_vec())
}

pub fn bls12_381_g2_multiplication(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 224 {
        return None;
    }

    let p1 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 192] = input[0..192].try_into().ok()?;
            G2Affine::from_uncompressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 192] = input[0..192].try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            swap_g2_c0_c1(&mut bytes);
            G2Affine::from_uncompressed(&bytes).into_option()?
        }
    };

    let scalar_bytes: &[u8; 32] = input[192..224].try_into().ok()?;
    let scalar = match endianness {
        Endianness::BE => Scalar::from_bytes_be(scalar_bytes).into_option()?,
        Endianness::LE => Scalar::from_bytes_le(scalar_bytes).into_option()?,
    };

    let result_proj = p1 * scalar;
    let mut result_affine = result_proj.to_uncompressed();

    if matches!(endianness, Endianness::LE) {
        swap_g2_c0_c1(&mut result_affine);
        reverse_48_byte_chunks(&mut result_affine);
    }
    Some(result_affine.to_vec())
}
