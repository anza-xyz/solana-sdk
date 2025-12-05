use {
    crate::{reverse_48_byte_chunks, swap_g2_c0_c1, Endianness, Version},
    blstrs::{G1Affine, G2Affine},
    std::convert::TryInto,
};

pub fn bls12_381_g1_decompress(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 48 {
        return None;
    }

    let p1 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 48] = input.try_into().ok()?;
            G1Affine::from_compressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 48] = input.try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            // Flags are now in the first byte (BE standard) after reversal
            G1Affine::from_compressed(&bytes).into_option()?
        }
    };

    let mut result_affine = p1.to_uncompressed();
    if matches!(endianness, Endianness::LE) {
        reverse_48_byte_chunks(&mut result_affine);
    }
    Some(result_affine.to_vec())
}

pub fn bls12_381_g2_decompress(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 96 {
        return None;
    }

    let p2 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 96] = input.try_into().ok()?;
            G2Affine::from_compressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 96] = input.try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            swap_g2_c0_c1(&mut bytes); // Swap c0/c1 for G2
            G2Affine::from_compressed(&bytes).into_option()?
        }
    };

    let mut result_affine = p2.to_uncompressed();
    if matches!(endianness, Endianness::LE) {
        swap_g2_c0_c1(&mut result_affine);
        reverse_48_byte_chunks(&mut result_affine);
    }
    Some(result_affine.to_vec())
}
