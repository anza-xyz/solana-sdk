use {
    crate::{reverse_48_byte_chunks, swap_g2_c0_c1, Endianness, Version},
    blstrs::{G1Affine, G1Projective, G2Affine, G2Projective},
};

pub fn bls12_381_g1_addition(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 192 {
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

    let p2 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 96] = input[96..192].try_into().ok()?;
            G1Affine::from_uncompressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 96] = input[96..192].try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            G1Affine::from_uncompressed(&bytes).into_option()?
        }
    };

    let p1_proj: G1Projective = p1.into();
    let sum_proj = p1_proj + p2;
    let mut sum_affine = sum_proj.to_uncompressed();

    if matches!(endianness, Endianness::LE) {
        reverse_48_byte_chunks(&mut sum_affine);
    }
    Some(sum_affine.to_vec())
}

pub fn bls12_381_g2_addition(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    if input.len() != 384 {
        return None;
    }

    let p1 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 192] = input[0..192].try_into().ok()?;
            G2Affine::from_uncompressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 192] = input[0..192].try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes); // Fix Fq endianness
            swap_g2_c0_c1(&mut bytes); // Fix Fq2 ordering
            G2Affine::from_uncompressed(&bytes).into_option()?
        }
    };

    let p2 = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 192] = input[192..384].try_into().ok()?;
            G2Affine::from_uncompressed(bytes).into_option()?
        }
        Endianness::LE => {
            let mut bytes: [u8; 192] = input[192..384].try_into().ok()?;
            reverse_48_byte_chunks(&mut bytes);
            swap_g2_c0_c1(&mut bytes);
            G2Affine::from_uncompressed(&bytes).into_option()?
        }
    };

    let p1_proj: G2Projective = p1.into();
    let sum_proj = p1_proj + p2;
    let mut sum_affine = sum_proj.to_uncompressed();

    if matches!(endianness, Endianness::LE) {
        swap_g2_c0_c1(&mut sum_affine);
        reverse_48_byte_chunks(&mut sum_affine);
    }
    Some(sum_affine.to_vec())
}
