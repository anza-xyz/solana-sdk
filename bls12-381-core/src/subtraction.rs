use {
    crate::{reverse_48_byte_chunks, swap_g2_c0_c1, Endianness, Version},
    blstrs::{G1Affine, G1Projective, G2Affine, G2Projective},
    group::prime::PrimeCurveAffine,
    std::convert::TryInto,
};

pub fn bls12_381_g1_subtraction(
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

    let mut diff_affine = if bool::from(p1.is_identity()) {
        (p2).to_uncompressed()
    } else {
        (G1Projective::from(p1) - p2).to_uncompressed()
    };

    if matches!(endianness, Endianness::LE) {
        reverse_48_byte_chunks(&mut diff_affine);
    }
    Some(diff_affine.to_vec())
}

pub fn bls12_381_g2_subtraction(
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
            reverse_48_byte_chunks(&mut bytes);
            swap_g2_c0_c1(&mut bytes);
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

    let mut diff_affine = if bool::from(p1.is_identity()) {
        (-p2).to_uncompressed()
    } else {
        (G2Projective::from(p1) - p2).to_uncompressed()
    };

    if matches!(endianness, Endianness::LE) {
        swap_g2_c0_c1(&mut diff_affine);
        reverse_48_byte_chunks(&mut diff_affine);
    }
    Some(diff_affine.to_vec())
}
