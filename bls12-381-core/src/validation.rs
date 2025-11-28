use {
    crate::{reverse_48_byte_chunks, swap_g2_c0_c1, Endianness, Version},
    blstrs::{G1Affine, G2Affine},
    std::convert::TryInto,
};

pub fn bls12_381_g1_point_validation(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> bool {
    if input.len() != 96 {
        return false;
    }

    let p1_opt = match endianness {
        Endianness::BE => {
            // ZERO-COPY: Cast slice directly to array reference
            let bytes: &[u8; 96] = input.try_into().expect("length checked");
            // from_uncompressed performs Field, On-Curve, and Subgroup checks
            G1Affine::from_uncompressed(bytes).into_option()
        }
        Endianness::LE => {
            // COPY & MUTATE: Allocate stack array to reverse bytes
            let mut bytes: [u8; 96] = input.try_into().expect("length checked");
            reverse_48_byte_chunks(&mut bytes);
            G1Affine::from_uncompressed(&bytes).into_option()
        }
    };

    p1_opt.is_some()
}

pub fn bls12_381_g2_point_validation(
    _version: Version,
    input: &[u8],
    endianness: Endianness,
) -> bool {
    if input.len() != 192 {
        return false;
    }

    let p2_opt = match endianness {
        Endianness::BE => {
            let bytes: &[u8; 192] = input.try_into().expect("length checked");
            G2Affine::from_uncompressed(bytes).into_option()
        }
        Endianness::LE => {
            let mut bytes: [u8; 192] = input.try_into().expect("length checked");
            // Apply G2 Little-Endian transformation
            reverse_48_byte_chunks(&mut bytes);
            swap_g2_c0_c1(&mut bytes);
            G2Affine::from_uncompressed(&bytes).into_option()
        }
    };

    p2_opt.is_some()
}
