use solana_bls12_381::{Endianness, G1Point, G2Point, SCALAR_SIZE};

/// The scalar field order `r`, big-endian.
pub fn scalar_field_order() -> [u8; SCALAR_SIZE] {
    array_bytes::hex2array("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
        .unwrap()
}

// Canonical on-curve encoding with G1 x = 4, obtained by decompressing
// without a subgroup check. The pairing tests check that it is on the curve
// but outside the prime-order subgroup.
pub fn g1_torsion(endianness: Endianness) -> G1Point {
    let mut p = G1Point(array_bytes::hex2array(concat!(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004",
        "0a989badd40d6212b33cffc3f3763e9bc760f988c9926b26da9dd85e928483446346b8ed00e1de5d5ea93e354abe706c",
    )).unwrap());
    if endianness == Endianness::Little {
        for coefficient in p.0.chunks_exact_mut(48) {
            coefficient.reverse();
        }
    }
    p
}

// Canonical on-curve encoding with G2 x = (2, 0), obtained by decompressing
// without a subgroup check. The pairing tests check that it is on the curve
// but outside the prime-order subgroup.
pub fn g2_torsion(endianness: Endianness) -> G2Point {
    let mut q = G2Point(array_bytes::hex2array(concat!(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "02d27e0ec3356299a346a09ad7dc4ef68a483c3aed53f9139d2f929a3eecebf72082e5e58c6da24ee32e03040c406d4f",
        "013a59858b6809fca4d9a3b6539246a70051a3c88899964a42bc9a69cf9acdd9dd387cfa9086b894185b9a46a402be73",
    )).unwrap());
    if endianness == Endianness::Little {
        // Reversing an Fq2 coordinate also swaps its c0/c1 coefficients.
        for coordinate in q.0.chunks_exact_mut(96) {
            coordinate.reverse();
        }
    }
    q
}
