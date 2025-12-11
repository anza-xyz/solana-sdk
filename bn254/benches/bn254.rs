use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bn254::{
        compression::prelude::convert_endianness,
        prelude::{
            alt_bn128_g1_addition_be, alt_bn128_g1_addition_le, alt_bn128_g1_multiplication_be,
            alt_bn128_g1_multiplication_le, alt_bn128_g2_addition_be, alt_bn128_g2_addition_le,
            alt_bn128_g2_multiplication_be, alt_bn128_g2_multiplication_le, alt_bn128_pairing_be,
            alt_bn128_pairing_le,
        },
    },
};

const ADD_G1_P_BYTES_BE: [u8; 64] = [
    24, 177, 138, 207, 180, 194, 195, 2, 118, 219, 84, 17, 54, 142, 113, 133, 179, 17, 221, 18, 70,
    145, 97, 12, 93, 59, 116, 3, 78, 9, 61, 201, 6, 60, 144, 156, 71, 32, 132, 12, 181, 19, 76,
    185, 245, 159, 167, 73, 117, 87, 150, 129, 150, 88, 211, 46, 252, 13, 40, 129, 152, 243, 114,
    102,
];

const ADD_G1_Q_BYTES_BE: [u8; 64] = [
    7, 194, 183, 245, 138, 132, 189, 97, 69, 240, 12, 156, 43, 192, 187, 26, 24, 127, 32, 255, 44,
    146, 150, 58, 136, 1, 158, 124, 106, 1, 78, 237, 6, 97, 78, 32, 193, 71, 233, 64, 242, 215, 13,
    163, 247, 76, 154, 23, 223, 54, 23, 6, 164, 72, 92, 116, 43, 214, 120, 132, 120, 250, 23, 215,
];

const ADD_G2_P_BYTES_BE: [u8; 128] = [
    12, 99, 121, 9, 195, 219, 210, 123, 2, 19, 174, 218, 136, 255, 218, 90, 193, 143, 68, 219, 107,
    131, 14, 86, 194, 82, 81, 109, 125, 217, 24, 255, 22, 74, 126, 194, 14, 148, 250, 229, 25, 217,
    177, 162, 186, 232, 39, 28, 161, 72, 198, 18, 180, 248, 72, 237, 127, 7, 198, 182, 40, 120,
    144, 117, 2, 222, 25, 1, 215, 100, 15, 117, 172, 87, 72, 219, 142, 99, 90, 242, 173, 129, 240,
    153, 136, 247, 9, 220, 198, 108, 165, 76, 214, 6, 199, 231, 2, 95, 67, 161, 219, 252, 140, 70,
    81, 7, 114, 57, 9, 30, 118, 220, 36, 140, 217, 157, 28, 138, 243, 153, 244, 12, 137, 22, 212,
    252, 10, 174,
];

const ADD_G2_Q_BYTES_BE: [u8; 128] = [
    7, 146, 58, 241, 144, 216, 37, 233, 89, 221, 123, 149, 166, 127, 171, 68, 145, 124, 78, 141,
    162, 120, 160, 110, 221, 44, 122, 234, 53, 188, 200, 176, 25, 182, 32, 116, 51, 20, 112, 200,
    62, 23, 19, 67, 116, 255, 173, 176, 186, 248, 67, 18, 25, 79, 218, 60, 175, 121, 92, 132, 201,
    43, 33, 109, 17, 238, 139, 205, 71, 85, 17, 196, 104, 217, 152, 58, 40, 131, 2, 232, 103, 60,
    220, 199, 20, 166, 221, 193, 128, 211, 93, 125, 208, 207, 172, 73, 21, 233, 235, 66, 187, 118,
    2, 113, 130, 155, 34, 74, 235, 42, 224, 192, 110, 128, 3, 72, 224, 209, 207, 111, 113, 40, 23,
    118, 128, 7, 204, 122,
];

const MUL_G1_POINT_BYTES_BE: [u8; 64] = [
    43, 211, 230, 208, 243, 177, 66, 146, 79, 92, 167, 180, 156, 229, 185, 213, 76, 71, 3, 215,
    174, 86, 72, 230, 29, 2, 38, 139, 26, 10, 159, 183, 33, 97, 28, 224, 166, 175, 133, 145, 94,
    47, 29, 112, 48, 9, 9, 206, 46, 73, 223, 173, 74, 70, 25, 200, 57, 12, 174, 102, 206, 253, 178,
    4,
];

const MUL_G2_POINT_BYTES_BE: [u8; 128] = [
    36, 185, 110, 165, 217, 87, 105, 205, 214, 17, 239, 59, 229, 102, 88, 162, 110, 78, 57, 14, 41,
    54, 22, 184, 236, 225, 147, 160, 35, 49, 121, 37, 7, 63, 225, 203, 118, 235, 175, 188, 209,
    215, 152, 62, 92, 193, 254, 67, 97, 10, 206, 24, 228, 20, 96, 248, 38, 154, 164, 80, 189, 219,
    120, 134, 0, 141, 103, 25, 254, 99, 148, 115, 112, 119, 206, 37, 52, 241, 132, 111, 134, 214,
    181, 204, 180, 15, 189, 42, 5, 96, 139, 18, 48, 37, 247, 185, 8, 90, 90, 82, 227, 15, 46, 64,
    60, 41, 236, 151, 3, 108, 136, 11, 73, 127, 46, 250, 96, 165, 226, 138, 169, 19, 7, 235, 250,
    245, 232, 90,
];

const MUL_SCALAR_BYTES_BE: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

const PAIRING_P_BYTES_BE: [u8; 64] = [
    28, 118, 71, 111, 77, 239, 75, 185, 69, 65, 213, 126, 187, 161, 25, 51, 129, 255, 167, 170,
    118, 173, 166, 100, 221, 49, 193, 96, 36, 196, 63, 89, 48, 52, 221, 41, 32, 246, 115, 226, 4,
    254, 226, 129, 28, 103, 135, 69, 252, 129, 155, 85, 211, 233, 210, 148, 228, 92, 155, 3, 167,
    106, 239, 65,
];

const PAIRING_Q_BYTES_BE: [u8; 128] = [
    32, 157, 209, 94, 191, 245, 212, 108, 75, 216, 136, 229, 26, 147, 207, 153, 167, 50, 150, 54,
    198, 53, 20, 57, 107, 74, 69, 32, 3, 163, 91, 247, 4, 191, 17, 202, 1, 72, 59, 250, 139, 52,
    180, 53, 97, 132, 141, 40, 144, 89, 96, 17, 76, 138, 192, 64, 73, 175, 75, 99, 21, 164, 22,
    120, 43, 184, 50, 74, 246, 207, 201, 53, 55, 162, 173, 26, 68, 92, 253, 12, 162, 167, 26, 205,
    122, 196, 31, 173, 191, 147, 60, 42, 81, 190, 52, 77, 18, 10, 42, 76, 243, 12, 27, 249, 132,
    95, 32, 198, 254, 57, 224, 126, 162, 204, 230, 31, 12, 155, 176, 72, 22, 95, 229, 228, 222,
    135, 117, 80,
];

fn bench_g1_addition_be(c: &mut Criterion) {
    let p_bytes = ADD_G1_P_BYTES_BE;
    let q_bytes = ADD_G1_Q_BYTES_BE;

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat();

    c.bench_function("bn128 g1 addition be", |b| {
        b.iter(|| alt_bn128_g1_addition_be(&input_bytes))
    });
}

fn bench_g1_addition_le(c: &mut Criterion) {
    let p_bytes = convert_endianness::<32, 64>(&ADD_G1_P_BYTES_BE);
    let q_bytes = convert_endianness::<32, 64>(&ADD_G1_Q_BYTES_BE);

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat().try_into().unwrap();

    c.bench_function("bn128 g1 addition le", |b| {
        b.iter(|| alt_bn128_g1_addition_le(&input_bytes))
    });
}

fn bench_g2_addition_be(c: &mut Criterion) {
    let p_bytes = ADD_G2_P_BYTES_BE;
    let q_bytes = ADD_G2_Q_BYTES_BE;

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat().try_into().unwrap();

    c.bench_function("bn128 g2 addition be", |b| {
        b.iter(|| alt_bn128_g2_addition_be(&input_bytes))
    });
}

fn bench_g2_addition_le(c: &mut Criterion) {
    let p_bytes = convert_endianness::<64, 128>(&ADD_G2_P_BYTES_BE);
    let q_bytes = convert_endianness::<64, 128>(&ADD_G2_Q_BYTES_BE);

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat().try_into().unwrap();

    c.bench_function("bn128 g2 addition le", |b| {
        b.iter(|| alt_bn128_g2_addition_le(&input_bytes))
    });
}

fn bench_g1_multiplication_be(c: &mut Criterion) {
    let point_bytes = MUL_G1_POINT_BYTES_BE;
    let scalar_bytes = MUL_SCALAR_BYTES_BE;

    let input_bytes = [&point_bytes[..], &scalar_bytes[..]].concat();

    c.bench_function("bn128 g1 multiplication be", |b| {
        b.iter(|| alt_bn128_g1_multiplication_be(&input_bytes))
    });
}

fn bench_g1_multiplication_le(c: &mut Criterion) {
    let point_bytes = convert_endianness::<32, 64>(&MUL_G1_POINT_BYTES_BE);
    let scalar_bytes = convert_endianness::<32, 32>(&MUL_SCALAR_BYTES_BE);

    let input_bytes = [&point_bytes[..], &scalar_bytes[..]]
        .concat()
        .try_into()
        .unwrap();

    c.bench_function("bn128 g1 multiplication le", |b| {
        b.iter(|| alt_bn128_g1_multiplication_le(&input_bytes))
    });
}

fn bench_g2_multiplication_be(c: &mut Criterion) {
    let point_bytes = MUL_G2_POINT_BYTES_BE;
    let scalar_bytes = MUL_SCALAR_BYTES_BE;

    let input_bytes = [&point_bytes[..], &scalar_bytes[..]]
        .concat()
        .try_into()
        .unwrap();
    c.bench_function("bn128 g2 multiplication be", |b| {
        b.iter(|| alt_bn128_g2_multiplication_be(&input_bytes))
    });
}

fn bench_g2_multiplication_le(c: &mut Criterion) {
    let point_bytes = convert_endianness::<64, 128>(&MUL_G2_POINT_BYTES_BE);
    let scalar_bytes = convert_endianness::<32, 32>(&MUL_SCALAR_BYTES_BE);

    let input_bytes = [&point_bytes[..], &scalar_bytes[..]]
        .concat()
        .try_into()
        .unwrap();
    c.bench_function("bn128 g2 multiplication le", |b| {
        b.iter(|| alt_bn128_g2_multiplication_le(&input_bytes))
    });
}

fn bench_pairing_be(c: &mut Criterion) {
    let p_bytes = PAIRING_P_BYTES_BE;
    let q_bytes = PAIRING_Q_BYTES_BE;

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat();

    c.bench_function("bn128 pairing be", |b| {
        b.iter(|| alt_bn128_pairing_be(&input_bytes))
    });
}

fn bench_pairing_le(c: &mut Criterion) {
    let p_bytes = convert_endianness::<32, 64>(&PAIRING_P_BYTES_BE);
    let q_bytes = convert_endianness::<64, 128>(&PAIRING_Q_BYTES_BE);

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat();

    c.bench_function("bn128 pairing le", |b| {
        b.iter(|| alt_bn128_pairing_le(&input_bytes))
    });
}

criterion_group!(
    benches,
    bench_g1_addition_be,
    bench_g1_addition_le,
    bench_g2_addition_be,
    bench_g2_addition_le,
    bench_g1_multiplication_be,
    bench_g1_multiplication_le,
    bench_g2_multiplication_be,
    bench_g2_multiplication_le,
    bench_pairing_be,
    bench_pairing_le,
);
criterion_main!(benches);
