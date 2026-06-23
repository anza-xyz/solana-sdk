use {
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput},
    solana_keccak_hasher::{hash, keccak_f, KECCAK_F1600_STATE_BYTES},
};

const KECCAK256_ONE_PERMUTATION_BYTES: usize = 135;
const KECCAK256_TWO_PERMUTATION_BYTES: usize = 136;

const INITIAL_STATE: [u64; 25] = [
    0x9e37_79b9_7f4a_7c15,
    0x3c6e_f372_fe94_f82b,
    0xdaa6_6d2c_7ddf_743e,
    0x78dd_e6e5_fd29_f054,
    0x1715_60a0_7c74_6c69,
    0xb54c_da59_fbb8_e87f,
    0x5384_5413_7b03_6494,
    0xf1bb_cdcc_fa4d_e0aa,
    0x8ff3_4786_7998_5cbf,
    0x2e2a_c13f_f8e2_d8d5,
    0xcc62_3af9_782d_54ea,
    0x6a99_b4b2_f777_d100,
    0x08d1_2e6c_76c2_4d15,
    0xa708_a825_f60c_c92b,
    0x4540_21df_7557_4540,
    0xe377_9b98_f4a1_c156,
    0x81af_1552_73ec_3d6b,
    0x1fe6_8f0b_f336_b981,
    0xbe1e_08c5_7271_3596,
    0x5c55_827e_f1bb_b1ac,
    0xfa8c_fc38_7106_2dc1,
    0x98c4_75f1_f050_a9d7,
    0x36fb_efab_6f9b_25ec,
    0xd533_6964_eee5_a202,
    0x736a_e31e_6e30_1e17,
];

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");

    group.throughput(Throughput::Bytes(KECCAK_F1600_STATE_BYTES as u64));
    group.bench_function("keccak_f1600", |b| {
        let mut state = INITIAL_STATE;
        b.iter(|| {
            keccak_f(black_box(&mut state));
            black_box(state[0]);
        })
    });

    for input_len in [
        0,
        KECCAK256_ONE_PERMUTATION_BYTES,
        KECCAK256_TWO_PERMUTATION_BYTES,
        KECCAK_F1600_STATE_BYTES,
    ] {
        let input = vec![0xa5; input_len];
        group.throughput(Throughput::Bytes(input_len as u64));
        group.bench_with_input(
            BenchmarkId::new("keccak256", input_len),
            input.as_slice(),
            |b, input| b.iter(|| black_box(hash(black_box(input)))),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_keccak);
criterion_main!(benches);
