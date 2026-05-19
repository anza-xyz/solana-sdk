use {
    criterion::{black_box, criterion_group, criterion_main, Criterion},
    serde::Deserialize,
    solana_big_mod_exp::big_mod_exp,
};

const SIMD_0529_MODULUS_BUCKETS: [(&str, usize); 9] = [
    ("1..=32 bits", 4),
    ("33..=64 bits", 8),
    ("65..=128 bits", 16),
    ("129..=256 bits", 32),
    ("257..=384 bits", 48),
    ("385..=512 bits", 64),
    ("513..=1024 bits", 128),
    ("1025..=2048 bits", 256),
    ("2049..=4096 bits", 512),
];

#[derive(Deserialize, Debug)]
struct BenchmarkData {
    exp_3_and_65537: BitSizeGroup,
    variable_exponents: VariableBitSizeGroup,
}

#[derive(Deserialize, Debug)]
struct BitSizeGroup {
    bits_512: BaseModSet,
    bits_1024: BaseModSet,
    bits_2048: BaseModSet,
    bits_4096: BaseModSet,
}

#[derive(Deserialize, Debug)]
struct BaseModSet {
    base: Vec<u8>,
    modulus_odd: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct VariableBitSizeGroup {
    bits_512: VariableSet,
    bits_1024: VariableSet,
    bits_2048: VariableSet,
    bits_4096: VariableSet,
}

#[derive(Deserialize, Debug)]
struct VariableSet {
    base: Vec<u8>,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

struct BucketSet {
    base: Vec<u8>,
    exponent: Vec<u8>,
    modulus: Vec<u8>,
}

fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

fn simd_0529_bucket_set(modulus_len: usize) -> BucketSet {
    let mut base = deterministic_bytes(modulus_len, modulus_len as u64);
    base[0] |= 0x80;

    // Dense, maximum-length exponents exercise the slower valid cases called
    // out by SIMD-0529 for the corresponding modulus size.
    let exponent = vec![0xff; modulus_len];

    let mut modulus = deterministic_bytes(modulus_len, (modulus_len as u64).reverse_bits());
    modulus[0] |= 0x80;
    *modulus.last_mut().expect("modulus buckets are non-empty") |= 1;

    BucketSet {
        base,
        exponent,
        modulus,
    }
}

fn all_benches(c: &mut Criterion) {
    let data_str = include_str!("data/benchmark_constants.json");
    let data: BenchmarkData =
        serde_json::from_str(data_str).expect("Failed to parse benchmark data");

    // --- Benchmark Group for Exponent 3 ---
    let mut group_exp_3 = c.benchmark_group("Exponent 3");
    let exponent_3 = [3u8];
    let const_exp_data = &data.exp_3_and_65537;

    group_exp_3.bench_function("512 bits odd", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &const_exp_data.bits_512.base,
                &exponent_3,
                &const_exp_data.bits_512.modulus_odd,
            ))
        })
    });
    group_exp_3.bench_function("1024 bits odd", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &const_exp_data.bits_1024.base,
                &exponent_3,
                &const_exp_data.bits_1024.modulus_odd,
            ))
        })
    });
    group_exp_3.finish();

    // --- Benchmark Group for Exponent 65537 ---
    let mut group_exp_65537 = c.benchmark_group("Exponent 65537");
    let exponent_65537 = [1, 0, 1];

    group_exp_65537.bench_function("2048 bits odd", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &const_exp_data.bits_2048.base,
                &exponent_65537,
                &const_exp_data.bits_2048.modulus_odd,
            ))
        })
    });
    group_exp_65537.bench_function("4096 bits odd", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &const_exp_data.bits_4096.base,
                &exponent_65537,
                &const_exp_data.bits_4096.modulus_odd,
            ))
        })
    });
    group_exp_65537.finish();

    // --- Benchmark Group for Variable Exponents ---
    let mut group_variable = c.benchmark_group("Variable Exponents");
    let var_exp_data = &data.variable_exponents;

    group_variable.bench_function("512-bit exp, 512-bit mod", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &var_exp_data.bits_512.base,
                &var_exp_data.bits_512.exponent,
                &var_exp_data.bits_512.modulus,
            ))
        })
    });
    group_variable.bench_function("1024-bit exp, 1024-bit mod", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &var_exp_data.bits_1024.base,
                &var_exp_data.bits_1024.exponent,
                &var_exp_data.bits_1024.modulus,
            ))
        })
    });
    group_variable.bench_function("2048-bit exp, 2048-bit mod", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &var_exp_data.bits_2048.base,
                &var_exp_data.bits_2048.exponent,
                &var_exp_data.bits_2048.modulus,
            ))
        })
    });
    group_variable.bench_function("4096-bit exp, 4096-bit mod", |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                &var_exp_data.bits_4096.base,
                &var_exp_data.bits_4096.exponent,
                &var_exp_data.bits_4096.modulus,
            ))
        })
    });
    group_variable.finish();

    // --- Benchmark Group for SIMD-0529 Modulus Size Buckets ---
    let mut group_buckets = c.benchmark_group("SIMD-0529 Modulus Size Buckets");
    for (bucket, modulus_len) in SIMD_0529_MODULUS_BUCKETS {
        let set = simd_0529_bucket_set(modulus_len);
        group_buckets.bench_function(format!("{bucket} modulus, base, and exponent"), |b| {
            b.iter(|| {
                black_box(big_mod_exp(
                    black_box(&set.base),
                    black_box(&set.exponent),
                    black_box(&set.modulus),
                ))
            })
        });
    }
    group_buckets.finish();
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
