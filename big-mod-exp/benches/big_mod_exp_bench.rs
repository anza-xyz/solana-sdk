use {
    criterion::{
        black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup,
        Criterion,
    },
    solana_big_mod_exp::{
        big_mod_exp, BIG_MOD_EXP_BASE_CU, BIG_MOD_EXP_CU_DIVISOR, BIG_MOD_EXP_MIN_EXPONENT_LENGTH,
    },
};

const SIMD_0529_OPERAND_SIZES: [(&str, usize); 12] = [
    ("32-bit", 4),
    ("64-bit", 8),
    ("128-bit", 16),
    ("256-bit", 32),
    ("384-bit", 48),
    ("512-bit", 64),
    ("768-bit", 96),
    ("1024-bit", 128),
    ("1536-bit", 192),
    ("2048-bit", 256),
    ("3072-bit", 384),
    ("4096-bit", 512),
];

const RSA_OPERAND_SIZES: [(&str, usize); 3] =
    [("2048-bit", 256), ("3072-bit", 384), ("4096-bit", 512)];

const EXPONENT_SWEEP_SIZES: [usize; 9] = [0, 1, 3, 32, 33, 64, 128, 256, 512];

struct BenchCase {
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

fn simd_0529_case(modulus_len: usize, exponent: Vec<u8>, seed: u64) -> BenchCase {
    let mut base = deterministic_bytes(modulus_len, modulus_len as u64);
    base[0] |= 2;
    *base.last_mut().expect("modulus lengths are non-empty") &= 0x7f;

    let mut modulus = deterministic_bytes(modulus_len, seed);
    modulus[0] |= 1;
    *modulus.last_mut().expect("modulus lengths are non-empty") |= 0x80;

    BenchCase {
        base,
        exponent,
        modulus,
    }
}

fn dense_exponent(exponent_len: usize) -> Vec<u8> {
    vec![0xff; exponent_len]
}

fn rsa_65537_exponent() -> Vec<u8> {
    vec![1, 0, 1]
}

fn mult_complexity(x: u64) -> u64 {
    if x <= 64 {
        x.saturating_mul(x)
    } else if x <= 1024 {
        x.saturating_mul(x) / 4 + 96 * x - 3072
    } else {
        x.saturating_mul(x) / 16 + 480 * x - 199_680
    }
}

fn highest_set_bit_index_le(bytes: &[u8]) -> Option<u64> {
    bytes
        .iter()
        .enumerate()
        .rev()
        .find_map(|(byte_index, byte)| {
            (*byte != 0).then(|| byte_index as u64 * 8 + u64::from(7 - byte.leading_zeros()))
        })
}

fn adjusted_exponent_length(exponent: &[u8]) -> u64 {
    if exponent.len() <= 32 {
        highest_set_bit_index_le(exponent).unwrap_or(0)
    } else {
        let most_significant_32_bytes = &exponent[exponent.len() - 32..];
        8 * (exponent.len() as u64 - 32)
            + highest_set_bit_index_le(most_significant_32_bytes).unwrap_or(0)
    }
}

fn compute_units(modulus_len: usize, exponent: &[u8]) -> u64 {
    let effective_exponent_length =
        adjusted_exponent_length(exponent).max(BIG_MOD_EXP_MIN_EXPONENT_LENGTH);
    let operation_complexity = mult_complexity(modulus_len as u64) * effective_exponent_length;
    BIG_MOD_EXP_BASE_CU + operation_complexity.div_ceil(BIG_MOD_EXP_CU_DIVISOR)
}

fn bench_label(case_name: &str, size_name: &str, case: &BenchCase) -> String {
    format!(
        "{case_name}/{size_name}/modulus_len={}B/exponent_len={}B/adjusted_exp_len={}/model_cu={}",
        case.modulus.len(),
        case.exponent.len(),
        adjusted_exponent_length(&case.exponent),
        compute_units(case.modulus.len(), &case.exponent),
    )
}

fn bench_case(group: &mut BenchmarkGroup<'_, WallTime>, label: String, case: BenchCase) {
    group.bench_function(label, |b| {
        b.iter(|| {
            black_box(big_mod_exp(
                black_box(&case.base),
                black_box(&case.exponent),
                black_box(&case.modulus),
            ))
        })
    });
}

fn all_benches(c: &mut Criterion) {
    let mut group_balanced = c.benchmark_group("SIMD-0529 balanced dense");
    for (size_name, modulus_len) in SIMD_0529_OPERAND_SIZES {
        let case = simd_0529_case(
            modulus_len,
            dense_exponent(modulus_len),
            (modulus_len as u64).reverse_bits(),
        );
        bench_case(
            &mut group_balanced,
            bench_label("balanced-dense", size_name, &case),
            case,
        );
    }
    group_balanced.finish();

    let mut group_rsa = c.benchmark_group("SIMD-0529 RSA-style 65537");
    for (size_name, modulus_len) in RSA_OPERAND_SIZES {
        let case = simd_0529_case(
            modulus_len,
            rsa_65537_exponent(),
            0x65537 ^ modulus_len as u64,
        );
        bench_case(
            &mut group_rsa,
            bench_label("rsa-65537", size_name, &case),
            case,
        );
    }
    group_rsa.finish();

    let mut group_modulus = c.benchmark_group("SIMD-0529 modulus-driven dense exponent");
    for (size_name, modulus_len) in SIMD_0529_OPERAND_SIZES {
        let case = simd_0529_case(modulus_len, dense_exponent(64), 0x5eed ^ modulus_len as u64);
        bench_case(
            &mut group_modulus,
            bench_label("modulus-driven", size_name, &case),
            case,
        );
    }
    group_modulus.finish();

    let mut group_exponent = c.benchmark_group("SIMD-0529 exponent-driven 4096-bit modulus");
    for exponent_len in EXPONENT_SWEEP_SIZES {
        let case = simd_0529_case(
            512,
            dense_exponent(exponent_len),
            0xe991_0529 ^ exponent_len as u64,
        );
        bench_case(
            &mut group_exponent,
            bench_label(
                "exponent-driven",
                &format!("{exponent_len}B exponent"),
                &case,
            ),
            case,
        );
    }
    group_exponent.finish();
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
