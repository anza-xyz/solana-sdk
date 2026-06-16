use {
    criterion::{
        black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup,
        Criterion,
    },
    solana_big_mod_exp::{
        big_mod_exp, BIG_MOD_EXP_BASE_CU, BIG_MOD_EXP_CU_DIVISOR, BIG_MOD_EXP_MIN_EXPONENT_LENGTH,
        BIG_MOD_EXP_MOD_REDUCTION_COMPLEXITY_FACTOR,
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

const MOD_REDUCTION_SIZES: [(&str, usize, usize); 8] = [
    ("64-bit base, 32-bit modulus", 8, 4),
    ("128-bit base, 64-bit modulus", 16, 8),
    ("256-bit base, 128-bit modulus", 32, 16),
    ("384-bit base, 192-bit modulus", 48, 24),
    ("512-bit base, 256-bit modulus", 64, 32),
    ("1024-bit base, 512-bit modulus", 128, 64),
    ("2048-bit base, 1024-bit modulus", 256, 128),
    ("4096-bit base, 2048-bit modulus", 512, 256),
];

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

fn mod_reduction_case(base_len: usize, modulus_len: usize, seed: u64) -> BenchCase {
    let mut base = deterministic_bytes(base_len, seed ^ base_len as u64);
    if let Some(last_byte) = base.last_mut() {
        *last_byte |= 0x80;
    }

    let mut modulus = deterministic_bytes(modulus_len, seed ^ modulus_len as u64);
    modulus[0] |= 1;
    *modulus.last_mut().expect("modulus lengths are non-empty") |= 0x80;

    BenchCase {
        base,
        exponent: vec![1],
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
    let x_squared = x.checked_mul(x).expect("modulus length square fits in u64");
    if x <= 64 {
        x_squared
    } else if x <= 1024 {
        x_squared
            .checked_div(4)
            .expect("divisor is nonzero")
            .checked_add(
                96_u64
                    .checked_mul(x)
                    .expect("linear complexity term fits in u64"),
            )
            .expect("complexity terms fit in u64")
            .checked_sub(3_072)
            .expect("complexity offset is valid for this branch")
    } else {
        x_squared
            .checked_div(16)
            .expect("divisor is nonzero")
            .checked_add(
                480_u64
                    .checked_mul(x)
                    .expect("linear complexity term fits in u64"),
            )
            .expect("complexity terms fit in u64")
            .checked_sub(199_680)
            .expect("complexity offset is valid for this branch")
    }
}

fn highest_set_bit_index_le(bytes: &[u8]) -> Option<u64> {
    bytes
        .iter()
        .enumerate()
        .rev()
        .find_map(|(byte_index, byte)| {
            (*byte != 0).then(|| {
                let byte_bit_offset = (byte_index as u64)
                    .checked_mul(8)
                    .expect("byte index bit offset fits in u64");
                let bit_index_in_byte = 7_u32
                    .checked_sub(byte.leading_zeros())
                    .expect("nonzero byte leading zeros are at most 7");
                byte_bit_offset
                    .checked_add(u64::from(bit_index_in_byte))
                    .expect("highest set bit index fits in u64")
            })
        })
}

fn is_one_le(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(1)) && bytes[1..].iter().all(|byte| *byte == 0)
}

fn adjusted_exponent_length(exponent: &[u8]) -> u64 {
    if exponent.len() <= 32 {
        highest_set_bit_index_le(exponent).unwrap_or(0)
    } else {
        let trailing_bytes = exponent
            .len()
            .checked_sub(32)
            .expect("exponent length is greater than 32");
        let most_significant_32_bytes = &exponent[trailing_bytes..];
        (trailing_bytes as u64)
            .checked_mul(8)
            .expect("trailing byte bit length fits in u64")
            .checked_add(highest_set_bit_index_le(most_significant_32_bytes).unwrap_or(0))
            .expect("adjusted exponent length fits in u64")
    }
}

fn mod_reduce_complexity(base_len: usize, modulus_len: usize) -> u64 {
    mult_complexity(base_len.max(modulus_len) as u64)
        .checked_mul(BIG_MOD_EXP_MOD_REDUCTION_COMPLEXITY_FACTOR)
        .expect("modular reduction complexity fits in u64")
}

fn mod_reduce_compute_units(base_len: usize, modulus_len: usize) -> u64 {
    BIG_MOD_EXP_BASE_CU
        .checked_add(mod_reduce_complexity(base_len, modulus_len).div_ceil(BIG_MOD_EXP_CU_DIVISOR))
        .expect("compute unit cost fits in u64")
}

fn compute_units(base_len: usize, modulus_len: usize, exponent: &[u8]) -> u64 {
    if is_one_le(exponent) {
        return mod_reduce_compute_units(base_len, modulus_len);
    }

    let effective_exponent_length =
        adjusted_exponent_length(exponent).max(BIG_MOD_EXP_MIN_EXPONENT_LENGTH);
    let operation_complexity = mult_complexity(base_len.max(modulus_len) as u64)
        .checked_mul(effective_exponent_length)
        .expect("operation complexity fits in u64");
    BIG_MOD_EXP_BASE_CU
        .checked_add(operation_complexity.div_ceil(BIG_MOD_EXP_CU_DIVISOR))
        .expect("compute unit cost fits in u64")
}

fn bench_label(case_name: &str, size_name: &str, case: &BenchCase) -> String {
    format!(
        "{case_name}/{size_name}/modulus_len={}B/exponent_len={}B/adjusted_exp_len={}/model_cu={}",
        case.modulus.len(),
        case.exponent.len(),
        adjusted_exponent_length(&case.exponent),
        compute_units(case.base.len(), case.modulus.len(), &case.exponent),
    )
}

fn mod_reduce_bench_label(size_name: &str, case: &BenchCase) -> String {
    format!(
        "mod-reduce/{size_name}/base_len={}B/modulus_len={}B/model_cu={}",
        case.base.len(),
        case.modulus.len(),
        mod_reduce_compute_units(case.base.len(), case.modulus.len()),
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

    let mut group_reduction = c.benchmark_group("SIMD-0529 modular reduction exponent 1");
    for (size_name, base_len, modulus_len) in MOD_REDUCTION_SIZES {
        let case = mod_reduction_case(base_len, modulus_len, 0x0529_0001 ^ base_len as u64);
        bench_case(
            &mut group_reduction,
            mod_reduce_bench_label(size_name, &case),
            case,
        );
    }
    group_reduction.finish();
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
