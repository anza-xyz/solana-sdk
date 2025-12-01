use {
    bitvec::prelude::*,
    criterion::{criterion_group, criterion_main, BenchmarkId, Criterion},
    rand::{rngs::ThreadRng, Rng},
    solana_signer_store::{decode, encode_base2, encode_base3, Decoded},
    std::iter,
};

/// Creates a single BitVec with pseudo-random data for Base2 benchmarking.
fn create_test_data_base2(rng: &mut ThreadRng, len: usize) -> BitVec<u8, Lsb0> {
    iter::repeat_with(|| rng.random_bool(0.5))
        .take(len)
        .collect()
}

/// Creates two BitVecs with a uniform distribution of valid Base3 pairs.
fn create_test_data_base3_uniform(len: usize) -> (BitVec<u8, Lsb0>, BitVec<u8, Lsb0>) {
    let mut base = BitVec::with_capacity(len);
    let mut fallback = BitVec::with_capacity(len);
    for i in 0..len {
        match i % 3 {
            0 => {
                base.push(false);
                fallback.push(false);
            }
            1 => {
                base.push(true);
                fallback.push(false);
            }
            _ => {
                base.push(false);
                fallback.push(true);
            }
        }
    }
    (base, fallback)
}

/// Creates two sparse BitVecs, where most pairs are (false, false).
fn create_test_data_base3_sparse(len: usize) -> (BitVec<u8, Lsb0>, BitVec<u8, Lsb0>) {
    let mut base = BitVec::with_capacity(len);
    let mut fallback = BitVec::with_capacity(len);
    for i in 0..len {
        // ~10% chance of being non-zero
        if i % 10 == 1 {
            base.push(true);
            fallback.push(false);
        } else {
            base.push(false);
            fallback.push(false);
        }
    }
    (base, fallback)
}

/// Benchmarks the Base2 encoding scheme.
fn bench_base2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Base2_Encoding");
    let mut rng = rand::rng();

    for size in [256, 512, 1024, 2048, 4096, 8192].iter() {
        let bit_vec = create_test_data_base2(&mut rng, *size);
        let encoded = encode_base2(&bit_vec).unwrap();

        group.bench_with_input(BenchmarkId::new("encode", size), size, |b, _| {
            b.iter(|| encode_base2(&bit_vec).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decode", size), size, |b, _| {
            b.iter(|| {
                let decoded = decode(&encoded, *size).unwrap();
                assert!(matches!(decoded, Decoded::Base2(_)));
            });
        });
    }
    group.finish();
}

/// Benchmarks the Base3 encoding scheme.
fn bench_base3(c: &mut Criterion) {
    let mut group = c.benchmark_group("Base3_Encoding");

    for size in [256, 512, 1024, 2048, 4096, 8192].iter() {
        // Benchmark for standard, uniformly distributed data
        let (base, fallback) = create_test_data_base3_uniform(*size);
        let encoded = encode_base3(&base, &fallback).unwrap();

        group.bench_with_input(BenchmarkId::new("encode_uniform", size), size, |b, _| {
            b.iter(|| encode_base3(&base, &fallback).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decode_uniform", size), size, |b, _| {
            b.iter(|| {
                let decoded = decode(&encoded, *size).unwrap();
                assert!(matches!(decoded, Decoded::Base3(_, _)));
            });
        });

        // Benchmark for sparse data
        let (base_sparse, fallback_sparse) = create_test_data_base3_sparse(*size);
        let encoded_sparse = encode_base3(&base_sparse, &fallback_sparse).unwrap();

        group.bench_with_input(BenchmarkId::new("encode_sparse", size), size, |b, _| {
            b.iter(|| encode_base3(&base_sparse, &fallback_sparse).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("decode_sparse", size), size, |b, _| {
            b.iter(|| {
                let decoded = decode(&encoded_sparse, *size).unwrap();
                assert!(matches!(decoded, Decoded::Base3(_, _)));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_base2, bench_base3);
criterion_main!(benches);
