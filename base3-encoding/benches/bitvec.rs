use {
    bitvec::prelude::*,
    criterion::{criterion_group, criterion_main, BenchmarkId, Criterion},
    solana_base3_encoding::{decode, encode},
};

fn create_test_data_bitvec(len: usize) -> (BitVec<u8, Lsb0>, BitVec<u8, Lsb0>) {
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

fn bench_bitvec(c: &mut Criterion) {
    let mut group = c.benchmark_group("BitVec");
    for size in [256, 512, 1024, 2048, 4096, 8192].iter() {
        let (base, fallback) = create_test_data_bitvec(*size);
        let encoded = encode(&base, &fallback).unwrap();

        group.bench_with_input(BenchmarkId::new("encode", size), size, |b, _| {
            b.iter(|| encode(&base, &fallback).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("decode", size), size, |b, _| {
            b.iter(|| decode(&encoded, *size).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_bitvec);
criterion_main!(benches);
