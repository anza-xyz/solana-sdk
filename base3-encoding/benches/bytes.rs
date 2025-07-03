use {
    criterion::{criterion_group, criterion_main, BenchmarkId, Criterion},
    solana_base3_encoding::{decode_to_bytes, encode_from_bytes},
};

fn create_test_data_bytes(len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut base = vec![0u8; (len + 7) / 8];
    let mut fallback = vec![0u8; (len + 7) / 8];
    for i in 0..len {
        match i % 3 {
            0 => { /* (false, false) */ }
            1 => base[i / 8] |= 1 << (i % 8),
            _ => fallback[i / 8] |= 1 << (i % 8),
        }
    }
    (base, fallback)
}

fn bench_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bytes");
    for size in [256, 512, 1024, 2048, 4096, 8192].iter() {
        let (base_bytes, fallback_bytes) = create_test_data_bytes(*size);
        let encoded = encode_from_bytes(&base_bytes, &fallback_bytes, *size).unwrap();

        group.bench_with_input(BenchmarkId::new("encode", size), size, |b, _| {
            b.iter(|| encode_from_bytes(&base_bytes, &fallback_bytes, *size).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("decode", size), size, |b, _| {
            b.iter(|| decode_to_bytes(&encoded, *size).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_bytes);
criterion_main!(benches);
