use {
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput},
    rand::{
        distr::{uniform::SampleUniform, StandardUniform},
        Rng,
    },
    solana_serde_varint::wincode::Leb128Int,
    wincode::Serialize,
};

const BATCH: usize = 1_000;

fn bench_write<T>(c: &mut Criterion, type_name: &str)
where
    T: Copy + From<u8> + PartialOrd + SampleUniform,
    StandardUniform: rand::distr::Distribution<T>,
    Leb128Int<T>: Serialize<Src = T>,
{
    let mut rng = rand::rng();
    // Small: fit in one byte (< 0x80 = single-byte LEB128 encoding).
    let small: Vec<T> = (0..BATCH)
        .map(|_| rng.random_range(T::from(0)..T::from(0x80)))
        .collect();
    // Random: uniform across the full type range.
    let random: Vec<T> = (0..BATCH).map(|_| rng.random()).collect();

    let mut write_buf = vec![0u8; BATCH * 10 /* max size used per any serialized int */];

    let mut group = c.benchmark_group("leb128_write");
    group.throughput(Throughput::Elements(BATCH as u64));

    group.bench_function(BenchmarkId::new(type_name, "small"), |b| {
        b.iter(|| {
            let mut buf = write_buf.as_mut_slice();
            for v in &small {
                <Leb128Int<T>>::serialize_into(black_box(&mut buf), black_box(v)).unwrap();
            }
            black_box(&write_buf);
        })
    });

    group.bench_function(BenchmarkId::new(type_name, "random"), |b| {
        b.iter(|| {
            let mut buf = write_buf.as_mut_slice();
            for v in &random {
                <Leb128Int<T>>::serialize_into(&mut buf, black_box(v)).unwrap();
            }
            black_box(&write_buf);
        })
    });

    group.finish();
}

fn bench_write_u16(c: &mut Criterion) {
    bench_write::<u16>(c, "u16");
}

fn bench_write_u32(c: &mut Criterion) {
    bench_write::<u32>(c, "u32");
}

fn bench_write_u64(c: &mut Criterion) {
    bench_write::<u64>(c, "u64");
}

criterion_group!(benches, bench_write_u16, bench_write_u32, bench_write_u64);
criterion_main!(benches);
