use {
    criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput},
    solana_short_vec::ShortU16,
    std::hint::black_box,
    wincode::{deserialize, serialize, serialize_into},
};

fn bench_short_u16_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ShortU16");

    let cases = [
        (0x7f_u16, &[0x7f][..]),
        (0x3fff_u16, &[0xff, 0x7f][..]),
        (0xffff_u16, &[0xff, 0xff, 0x03][..]),
    ];

    let mut ser_buffer = [0u8; 3];
    for (val, bytes) in cases {
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("solana_short_vec:decode_shortu16_len", val),
            &bytes,
            |b, bytes| b.iter(|| solana_short_vec::decode_shortu16_len(black_box(bytes)).unwrap()),
        );

        let short_u16 = ShortU16(val);
        let serialized = bincode::serialize(&short_u16).unwrap();
        assert_eq!(serialize(&short_u16).unwrap(), serialized);
        assert_eq!(
            deserialize::<ShortU16>(&serialized).unwrap().0,
            bincode::deserialize::<ShortU16>(&serialized).unwrap().0
        );

        group.bench_with_input(
            BenchmarkId::new("wincode:serialize", val),
            &short_u16,
            |b, s| {
                b.iter(|| {
                    serialize_into(black_box(&mut ser_buffer.as_mut_slice()), black_box(s)).unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("bincode:serialize", val),
            &short_u16,
            |b, s| {
                b.iter(|| {
                    bincode::serialize_into(black_box(&mut ser_buffer.as_mut_slice()), black_box(s))
                        .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("wincode:deserialize", val),
            &serialized,
            |b, s| b.iter(|| deserialize::<ShortU16>(black_box(s)).unwrap()),
        );

        group.bench_with_input(
            BenchmarkId::new("bincode:deserialize", val),
            &serialized,
            |b, s| b.iter(|| bincode::deserialize::<ShortU16>(black_box(s)).unwrap()),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_short_u16_comparison);
criterion_main!(benches);
