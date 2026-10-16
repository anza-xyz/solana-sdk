//! Where the time actually goes inside the cheap curve25519 syscalls.
//!
//! `sol_curve_validate_point` and the `ADD`/`SUB` cases of
//! `sol_curve_group_op` take compressed points and return compressed points, so
//! each call pays for point decompression (a field square root) and point
//! compression (a field inversion) around a group operation that is orders of
//! magnitude cheaper. This benchmark separates those three costs, and measures
//! the batched compression that a batching syscall could amortize.

use {
    criterion::{black_box, criterion_group, criterion_main, Criterion},
    solana_ed25519::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    },
};

const BATCH_LENS: [usize; 4] = [1, 8, 64, 512];

fn deterministic_scalar(seed: u64) -> Scalar {
    let mut state = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 56) as u8;
    }
    Scalar::from_bytes_mod_order(bytes)
}

fn point(seed: u64) -> EdwardsPoint {
    EdwardsPoint::mul_base(&deterministic_scalar(seed))
}

fn all_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("edwards cost breakdown");

    let left_point = point(1);
    let right_point = point(2);
    let left_bytes = left_point.compress();

    // The two field exponentiations the syscall ABI forces on every call.
    group.bench_function("decompress (field sqrt)", |b| {
        b.iter(|| black_box(black_box(&left_bytes).decompress()))
    });
    group.bench_function("compress (field inversion)", |b| {
        b.iter(|| black_box(black_box(&left_point).compress()))
    });

    // The group operations themselves, on points that are already decompressed.
    group.bench_function("add (extended coordinates)", |b| {
        b.iter(|| black_box(black_box(&left_point) + black_box(&right_point)))
    });
    group.bench_function("subtract (extended coordinates)", |b| {
        b.iter(|| black_box(black_box(&left_point) - black_box(&right_point)))
    });

    // What a batching syscall could amortize: one field inversion for the whole
    // batch instead of one per point.
    let points: Vec<EdwardsPoint> = (0..*BATCH_LENS.last().expect("batch lens are non-empty"))
        .map(|index| point(0xba7c4 ^ index as u64))
        .collect();
    for batch_len in BATCH_LENS {
        group.bench_function(format!("compress_batch/len={batch_len}"), |b| {
            b.iter(|| {
                black_box(EdwardsPoint::compress_batch(black_box(
                    &points[..batch_len],
                )))
            })
        });
    }

    // For reference, decompressing the same batch one point at a time, which is
    // what a batching syscall would still have to do without an uncompressed
    // input representation.
    let compressed: Vec<CompressedEdwardsY> = points.iter().map(EdwardsPoint::compress).collect();
    for batch_len in BATCH_LENS {
        group.bench_function(format!("decompress_each/len={batch_len}"), |b| {
            b.iter(|| {
                black_box(
                    black_box(&compressed[..batch_len])
                        .iter()
                        .map(CompressedEdwardsY::decompress)
                        .collect::<Vec<_>>(),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
